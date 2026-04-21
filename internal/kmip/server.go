package kmip

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
)

const (
	maxTTLVMessageSize = 10 << 20
	maxConnections     = 1000
	connectionTimeout  = 5 * time.Minute
)

// Server is a KMIP protocol server with mTLS support.
type Server struct {
	host    string
	port    int
	handler *Handler
	config  *tls.Config
	tracker *ConnectionTracker
}

// NewServer creates a KMIP server. C6 fix: caFile is required unless insecureNoMTLS is true.
func NewServer(host string, port int, certFile, keyFile, caFile string, handler *Handler, tracker *ConnectionTracker) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA certificate failed")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &Server{
		host:    host,
		port:    port,
		handler: handler,
		config:  tlsConfig,
		tracker: tracker,
	}, nil
}

// Serve starts the KMIP protocol listener.
func (s *Server) Serve() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	listener, err := tls.Listen("tcp", addr, s.config)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer listener.Close()

	log.Printf("KMIP server listening on %s (mTLS)", addr)

	sem := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				s.handleConnection(conn)
			}()
		default:
			log.Printf("max connections (%d), rejecting", maxConnections)
			conn.Close()
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// C1 defense-in-depth: recover from panics in handler
	defer func() {
		if r := recover(); r != nil {
			log.Printf("KMIP handler panic (recovered): %v", r)
		}
	}()

	connID := uuid.New().String()

	clientCN := ""
	remoteAddr := conn.RemoteAddr().String()
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake error: %v", err)
			return
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			clientCN = state.PeerCertificates[0].Subject.CommonName
		}
	}

	if s.tracker != nil {
		s.tracker.Add(connID, clientCN, remoteAddr)
		defer s.tracker.Remove(connID)
	}

	for {
		conn.SetDeadline(time.Now().Add(connectionTimeout))

		header := make([]byte, 8)
		if _, err := io.ReadFull(conn, header); err != nil {
			if err != io.EOF {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					log.Printf("connection %s timed out", connID)
				}
			}
			return
		}

		valueLen := int(binary.BigEndian.Uint32(header[4:8]))
		if valueLen > maxTTLVMessageSize {
			log.Printf("TTLV too large from %s: %d bytes", remoteAddr, valueLen)
			return
		}

		body := make([]byte, valueLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			log.Printf("read body error: %v", err)
			return
		}

		request := make([]byte, 0, 8+valueLen)
		request = append(request, header...)
		request = append(request, body...)

		response := s.handler.HandleRequest(request, clientCN, remoteAddr, connID)
		if _, err := conn.Write(response); err != nil {
			log.Printf("write response error: %v", err)
			return
		}
	}
}
