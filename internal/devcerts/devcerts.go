package devcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Certs holds paths to auto-generated dev mode certificates.
type Certs struct {
	CACert     string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
	APIKey     string
}

// Generate creates a self-signed CA, server cert, and client cert for development.
func Generate(dir string) (*Certs, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create cert directory: %w", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KMIP Dev CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, _ := x509.ParseCertificate(caCertDER)

	caCertPath := filepath.Join(dir, "ca.pem")
	writePEM(caCertPath, "CERTIFICATE", caCertDER)

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "kmip-server"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
	}
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)

	serverCertPath := filepath.Join(dir, "server.pem")
	writePEM(serverCertPath, "CERTIFICATE", serverCertDER)
	serverKeyPath := filepath.Join(dir, "server-key.pem")
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	writePEM(serverKeyPath, "EC PRIVATE KEY", serverKeyDER)

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "dev-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)

	clientCertPath := filepath.Join(dir, "client.pem")
	writePEM(clientCertPath, "CERTIFICATE", clientCertDER)
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	writePEM(clientKeyPath, "EC PRIVATE KEY", clientKeyDER)

	apiKeyBytes := make([]byte, 24)
	rand.Read(apiKeyBytes)

	return &Certs{
		CACert:     caCertPath,
		ServerCert: serverCertPath,
		ServerKey:  serverKeyPath,
		ClientCert: clientCertPath,
		ClientKey:  clientKeyPath,
		APIKey:     "dev-" + hex.EncodeToString(apiKeyBytes)[:32],
	}, nil
}

func writePEM(path, blockType string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}
