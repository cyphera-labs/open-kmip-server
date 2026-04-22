package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cyphera-labs/open-kmip-server/internal/api"
	"github.com/cyphera-labs/open-kmip-server/internal/audit"
	"github.com/cyphera-labs/open-kmip-server/internal/devcerts"
	"github.com/cyphera-labs/open-kmip-server/internal/kmip"
	"github.com/cyphera-labs/open-kmip-server/internal/storage"
)

func main() {
	devMode := flag.Bool("dev", false, "Dev mode: auto-generate self-signed certs + API key")
	host := flag.String("host", "0.0.0.0", "Listen address")
	port := flag.Int("port", 5696, "KMIP listen port")
	apiPort := flag.Int("api-port", 8200, "REST API listen port (0 to disable)")
	apiKey := flag.String("api-key", "", "REST API key (or set KMIP_API_KEY env var)")
	corsOrigin := flag.String("cors-origin", "", "Allowed CORS origin")
	certFile := flag.String("cert", "", "Server certificate PEM")
	keyFile := flag.String("key", "", "Server private key PEM")
	caFile := flag.String("ca", "", "CA certificate PEM (required for mTLS)")
	insecureNoMTLS := flag.Bool("insecure-no-mtls", false, "DANGER: disable mTLS client auth (dev only)")
	storageType := flag.String("storage", "sqlite", "Storage backend: memory or sqlite")
	dbPath := flag.String("db", "open-kmip.db", "SQLite database path")
	flag.Parse()

	// API key from env var
	if envKey := os.Getenv("KMIP_API_KEY"); envKey != "" && *apiKey == "" {
		*apiKey = envKey
	}

	if *devMode {
		setupDevMode(certFile, keyFile, caFile, apiKey)
	} else {
		// C6 fix: require mTLS unless explicitly opted out
		if *caFile == "" && !*insecureNoMTLS {
			log.Fatal("FATAL: --ca is required for mTLS.\n" +
				"  Use --dev for development with auto-generated certs.\n" +
				"  Use --insecure-no-mtls to disable client auth (NOT for production).")
		}
		if *insecureNoMTLS {
			log.Println("WARNING: mTLS disabled — any TLS client can connect. NOT FOR PRODUCTION.")
		}
		if *certFile == "" || *keyFile == "" {
			log.Fatal("FATAL: --cert and --key are required.\n" +
				"  Use --dev for development with auto-generated certs.")
		}
		// C3 fix: require API key when REST API is enabled
		if *apiKey == "" && *apiPort > 0 {
			log.Fatal("FATAL: --api-key (or KMIP_API_KEY) is required when REST API is enabled.\n" +
				"  Use --dev for development with auto-generated API key.\n" +
				"  Use --api-port 0 to disable the REST API.")
		}
	}

	// Storage
	var store storage.Storage
	var auditLog *audit.Logger

	if *storageType == "memory" && !*devMode {
		log.Fatal("FATAL: --storage memory disables audit and is only allowed with --dev.\n" +
			"  Use --storage sqlite for evaluation/alpha use.")
	}

	switch *storageType {
	case "memory":
		store = storage.NewMemoryStore()
		log.Println("using in-memory storage (audit disabled)")
	case "sqlite":
		s, err := storage.NewSQLiteStore(*dbPath)
		if err != nil {
			log.Fatalf("failed to open SQLite store: %v", err)
		}
		store = s
		auditLog = audit.NewLogger(s.DB())
		log.Printf("using SQLite storage: %s", *dbPath)
	default:
		log.Fatalf("unknown storage type: %s", *storageType)
	}
	defer store.Close()
	if auditLog != nil {
		defer auditLog.Close()
	}

	tracker := kmip.NewConnectionTracker()

	// Start REST API
	if *apiPort > 0 {
		a := api.NewAPI(store, *apiKey, *corsOrigin, *certFile, *keyFile, auditLog, tracker, *devMode)
		apiAddr := fmt.Sprintf("%s:%d", *host, *apiPort)
		go func() {
			if err := a.Serve(apiAddr); err != nil {
				log.Fatalf("REST API error: %v", err)
			}
		}()
	}

	// Start KMIP server
	handler := kmip.NewHandler(store, auditLog, tracker)
	server, err := kmip.NewServer(*host, *port, *certFile, *keyFile, *caFile, handler, tracker)
	if err != nil {
		log.Fatalf("failed to create KMIP server: %v", err)
	}

	listenerMode := "mTLS"
	if *insecureNoMTLS {
		listenerMode = "TLS, client auth disabled"
	}
	log.Printf("Cyphera Open KMIP Server")
	log.Printf("  KMIP:    %s:%d (%s)", *host, *port, listenerMode)
	if *apiPort > 0 {
		log.Printf("  REST:    %s:%d (TLS)", *host, *apiPort)
	}
	log.Printf("  Storage: %s", *storageType)

	if err := server.Serve(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func setupDevMode(certFile, keyFile, caFile, apiKey *string) {
	log.Println("========================================")
	log.Println("  DEV MODE — NOT FOR PRODUCTION")
	log.Println("========================================")

	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	certDir := filepath.Join(home, ".open-kmip", "certs")

	caCertPath := filepath.Join(certDir, "ca.pem")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		log.Println("Generating self-signed certificates...")
		certs, err := devcerts.Generate(certDir)
		if err != nil {
			log.Fatalf("failed to generate dev certs: %v", err)
		}
		*certFile = certs.ServerCert
		*keyFile = certs.ServerKey
		*caFile = certs.CACert
		if *apiKey == "" {
			*apiKey = certs.APIKey
		}
		log.Printf("  Client cert: %s", certs.ClientCert)
		log.Printf("  Client key:  %s", certs.ClientKey)
		log.Printf("  CA cert:     %s", certs.CACert)
		log.Printf("  API key:     %s", *apiKey)
	} else {
		*certFile = filepath.Join(certDir, "server.pem")
		*keyFile = filepath.Join(certDir, "server-key.pem")
		*caFile = caCertPath
		if *apiKey == "" {
			certs, _ := devcerts.Generate(os.TempDir())
			*apiKey = certs.APIKey
		}
		log.Printf("Reusing dev certs from %s", certDir)
		log.Printf("  API key: %s", *apiKey)
	}
}
