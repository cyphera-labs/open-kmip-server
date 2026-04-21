package api

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	kmiplib "github.com/cyphera-labs/kmip-go"
	"github.com/cyphera-labs/open-kmip-server/internal/audit"
	"github.com/cyphera-labs/open-kmip-server/internal/dashboard"
	"github.com/cyphera-labs/open-kmip-server/internal/kmip"
	"github.com/cyphera-labs/open-kmip-server/internal/storage"
	"golang.org/x/crypto/chacha20poly1305"
)

const maxRequestBodySize = 1 << 20

// H4 fix: per-IP rate limiter
type ipRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rateBucket
}

type rateBucket struct {
	tokens   int
	lastSeen time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{visitors: make(map[string]*rateBucket)}
}

func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.visitors[ip]
	if !ok {
		rl.visitors[ip] = &rateBucket{tokens: 99, lastSeen: now} // 100/min, just used 1
		return true
	}

	// Refill tokens: 100 per minute
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += int(elapsed * (100.0 / 60.0))
	if b.tokens > 100 {
		b.tokens = 100
	}
	b.lastSeen = now

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// API is the REST API server.
type API struct {
	store      storage.Storage
	audit      *audit.Logger
	apiKey     string
	corsOrigin string
	certFile   string
	keyFile    string
	start      time.Time
	tracker    *kmip.ConnectionTracker
	rateLimiter *ipRateLimiter
}

// NewAPI creates a REST API server.
func NewAPI(store storage.Storage, apiKey, corsOrigin, certFile, keyFile string, auditLog *audit.Logger, tracker *kmip.ConnectionTracker) *API {
	return &API{
		store:       store,
		audit:       auditLog,
		apiKey:      apiKey,
		corsOrigin:  corsOrigin,
		certFile:    certFile,
		keyFile:     keyFile,
		start:       time.Now(),
		tracker:     tracker,
		rateLimiter: newIPRateLimiter(),
	}
}

func (a *API) logAudit(r *http.Request, operation, objectUID, objectName, status, message string) {
	if a.audit == nil {
		return
	}
	clientID := ""
	if a.apiKey != "" {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(token) >= 8 {
			clientID = token[:8] + "..."
		}
	}
	a.audit.Log(audit.Entry{
		Timestamp:  time.Now(),
		Source:     "rest",
		Operation:  operation,
		ClientID:   clientID,
		ObjectUID:  objectUID,
		ObjectName: objectName,
		Status:     status,
		Message:    message,
		RemoteAddr: r.RemoteAddr,
	})
}

// Serve starts the HTTPS server. C5 fix: TLS is required, no HTTP fallback.
func (a *API) Serve(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/keys", a.auth(a.handleListKeys))
	mux.HandleFunc("POST /v1/keys", a.auth(a.handleCreateKey))
	mux.HandleFunc("GET /v1/keys/{uid}", a.auth(a.handleGetKey))
	// C4 fix: material export endpoint removed
	mux.HandleFunc("POST /v1/keys/{uid}/activate", a.auth(a.handleActivateKey))
	mux.HandleFunc("POST /v1/keys/{uid}/revoke", a.auth(a.handleRevokeKey))
	mux.HandleFunc("DELETE /v1/keys/{uid}", a.auth(a.handleDestroyKey))
	mux.HandleFunc("POST /v1/keys/{uid}/encrypt", a.auth(a.handleEncryptKey))
	mux.HandleFunc("POST /v1/keys/{uid}/decrypt", a.auth(a.handleDecryptKey))
	mux.HandleFunc("POST /v1/keys/{uid}/sign", a.auth(a.handleSignKey))
	mux.HandleFunc("POST /v1/keys/{uid}/verify", a.auth(a.handleVerifyKey))
	mux.HandleFunc("POST /v1/keys/{uid}/mac", a.auth(a.handleMACKey))
	mux.HandleFunc("POST /v1/keys/{uid}/rekey", a.auth(a.handleRekeyKey))
	mux.HandleFunc("POST /v1/keys/{uid}/wrap", a.auth(a.handleWrapKey))
	mux.HandleFunc("POST /v1/keys/{uid}/unwrap", a.auth(a.handleUnwrapKey))
	mux.HandleFunc("POST /v1/certificates", a.auth(a.handleUploadCertificate))
	mux.HandleFunc("GET /v1/connections", a.auth(a.handleConnections))
	mux.HandleFunc("GET /v1/status", a.auth(a.handleStatus))
	mux.HandleFunc("GET /v1/audit", a.auth(a.handleAuditLog))
	mux.HandleFunc("GET /v1/inventory", a.auth(a.handleInventory))
	mux.HandleFunc("GET /metrics", a.handleMetrics) // public for Prometheus scraping
	// Dashboard auth-protected when API key is set
	if a.apiKey != "" {
		mux.HandleFunc("/ui/", a.auth(func(w http.ResponseWriter, r *http.Request) {
			http.StripPrefix("/ui", dashboard.Handler()).ServeHTTP(w, r)
		}))
	} else {
		mux.Handle("/ui/", http.StripPrefix("/ui", dashboard.Handler()))
	}

	handler := a.rateLimitMiddleware(a.limitBodyMiddleware(a.corsMiddleware(mux)))

	// C5 fix: TLS required — no HTTP fallback
	if a.certFile == "" || a.keyFile == "" {
		return fmt.Errorf("TLS cert and key are required for REST API")
	}
	log.Printf("REST API + UI listening on %s (TLS)", addr)
	return http.ListenAndServeTLS(addr, a.certFile, a.keyFile, handler)
}

// C3 fix: auth requires API key when configured — no bypass
func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.apiKey == "" {
			// H3 note: in production, apiKey is required (enforced in main)
			next(w, r)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// H3 fix: log failed auth
			a.logAudit(r, "AUTHN_FAILURE", "", "", "failure", "missing Authorization header")
			a.writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader || subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) != 1 {
			// H3 fix: log failed auth
			a.logAudit(r, "AUTHN_FAILURE", "", "", "failure", "invalid API key")
			a.writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next(w, r)
	}
}

func (a *API) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		if !a.rateLimiter.allow(ip) {
			a.logAudit(r, "RATE_LIMITED", "", "", "failure", "too many requests")
			w.Header().Set("Retry-After", "5")
			a.writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) limitBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.corsOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", a.corsOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Key handlers ---

func (a *API) handleListKeys(w http.ResponseWriter, r *http.Request) {
	records := a.store.List()
	type keyItem struct {
		UID       string `json:"uid"`
		Name      string `json:"name"`
		ObjType   int    `json:"object_type"`
		Algorithm int    `json:"algorithm"`
		Length    int32  `json:"length"`
		State     string `json:"state"`
		UsageMask int    `json:"usage_mask"`
		CreatedAt string `json:"created_at"`
	}
	items := make([]keyItem, 0, len(records))
	for _, rec := range records {
		items = append(items, keyItem{
			UID: rec.UID, Name: rec.Name, ObjType: rec.ObjectType, Algorithm: rec.Algorithm,
			Length: rec.Length, State: stateString(rec.State), UsageMask: rec.UsageMask,
			CreatedAt: rec.CreatedAt.Format(time.RFC3339),
		})
	}
	a.logAudit(r, "List", "", "", "success", fmt.Sprintf("%d keys", len(items)))
	a.writeJSON(w, http.StatusOK, map[string]any{"keys": items, "total": len(items)})
}

func (a *API) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Algorithm string `json:"algorithm"`
		Length    int32  `json:"length"`
		Type      string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		a.writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	keyType := strings.ToLower(req.Type)
	if keyType == "" {
		keyType = "symmetric"
	}

	switch keyType {
	case "rsa", "ec":
		a.handleCreateKeyPair(w, r, req.Name, keyType, req.Length)
	default:
		algo := resolveAlgorithm(req.Algorithm)
		length := req.Length
		if length == 0 {
			length = 256
		}
		// Owner = API client identity (for now just "rest")
		rec, err := a.store.Create(req.Name, algo, length, kmiplib.UsageMaskEncrypt|kmiplib.UsageMaskDecrypt, "rest")
		if err != nil {
			a.logAudit(r, "CreateKey", "", req.Name, "failure", err.Error())
			a.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.logAudit(r, "CreateKey", rec.UID, req.Name, "success", "")
		a.writeJSON(w, http.StatusCreated, map[string]any{
			"uid": rec.UID, "name": rec.Name, "object_type": rec.ObjectType,
			"algorithm": rec.Algorithm, "length": rec.Length, "state": stateString(rec.State),
			"created_at": rec.CreatedAt.Format(time.RFC3339),
		})
	}
}

func (a *API) handleCreateKeyPair(w http.ResponseWriter, r *http.Request, name, keyType string, length int32) {
	var privDER, pubDER []byte
	var algorithm int
	var err error

	switch keyType {
	case "rsa":
		algorithm = kmiplib.AlgorithmRSA
		if length == 0 {
			length = 2048
		}
		privKey, genErr := rsa.GenerateKey(rand.Reader, int(length))
		if genErr != nil {
			a.writeError(w, http.StatusInternalServerError, genErr.Error())
			return
		}
		privDER, _ = x509.MarshalPKCS8PrivateKey(privKey)
		pubDER, _ = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	case "ec":
		algorithm = kmiplib.AlgorithmECDSA
		var curve elliptic.Curve
		switch length {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
			length = 256
		}
		privKey, genErr := ecdsa.GenerateKey(curve, rand.Reader)
		if genErr != nil {
			a.writeError(w, http.StatusInternalServerError, genErr.Error())
			return
		}
		privDER, _ = x509.MarshalPKCS8PrivateKey(privKey)
		pubDER, _ = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	}

	usageMask := kmiplib.UsageMaskSign | kmiplib.UsageMaskVerify
	privRec := &storage.KeyRecord{ObjectType: kmiplib.ObjectTypePrivateKey, Name: name, Algorithm: algorithm, Length: length, Material: privDER, UsageMask: usageMask}
	privRec, err = a.store.Register(privRec)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	pubRec := &storage.KeyRecord{ObjectType: kmiplib.ObjectTypePublicKey, Name: name, Algorithm: algorithm, Length: length, Material: pubDER, UsageMask: usageMask}
	pubRec, err = a.store.Register(pubRec)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.logAudit(r, "CreateKeyPair", privRec.UID, name, "success", "")
	a.writeJSON(w, http.StatusCreated, map[string]any{
		"private_key_uid": privRec.UID, "public_key_uid": pubRec.UID,
		"name": name, "algorithm": algorithm, "length": length,
		"state": stateString(privRec.State), "created_at": privRec.CreatedAt.Format(time.RFC3339),
	})
}

func (a *API) handleUploadCertificate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(body) == 0 {
		a.writeError(w, http.StatusBadRequest, "empty or invalid body")
		return
	}
	var certDER []byte
	if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
		certDER = block.Bytes
	} else {
		certDER = body
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid certificate: %v", err))
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = cert.Subject.CommonName
	}
	rec := &storage.KeyRecord{ObjectType: kmiplib.ObjectTypeCertificate, Name: name, Material: certDER}
	rec, err = a.store.Register(rec)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.logAudit(r, "UploadCertificate", rec.UID, name, "success", "")
	a.writeJSON(w, http.StatusCreated, map[string]any{
		"uid": rec.UID, "name": name, "subject": cert.Subject.String(),
		"issuer": cert.Issuer.String(), "not_after": cert.NotAfter.Format(time.RFC3339),
	})
}

func (a *API) handleGetKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	rec, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "key not found")
		return
	}
	a.logAudit(r, "Get", rec.UID, rec.Name, "success", "")
	a.writeJSON(w, http.StatusOK, map[string]any{
		"uid": rec.UID, "name": rec.Name, "object_type": rec.ObjectType,
		"algorithm": rec.Algorithm, "length": rec.Length, "state": stateString(rec.State),
		"usage_mask": rec.UsageMask, "created_at": rec.CreatedAt.Format(time.RFC3339),
	})
}

func (a *API) handleActivateKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if err := a.store.Activate(uid); err != nil {
		a.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	a.logAudit(r, "Activate", uid, "", "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{"uid": uid, "state": "active"})
}

func (a *API) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		Reason int `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if err := a.store.Revoke(uid, req.Reason); err != nil {
		a.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	a.logAudit(r, "Revoke", uid, "", "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{"uid": uid, "state": "revoked"})
}

func (a *API) handleDestroyKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if err := a.store.Destroy(uid); err != nil {
		a.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	a.logAudit(r, "Destroy", uid, "", "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{"uid": uid, "state": "destroyed"})
}

// --- Crypto operations ---

func (a *API) handleEncryptKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid base64 data")
		return
	}

	rec, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if rec.ObjectType != kmiplib.ObjectTypeSymmetricKey {
		a.writeError(w, http.StatusBadRequest, "encrypt requires a symmetric key")
		return
	}
	if rec.State != storage.StateActive {
		a.writeError(w, http.StatusConflict, "key must be Active to encrypt")
		return
	}

	aead, err := createAEAD(rec)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	a.logAudit(r, "Encrypt", uid, rec.Name, "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{
		"data": base64.StdEncoding.EncodeToString(ciphertext), "nonce": hex.EncodeToString(nonce),
	})
}

func (a *API) handleDecryptKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		Data  string `json:"data"`
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ciphertext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid base64 data")
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid hex nonce")
		return
	}

	rec, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if rec.ObjectType != kmiplib.ObjectTypeSymmetricKey {
		a.writeError(w, http.StatusBadRequest, "decrypt requires a symmetric key")
		return
	}
	if rec.State != storage.StateActive {
		a.writeError(w, http.StatusConflict, "key must be Active to decrypt")
		return
	}

	aead, err := createAEAD(rec)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, fmt.Sprintf("decryption failed: %v", err))
		return
	}
	a.logAudit(r, "Decrypt", uid, rec.Name, "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{"data": base64.StdEncoding.EncodeToString(plaintext)})
}

func (a *API) handleWrapKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		WrappingKeyUID string `json:"wrapping_key_uid"`
		Method         string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.WrappingKeyUID == "" {
		a.writeError(w, http.StatusBadRequest, "wrapping_key_uid required")
		return
	}
	targetRec, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "target key not found")
		return
	}
	wrapRec, ok := a.store.Get(req.WrappingKeyUID)
	if !ok {
		a.writeError(w, http.StatusNotFound, "wrapping key not found")
		return
	}
	if wrapRec.ObjectType != kmiplib.ObjectTypeSymmetricKey {
		a.writeError(w, http.StatusBadRequest, "wrapping key must be symmetric")
		return
	}

	aead, err := createAEADFromMaterial(wrapRec.Material, wrapRec.Algorithm, req.Method)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	wrapped := aead.Seal(nil, nonce, targetRec.Material, nil)

	a.logAudit(r, "WrapKey", uid, targetRec.Name, "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{
		"wrapped_key": base64.StdEncoding.EncodeToString(wrapped), "nonce": hex.EncodeToString(nonce),
	})
}

func (a *API) handleUnwrapKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WrappingKeyUID string `json:"wrapping_key_uid"`
		WrappedKey     string `json:"wrapped_key"`
		Nonce          string `json:"nonce"`
		Method         string `json:"method"`
		Name           string `json:"name"`
		Algorithm      string `json:"algorithm"`
		Length         int32  `json:"length"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	wrappedKey, _ := base64.StdEncoding.DecodeString(req.WrappedKey)
	nonce, _ := hex.DecodeString(req.Nonce)

	wrapRec, ok := a.store.Get(req.WrappingKeyUID)
	if !ok {
		a.writeError(w, http.StatusNotFound, "wrapping key not found")
		return
	}

	aead, err := createAEADFromMaterial(wrapRec.Material, wrapRec.Algorithm, req.Method)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	keyMaterial, err := aead.Open(nil, nonce, wrappedKey, nil)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, fmt.Sprintf("unwrap failed: %v", err))
		return
	}

	name := req.Name
	if name == "" {
		name = "unwrapped-key"
	}
	algo := resolveAlgorithm(req.Algorithm)
	length := req.Length
	if length == 0 {
		length = int32(len(keyMaterial) * 8)
	}

	newRec := &storage.KeyRecord{
		Name: name, ObjectType: kmiplib.ObjectTypeSymmetricKey, Algorithm: algo,
		Length: length, Material: keyMaterial, UsageMask: kmiplib.UsageMaskEncrypt | kmiplib.UsageMaskDecrypt,
		State: storage.StatePreActive, CreatedAt: time.Now(),
	}
	registered, err := a.store.Register(newRec)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.logAudit(r, "UnwrapKey", registered.UID, name, "success", "")
	a.writeJSON(w, http.StatusCreated, map[string]any{
		"uid": registered.UID, "name": name, "algorithm": algo, "length": length, "state": stateString(registered.State),
	})
}

func (a *API) handleSignKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		Data string `json:"data"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	data, _ := base64.StdEncoding.DecodeString(req.Data)

	rec, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if rec.State != storage.StateActive || rec.ObjectType != kmiplib.ObjectTypePrivateKey {
		a.writeError(w, http.StatusBadRequest, "sign requires an active private key")
		return
	}

	privKey, err := x509.ParsePKCS8PrivateKey(rec.Material)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash := sha256.Sum256(data)
	var signature []byte
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, key, hash[:])
	default:
		a.writeError(w, http.StatusBadRequest, "unsupported key type")
		return
	}
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.logAudit(r, "Sign", uid, rec.Name, "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{"signature": base64.StdEncoding.EncodeToString(signature)})
}

func (a *API) handleVerifyKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		Data      string `json:"data"`
		Signature string `json:"signature"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	data, _ := base64.StdEncoding.DecodeString(req.Data)
	sig, _ := base64.StdEncoding.DecodeString(req.Signature)

	rec, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if rec.ObjectType != kmiplib.ObjectTypePublicKey {
		a.writeError(w, http.StatusBadRequest, "verify requires a public key")
		return
	}

	pubKey, err := x509.ParsePKIXPublicKey(rec.Material)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash := sha256.Sum256(data)
	valid := true
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig) != nil {
			valid = false
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hash[:], sig) {
			valid = false
		}
	}
	a.logAudit(r, "Verify", uid, rec.Name, "success", fmt.Sprintf("valid=%v", valid))
	a.writeJSON(w, http.StatusOK, map[string]any{"valid": valid})
}

func (a *API) handleMACKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		Data string `json:"data"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	data, _ := base64.StdEncoding.DecodeString(req.Data)

	rec, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if rec.State != storage.StateActive || rec.ObjectType != kmiplib.ObjectTypeSymmetricKey {
		a.writeError(w, http.StatusBadRequest, "MAC requires an active symmetric key")
		return
	}
	mac := hmac.New(sha256.New, rec.Material)
	mac.Write(data)
	a.logAudit(r, "MAC", uid, rec.Name, "success", "")
	a.writeJSON(w, http.StatusOK, map[string]string{"mac": base64.StdEncoding.EncodeToString(mac.Sum(nil))})
}

func (a *API) handleRekeyKey(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	// M6 fix: check state before rekey (KMIP spec: only Active keys)
	existing, ok := a.store.Get(uid)
	if !ok {
		a.writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if existing.State != storage.StateActive {
		a.writeError(w, http.StatusConflict, "key must be Active to rekey")
		return
	}
	rec, err := a.store.Rekey(uid)
	if err != nil {
		a.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	a.logAudit(r, "Rekey", uid, rec.Name, "success", "")
	a.writeJSON(w, http.StatusOK, map[string]any{
		"uid": rec.UID, "name": rec.Name, "version": rec.Version, "state": stateString(rec.State),
	})
}

// --- Audit + Status ---

func (a *API) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if a.audit == nil {
		a.writeJSON(w, http.StatusOK, map[string]any{"entries": []any{}, "total": 0})
		return
	}
	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	// M3 fix: cap limit to prevent OOM
	if limit > 1000 {
		limit = 1000
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	entries, total := a.audit.Query(limit, offset, r.URL.Query().Get("operation"), r.URL.Query().Get("status"))
	a.writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": total, "limit": limit, "offset": offset})
}

func (a *API) handleConnections(w http.ResponseWriter, r *http.Request) {
	var conns []*kmip.ConnectionInfo
	if a.tracker != nil {
		conns = a.tracker.List()
	}
	if conns == nil {
		conns = []*kmip.ConnectionInfo{}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"connections": conns, "total": len(conns)})
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	records := a.store.List()
	counts := map[string]int{"total": len(records)}
	for _, rec := range records {
		switch rec.State {
		case storage.StatePreActive:
			counts["pre_active"]++
		case storage.StateActive:
			counts["active"]++
		case storage.StateDeactivated:
			counts["deactivated"]++
		case storage.StateCompromised:
			counts["compromised"]++
		}
	}
	connCount := 0
	if a.tracker != nil {
		connCount = a.tracker.Count()
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "version": "0.1.0", "connections": connCount,
		"kmip": map[string]any{"protocol": "1.4", "port": 5696},
		"uptime_seconds": int(time.Since(a.start).Seconds()), "keys": counts,
	})
}

// --- Helpers ---

func (a *API) handleInventory(w http.ResponseWriter, r *http.Request) {
	sqlStore, ok := a.store.(*storage.SQLiteStore)
	if !ok {
		a.writeJSON(w, http.StatusOK, []any{})
		return
	}
	views, err := sqlStore.ListInventory()
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.writeJSON(w, http.StatusOK, views)
}

func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	records := a.store.List()
	active, revoked, preActive := 0, 0, 0
	for _, rec := range records {
		switch rec.State {
		case storage.StateActive:
			active++
		case storage.StateCompromised:
			revoked++
		case storage.StatePreActive:
			preActive++
		}
	}
	connCount := 0
	if a.tracker != nil {
		connCount = a.tracker.Count()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "# HELP open_kmip_keys_total Total managed keys\n")
	fmt.Fprintf(w, "# TYPE open_kmip_keys_total gauge\n")
	fmt.Fprintf(w, "open_kmip_keys_total %d\n", len(records))
	fmt.Fprintf(w, "# HELP open_kmip_keys_active Active keys\n")
	fmt.Fprintf(w, "# TYPE open_kmip_keys_active gauge\n")
	fmt.Fprintf(w, "open_kmip_keys_active %d\n", active)
	fmt.Fprintf(w, "# HELP open_kmip_keys_pre_active Pre-active keys\n")
	fmt.Fprintf(w, "# TYPE open_kmip_keys_pre_active gauge\n")
	fmt.Fprintf(w, "open_kmip_keys_pre_active %d\n", preActive)
	fmt.Fprintf(w, "# HELP open_kmip_keys_revoked Revoked keys\n")
	fmt.Fprintf(w, "# TYPE open_kmip_keys_revoked gauge\n")
	fmt.Fprintf(w, "open_kmip_keys_revoked %d\n", revoked)
	fmt.Fprintf(w, "# HELP open_kmip_connections_active Active KMIP connections\n")
	fmt.Fprintf(w, "# TYPE open_kmip_connections_active gauge\n")
	fmt.Fprintf(w, "open_kmip_connections_active %d\n", connCount)
}

func (a *API) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (a *API) writeError(w http.ResponseWriter, status int, message string) {
	a.writeJSON(w, status, map[string]string{"error": message})
}

func stateString(s storage.KeyState) string {
	switch s {
	case storage.StatePreActive:
		return "pre-active"
	case storage.StateActive:
		return "active"
	case storage.StateDeactivated:
		return "deactivated"
	case storage.StateCompromised:
		return "compromised"
	case storage.StateDestroyed:
		return "destroyed"
	case storage.StateDestroyedCompromised:
		return "destroyed-compromised"
	case storage.StateArchived:
		return "archived"
	default:
		return "unknown"
	}
}

// H5 fix: reject DES/3DES
func resolveAlgorithm(name string) int {
	switch strings.ToUpper(name) {
	case "AES", "":
		return 0x00000003
	case "RSA":
		return 0x00000004
	case "EC", "ECDSA":
		return 0x00000006
	case "CHACHA20", "CHACHA20-POLY1305":
		return 0x0000001E
	case "DES", "3DES", "TRIPLEDES":
		return -1 // rejected
	default:
		return 0x00000003
	}
}

func createAEAD(rec *storage.KeyRecord) (cipher.AEAD, error) {
	return createAEADFromMaterial(rec.Material, rec.Algorithm, "")
}

func createAEADFromMaterial(material []byte, algorithm int, method string) (cipher.AEAD, error) {
	m := strings.ToLower(method)
	if m == "chacha20-poly1305" || algorithm == 0x0000001E {
		return chacha20poly1305.New(material)
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
