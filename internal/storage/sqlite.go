package storage

import (
	"crypto/sha256"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
	_ "modernc.org/sqlite"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS keys (
    uid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    object_type INTEGER NOT NULL,
    algorithm INTEGER NOT NULL,
    length INTEGER NOT NULL,
    material BLOB NOT NULL,
    usage_mask INTEGER NOT NULL,
    state INTEGER NOT NULL DEFAULT 0,
    revocation_reason INTEGER NOT NULL DEFAULT 0,
    owner TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name);
CREATE INDEX IF NOT EXISTS idx_keys_state ON keys(state);
CREATE INDEX IF NOT EXISTS idx_keys_owner ON keys(owner);

CREATE TABLE IF NOT EXISTS key_attributes (
    uid TEXT NOT NULL,
    attr_name TEXT NOT NULL,
    attr_value TEXT NOT NULL,
    PRIMARY KEY (uid, attr_name),
    FOREIGN KEY (uid) REFERENCES keys(uid)
);
`
// TODO: C8 — Key material is stored as plaintext BLOB. Implement envelope encryption
// (AES-256-GCM wrapping with KEK from HSM/KMS/file) before production deployment.

// SQLiteStore is a SQLite-backed key store.
type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex
}

// NewSQLiteStore opens (or creates) a SQLite database.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.Exec("PRAGMA journal_mode = WAL")
	db.Exec("PRAGMA secure_delete = ON")
	db.Exec("PRAGMA foreign_keys = ON")

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	// H2 fix: restrict file permissions
	os.Chmod(dbPath, 0600)

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) DB() *sql.DB { return s.db }

// Create generates a new symmetric key. C2 fix: validates length before allocation.
func (s *SQLiteStore) Create(name string, algorithm int, length int32, usageMask int, owner string) (*KeyRecord, error) {
	if length <= 0 || length > MaxKeyLengthBits {
		return nil, fmt.Errorf("invalid key length: %d (must be 1-%d bits)", length, MaxKeyLengthBits)
	}

	keyBytes := make([]byte, length/8)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("generate key material: %w", err)
	}

	uid := uuid.New().String()
	now := time.Now()
	rec := &KeyRecord{
		UID:        uid,
		Name:       name,
		ObjectType: 0x00000002,
		Algorithm:  algorithm,
		Length:     length,
		Material:   keyBytes,
		UsageMask:  usageMask,
		State:      StatePreActive,
		Owner:      owner,
		CreatedAt:  now,
		Version:    1,
	}

	_, err := s.db.Exec(
		`INSERT INTO keys (uid, name, object_type, algorithm, length, material, usage_mask, state, revocation_reason, owner, created_at, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.UID, rec.Name, rec.ObjectType, rec.Algorithm, rec.Length,
		rec.Material, rec.UsageMask, int(rec.State), rec.RevocationReason,
		rec.Owner, rec.CreatedAt.Format(time.RFC3339Nano), rec.Version,
	)
	if err != nil {
		return nil, fmt.Errorf("insert key: %w", err)
	}

	return rec, nil
}

func (s *SQLiteStore) Get(uid string) (*KeyRecord, bool) {
	rec, err := s.scanKey(
		`SELECT uid, name, object_type, algorithm, length, material, usage_mask, state, revocation_reason, owner, created_at, version
		 FROM keys WHERE uid = ? AND state != ?`, uid, int(StateDestroyed),
	)
	if err != nil {
		return nil, false
	}
	return rec, true
}

func (s *SQLiteStore) Locate(name string) []string {
	rows, err := s.db.Query(`SELECT uid FROM keys WHERE name = ? AND state != ?`, name, int(StateDestroyed))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var uids []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err == nil {
			uids = append(uids, uid)
		}
	}
	return uids
}

func (s *SQLiteStore) List() []*KeyRecord {
	rows, err := s.db.Query(
		`SELECT uid, name, object_type, algorithm, length, material, usage_mask, state, revocation_reason, owner, created_at, version
		 FROM keys WHERE state != ? ORDER BY created_at DESC`, int(StateDestroyed))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var records []*KeyRecord
	for rows.Next() {
		rec := &KeyRecord{}
		var stateInt int
		var createdStr string
		if err := rows.Scan(&rec.UID, &rec.Name, &rec.ObjectType, &rec.Algorithm, &rec.Length,
			&rec.Material, &rec.UsageMask, &stateInt, &rec.RevocationReason, &rec.Owner, &createdStr, &rec.Version); err == nil {
			rec.State = KeyState(stateInt)
			rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdStr)
			records = append(records, rec)
		}
	}
	return records
}

func (s *SQLiteStore) Activate(uid string) error {
	res, err := s.db.Exec(`UPDATE keys SET state = ? WHERE uid = ? AND state != ?`, int(StateActive), uid, int(StateDestroyed))
	if err != nil {
		return fmt.Errorf("activate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("object not found: %s", uid)
	}
	return nil
}

func (s *SQLiteStore) Destroy(uid string) error {
	res, err := s.db.Exec(`UPDATE keys SET state = ?, material = X'' WHERE uid = ? AND state != ?`, int(StateDestroyed), uid, int(StateDestroyed))
	if err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("object not found: %s", uid)
	}
	return nil
}

func (s *SQLiteStore) Register(rec *KeyRecord) (*KeyRecord, error) {
	rec.UID = uuid.New().String()
	rec.CreatedAt = time.Now()
	if rec.State == 0 {
		rec.State = StatePreActive
	}
	if rec.Version == 0 {
		rec.Version = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO keys (uid, name, object_type, algorithm, length, material, usage_mask, state, revocation_reason, owner, created_at, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.UID, rec.Name, rec.ObjectType, rec.Algorithm, rec.Length,
		rec.Material, rec.UsageMask, int(rec.State), rec.RevocationReason,
		rec.Owner, rec.CreatedAt.Format(time.RFC3339Nano), rec.Version,
	)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	return rec, nil
}

func (s *SQLiteStore) Revoke(uid string, reason int) error {
	res, err := s.db.Exec(`UPDATE keys SET state = ?, revocation_reason = ? WHERE uid = ? AND state != ?`,
		int(StateRevoked), reason, uid, int(StateDestroyed))
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("object not found: %s", uid)
	}
	return nil
}

// Rekey generates new key material. C2 fix: validates length.
func (s *SQLiteStore) Rekey(uid string) (*KeyRecord, error) {
	rec, ok := s.Get(uid)
	if !ok {
		return nil, fmt.Errorf("object not found: %s", uid)
	}
	if rec.Length <= 0 || rec.Length > MaxKeyLengthBits {
		return nil, fmt.Errorf("invalid key length for rekey: %d", rec.Length)
	}

	keyBytes := make([]byte, rec.Length/8)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("generate key material: %w", err)
	}
	newVersion := rec.Version + 1
	_, err := s.db.Exec(`UPDATE keys SET material = ?, version = ? WHERE uid = ? AND state != ?`,
		keyBytes, newVersion, uid, int(StateDestroyed))
	if err != nil {
		return nil, fmt.Errorf("rekey: %w", err)
	}
	rec.Material = keyBytes
	rec.Version = newVersion
	return rec, nil
}

func (s *SQLiteStore) Archive(uid string) error {
	res, err := s.db.Exec(`UPDATE keys SET state = ? WHERE uid = ? AND state != ?`, int(StateArchived), uid, int(StateDestroyed))
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("object not found: %s", uid)
	}
	return nil
}

func (s *SQLiteStore) Recover(uid string) error {
	res, err := s.db.Exec(`UPDATE keys SET state = ? WHERE uid = ? AND state = ?`, int(StatePreActive), uid, int(StateArchived))
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("object not found or not archived: %s", uid)
	}
	return nil
}

// DeriveKey using HKDF (H1 fix: replaces O(n²) custom HMAC loop).
func (s *SQLiteStore) DeriveKey(sourceUID string, derivationData []byte, name string, length int32) (*KeyRecord, error) {
	src, ok := s.Get(sourceUID)
	if !ok {
		return nil, fmt.Errorf("source key not found: %s", sourceUID)
	}

	keyLen := int(length / 8)
	if keyLen <= 0 {
		keyLen = 32
	}
	if keyLen > MaxDerivedKeyBytes {
		return nil, fmt.Errorf("derived key length %d bytes exceeds maximum %d", keyLen, MaxDerivedKeyBytes)
	}

	hkdfReader := hkdf.New(sha256.New, src.Material, derivationData, []byte("kmip-derive"))
	derived := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, derived); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	uid := uuid.New().String()
	now := time.Now()
	rec := &KeyRecord{
		UID:        uid,
		Name:       name,
		ObjectType: 0x00000002,
		Algorithm:  src.Algorithm,
		Length:     length,
		Material:   derived,
		UsageMask:  src.UsageMask,
		State:      StatePreActive,
		Owner:      src.Owner,
		CreatedAt:  now,
		Version:    1,
	}

	_, err := s.db.Exec(
		`INSERT INTO keys (uid, name, object_type, algorithm, length, material, usage_mask, state, revocation_reason, owner, created_at, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.UID, rec.Name, rec.ObjectType, rec.Algorithm, rec.Length,
		rec.Material, rec.UsageMask, int(rec.State), rec.RevocationReason,
		rec.Owner, rec.CreatedAt.Format(time.RFC3339Nano), rec.Version,
	)
	if err != nil {
		return nil, fmt.Errorf("insert derived key: %w", err)
	}
	return rec, nil
}

func (s *SQLiteStore) GetAttributes(uid string) (*KeyRecord, bool) { return s.Get(uid) }

func (s *SQLiteStore) GetCustomAttributes(uid string) (map[string]string, error) {
	if _, ok := s.Get(uid); !ok {
		return nil, fmt.Errorf("object not found: %s", uid)
	}
	rows, err := s.db.Query(`SELECT attr_name, attr_value FROM key_attributes WHERE uid = ?`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	attrs := make(map[string]string)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		attrs[k] = v
	}
	return attrs, nil
}

func (s *SQLiteStore) SetCustomAttribute(uid, name, value string) error {
	if _, ok := s.Get(uid); !ok {
		return fmt.Errorf("object not found: %s", uid)
	}
	_, err := s.db.Exec(`INSERT INTO key_attributes (uid, attr_name, attr_value) VALUES (?, ?, ?)
		ON CONFLICT(uid, attr_name) DO UPDATE SET attr_value = excluded.attr_value`, uid, name, value)
	return err
}

func (s *SQLiteStore) DeleteCustomAttribute(uid, name string) error {
	if _, ok := s.Get(uid); !ok {
		return fmt.Errorf("object not found: %s", uid)
	}
	_, err := s.db.Exec(`DELETE FROM key_attributes WHERE uid = ? AND attr_name = ?`, uid, name)
	return err
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) scanKey(query string, args ...interface{}) (*KeyRecord, error) {
	row := s.db.QueryRow(query, args...)
	rec := &KeyRecord{}
	var stateInt int
	var createdStr string
	err := row.Scan(&rec.UID, &rec.Name, &rec.ObjectType, &rec.Algorithm, &rec.Length,
		&rec.Material, &rec.UsageMask, &stateInt, &rec.RevocationReason, &rec.Owner, &createdStr, &rec.Version)
	if err != nil {
		return nil, err
	}
	rec.State = KeyState(stateInt)
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdStr)
	return rec, nil
}
