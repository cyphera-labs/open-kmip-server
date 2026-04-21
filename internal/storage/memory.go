package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// MemoryStore is an in-memory key store for testing and development.
type MemoryStore struct {
	mu    sync.RWMutex
	keys  map[string]*KeyRecord
	attrs map[string]map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		keys:  make(map[string]*KeyRecord),
		attrs: make(map[string]map[string]string),
	}
}

func (m *MemoryStore) Create(name string, algorithm int, length int32, usageMask int, owner string) (*KeyRecord, error) {
	if length <= 0 || length > MaxKeyLengthBits {
		return nil, fmt.Errorf("invalid key length: %d", length)
	}
	keyBytes := make([]byte, length/8)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	rec := &KeyRecord{
		UID: uuid.New().String(), Name: name, ObjectType: 0x00000002, Algorithm: algorithm,
		Length: length, Material: keyBytes, UsageMask: usageMask, State: StatePreActive,
		Owner: owner, CreatedAt: time.Now(), Version: 1,
	}
	m.mu.Lock()
	m.keys[rec.UID] = rec
	m.mu.Unlock()
	return rec, nil
}

func (m *MemoryStore) Get(uid string) (*KeyRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.keys[uid]
	if !ok || rec.State == StateDestroyed {
		return nil, false
	}
	return rec, true
}

func (m *MemoryStore) Locate(name string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var uids []string
	for _, rec := range m.keys {
		if rec.Name == name && rec.State != StateDestroyed {
			uids = append(uids, rec.UID)
		}
	}
	return uids
}

func (m *MemoryStore) List() []*KeyRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var records []*KeyRecord
	for _, rec := range m.keys {
		if rec.State != StateDestroyed {
			records = append(records, rec)
		}
	}
	return records
}

func (m *MemoryStore) Activate(uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[uid]
	if !ok || rec.State == StateDestroyed {
		return fmt.Errorf("object not found: %s", uid)
	}
	rec.State = StateActive
	return nil
}

func (m *MemoryStore) Destroy(uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[uid]
	if !ok || rec.State == StateDestroyed {
		return fmt.Errorf("object not found: %s", uid)
	}
	for i := range rec.Material {
		rec.Material[i] = 0
	}
	rec.Material = nil
	rec.State = StateDestroyed
	return nil
}

func (m *MemoryStore) Register(rec *KeyRecord) (*KeyRecord, error) {
	if rec.ObjectType != 0x00000001 && rec.Length < 0 {
		return nil, fmt.Errorf("invalid key length: %d", rec.Length)
	}
	rec.UID = uuid.New().String()
	rec.CreatedAt = time.Now()
	rec.State = StatePreActive
	if rec.Version == 0 {
		rec.Version = 1
	}
	m.mu.Lock()
	m.keys[rec.UID] = rec
	m.mu.Unlock()
	return rec, nil
}

func (m *MemoryStore) Revoke(uid string, reason int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[uid]
	if !ok || rec.State == StateDestroyed {
		return fmt.Errorf("object not found: %s", uid)
	}
	rec.State = StateRevoked
	rec.RevocationReason = reason
	return nil
}

func (m *MemoryStore) GetAttributes(uid string) (*KeyRecord, bool) { return m.Get(uid) }

func (m *MemoryStore) Rekey(uid string) (*KeyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[uid]
	if !ok || rec.State == StateDestroyed {
		return nil, fmt.Errorf("object not found: %s", uid)
	}
	if rec.Length <= 0 || rec.Length > MaxKeyLengthBits {
		return nil, fmt.Errorf("invalid key length: %d", rec.Length)
	}
	keyBytes := make([]byte, rec.Length/8)
	rand.Read(keyBytes)
	rec.Material = keyBytes
	rec.Version++
	return rec, nil
}

func (m *MemoryStore) Archive(uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[uid]
	if !ok || rec.State == StateDestroyed {
		return fmt.Errorf("object not found: %s", uid)
	}
	rec.State = StateArchived
	return nil
}

func (m *MemoryStore) Recover(uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[uid]
	if !ok || rec.State != StateArchived {
		return fmt.Errorf("object not found or not archived: %s", uid)
	}
	rec.State = StatePreActive
	return nil
}

func (m *MemoryStore) DeriveKey(sourceUID string, derivationData []byte, name string, length int32) (*KeyRecord, error) {
	src, ok := m.Get(sourceUID)
	if !ok {
		return nil, fmt.Errorf("source key not found: %s", sourceUID)
	}
	keyLen := int(length / 8)
	if keyLen <= 0 {
		keyLen = 32
	}
	if keyLen > MaxDerivedKeyBytes {
		return nil, fmt.Errorf("derived key length %d exceeds max %d", keyLen, MaxDerivedKeyBytes)
	}
	hkdfReader := hkdf.New(sha256.New, src.Material, derivationData, []byte("kmip-derive"))
	derived := make([]byte, keyLen)
	io.ReadFull(hkdfReader, derived)

	rec := &KeyRecord{
		UID: uuid.New().String(), Name: name, ObjectType: 0x00000002, Algorithm: src.Algorithm,
		Length: length, Material: derived, UsageMask: src.UsageMask, State: StatePreActive,
		Owner: src.Owner, CreatedAt: time.Now(), Version: 1,
	}
	m.mu.Lock()
	m.keys[rec.UID] = rec
	m.mu.Unlock()
	return rec, nil
}

func (m *MemoryStore) GetCustomAttributes(uid string) (map[string]string, error) {
	if _, ok := m.Get(uid); !ok {
		return nil, fmt.Errorf("object not found: %s", uid)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	attrs := m.attrs[uid]
	if attrs == nil {
		return make(map[string]string), nil
	}
	cp := make(map[string]string, len(attrs))
	for k, v := range attrs {
		cp[k] = v
	}
	return cp, nil
}

func (m *MemoryStore) SetCustomAttribute(uid, name, value string) error {
	if _, ok := m.Get(uid); !ok {
		return fmt.Errorf("object not found: %s", uid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.attrs[uid] == nil {
		m.attrs[uid] = make(map[string]string)
	}
	m.attrs[uid][name] = value
	return nil
}

func (m *MemoryStore) DeleteCustomAttribute(uid, name string) error {
	if _, ok := m.Get(uid); !ok {
		return fmt.Errorf("object not found: %s", uid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.attrs[uid], name)
	return nil
}

func (m *MemoryStore) Close() error { return nil }
