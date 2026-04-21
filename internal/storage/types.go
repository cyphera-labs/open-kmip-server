package storage

import "time"

// KeyState represents the lifecycle state of a managed object.
type KeyState int

const (
	StatePreActive          KeyState = 1
	StateActive             KeyState = 2
	StateDeactivated        KeyState = 3
	StateCompromised        KeyState = 4
	StateDestroyed          KeyState = 5
	StateDestroyedCompromised KeyState = 6
	StateArchived           KeyState = 100
)

const StateRevoked = StateCompromised

// KeyRecord represents a managed cryptographic object.
type KeyRecord struct {
	UID              string
	Name             string
	ObjectType       int
	Algorithm        int
	Length           int32
	Material         []byte
	UsageMask        int
	State            KeyState
	RevocationReason int
	Owner            string
	CreatedAt        time.Time
	Version          int
}

// Storage defines the pluggable key storage interface.
type Storage interface {
	Create(name string, algorithm int, length int32, usageMask int, owner string) (*KeyRecord, error)
	Get(uid string) (*KeyRecord, bool)
	Locate(name string) []string
	List() []*KeyRecord
	Activate(uid string) error
	Destroy(uid string) error
	Register(rec *KeyRecord) (*KeyRecord, error)
	Revoke(uid string, reason int) error
	GetAttributes(uid string) (*KeyRecord, bool)
	Rekey(uid string) (*KeyRecord, error)
	Archive(uid string) error
	Recover(uid string) error
	DeriveKey(sourceUID string, derivationData []byte, name string, length int32) (*KeyRecord, error)
	GetCustomAttributes(uid string) (map[string]string, error)
	SetCustomAttribute(uid, name, value string) error
	DeleteCustomAttribute(uid, name string) error
	Close() error
}

// Maximum allowed key length in bits (security: prevents negative/huge allocations).
const MaxKeyLengthBits = 32768

// Maximum derived key length in bytes (security: prevents O(n²) CPU + O(n) memory).
const MaxDerivedKeyBytes = 512
