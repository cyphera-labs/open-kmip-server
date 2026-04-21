package audit

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    operation TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    object_uid TEXT NOT NULL DEFAULT '',
    object_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    remote_addr TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_log(operation);
`

// Entry represents a single audit log record.
type Entry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Source     string    `json:"source"`      // "kmip" or "rest"
	Operation  string    `json:"operation"`
	ClientID   string    `json:"client_id"`   // cert CN for KMIP, API key prefix for REST
	ObjectUID  string    `json:"object_uid"`
	ObjectName string    `json:"object_name"`
	Status     string    `json:"status"`      // "success" or "failure"
	Message    string    `json:"message"`
	RemoteAddr string    `json:"remote_addr"`
}

// Logger writes audit entries to SQLite asynchronously via a buffered channel.
type Logger struct {
	db   *sql.DB
	ch   chan Entry
	done chan struct{}
}

// NewLogger creates the audit table and starts the background writer goroutine.
func NewLogger(db *sql.DB) *Logger {
	if _, err := db.Exec(createTableSQL); err != nil {
		log.Printf("WARNING: failed to create audit_log table: %v", err)
		return nil
	}
	a := &Logger{
		db:   db,
		ch:   make(chan Entry, 256),
		done: make(chan struct{}),
	}
	go a.writer()
	return a
}

func (a *Logger) writer() {
	defer close(a.done)
	for entry := range a.ch {
		_, err := a.db.Exec(
			`INSERT INTO audit_log (timestamp, source, operation, client_id, object_uid, object_name, status, message, remote_addr)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.Timestamp.Format(time.RFC3339Nano),
			entry.Source, entry.Operation, entry.ClientID,
			entry.ObjectUID, entry.ObjectName, entry.Status,
			entry.Message, entry.RemoteAddr,
		)
		if err != nil {
			log.Printf("audit write error: %v", err)
		}
	}
}

// Log enqueues an audit entry. Non-blocking — drops if the channel is full.
func (a *Logger) Log(entry Entry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	select {
	case a.ch <- entry:
	default:
		log.Printf("audit channel full, dropping: %s %s", entry.Operation, entry.ObjectUID)
	}
}

// Query returns paginated audit entries with optional filters.
func (a *Logger) Query(limit, offset int, operation, status string) ([]Entry, int) {
	where := "1=1"
	var args []interface{}

	if operation != "" {
		where += " AND operation = ?"
		args = append(args, operation)
	}
	if status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}

	var total int
	a.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM audit_log WHERE %s", where), args...).Scan(&total)

	query := fmt.Sprintf(
		`SELECT id, timestamp, source, operation, client_id, object_uid, object_name, status, message, remote_addr
		 FROM audit_log WHERE %s ORDER BY id DESC LIMIT ? OFFSET ?`, where,
	)
	rows, err := a.db.Query(query, append(args, limit, offset)...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Operation, &e.ClientID, &e.ObjectUID, &e.ObjectName, &e.Status, &e.Message, &e.RemoteAddr); err == nil {
			e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
			entries = append(entries, e)
		}
	}
	return entries, total
}

// Close drains remaining entries and shuts down the background writer.
func (a *Logger) Close() {
	close(a.ch)
	<-a.done
}
