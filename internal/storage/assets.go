package storage

import (
	"encoding/json"
	"time"
)

// --- Asset graph (shared Cyphera inventory model) ---
// Same schema and API as Open PKI Server so Suite can ingest uniformly.

// RegisterAsset creates or updates an asset record.
func (s *SQLiteStore) RegisterAsset(id, assetType, nativeID, name, status string) error {
	_, err := s.db.Exec(`
		INSERT INTO assets (id, asset_type, native_id, source, name, status)
		VALUES (?, ?, ?, 'open-kmip-server', ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, status = excluded.status, updated_at = datetime('now')`,
		id, assetType, nativeID, name, status)
	return err
}

// SetMetadata upserts a metadata key-value on an asset.
func (s *SQLiteStore) SetMetadata(assetID, key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO asset_metadata (asset_id, key, value)
		VALUES (?, ?, ?)
		ON CONFLICT(asset_id, key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
		assetID, key, value)
	return err
}

// GetMetadata returns all metadata for an asset.
func (s *SQLiteStore) GetMetadata(assetID string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM asset_metadata WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		m[k] = v
	}
	return m, nil
}

// TagAsset attaches a tag to an asset.
func (s *SQLiteStore) TagAsset(assetID, tagName string) error {
	s.db.Exec(`INSERT OR IGNORE INTO tags (name) VALUES (?)`, tagName)
	_, err := s.db.Exec(`INSERT OR IGNORE INTO asset_tags (asset_id, tag_id) SELECT ?, id FROM tags WHERE name = ?`, assetID, tagName)
	return err
}

// GetTags returns all tag names for an asset.
func (s *SQLiteStore) GetTags(assetID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT t.name FROM tags t JOIN asset_tags at ON t.id = at.tag_id WHERE at.asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		tags = append(tags, name)
	}
	return tags, nil
}

// AddRelationship links two assets.
func (s *SQLiteStore) AddRelationship(fromAssetID, relType, toAssetID string, metadata map[string]any) error {
	metaJSON, _ := json.Marshal(metadata)
	_, err := s.db.Exec(`INSERT INTO asset_relationships (from_asset_id, relationship_type, to_asset_id, metadata_json) VALUES (?, ?, ?, ?)`,
		fromAssetID, relType, toAssetID, string(metaJSON))
	return err
}

// AssetRelationship represents a link between assets.
type AssetRelationship struct {
	Type     string         `json:"type"`
	Target   string         `json:"target"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// GetRelationships returns all outgoing relationships from an asset.
func (s *SQLiteStore) GetRelationships(assetID string) ([]AssetRelationship, error) {
	rows, err := s.db.Query(`SELECT relationship_type, to_asset_id, metadata_json FROM asset_relationships WHERE from_asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rels []AssetRelationship
	for rows.Next() {
		var r AssetRelationship
		var metaJSON string
		rows.Scan(&r.Type, &r.Target, &metaJSON)
		json.Unmarshal([]byte(metaJSON), &r.Metadata)
		rels = append(rels, r)
	}
	return rels, nil
}

// EmitLifecycleEvent records a lifecycle event on an asset.
func (s *SQLiteStore) EmitLifecycleEvent(assetID, eventType, actor string, details map[string]any) error {
	detailsJSON, _ := json.Marshal(details)
	_, err := s.db.Exec(`INSERT INTO asset_lifecycle_events (asset_id, event_type, actor, details_json) VALUES (?, ?, ?, ?)`,
		assetID, eventType, actor, string(detailsJSON))
	return err
}

// LifecycleEvent represents a stored lifecycle event.
type LifecycleEvent struct {
	ID        int64          `json:"id"`
	AssetID   string         `json:"asset_id"`
	EventType string         `json:"event_type"`
	Actor     string         `json:"actor"`
	Timestamp time.Time      `json:"timestamp"`
	Result    string         `json:"result"`
	Details   map[string]any `json:"details,omitempty"`
}

// ListLifecycleEvents returns recent events.
func (s *SQLiteStore) ListLifecycleEvents(assetID string, limit int) ([]*LifecycleEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	var query string
	var args []any
	if assetID != "" {
		query = `SELECT id, asset_id, event_type, actor, timestamp, result, details_json FROM asset_lifecycle_events WHERE asset_id = ? ORDER BY timestamp DESC LIMIT ?`
		args = []any{assetID, limit}
	} else {
		query = `SELECT id, asset_id, event_type, actor, timestamp, result, details_json FROM asset_lifecycle_events ORDER BY timestamp DESC LIMIT ?`
		args = []any{limit}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []*LifecycleEvent
	for rows.Next() {
		e := &LifecycleEvent{}
		var ts, detailsJSON string
		rows.Scan(&e.ID, &e.AssetID, &e.EventType, &e.Actor, &ts, &e.Result, &detailsJSON)
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		json.Unmarshal([]byte(detailsJSON), &e.Details)
		events = append(events, e)
	}
	return events, nil
}

// AssetView is the combined view for inventory export.
type AssetView struct {
	ID            string              `json:"id"`
	Type          string              `json:"type"`
	Source        string              `json:"source"`
	Name          string              `json:"name"`
	Status        string              `json:"status"`
	CreatedAt     string              `json:"created_at"`
	Metadata      map[string]string   `json:"metadata,omitempty"`
	Tags          []string            `json:"tags,omitempty"`
	Relationships []AssetRelationship `json:"relationships,omitempty"`
}

// ListInventory returns full asset views.
func (s *SQLiteStore) ListInventory() ([]*AssetView, error) {
	rows, err := s.db.Query(`SELECT id, asset_type, name, status, created_at FROM assets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var views []*AssetView
	for rows.Next() {
		v := &AssetView{Source: "open-kmip-server"}
		var createdAt string
		rows.Scan(&v.ID, &v.Type, &v.Name, &v.Status, &createdAt)
		v.CreatedAt = createdAt
		v.Metadata, _ = s.GetMetadata(v.ID)
		v.Tags, _ = s.GetTags(v.ID)
		v.Relationships, _ = s.GetRelationships(v.ID)
		views = append(views, v)
	}
	return views, nil
}
