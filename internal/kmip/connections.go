// Copyright 2026 Horizon Digital Engineering LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kmip

import (
	"sync"
	"time"
)

// ConnectionInfo describes a single active KMIP client connection.
type ConnectionInfo struct {
	ID          string    `json:"id"`
	ClientCN    string    `json:"client_cn"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	Operations  int       `json:"operations"`
	LastOp      string    `json:"last_op"`
	LastOpAt    time.Time `json:"last_op_at"`
}

// ConnectionTracker keeps track of active KMIP connections.
type ConnectionTracker struct {
	mu    sync.RWMutex
	conns map[string]*ConnectionInfo
}

// NewConnectionTracker creates a new ConnectionTracker.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		conns: make(map[string]*ConnectionInfo),
	}
}

// Add registers a new connection.
func (ct *ConnectionTracker) Add(id, clientCN, remoteAddr string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.conns[id] = &ConnectionInfo{
		ID:          id,
		ClientCN:    clientCN,
		RemoteAddr:  remoteAddr,
		ConnectedAt: time.Now(),
	}
}

// Remove unregisters a connection on disconnect.
func (ct *ConnectionTracker) Remove(id string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.conns, id)
}

// RecordOp increments the operation counter and updates last operation info.
func (ct *ConnectionTracker) RecordOp(id, operation string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	info, ok := ct.conns[id]
	if !ok {
		return
	}
	info.Operations++
	info.LastOp = operation
	info.LastOpAt = time.Now()
}

// List returns all active connections.
func (ct *ConnectionTracker) List() []*ConnectionInfo {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	result := make([]*ConnectionInfo, 0, len(ct.conns))
	for _, info := range ct.conns {
		cp := *info
		result = append(result, &cp)
	}
	return result
}

// Count returns the number of active connections.
func (ct *ConnectionTracker) Count() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.conns)
}
