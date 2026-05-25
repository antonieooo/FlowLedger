package cache

import (
	"container/list"
	"sync"
)

// Key identifies a baseline entry by (image_digest, dst_edge_class).
// The image is the source pod's container image SHA256 digest; dst_edge_class
// is the coarse destination type ("same_namespace_pod" / "cross_namespace_pod"
// / "cluster_service" / "external_known" / "external_unknown" / "host_network"
// per design §3.1 with §H4 follow-ups).
type Key struct {
	ImageDigest  string
	DstEdgeClass string
}

// Manager is an LRU-bounded cache of BaselineEntry values.
//
// Concurrency: Manager-level mutex protects the LRU list + lookup map; per-
// entry updates use BaselineEntry.Lock() / Unlock() so callers can perform
// multi-field updates atomically without holding the manager lock.
//
// LRU is the bounding mechanism because per design §5.1 we expect ~500 entries
// per node steady-state but want a hard cap of 256 (~2 MB) in case a node
// suddenly sees a flood of new images (e.g. CI test runner spinning images
// up/down). Evicted entries are dropped; cold-start recovery on re-add is
// acceptable.
type Manager struct {
	mu       sync.RWMutex
	capacity int
	lookup   map[Key]*list.Element
	lru      *list.List
}

type lruItem struct {
	key   Key
	entry *BaselineEntry
}

// NewManager creates a manager bounded by `capacity` entries (default 256
// recommended per design).
func NewManager(capacity int) *Manager {
	if capacity <= 0 {
		capacity = 256
	}
	return &Manager{
		capacity: capacity,
		lookup:   make(map[Key]*list.Element, capacity),
		lru:      list.New(),
	}
}

// GetOrCreate returns the entry for `key`, creating it if absent and evicting
// the least-recently-used entry if the cache is at capacity. The returned
// entry is moved to MRU position. Caller should immediately Lock() it for
// atomic multi-step updates.
func (m *Manager) GetOrCreate(key Key) *BaselineEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	if el, ok := m.lookup[key]; ok {
		m.lru.MoveToFront(el)
		return el.Value.(*lruItem).entry
	}

	if m.lru.Len() >= m.capacity {
		oldest := m.lru.Back()
		if oldest != nil {
			delete(m.lookup, oldest.Value.(*lruItem).key)
			m.lru.Remove(oldest)
		}
	}

	entry := NewBaselineEntry()
	el := m.lru.PushFront(&lruItem{key: key, entry: entry})
	m.lookup[key] = el
	return entry
}

// Get returns the entry for `key` if present, without affecting LRU position.
// Returns nil if absent. Use this for read-only lookups (e.g. computing a
// score against an existing baseline without updating it).
func (m *Manager) Get(key Key) *BaselineEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	el, ok := m.lookup[key]
	if !ok {
		return nil
	}
	return el.Value.(*lruItem).entry
}

// Len returns the current cache size.
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lru.Len()
}

// Keys returns a snapshot of currently-cached keys (debug / observability).
func (m *Manager) Keys() []Key {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Key, 0, m.lru.Len())
	for el := m.lru.Front(); el != nil; el = el.Next() {
		out = append(out, el.Value.(*lruItem).key)
	}
	return out
}
