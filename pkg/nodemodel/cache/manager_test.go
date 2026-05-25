package cache

import (
	"fmt"
	"testing"
)

func TestManager_GetOrCreate(t *testing.T) {
	m := NewManager(4)
	k1 := Key{"img-a", "same_namespace_pod"}

	e1 := m.GetOrCreate(k1)
	if e1 == nil {
		t.Fatalf("nil entry")
	}
	if m.Len() != 1 {
		t.Fatalf("len = %d, want 1", m.Len())
	}

	// Same key should return same entry (not create a new one).
	e2 := m.GetOrCreate(k1)
	if e2 != e1 {
		t.Fatalf("second GetOrCreate returned different entry")
	}
	if m.Len() != 1 {
		t.Fatalf("len = %d, want 1 after duplicate fetch", m.Len())
	}
}

func TestManager_LRUEviction(t *testing.T) {
	m := NewManager(3)
	keys := []Key{
		{"img-a", "x"},
		{"img-b", "x"},
		{"img-c", "x"},
		{"img-d", "x"}, // triggers eviction of LRU (img-a)
	}
	for _, k := range keys {
		m.GetOrCreate(k)
	}
	if m.Len() != 3 {
		t.Fatalf("len = %d, want 3 (capacity-bounded)", m.Len())
	}
	// img-a should have been evicted.
	if e := m.Get(Key{"img-a", "x"}); e != nil {
		t.Fatalf("img-a should have been evicted but is still present")
	}
	// img-b/c/d should remain.
	for _, k := range keys[1:] {
		if e := m.Get(k); e == nil {
			t.Fatalf("%v missing", k)
		}
	}
}

func TestManager_LRUOrderingUpdatedByGetOrCreate(t *testing.T) {
	m := NewManager(3)
	a := Key{"a", "x"}
	b := Key{"b", "x"}
	c := Key{"c", "x"}
	m.GetOrCreate(a)
	m.GetOrCreate(b)
	m.GetOrCreate(c)
	// Touch `a` so it becomes MRU; `b` is now LRU.
	m.GetOrCreate(a)
	// Add `d` → should evict `b`, not `a`.
	m.GetOrCreate(Key{"d", "x"})
	if m.Get(b) != nil {
		t.Fatalf("b should have been evicted (was LRU)")
	}
	if m.Get(a) == nil {
		t.Fatalf("a should still be present (recently touched)")
	}
}

func TestManager_GetDoesNotPromoteLRU(t *testing.T) {
	// Read-only Get must NOT change LRU order, otherwise the score-without-
	// update use case would accidentally keep cold entries warm.
	m := NewManager(3)
	a := Key{"a", "x"}
	m.GetOrCreate(a)
	m.GetOrCreate(Key{"b", "x"})
	m.GetOrCreate(Key{"c", "x"})
	// Read `a` (should not touch LRU).
	_ = m.Get(a)
	// Add `d` — `a` should be evicted because it was the actual LRU.
	m.GetOrCreate(Key{"d", "x"})
	if m.Get(a) != nil {
		t.Fatalf("a should have been evicted (Get must not promote)")
	}
}

func TestManager_ConcurrentSafe(t *testing.T) {
	m := NewManager(64)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(workerID int) {
			for j := 0; j < 200; j++ {
				k := Key{fmt.Sprintf("img-%d", j%20), "same_namespace_pod"}
				e := m.GetOrCreate(k)
				e.Lock()
				e.SampleCount++
				e.Unlock()
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	// 8 workers × 200 increments = 1600 total. With 20 unique keys, each entry
	// (if all stayed in cache, capacity is 64 ≥ 20) should have sum = 80.
	total := uint64(0)
	for _, k := range m.Keys() {
		e := m.Get(k)
		e.Lock()
		total += e.SampleCount
		e.Unlock()
	}
	if total != 1600 {
		t.Fatalf("total SampleCount = %d, want 1600", total)
	}
}
