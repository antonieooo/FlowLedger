package cache

import "testing"

func TestCMSCU_ExactWhenSmall(t *testing.T) {
	// When unique keys << width, CMS is essentially exact.
	c := NewCountMinSketchCU(1024, 4)
	keys := []string{"a", "b", "c", "a", "a", "b"}
	for _, k := range keys {
		c.Update(k)
	}
	if got := c.Estimate("a"); got != 3 {
		t.Fatalf("a count = %d, want 3", got)
	}
	if got := c.Estimate("b"); got != 2 {
		t.Fatalf("b count = %d, want 2", got)
	}
	if got := c.Estimate("c"); got != 1 {
		t.Fatalf("c count = %d, want 1", got)
	}
	if got := c.Total(); got != 6 {
		t.Fatalf("total = %d, want 6", got)
	}
}

func TestCMSCU_NeverUnderestimates(t *testing.T) {
	// Property test: estimate ≥ true count for every key, always.
	c := NewCountMinSketchCU(64, 4) // small width = more collisions
	truth := map[string]uint32{}
	for i := 0; i < 5000; i++ {
		k := string(rune(i % 200))
		c.Update(k)
		truth[k]++
	}
	for k, want := range truth {
		got := c.Estimate(k)
		if got < want {
			t.Fatalf("key %q estimate %d < true %d", k, got, want)
		}
	}
}

func TestCMSCU_UnknownKey(t *testing.T) {
	c := NewCountMinSketchCU(128, 4)
	c.Update("known")
	// Unknown key may collide with "known" and report >=0; here verify it's
	// bounded by the total count (CMS upper bound).
	got := c.Estimate("unknown-key")
	if got > uint32(c.Total()) {
		t.Fatalf("unknown estimate %d > total %d", got, c.Total())
	}
}

func TestCMSCU_UpdateBy(t *testing.T) {
	c := NewCountMinSketchCU(128, 4)
	c.UpdateBy("x", 17)
	if got := c.Estimate("x"); got != 17 {
		t.Fatalf("got %d, want 17", got)
	}
	if c.Total() != 17 {
		t.Fatalf("total = %d, want 17", c.Total())
	}
}
