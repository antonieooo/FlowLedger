package sessionizer

import (
	"testing"
	"time"
)

// fakeSrcResolver returns queued results in order (the last result repeats)
// and counts resolution calls, so tests can assert both frozen values and
// the exact number of resolver invocations.
type fakeSrcResult struct {
	snap     SourceIdentity
	terminal bool
}

type fakeSrcResolver struct {
	calls int
	queue []fakeSrcResult
}

func (f *fakeSrcResolver) ResolveSourceIdentity(req SourceIdentityRequest) (SourceIdentity, bool) {
	f.calls++
	r := f.queue[0]
	if len(f.queue) > 1 {
		f.queue = f.queue[1:]
	}
	return r.snap, r.terminal
}

func resolvedSnap(podUID string) SourceIdentity {
	return SourceIdentity{
		ObservedAt:       time.Unix(50, 0).UTC(),
		Namespace:        "shop",
		PodName:          podUID + "-name",
		PodUID:           podUID,
		WorkloadKind:     "Deployment",
		WorkloadName:     "api",
		WorkloadUID:      "dep-uid",
		Revision:         "3",
		RevisionSource:   "replicaset_revision",
		Confidence:       "high",
		Method:           "cgroup_id",
		ResolutionStatus: "resolved",
	}
}

func missingSnap(reason, status string) SourceIdentity {
	return SourceIdentity{
		ObservedAt:       time.Unix(50, 0).UTC(),
		MissingReason:    reason,
		Confidence:       "unknown",
		Method:           status,
		ResolutionStatus: status,
	}
}

// Tests 1+2+4: the identity resolved at CONNECT is frozen; later resolver
// state changes (cache update / pod deletion) cannot rewrite it because the
// resolver is never called again; every window and the final records carry
// byte-identical identity.
func TestSourceIdentityFrozenAtConnectAcrossWindows(t *testing.T) {
	base := time.Unix(3000, 0).UTC()
	fake := &fakeSrcResolver{queue: []fakeSrcResult{{resolvedSnap("pod-a"), true}}}
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.SetSourceIdentityResolver(fake)

	s.Process(cumEvent(base, "CONNECT", 0, 0))
	if fake.calls != 1 {
		t.Fatalf("resolver calls after CONNECT = %d, want 1", fake.calls)
	}
	// The world changes: were the resolver consulted again it would now
	// return a different pod (cache update / pod deletion + IP reuse).
	fake.queue = []fakeSrcResult{{resolvedSnap("pod-b"), true}}

	w1 := s.Process(cumEvent(base.Add(10*time.Second), "STATS", 100, 0))[0]
	w2 := s.Process(cumEvent(base.Add(20*time.Second), "STATS", 200, 0))[0]
	out := s.Process(cumEvent(base.Add(25*time.Second), "CLOSE", 200, 0))
	finalWindow, summary := out[0], out[1]

	for i, rec := range []FlowSession{w1, w2, finalWindow, summary} {
		id := rec.SourceIdentity
		if id.PodUID != "pod-a" || id.PodName != "pod-a-name" || id.Revision != "3" || !id.Frozen {
			t.Fatalf("record %d identity drifted: %#v", i, id)
		}
		if !id.ObservedAt.Equal(w1.SourceIdentity.ObservedAt) {
			t.Fatalf("record %d observed_at differs: %v vs %v", i, id.ObservedAt, w1.SourceIdentity.ObservedAt)
		}
	}
	if fake.calls != 1 {
		t.Fatalf("resolver calls after emissions = %d, want 1 (no output-time re-resolution)", fake.calls)
	}
}

// Test 3: a transient miss (informer not ready) retries on the next event;
// once resolved the snapshot freezes and no further calls happen.
func TestSourceIdentityRetryThenFreeze(t *testing.T) {
	base := time.Unix(3100, 0).UTC()
	fake := &fakeSrcResolver{queue: []fakeSrcResult{
		{missingSnap("informer_miss", "informer_miss"), false},
		{resolvedSnap("pod-a"), true},
	}}
	s := New("node-a", 5*time.Minute, 30*time.Second)
	s.SetSourceIdentityResolver(fake)

	s.Process(cumEvent(base, "CONNECT", 0, 0))
	if fake.calls != 1 {
		t.Fatalf("calls = %d, want 1", fake.calls)
	}

	s.Process(cumEvent(base.Add(time.Second), "STATS", 10, 0))
	if fake.calls != 2 {
		t.Fatalf("calls = %d, want 2 (one retry)", fake.calls)
	}
	s.Process(cumEvent(base.Add(2*time.Second), "STATS", 20, 0))
	if fake.calls != 2 {
		t.Fatalf("calls = %d, want 2 (frozen, no more retries)", fake.calls)
	}

	out := s.Process(cumEvent(base.Add(3*time.Second), "CLOSE", 20, 0))
	id := out[1].SourceIdentity
	if !id.Frozen || id.PodUID != "pod-a" || id.Attempts != 2 || id.MissingReason != "" {
		t.Fatalf("unexpected frozen identity after retry: %#v", id)
	}
}

// Test 5: a superseding CONNECT (5-tuple reuse / lost CLOSE) never inherits
// the previous generation's snapshot: the old generation's records keep
// identity A, the new generation resolves fresh to identity B.
func TestSourceIdentityNotInheritedAcrossGenerations(t *testing.T) {
	base := time.Unix(3200, 0).UTC()
	fake := &fakeSrcResolver{queue: []fakeSrcResult{
		{resolvedSnap("pod-a"), true},
		{resolvedSnap("pod-b"), true},
	}}
	s := New("node-a", 5*time.Minute, 30*time.Second)
	s.SetSourceIdentityResolver(fake)

	s.Process(cumEvent(base, "CONNECT", 0, 0))
	s.Process(cumEvent(base.Add(time.Second), "STATS", 40, 0))

	out := s.Process(cumEvent(base.Add(5*time.Second), "CONNECT", 0, 0))
	if len(out) != 2 {
		t.Fatalf("superseding CONNECT emitted %d records, want 2", len(out))
	}
	for i, rec := range out {
		if rec.SourceIdentity.PodUID != "pod-a" {
			t.Fatalf("old generation record %d lost identity A: %#v", i, rec.SourceIdentity)
		}
	}
	if fake.calls != 2 {
		t.Fatalf("calls = %d, want 2 (one per generation)", fake.calls)
	}

	out = s.Process(cumEvent(base.Add(6*time.Second), "CLOSE", 10, 0))
	for i, rec := range out {
		if rec.SourceIdentity.PodUID != "pod-b" || rec.SourceIdentity.Attempts != 1 {
			t.Fatalf("new generation record %d wrong identity: %#v", i, rec.SourceIdentity)
		}
	}
}

// Test 6: CLOSE and inactivity timeout destroy the session and with it the
// snapshot; a later connection on the same tuple starts a fresh resolution.
func TestSourceIdentityClearedOnCloseAndTimeout(t *testing.T) {
	base := time.Unix(3300, 0).UTC()
	fake := &fakeSrcResolver{queue: []fakeSrcResult{{resolvedSnap("pod-a"), true}}}
	s := New("node-a", 5*time.Second, 30*time.Second)
	s.SetSourceIdentityResolver(fake)

	s.Process(cumEvent(base, "CONNECT", 0, 0))
	s.Process(cumEvent(base.Add(time.Second), "CLOSE", 5, 0))
	if s.ActiveCount() != 0 {
		t.Fatalf("session survived CLOSE")
	}

	s.Process(cumEvent(base.Add(2*time.Second), "CONNECT", 0, 0))
	if fake.calls != 2 {
		t.Fatalf("calls = %d, want 2 (fresh resolution after CLOSE)", fake.calls)
	}
	s.Sweep(base.Add(30 * time.Second)) // inactivity timeout
	if s.ActiveCount() != 0 {
		t.Fatalf("session survived timeout")
	}
	s.Process(cumEvent(base.Add(31*time.Second), "CONNECT", 0, 0))
	if fake.calls != 3 {
		t.Fatalf("calls = %d, want 3 (fresh resolution after timeout)", fake.calls)
	}
}

// Test 9: permanently missing identity freezes as missing after the retry
// budget — with its explicit reason, zeroed pod fields, and no IP/name
// substitution — and stays missing on every emitted record.
func TestSourceIdentityPermanentlyMissingNoFallback(t *testing.T) {
	base := time.Unix(3400, 0).UTC()
	fake := &fakeSrcResolver{queue: []fakeSrcResult{{missingSnap("unknown_source", "unknown"), false}}}
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.SetSourceIdentityResolver(fake)

	s.Process(cumEvent(base, "CONNECT", 0, 0))
	for i := 1; i <= 7; i++ {
		s.Process(cumEvent(base.Add(time.Duration(i)*time.Second), "STATS", uint64(i*10), 0))
	}
	if fake.calls != maxSourceIdentityAttempts {
		t.Fatalf("calls = %d, want %d (budget cap)", fake.calls, maxSourceIdentityAttempts)
	}

	out := s.Process(cumEvent(base.Add(10*time.Second), "STATS", 100, 0))
	if len(out) != 1 {
		t.Fatalf("window: got %d records, want 1", len(out))
	}
	id := out[0].SourceIdentity
	if !id.Frozen || id.Attempts != maxSourceIdentityAttempts {
		t.Fatalf("identity not frozen at cap: %#v", id)
	}
	if id.PodUID != "" || id.PodName != "" || id.Namespace != "" || id.WorkloadUID != "" {
		t.Fatalf("missing identity was substituted: %#v", id)
	}
	if id.MissingReason != "unknown_source" || id.ResolutionStatus != "unknown" {
		t.Fatalf("missing reason lost: %#v", id)
	}
}

// Boundary fix: a CLOSE landing exactly on the previous window boundary
// (zero data span since the last window) emits no extra window — only the
// session summary. A positive-span zero-delta final window is still emitted
// (covered by TestCloseAtWindowBoundaryZeroDeltaFinalWindow).
func TestCloseExactlyAtWindowBoundarySkipsFinalWindow(t *testing.T) {
	base := time.Unix(3500, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))
	out := s.Process(cumEvent(base.Add(10*time.Second), "STATS", 100, 0))
	requireWindow(t, out[0], true, "", 100)

	out = s.Process(cumEvent(base.Add(10*time.Second), "CLOSE", 100, 0))
	if len(out) != 1 {
		t.Fatalf("boundary CLOSE emitted %d records, want summary only", len(out))
	}
	if out[0].RecordType != "session_summary" || out[0].BytesOut != 100 {
		t.Fatalf("unexpected boundary-close record: %#v", out[0])
	}
}
