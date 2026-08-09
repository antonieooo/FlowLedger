package ledger

import (
	"testing"
	"time"

	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/identity"
	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/sessionizer"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func sourceSnapshotPod(name, uid, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "shop", UID: types.UID(uid),
			Labels: map[string]string{"pod-template-hash": "aaa"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "api-aaa", UID: types.UID("rs3-uid")},
			},
			CreationTimestamp: metav1.NewTime(time.Unix(10, 0)),
		},
		Status: corev1.PodStatus{PodIP: ip},
	}
}

// End-to-end freeze proof over the real pipeline (sessionizer wired with the
// real identity resolver on a real k8smeta cache): identity resolves at
// CONNECT; the pod is then DELETED and its IP reused by another pod; the
// window emitted afterwards still carries the original identity with the
// pod-scoped revision, the record self-describes as frozen, and G1-G4
// availability plus destination Service fields are correct.
func TestRecordSourceIdentityFrozenAgainstCacheChange(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertDeployment(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api", Namespace: "shop", UID: types.UID("dep-uid"),
			Annotations: map[string]string{"deployment.kubernetes.io/revision": "4"},
		},
	})
	cache.UpsertReplicaSet(&appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-aaa", Namespace: "shop", UID: types.UID("rs3-uid"),
			Annotations: map[string]string{"deployment.kubernetes.io/revision": "3"},
			Labels:      map[string]string{"pod-template-hash": "aaa"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "api", UID: types.UID("dep-uid")},
			},
		},
	})
	originalPod := sourceSnapshotPod("api-aaa-1", "pod-a-uid", "10.1.1.10")
	cache.UpsertPod(originalPod)
	cache.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop", UID: types.UID("svc-uid")},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports:     []corev1.ServicePort{{Port: 443, Name: "https"}},
		},
	})

	resolver := identity.NewResolver(cache)
	base := time.Unix(4000, 0).UTC()
	s := sessionizer.New("node-a", 5*time.Minute, 10*time.Second)
	s.SetSourceIdentityResolver(resolver)

	connect := windowTestEvent(base, "CONNECT", 0)
	connect.SrcIP = "10.1.1.10"
	connect.DstIP = "10.96.0.10"
	s.Process(connect)

	// After the freeze: pod deleted, IP reused by a different pod on a
	// different rollout — the exact churn G-key experiments care about.
	cache.DeletePod(originalPod)
	cache.UpsertPod(sourceSnapshotPod("imposter-1", "pod-b-uid", "10.1.1.10"))

	stats := windowTestEvent(base.Add(10*time.Second), "STATS", 300)
	stats.SrcIP = "10.1.1.10"
	stats.DstIP = "10.96.0.10"
	out := s.Process(stats)
	if len(out) != 1 {
		t.Fatalf("window: got %d records, want 1", len(out))
	}
	record := BuildRecord(out[0], resolver.Resolve(out[0]), experiment.Labels{})

	if record.SrcPodUID != "pod-a-uid" || record.SrcPodName != "api-aaa-1" {
		t.Fatalf("source identity re-resolved after cache change: %q/%q", record.SrcPodUID, record.SrcPodName)
	}
	if !record.SrcIdentityFrozen || record.SrcIdentityAttempts != 1 || record.SrcIdentityObservedTime == "" {
		t.Fatalf("freeze metadata wrong: frozen=%v attempts=%d observed=%q",
			record.SrcIdentityFrozen, record.SrcIdentityAttempts, record.SrcIdentityObservedTime)
	}
	if record.SrcRevision != "3" || record.SrcRevisionSource != k8smeta.RevisionSourceReplicaSet {
		t.Fatalf("revision = %q (source %q), want pod-scoped 3/%q",
			record.SrcRevision, record.SrcRevisionSource, k8smeta.RevisionSourceReplicaSet)
	}
	if !record.SrcKeyG2Available || !record.SrcKeyG3Available || !record.SrcKeyG4Available {
		t.Fatalf("G-key availability = %v/%v/%v, want all true",
			record.SrcKeyG2Available, record.SrcKeyG3Available, record.SrcKeyG4Available)
	}
	if record.SrcWorkloadKind != "Deployment" || record.SrcWorkloadUID != "dep-uid" {
		t.Fatalf("G3 fields wrong: %q/%q", record.SrcWorkloadKind, record.SrcWorkloadUID)
	}
	// Destination stays on the live-resolution path, unaffected.
	if record.DstServiceName != "checkout" || record.DstServiceUID != "svc-uid" {
		t.Fatalf("destination service resolution affected: %q/%q", record.DstServiceName, record.DstServiceUID)
	}
	if record.SrcIdentityResolutionMethod != "pod_ip" {
		t.Fatalf("src method = %q, want pod_ip", record.SrcIdentityResolutionMethod)
	}
}

// Source/destination provenance independence: when the source resolves via
// pod_ip and the destination via a Service, the record-level mapping_method
// reports the DESTINATION path while src_identity_resolution_method must
// keep the SOURCE path — the destination must never overwrite it.
func TestRecordSourceMethodIndependentOfDestination(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertPod(sourceSnapshotPod("api-aaa-1", "pod-a-uid", "10.1.1.10"))
	cache.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop", UID: types.UID("svc-uid")},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports:     []corev1.ServicePort{{Port: 443, Name: "https"}},
		},
	})
	resolver := identity.NewResolver(cache) // no cgroup lookup wired -> source resolves via pod_ip
	base := time.Unix(4200, 0).UTC()
	s := sessionizer.New("node-a", 5*time.Minute, 10*time.Second)
	s.SetSourceIdentityResolver(resolver)

	connect := windowTestEvent(base, "CONNECT", 0)
	connect.DstIP = "10.96.0.10"
	s.Process(connect)
	stats := windowTestEvent(base.Add(10*time.Second), "STATS", 100)
	stats.DstIP = "10.96.0.10"
	out := s.Process(stats)
	if len(out) != 1 {
		t.Fatalf("window: got %d records, want 1", len(out))
	}
	record := BuildRecord(out[0], resolver.Resolve(out[0]), experiment.Labels{})

	if record.SrcIdentityResolutionMethod != "pod_ip" {
		t.Fatalf("src_identity_resolution_method = %q, want pod_ip", record.SrcIdentityResolutionMethod)
	}
	if record.MappingMethod != "service_cluster_ip" {
		t.Fatalf("mapping_method = %q, want destination-side service_cluster_ip", record.MappingMethod)
	}
	if record.SrcMappingConfidence != "high" {
		t.Fatalf("src confidence = %q, want high (source-only)", record.SrcMappingConfidence)
	}
}

// Permanently unresolvable source: after the retry budget the record carries
// an explicitly frozen-missing identity — G2/G3/G4 unavailable with a
// reason, and no IP/name substituted into pod fields.
func TestRecordSourceIdentityPermanentMissing(t *testing.T) {
	resolver := identity.NewResolver(k8smeta.NewCache())
	base := time.Unix(4100, 0).UTC()
	s := sessionizer.New("node-a", 5*time.Minute, 30*time.Second)
	s.SetSourceIdentityResolver(resolver)

	mk := func(offset time.Duration, evType string, bytes uint64) {
		ev := windowTestEvent(base.Add(offset), evType, bytes)
		ev.SrcIP = "10.9.9.9" // private, no pod, not loopback, not external
		s.Process(ev)
	}
	mk(0, "CONNECT", 0)
	for i := 1; i <= 5; i++ {
		mk(time.Duration(i)*time.Second, "STATS", uint64(i*10))
	}
	closeEv := windowTestEvent(base.Add(10*time.Second), "CLOSE", 50)
	closeEv.SrcIP = "10.9.9.9"
	records := s.Process(closeEv)
	if len(records) != 2 {
		t.Fatalf("close: got %d records, want 2", len(records))
	}
	record := BuildRecord(records[1], resolver.Resolve(records[1]), experiment.Labels{})

	if !record.SrcIdentityFrozen || record.SrcIdentityAttempts != 5 {
		t.Fatalf("missing identity not frozen at budget: frozen=%v attempts=%d",
			record.SrcIdentityFrozen, record.SrcIdentityAttempts)
	}
	if record.SrcIdentityMissingReason != "unknown_source" {
		t.Fatalf("missing reason = %q, want unknown_source", record.SrcIdentityMissingReason)
	}
	if record.SrcPodUID != "" || record.SrcPodName != "" || record.SrcWorkloadUID != "" {
		t.Fatalf("missing identity substituted: %q/%q/%q", record.SrcPodUID, record.SrcPodName, record.SrcWorkloadUID)
	}
	if record.SrcKeyG2Available || record.SrcKeyG3Available || record.SrcKeyG4Available {
		t.Fatalf("G-keys claimed constructible on missing identity")
	}
	if record.SrcIP != "10.9.9.9" {
		t.Fatalf("G1 lost: src_ip = %q", record.SrcIP)
	}
}
