package identity

import (
	"testing"
	"time"

	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/sessionizer"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// rolloutCache builds a Deployment mid-rolling-update: the Deployment's own
// annotation already says revision 4 (latest), ReplicaSet rs3 carries
// revision 3 and rs4 revision 4, with pods of both revisions coexisting
// (plus a second pod on rs4 = same-rollout scale-up).
func rolloutCache() *k8smeta.Cache {
	cache := k8smeta.NewCache()
	cache.UpsertDeployment(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api", Namespace: "shop", UID: types.UID("dep-uid"),
			Annotations: map[string]string{"deployment.kubernetes.io/revision": "4"},
		},
	})
	for _, rs := range []struct{ name, uid, rev, hash string }{
		{"api-aaa", "rs3-uid", "3", "aaa"},
		{"api-bbb", "rs4-uid", "4", "bbb"},
	} {
		cache.UpsertReplicaSet(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: rs.name, Namespace: "shop", UID: types.UID(rs.uid),
				Annotations: map[string]string{"deployment.kubernetes.io/revision": rs.rev},
				Labels:      map[string]string{"pod-template-hash": rs.hash},
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "Deployment", Name: "api", UID: types.UID("dep-uid")},
				},
			},
		})
	}
	for _, p := range []struct{ name, uid, ip, rsName, rsUID, hash string }{
		{"api-aaa-1", "pod-old-uid", "10.1.1.11", "api-aaa", "rs3-uid", "aaa"},
		{"api-bbb-1", "pod-new-uid", "10.1.1.12", "api-bbb", "rs4-uid", "bbb"},
		{"api-bbb-2", "pod-new2-uid", "10.1.1.13", "api-bbb", "rs4-uid", "bbb"},
	} {
		cache.UpsertPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.name, Namespace: "shop", UID: types.UID(p.uid),
				Labels: map[string]string{"pod-template-hash": p.hash},
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: p.rsName, UID: types.UID(p.rsUID)},
				},
				CreationTimestamp: metav1.NewTime(time.Unix(10, 0)),
			},
			Status: corev1.PodStatus{PodIP: p.ip},
		})
	}
	return cache
}

func snapshotByIP(t *testing.T, r *Resolver, ip string) sessionizer.SourceIdentity {
	t.Helper()
	snap, terminal := r.ResolveSourceIdentity(sessionizer.SourceIdentityRequest{
		SrcIP: ip, ConnStart: time.Unix(100, 0).UTC(),
	})
	if !terminal {
		t.Fatalf("resolution for %s not terminal", ip)
	}
	return snap
}

// Tests 7+8: during a rolling update, old- and new-revision pods share G3
// (same top-level controller) but carry their OWN rollout revision (G4
// differs); same-rollout scale-up and pod recreation keep G4 identical. The
// old pod must NOT receive the Deployment's current latest revision.
func TestSourceSnapshotRolloutRevisions(t *testing.T) {
	r := NewResolver(rolloutCache())

	oldPod := snapshotByIP(t, r, "10.1.1.11")
	newPod := snapshotByIP(t, r, "10.1.1.12")
	scaled := snapshotByIP(t, r, "10.1.1.13")

	// G3: all three key to the same top-level controller.
	for i, s := range []sessionizer.SourceIdentity{oldPod, newPod, scaled} {
		if s.Namespace != "shop" || s.WorkloadKind != "Deployment" || s.WorkloadUID != "dep-uid" {
			t.Fatalf("pod %d G3 wrong: %#v", i, s)
		}
		if s.RevisionSource != k8smeta.RevisionSourceReplicaSet {
			t.Fatalf("pod %d revision source = %q, want %q", i, s.RevisionSource, k8smeta.RevisionSourceReplicaSet)
		}
	}
	// G4: pod-scoped revisions — the old pod keeps 3 even though the
	// Deployment object already says 4.
	if oldPod.Revision != "3" {
		t.Fatalf("old pod revision = %q, want 3 (got the Deployment's latest?)", oldPod.Revision)
	}
	if newPod.Revision != "4" || scaled.Revision != "4" {
		t.Fatalf("new-rollout revisions = %q/%q, want 4/4", newPod.Revision, scaled.Revision)
	}
	// G2 differs per pod; same-rollout pods share G4.
	if newPod.PodUID == scaled.PodUID {
		t.Fatalf("distinct pods share a UID")
	}
	if oldPod.PodTemplateHash != "aaa" || newPod.PodTemplateHash != "bbb" {
		t.Fatalf("pod template hashes = %q/%q, want aaa/bbb", oldPod.PodTemplateHash, newPod.PodTemplateHash)
	}
}

// Revision-source taxonomy: DaemonSet/StatefulSet pods use their
// controller-revision-hash label; workload kinds without a rollout concept
// are not_applicable — explicitly distinct from a transient failure.
func TestSourceSnapshotRevisionSources(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ds-1", Namespace: "infra", UID: types.UID("ds-pod-uid"),
			Labels: map[string]string{"controller-revision-hash": "ds-rev-7"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "DaemonSet", Name: "agent", UID: types.UID("ds-uid")},
			},
		},
		Status: corev1.PodStatus{PodIP: "10.2.1.1"},
	})
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bare-1", Namespace: "infra", UID: types.UID("bare-pod-uid"),
		},
		Status: corev1.PodStatus{PodIP: "10.2.1.2"},
	})
	r := NewResolver(cache)

	ds := snapshotByIP(t, r, "10.2.1.1")
	if ds.Revision != "ds-rev-7" || ds.RevisionSource != k8smeta.RevisionSourceControllerRevision {
		t.Fatalf("daemonset revision = %q/%q, want ds-rev-7/%q", ds.Revision, ds.RevisionSource, k8smeta.RevisionSourceControllerRevision)
	}
	bare := snapshotByIP(t, r, "10.2.1.2")
	if bare.Revision != "" || bare.RevisionSource != k8smeta.RevisionSourceNotApplicable {
		t.Fatalf("bare pod revision = %q/%q, want empty/%q", bare.Revision, bare.RevisionSource, k8smeta.RevisionSourceNotApplicable)
	}
}

// Tests 1 (identity half) + 10: Resolve materializes the session's frozen
// snapshot for the source even when the cache now says something else, while
// the destination is still resolved live and stays unaffected.
func TestResolveUsesFrozenSourceSnapshotAndLiveDestination(t *testing.T) {
	cache := k8smeta.NewCache()
	// The cache's CURRENT view of the source IP is a different pod.
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "imposter", Namespace: "shop", UID: types.UID("pod-current-uid")},
		Status:     corev1.PodStatus{PodIP: "10.1.1.10"},
	})
	cache.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop", UID: types.UID("svc-uid")},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports:     []corev1.ServicePort{{Port: 443, Name: "https"}},
		},
	})

	session := sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.96.0.10", DstPort: 443,
		Protocol: "tcp",
		SourceIdentity: sessionizer.SourceIdentity{
			Attempted: true, Frozen: true,
			ObservedAt: time.Unix(99, 0).UTC(),
			Namespace:  "shop", PodName: "api-aaa-1", PodUID: "pod-frozen-uid",
			WorkloadKind: "Deployment", WorkloadName: "api", WorkloadUID: "dep-uid",
			Revision: "3", RevisionSource: k8smeta.RevisionSourceReplicaSet,
			Confidence: "high", Method: "cgroup_id", ResolutionStatus: "resolved",
		},
	}
	resolved := NewResolver(cache).Resolve(session)

	if resolved.Src.PodUID != "pod-frozen-uid" || resolved.Src.PodName != "api-aaa-1" {
		t.Fatalf("source re-resolved at output time: %#v", resolved.Src)
	}
	if resolved.Src.Revision != "3" {
		t.Fatalf("frozen revision lost: %#v", resolved.Src)
	}
	if resolved.Dst.ServiceName != "checkout" || resolved.Dst.ServiceUID != "svc-uid" {
		t.Fatalf("destination resolution affected: %#v", resolved.Dst)
	}
}
