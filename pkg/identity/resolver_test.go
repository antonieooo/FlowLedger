package identity

import (
	"testing"
	"time"

	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/sessionizer"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestIdentityResolverPodIP(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "api-1",
			Namespace:         "default",
			UID:               types.UID("pod-uid"),
			CreationTimestamp: metav1.NewTime(time.Unix(90, 0)),
		},
		Spec: corev1.PodSpec{ServiceAccountName: "api-sa"},
		Status: corev1.PodStatus{
			PodIP: "10.1.1.10",
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "api",
				ContainerID: "containerd://abc",
				ImageID:     "repo/api@sha256:deadbeef",
			}},
		},
	})
	session := sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol: "tcp",
	}

	resolved := NewResolver(cache).Resolve(session)
	if resolved.Src.PodUID != "pod-uid" || resolved.Src.PodName != "api-1" || resolved.Src.Confidence != "high" {
		t.Fatalf("unexpected source identity: %#v", resolved.Src)
	}
	if resolved.Src.WorkloadKind != "BarePod" {
		t.Fatalf("expected BarePod workload, got %#v", resolved.Src)
	}
	if resolved.Src.ContainerID != "containerd://abc" || resolved.Src.ImageDigest != "sha256:deadbeef" {
		t.Fatalf("expected container metadata, got %#v", resolved.Src)
	}
}

type fakeCgroupLookup map[uint64]struct {
	podUID      string
	containerID string
}

func (f fakeCgroupLookup) Resolve(cgroupID uint64) (string, string, bool) {
	v, ok := f[cgroupID]
	return v.podUID, v.containerID, ok
}

func TestIdentityResolverCgroupIDPreferredOverPodIP(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "new-api", Namespace: "default", UID: types.UID("new-pod-uid")},
		Status:     corev1.PodStatus{PodIP: "10.1.1.10"},
	})
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "old-api", Namespace: "default", UID: types.UID("old-pod-uid")},
		Status:     corev1.PodStatus{PodIP: "10.1.1.99"},
	})
	resolver := NewResolverWithCgroups(cache, fakeCgroupLookup{
		42: {podUID: "old-pod-uid", containerID: "containerd://old"},
	})

	resolved := resolver.Resolve(sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		CgroupID:  42,
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol: "tcp",
	})
	if resolved.Src.PodUID != "old-pod-uid" || resolved.Src.PodName != "old-api" || resolved.Src.Method != "cgroup_id" || resolved.Src.Confidence != "high" {
		t.Fatalf("unexpected cgroup identity: %#v", resolved.Src)
	}
	if resolved.MappingMethod != "cgroup_id" {
		t.Fatalf("MappingMethod = %q, want cgroup_id", resolved.MappingMethod)
	}
}

func TestIdentityResolverServiceIP(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default", UID: types.UID("svc-uid")},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports: []corev1.ServicePort{{
				Name:        "https",
				Port:        443,
				Protocol:    corev1.ProtocolTCP,
				AppProtocol: strPtr("kubernetes.io/h2c"),
			}},
		},
	})
	session := sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.96.0.10", DstPort: 443,
		Protocol: "tcp",
	}

	resolved := NewResolver(cache).Resolve(session)
	if resolved.Dst.ServiceName != "api" || resolved.Dst.Confidence != "medium" || resolved.MappingMethod != "service_cluster_ip" {
		t.Fatalf("unexpected destination service identity: %#v", resolved)
	}
	if resolved.Dst.ServiceUID != "svc-uid" || resolved.Dst.ServicePortName != "https" || resolved.Dst.AppProtocol != "kubernetes.io/h2c" {
		t.Fatalf("unexpected service context: %#v", resolved.Dst)
	}
}

func TestIdentityResolverEndpointSliceBackendAndDeploymentOwner(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertDeployment(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default", UID: types.UID("dep-uid")},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"pod-template-hash": "abc123"}},
		}},
	})
	cache.UpsertReplicaSet(&appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-abc123",
			Namespace: "default",
			UID:       types.UID("rs-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "Deployment",
				Name: "api",
				UID:  types.UID("dep-uid"),
			}},
		},
		Spec: appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"pod-template-hash": "abc123"}},
		}},
	})
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-abc123-x",
			Namespace: "default",
			UID:       types.UID("pod-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "ReplicaSet",
				Name: "api-abc123",
				UID:  types.UID("rs-uid"),
			}},
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "api-sa"},
		Status: corev1.PodStatus{PodIP: "10.1.1.20"},
	})
	cache.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default", UID: types.UID("svc-uid")},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.20",
			Ports:     []corev1.ServicePort{{Name: "http", Port: 8080, Protocol: corev1.ProtocolTCP}},
		},
	})
	port := int32(8080)
	cache.UpsertEndpointSlice(&discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-slice",
			Namespace: "default",
			UID:       types.UID("slice-uid"),
			Labels:    map[string]string{discoveryv1.LabelServiceName: "api"},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.1.1.20"},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", UID: types.UID("pod-uid")},
		}},
		Ports: []discoveryv1.EndpointPort{{Port: &port}},
	})

	resolved := NewResolver(cache).Resolve(sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 8080,
		Protocol: "tcp",
	})
	if resolved.Dst.WorkloadKind != "Deployment" || resolved.Dst.WorkloadName != "api" || resolved.Dst.ReplicaSet != "api-abc123" {
		t.Fatalf("unexpected endpoint backend identity: %#v", resolved.Dst)
	}
	if resolved.Dst.ServiceName != "api" || resolved.Dst.ServicePortName != "http" || resolved.MappingMethod != "endpoint_slice" {
		t.Fatalf("unexpected endpoint service context: %#v", resolved)
	}
}

func TestIdentityResolverCgroupIDResolvesSidecarContainerName(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "multi", Namespace: "default", UID: types.UID("pod-uid")},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "web-frontend"},
			{Name: "c2-sim-sidecar"},
		}},
		Status: corev1.PodStatus{
			PodIP: "10.1.1.10",
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "web-frontend", ContainerID: "containerd://primary-id"},
				{Name: "c2-sim-sidecar", ContainerID: "containerd://sidecar-id"},
			},
		},
	})
	resolver := NewResolverWithCgroups(cache, fakeCgroupLookup{
		42: {podUID: "pod-uid", containerID: "containerd://sidecar-id"},
	})

	resolved := resolver.Resolve(sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		CgroupID:  42,
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol: "tcp",
	})
	if resolved.Src.ContainerName != "c2-sim-sidecar" {
		t.Fatalf("ContainerName = %q, want %q", resolved.Src.ContainerName, "c2-sim-sidecar")
	}
	if resolved.Src.ContainerID != "containerd://sidecar-id" {
		t.Fatalf("ContainerID = %q, want %q", resolved.Src.ContainerID, "containerd://sidecar-id")
	}
}

func TestIdentityResolverCgroupIDEmptyContainerIDFallsBackToPrimary(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "multi", Namespace: "default", UID: types.UID("pod-uid")},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "web-frontend"},
			{Name: "c2-sim-sidecar"},
		}},
		Status: corev1.PodStatus{
			PodIP: "10.1.1.10",
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "web-frontend", ContainerID: "containerd://primary-id"},
				{Name: "c2-sim-sidecar", ContainerID: "containerd://sidecar-id"},
			},
		},
	})
	resolver := NewResolverWithCgroups(cache, fakeCgroupLookup{
		42: {podUID: "pod-uid", containerID: ""},
	})

	resolved := resolver.Resolve(sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		CgroupID:  42,
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol: "tcp",
	})
	if resolved.Src.ContainerName != "web-frontend" {
		t.Fatalf("ContainerName = %q, want primary fallback %q", resolved.Src.ContainerName, "web-frontend")
	}
}

func TestIdentityResolverUnknown(t *testing.T) {
	resolved := NewResolver(k8smeta.NewCache()).Resolve(sessionizer.FlowSession{
		StartTime: time.Unix(100, 0).UTC(),
		SrcIP:     "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol: "tcp",
	})
	if resolved.Src.Confidence != "unknown" || resolved.Dst.Confidence != "unknown" || resolved.MappingMethod != "unknown" {
		t.Fatalf("unexpected unknown mapping: %#v", resolved)
	}
}

func strPtr(s string) *string {
	return &s
}
