package identity

import (
	"testing"
	"time"

	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/sessionizer"

	corev1 "k8s.io/api/core/v1"
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
		Spec:   corev1.PodSpec{ServiceAccountName: "api-sa"},
		Status: corev1.PodStatus{PodIP: "10.1.1.10"},
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
}

func TestIdentityResolverServiceIP(t *testing.T) {
	cache := k8smeta.NewCache()
	cache.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default", UID: types.UID("svc-uid")},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports: []corev1.ServicePort{{
				Port:     443,
				Protocol: corev1.ProtocolTCP,
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
}
