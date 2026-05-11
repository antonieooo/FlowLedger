package k8smeta

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestOwnerResolverDeployment(t *testing.T) {
	cache := NewCache()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default", UID: types.UID("dep-uid")},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"pod-template-hash": "abc123"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Image: "repo/api:v1"}}},
		}},
	}
	rs := &appsv1.ReplicaSet{
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
	}
	cache.UpsertDeployment(dep)
	cache.UpsertReplicaSet(rs)
	pod := &PodInfo{
		Namespace: "default",
		Name:      "api-abc123-x",
		UID:       types.UID("pod-uid"),
		Labels:    map[string]string{"pod-template-hash": "abc123"},
		OwnerReferences: []metav1.OwnerReference{{
			Kind: "ReplicaSet",
			Name: "api-abc123",
			UID:  types.UID("rs-uid"),
		}},
	}

	wl := cache.ResolvePod(pod)
	if wl == nil || wl.Kind != "Deployment" || wl.Name != "api" || wl.UID != types.UID("dep-uid") {
		t.Fatalf("expected Deployment/api dep-uid, got %#v", wl)
	}
}

func TestOwnerResolverStatefulSet(t *testing.T) {
	cache := NewCache()
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "default", UID: types.UID("sts-uid")},
		Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "postgres:16"}}},
		}},
	}
	cache.UpsertStatefulSet(sts)
	pod := &PodInfo{
		Namespace: "default",
		Name:      "db-0",
		UID:       types.UID("pod-uid"),
		OwnerReferences: []metav1.OwnerReference{{
			Kind: "StatefulSet",
			Name: "db",
			UID:  types.UID("sts-uid"),
		}},
	}

	wl := cache.ResolvePod(pod)
	if wl == nil || wl.Kind != "StatefulSet" || wl.Name != "db" || wl.UID != types.UID("sts-uid") {
		t.Fatalf("expected StatefulSet/db sts-uid, got %#v", wl)
	}
}
