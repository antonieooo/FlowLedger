package k8smeta

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func makeMultiContainerPod(uid string, statuses []corev1.ContainerStatus) *corev1.Pod {
	specContainers := make([]corev1.Container, 0, len(statuses))
	for _, cs := range statuses {
		specContainers = append(specContainers, corev1.Container{Name: cs.Name})
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-" + uid,
			Namespace: "default",
			UID:       types.UID(uid),
		},
		Spec:   corev1.PodSpec{Containers: specContainers},
		Status: corev1.PodStatus{ContainerStatuses: statuses},
	}
}

func TestContainerNameByIDPrimaryAndSidecar(t *testing.T) {
	cache := NewCache()
	cache.UpsertPod(makeMultiContainerPod("pod-uid", []corev1.ContainerStatus{
		{Name: "web-frontend", ContainerID: "containerd://primary-id"},
		{Name: "c2-sim-sidecar", ContainerID: "containerd://sidecar-id"},
	}))

	if name, ok := cache.ContainerNameByID("pod-uid", "containerd://primary-id"); !ok || name != "web-frontend" {
		t.Fatalf("primary lookup: got (%q, %v), want (\"web-frontend\", true)", name, ok)
	}
	if name, ok := cache.ContainerNameByID("pod-uid", "containerd://sidecar-id"); !ok || name != "c2-sim-sidecar" {
		t.Fatalf("sidecar lookup: got (%q, %v), want (\"c2-sim-sidecar\", true)", name, ok)
	}
}

func TestContainerNameByIDPrefixCombinations(t *testing.T) {
	cases := []struct {
		name      string
		storedID  string
		queriedID string
	}{
		{"bare/bare", "abc123", "abc123"},
		{"bare/prefixed", "abc123", "containerd://abc123"},
		{"prefixed/bare", "containerd://abc123", "abc123"},
		{"prefixed/prefixed", "containerd://abc123", "containerd://abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewCache()
			cache.UpsertPod(makeMultiContainerPod("pod-uid", []corev1.ContainerStatus{
				{Name: "app", ContainerID: tc.storedID},
			}))
			name, ok := cache.ContainerNameByID("pod-uid", tc.queriedID)
			if !ok || name != "app" {
				t.Fatalf("got (%q, %v), want (\"app\", true)", name, ok)
			}
		})
	}
}

func TestContainerNameByIDUnknownPod(t *testing.T) {
	cache := NewCache()
	cache.UpsertPod(makeMultiContainerPod("pod-uid", []corev1.ContainerStatus{
		{Name: "app", ContainerID: "containerd://abc"},
	}))
	if name, ok := cache.ContainerNameByID("missing-uid", "containerd://abc"); ok || name != "" {
		t.Fatalf("got (%q, %v), want (\"\", false)", name, ok)
	}
}

func TestContainerNameByIDUnknownContainer(t *testing.T) {
	cache := NewCache()
	cache.UpsertPod(makeMultiContainerPod("pod-uid", []corev1.ContainerStatus{
		{Name: "app", ContainerID: "containerd://abc"},
	}))
	if name, ok := cache.ContainerNameByID("pod-uid", "containerd://does-not-exist"); ok || name != "" {
		t.Fatalf("got (%q, %v), want (\"\", false)", name, ok)
	}
}

func TestContainerNameByIDEmptyContainerStatuses(t *testing.T) {
	cache := NewCache()
	cache.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-pending", Namespace: "default", UID: types.UID("pod-uid")},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	})

	pod, ok := cache.PodByUID("pod-uid")
	if !ok {
		t.Fatalf("PodByUID returned not ok")
	}
	if len(pod.Containers) != 0 {
		t.Fatalf("expected empty Containers map, got %v", pod.Containers)
	}
	if name, ok := cache.ContainerNameByID("pod-uid", "containerd://anything"); ok || name != "" {
		t.Fatalf("got (%q, %v), want (\"\", false)", name, ok)
	}
}

func TestContainerNameByIDSkipsEmptyContainerIDs(t *testing.T) {
	cache := NewCache()
	cache.UpsertPod(makeMultiContainerPod("pod-uid", []corev1.ContainerStatus{
		{Name: "started", ContainerID: "containerd://abc"},
		{Name: "not-started", ContainerID: ""},
	}))
	if name, ok := cache.ContainerNameByID("pod-uid", "containerd://abc"); !ok || name != "started" {
		t.Fatalf("started lookup: got (%q, %v), want (\"started\", true)", name, ok)
	}
	if name, ok := cache.ContainerNameByID("pod-uid", ""); ok || name != "" {
		t.Fatalf("empty containerID lookup: got (%q, %v), want (\"\", false)", name, ok)
	}
}
