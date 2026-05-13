//go:build linux

package k8smeta

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPodUIDFromCgroupPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "systemd underscores",
			path: "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podde70e4f3_de2b_4e9a_b8af_e1477d544a6d.slice",
			want: "de70e4f3-de2b-4e9a-b8af-e1477d544a6d",
		},
		{
			name: "systemd compact uid",
			path: "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod24eb0a3c1993d1f940b60036cdddefbf.slice",
			want: "24eb0a3c-1993-d1f9-40b6-0036cdddefbf",
		},
		{
			name: "legacy kubepods slice underscore uid",
			path: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/" +
				"kubepods-burstable-podde70e4f3_de2b_4e9a_b8af_e1477d544a6d" +
				".slice/cri-containerd-abcdef.scope",
			want: "de70e4f3-de2b-4e9a-b8af-e1477d544a6d",
		},
		{
			// Defensive normalization case; this is not known to be produced by
			// upstream kubelet with systemd.
			name: "compact uid is normalized to hyphenated uuid",
			path: "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/" +
				"kubelet-kubepods-burstable.slice/" +
				"kubelet-kubepods-burstable-pod24eb0a3c1993d1f940b60036" +
				"cdddefbf.slice",
			want: "24eb0a3c-1993-d1f9-40b6-0036cdddefbf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := podUIDFromCgroupPath(tt.path); got != tt.want {
				t.Fatalf("podUIDFromCgroupPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCgroupResolverScanWalksBothSupportedRoots(t *testing.T) {
	cgroupRoot := filepath.Join(t.TempDir(), "sys", "fs", "cgroup")
	legacyLeaf := filepath.Join(
		cgroupRoot,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-podde70e4f3_de2b_4e9a_b8af_e1477d544a6d.slice",
		"cri-containerd-A.scope",
	)
	kubeletLeaf := filepath.Join(
		cgroupRoot,
		"kubelet.slice",
		"kubelet-kubepods.slice",
		"kubelet-kubepods-burstable.slice",
		"kubelet-kubepods-burstable-pod24eb0a3c1993d1f940b60036cdddefbf.slice",
		"cri-containerd-B.scope",
	)

	for _, path := range []string{legacyLeaf, kubeletLeaf} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create cgroup path %q: %v", path, err)
		}
	}

	resolver := &CgroupResolver{
		roots: []string{
			filepath.Join(cgroupRoot, "kubepods.slice"),
			filepath.Join(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice"),
		},
		period:  10 * time.Second,
		entries: map[uint64]cgroupEntry{},
	}
	if err := resolver.scan(); err != nil {
		t.Fatalf("scan() error = %v", err)
	}

	tests := []struct {
		name       string
		path       string
		wantPodUID string
		wantContID string
	}{
		{
			name:       "legacy root",
			path:       legacyLeaf,
			wantPodUID: "de70e4f3-de2b-4e9a-b8af-e1477d544a6d",
			wantContID: "A",
		},
		{
			name:       "kubelet root",
			path:       kubeletLeaf,
			wantPodUID: "24eb0a3c-1993-d1f9-40b6-0036cdddefbf",
			wantContID: "B",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := cgroupID(tt.path)
			if err != nil {
				t.Fatalf("cgroupID(%q) error = %v", tt.path, err)
			}
			entry, ok := resolver.entries[id]
			if !ok {
				t.Fatalf("resolver.entries[%d] missing", id)
			}
			if entry.podUID != tt.wantPodUID {
				t.Fatalf("podUID = %q, want %q", entry.podUID, tt.wantPodUID)
			}
			if entry.containerID != tt.wantContID {
				t.Fatalf("containerID = %q, want %q", entry.containerID, tt.wantContID)
			}
			podUID, containerID, ok := resolver.Resolve(id)
			if !ok || podUID != tt.wantPodUID || containerID != tt.wantContID {
				t.Fatalf("Resolve(%d) = (%q, %q, %v), want (%q, %q, true)", id, podUID, containerID, ok, tt.wantPodUID, tt.wantContID)
			}
		})
	}
}
