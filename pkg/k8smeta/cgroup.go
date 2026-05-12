//go:build linux

package k8smeta

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var podUIDInCgroupPath = regexp.MustCompile(`pod([0-9a-fA-F_]{36})`)

type CgroupResolver struct {
	root     string
	period   time.Duration
	mu       sync.RWMutex
	entries  map[uint64]cgroupEntry
	lastErrs uint64
}

type cgroupEntry struct {
	podUID      string
	containerID string
}

func NewCgroupResolver() *CgroupResolver {
	return &CgroupResolver{
		root:    "/sys/fs/cgroup/kubepods.slice",
		period:  10 * time.Second,
		entries: map[uint64]cgroupEntry{},
	}
}

func (r *CgroupResolver) Start(ctx context.Context) {
	if r == nil {
		return
	}
	if err := r.scan(); err != nil {
		log.Printf("cgroup resolver initial scan skipped: %v", err)
	}
	ticker := time.NewTicker(r.period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.scan(); err != nil {
				r.mu.Lock()
				r.lastErrs++
				r.mu.Unlock()
				log.Printf("cgroup resolver scan skipped: %v", err)
			}
		}
	}
}

func (r *CgroupResolver) Resolve(cgroupID uint64) (podUID string, containerID string, ok bool) {
	if r == nil || cgroupID == 0 {
		return "", "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[cgroupID]
	return entry.podUID, entry.containerID, ok
}

func (r *CgroupResolver) Size() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

func (r *CgroupResolver) ErrorCount() uint64 {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastErrs
}

func (r *CgroupResolver) scan() error {
	if _, err := os.Stat(r.root); err != nil {
		return err
	}
	next := map[uint64]cgroupEntry{}
	err := filepath.WalkDir(r.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		podUID := podUIDFromCgroupPath(path)
		if podUID == "" {
			return nil
		}
		id, err := cgroupID(path)
		if err != nil {
			return nil
		}
		next[id] = cgroupEntry{podUID: podUID, containerID: containerIDFromCgroupPath(path)}
		return nil
	})
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.entries = next
	r.mu.Unlock()
	return nil
}

func podUIDFromCgroupPath(path string) string {
	match := podUIDInCgroupPath.FindStringSubmatch(path)
	if len(match) != 2 {
		return ""
	}
	return strings.ReplaceAll(match[1], "_", "-")
}

func containerIDFromCgroupPath(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, ".scope")
	for _, prefix := range []string{"cri-containerd-", "docker-", "crio-"} {
		if strings.HasPrefix(base, prefix) {
			return strings.TrimPrefix(base, prefix)
		}
	}
	return ""
}

func cgroupID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, os.ErrInvalid
	}
	return stat.Ino, nil
}
