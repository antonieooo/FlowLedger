//go:build linux

package k8smeta

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var podUIDInCgroupPath = regexp.MustCompile(`pod([0-9a-fA-F_-]{32,36})\.slice`)

type CgroupResolver struct {
	roots      []string
	period     time.Duration
	mu         sync.RWMutex
	entries    map[uint64]cgroupEntry
	lastErrs   uint64
	lastScan   time.Time
	minRescan  time.Duration // C10: minimum interval between on-demand rescans
	rescanCh   chan struct{} // C10: signal channel for on-demand rescan
	metrics    CgroupMetrics // C10: optional sink for resolution result metrics
}

type cgroupEntry struct {
	podUID      string
	containerID string
}

// CgroupMetrics is an optional sink for cgroup resolution outcomes.
// Result label values: "hit", "miss", "retry_hit", "retry_miss".
type CgroupMetrics interface {
	IncCgroupResolution(result string)
}

func NewCgroupResolver() *CgroupResolver {
	return &CgroupResolver{
		roots: []string{
			"/sys/fs/cgroup/kubepods.slice",
			"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice",
		},
		// C10: was 10s. Tighten to 2s so the race window between pod creation
		// (and its first network event) and the next cgroup scan is small enough
		// that most flows resolve on the first emit attempt.
		period:    2 * time.Second,
		// C10: debounce on-demand rescans triggered by Resolve misses.
		minRescan: 200 * time.Millisecond,
		entries:   map[uint64]cgroupEntry{},
		rescanCh:  make(chan struct{}, 1),
	}
}

// SetMetrics attaches an optional metrics sink. Call before Start().
func (r *CgroupResolver) SetMetrics(m CgroupMetrics) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.metrics = m
	r.mu.Unlock()
}

// triggerRescan signals the background goroutine to scan now. Non-blocking and
// debounced via the channel's capacity-1 buffer.
func (r *CgroupResolver) triggerRescan() {
	if r == nil {
		return
	}
	select {
	case r.rescanCh <- struct{}{}:
	default:
	}
}

func (r *CgroupResolver) sinceLastScan() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.lastScan.IsZero() {
		return time.Hour
	}
	return time.Since(r.lastScan)
}

func (r *CgroupResolver) emitResolution(result string) {
	r.mu.RLock()
	m := r.metrics
	r.mu.RUnlock()
	if m != nil {
		m.IncCgroupResolution(result)
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
		case <-r.rescanCh:
			// C10: on-demand rescan triggered by a Resolve miss. Debounced via
			// minRescan to avoid pathological loops when a flow has a stale
			// cgroup_id that will never be in the slice tree.
			if r.sinceLastScan() < r.minRescan {
				continue
			}
			if err := r.scan(); err != nil {
				r.mu.Lock()
				r.lastErrs++
				r.mu.Unlock()
				log.Printf("cgroup resolver on-demand scan skipped: %v", err)
			}
		}
	}
}

func (r *CgroupResolver) Resolve(cgroupID uint64) (podUID string, containerID string, ok bool) {
	if r == nil || cgroupID == 0 {
		return "", "", false
	}
	r.mu.RLock()
	entry, ok := r.entries[cgroupID]
	r.mu.RUnlock()
	if ok {
		r.emitResolution("hit")
		return entry.podUID, entry.containerID, true
	}
	r.emitResolution("miss")
	return "", "", false
}

// ResolveWithRetry (C10) is the preferred entry point at session_summary
// emission time. If the initial lookup misses, it asynchronously triggers an
// on-demand cgroup rescan so that the next emission cycle (typically 1s later)
// has a fresh chance to resolve. This is NON-BLOCKING: it never sleeps.
//
// Earlier versions polled for up to 500ms after a miss, but in practice with
// 100s of session emissions per tick that turned the emit loop into a >1s
// stall every tick, starving the events channel and dropping TLS handshake
// events from the BPF ring buffer. The empirical retry_hit rate was 0%
// anyway (cgroup IDs that miss tend to stay missing — host_network, deleted
// pods, kube-system, etc.). The on-demand rescan still helps subsequent
// emissions; the metric labels are kept the same for backwards compat.
func (r *CgroupResolver) ResolveWithRetry(cgroupID uint64) (podUID string, containerID string, ok bool) {
	if r == nil || cgroupID == 0 {
		return "", "", false
	}
	r.mu.RLock()
	entry, ok := r.entries[cgroupID]
	r.mu.RUnlock()
	if ok {
		r.emitResolution("hit")
		return entry.podUID, entry.containerID, true
	}
	// Async: signal background scanner, return immediately. The next session
	// emission tick (typically 1s later) will see the refreshed cache.
	r.triggerRescan()
	r.emitResolution("retry_miss")
	return "", "", false
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
	foundRoot := false
	next := map[uint64]cgroupEntry{}

	for _, root := range r.roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		foundRoot = true
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
	}
	if !foundRoot {
		return fmt.Errorf("no supported Kubernetes cgroup root found under /sys/fs/cgroup")
	}
	r.mu.Lock()
	r.entries = next
	r.lastScan = time.Now()
	r.mu.Unlock()
	return nil
}

func podUIDFromCgroupPath(path string) string {
	match := podUIDInCgroupPath.FindStringSubmatch(path)
	if len(match) != 2 {
		return ""
	}
	uid := strings.ReplaceAll(match[1], "_", "-")
	if len(uid) == 32 {
		return uid[0:8] + "-" + uid[8:12] + "-" + uid[12:16] + "-" + uid[16:20] + "-" + uid[20:32]
	}
	return uid
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
