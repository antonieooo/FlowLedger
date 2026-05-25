//go:build !linux

package k8smeta

import "context"

type CgroupResolver struct{}

// CgroupMetrics mirrors the linux build's interface for cross-platform builds.
type CgroupMetrics interface {
	IncCgroupResolution(result string)
}

func NewCgroupResolver() *CgroupResolver            { return &CgroupResolver{} }
func (r *CgroupResolver) Start(ctx context.Context) {}
func (r *CgroupResolver) Resolve(cgroupID uint64) (string, string, bool) {
	return "", "", false
}

// ResolveWithRetry mirrors the linux build. On non-linux builds there is no
// cgroup filesystem to scan; behaves identically to Resolve.
func (r *CgroupResolver) ResolveWithRetry(cgroupID uint64) (string, string, bool) {
	return "", "", false
}

func (r *CgroupResolver) SetMetrics(m CgroupMetrics) {}
func (r *CgroupResolver) Size() int                  { return 0 }
func (r *CgroupResolver) ErrorCount() uint64         { return 0 }
