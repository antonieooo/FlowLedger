//go:build !linux

package k8smeta

import "context"

type CgroupResolver struct{}

func NewCgroupResolver() *CgroupResolver            { return &CgroupResolver{} }
func (r *CgroupResolver) Start(ctx context.Context) {}
func (r *CgroupResolver) Resolve(cgroupID uint64) (string, string, bool) {
	return "", "", false
}
func (r *CgroupResolver) Size() int          { return 0 }
func (r *CgroupResolver) ErrorCount() uint64 { return 0 }
