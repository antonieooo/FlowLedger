package k8smeta

import "k8s.io/apimachinery/pkg/types"

func (c *Cache) ResolvePod(pod *PodInfo) *WorkloadInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolvePodLocked(pod)
}

func (c *Cache) resolvePodLocked(pod *PodInfo) *WorkloadInfo {
	if pod == nil {
		return nil
	}
	for _, owner := range pod.OwnerReferences {
		uid := types.UID(owner.UID)
		switch owner.Kind {
		case "ReplicaSet":
			if dep := c.replicaSetToDeploy[uid]; dep != nil {
				return cloneWorkload(dep)
			}
			if rs := c.replicaSets[uid]; rs != nil {
				return cloneWorkload(rs)
			}
			return &WorkloadInfo{
				Kind:            "ReplicaSet",
				Name:            owner.Name,
				UID:             uid,
				Namespace:       pod.Namespace,
				PodTemplateHash: pod.Labels["pod-template-hash"],
			}
		case "StatefulSet", "DaemonSet":
			if wl := c.workloads[uid]; wl != nil {
				return cloneWorkload(wl)
			}
			return &WorkloadInfo{Kind: owner.Kind, Name: owner.Name, UID: uid, Namespace: pod.Namespace}
		case "Job":
			if cj := c.jobsToCronJobs[uid]; cj != nil {
				return cloneWorkload(cj)
			}
			if job := c.workloads[uid]; job != nil {
				return cloneWorkload(job)
			}
			return &WorkloadInfo{Kind: "Job", Name: owner.Name, UID: uid, Namespace: pod.Namespace}
		}
	}
	return &WorkloadInfo{
		Kind:            "BarePod",
		Name:            pod.Name,
		UID:             pod.UID,
		Namespace:       pod.Namespace,
		PodTemplateHash: pod.Labels["pod-template-hash"],
	}
}

func cloneWorkload(w *WorkloadInfo) *WorkloadInfo {
	if w == nil {
		return nil
	}
	cp := *w
	return &cp
}
