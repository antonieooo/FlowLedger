package k8smeta

import "k8s.io/apimachinery/pkg/types"

// Revision sources for PodRolloutRevision. "not_applicable" (the workload
// kind has no rollout-revision concept) is deliberately distinct from
// "unavailable" (the pod should have one but it could not be derived) — the
// two must never be conflated with a transient resolution failure.
const (
	RevisionSourceReplicaSet         = "replicaset_revision"
	RevisionSourceControllerRevision = "controller_revision_hash"
	RevisionSourcePodTemplateHash    = "pod_template_hash"
	RevisionSourceNotApplicable      = "not_applicable"
	RevisionSourceUnavailable        = "unavailable"
)

// PodRolloutRevision returns the rollout revision THIS pod belongs to, plus
// its source. It is deliberately pod-scoped: a Deployment pod's revision
// comes from its owner ReplicaSet (each ReplicaSet carries the
// deployment.kubernetes.io/revision annotation of the rollout that created
// it), falling back to the pod's own pod-template-hash label; StatefulSet/
// DaemonSet pods use their controller-revision-hash label. It must NEVER be
// taken from the Deployment object's current revision annotation — during a
// rolling update that would stamp old-ReplicaSet pods with the newest
// revision (the WorkloadInfo.Revision populated via replicaSetToDeploy has
// exactly that defect and must not be used for per-pod rollout identity).
func (c *Cache) PodRolloutRevision(pod *PodInfo) (string, string) {
	if pod == nil {
		return "", RevisionSourceUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, owner := range pod.OwnerReferences {
		switch owner.Kind {
		case "ReplicaSet":
			if rs := c.replicaSets[types.UID(owner.UID)]; rs != nil && rs.Revision != "" {
				return rs.Revision, RevisionSourceReplicaSet
			}
			if hash := pod.Labels["pod-template-hash"]; hash != "" {
				return hash, RevisionSourcePodTemplateHash
			}
			return "", RevisionSourceUnavailable
		case "StatefulSet", "DaemonSet":
			if hash := pod.Labels["controller-revision-hash"]; hash != "" {
				return hash, RevisionSourceControllerRevision
			}
			return "", RevisionSourceUnavailable
		case "Job":
			return "", RevisionSourceNotApplicable
		}
	}
	return "", RevisionSourceNotApplicable
}

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
