package identity

import (
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"time"

	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/sessionizer"
)

// Resolution status (C11) — separates "we know who this is" from the various
// reasons identity lookup failed. Previously the resolver returned the same
// empty EndpointIdentity for host-network pods, kube-system traffic, informer
// cache misses, and unknown external endpoints, making the downstream
// dataset builder unable to tell apart "broken resolution" from "by design
// no identity" (etcd loopback, kubelet host network, etc.).
const (
	ResolutionStatusResolved     = "resolved"      // full pod identity known
	ResolutionStatusServiceOnly  = "service_only"  // service context known, backend pod unknown
	ResolutionStatusHostNetwork  = "host_network"  // pod runs in host network, no cgroup namespace
	ResolutionStatusKubeSystem   = "kube_system"   // control-plane / system namespace
	ResolutionStatusInformerMiss = "informer_miss" // cgroup_id resolved but pod not in informer cache (race)
	ResolutionStatusExternal     = "external"      // off-cluster endpoint
	ResolutionStatusUnknown      = "unknown"       // cannot determine
)

// SystemNamespaces are control-plane namespaces whose flows are not
// considered business workload. Mirrors the cluster-side L15 filter.
var SystemNamespaces = map[string]bool{
	"kube-system":        true,
	"kube-node-lease":    true,
	"kube-public":        true,
	"local-path-storage": true,
}

type EndpointIdentity struct {
	Namespace        string
	PodName          string
	PodUID           string
	NodeName         string
	ContainerName    string
	ContainerID      string
	CgroupID         uint64
	WorkloadKind     string
	WorkloadName     string
	WorkloadUID      string
	ReplicaSet       string
	PodTemplateHash  string
	ImageDigest      string
	ServiceAccount   string
	Revision         string
	ServiceName      string
	ServiceUID       string
	ServiceNamespace string
	ServicePortName  string
	AppProtocol      string
	External         bool
	Confidence       string
	Method           string
	Reason           string
	// ResolutionStatus (C11) categorises why this identity was or was not
	// populated, so downstream consumers can distinguish host-network/system
	// flows from genuine informer race conditions or unknown external endpoints.
	ResolutionStatus string
}

func classifyResolutionStatus(id EndpointIdentity, hostNetwork bool) string {
	if hostNetwork {
		return ResolutionStatusHostNetwork
	}
	if id.Namespace != "" && SystemNamespaces[id.Namespace] {
		return ResolutionStatusKubeSystem
	}
	if id.PodUID != "" {
		return ResolutionStatusResolved
	}
	if id.ServiceName != "" || id.ServiceUID != "" {
		return ResolutionStatusServiceOnly
	}
	if id.External {
		return ResolutionStatusExternal
	}
	return ResolutionStatusUnknown
}

type ResolvedFlow struct {
	Src              EndpointIdentity
	Dst              EndpointIdentity
	MappingMethod    string
	PodRestartWindow bool
}

type Resolver struct {
	cache        *k8smeta.Cache
	cgroups      CgroupLookup
	hostNetnsIno uint64
}

type CgroupLookup interface {
	Resolve(cgroupID uint64) (podUID string, containerID string, ok bool)
	// ResolveWithRetry (C10) is called by the resolver at session emission
	// time. Implementations should trigger an on-demand cgroup tree rescan
	// and retry the lookup briefly so that flows whose pods appeared after
	// the eBPF tracepoint fired still resolve before the record is written.
	ResolveWithRetry(cgroupID uint64) (podUID string, containerID string, ok bool)
}

func NewResolver(cache *k8smeta.Cache) *Resolver {
	return NewResolverWithCgroups(cache, nil)
}

func NewResolverWithCgroups(cache *k8smeta.Cache, cgroups CgroupLookup) *Resolver {
	return &Resolver{cache: cache, cgroups: cgroups, hostNetnsIno: HostNetnsIno()}
}

func (r *Resolver) Resolve(session sessionizer.FlowSession) ResolvedFlow {
	// Source identity: when the sessionizer captured a per-generation
	// snapshot, materialize THAT — emission must never re-resolve the source
	// against the current cache state. The legacy resolve-at-output path
	// remains only for pipelines without a wired snapshotter.
	var src EndpointIdentity
	if session.SourceIdentity.Attempted {
		src = endpointFromSourceSnapshot(session.SourceIdentity)
	} else {
		src = r.resolveSource(session)
	}
	dst := r.resolveDestination(session)
	return ResolvedFlow{
		Src:              src,
		Dst:              dst,
		MappingMethod:    pickMappingMethod(src, dst),
		PodRestartWindow: src.Confidence == "low" || dst.Confidence == "low",
	}
}

func (r *Resolver) resolveSource(session sessionizer.FlowSession) EndpointIdentity {
	id, _ := r.resolveSourceEndpoint(session.CgroupID, session.SrcIP, session.NetnsIno, session.StartTime)
	return id
}

// resolveSourceEndpoint is ONE atomic source resolution: every field of the
// returned identity comes from the same cache-read moment. It also returns
// the pod it resolved (nil when no pod identity was found) so callers can
// derive pod-scoped context (rollout revision) from the SAME pod object.
func (r *Resolver) resolveSourceEndpoint(cgroupID uint64, srcIP string, netnsIno uint64, flowStart time.Time) (EndpointIdentity, *k8smeta.PodInfo) {
	if r.cache == nil {
		id := unknown("unknown")
		id.ResolutionStatus = ResolutionStatusUnknown
		return id, nil
	}
	// Path 1: cgroup_id -> pod_uid -> pod
	// C10: use ResolveWithRetry so a Pod created just before its first network
	// event still has a chance to be picked up by an on-demand cgroup rescan
	// before we declare the identity unresolved.
	if cgroupID != 0 && r.cgroups != nil {
		if podUID, containerID, ok := r.cgroups.ResolveWithRetry(cgroupID); ok {
			if pod, podOK := r.cache.PodByUID(podUID); podOK {
				id := identityFromPod(pod, flowStart, "cgroup_id")
				id.CgroupID = cgroupID
				if containerID != "" {
					id.ContainerID = containerID
					if name, nameOK := r.cache.ContainerNameByID(podUID, containerID); nameOK {
						id.ContainerName = name
					}
				}
				id.ResolutionStatus = classifyResolutionStatus(id, pod.HostNetwork)
				return id, pod
			}
			// C10/C11: cgroup resolved to a pod_uid but informer cache has no
			// pod entry yet (eBPF triggered before pod cache populated).
			id := unknown("informer_miss")
			id.CgroupID = cgroupID
			id.ResolutionStatus = ResolutionStatusInformerMiss
			id.Reason = "cgroup_resolved_but_pod_uncached"
			return id, nil
		}
	}
	// Path 2: source IP -> pod via informer cache (works for host-network too)
	if pod, ok := r.cache.PodByIP(srcIP); ok {
		id := identityFromPod(pod, flowStart, "pod_ip")
		id.CgroupID = 0
		if netnsIno != 0 && r.hostNetnsIno != 0 && netnsIno == r.hostNetnsIno {
			id.Confidence = "medium"
			id.Reason = "host_netns"
		}
		if pod.HostNetwork {
			id.Method = "pod_ip"
			id.Reason = "hostNetwork"
		}
		id.ResolutionStatus = classifyResolutionStatus(id, pod.HostNetwork)
		return id, pod
	}
	// C11: host-loopback / host-netns flows without a backing pod entry
	if netnsIno != 0 && r.hostNetnsIno != 0 && netnsIno == r.hostNetnsIno {
		id := unknown("host_netns")
		id.Reason = "host_netns_no_pod"
		id.ResolutionStatus = ResolutionStatusHostNetwork
		return id, nil
	}
	if isLoopback(srcIP) {
		id := unknown("host_netns")
		id.Reason = "loopback_src"
		id.ResolutionStatus = ResolutionStatusHostNetwork
		return id, nil
	}
	if isProbablyExternal(srcIP) {
		id := unknown("external")
		id.External = true
		id.Confidence = "low"
		id.ResolutionStatus = ResolutionStatusExternal
		return id, nil
	}
	id := unknown("unknown")
	id.ResolutionStatus = ResolutionStatusUnknown
	return id, nil
}

// ResolveSourceIdentity implements sessionizer.SourceIdentityResolver: one
// atomic resolution attempt whose result the sessionizer freezes per
// connection generation. terminal=false only for transient states
// (informer/cgroup caches not ready yet) that deserve a retry; resolved
// identities and by-design-no-identity outcomes (host network, external,
// loopback) are terminal. The revision is derived from the SAME pod object
// the identity came from, pod-scoped (owner ReplicaSet / revision hash) —
// never the controller's current latest revision.
func (r *Resolver) ResolveSourceIdentity(req sessionizer.SourceIdentityRequest) (sessionizer.SourceIdentity, bool) {
	id, pod := r.resolveSourceEndpoint(req.CgroupID, req.SrcIP, req.NetnsIno, req.ConnStart)

	snapshot := sessionizer.SourceIdentity{
		ObservedAt:       time.Now().UTC(),
		CgroupID:         id.CgroupID,
		SrcIP:            req.SrcIP,
		Namespace:        id.Namespace,
		PodName:          id.PodName,
		PodUID:           id.PodUID,
		NodeName:         id.NodeName,
		ContainerName:    id.ContainerName,
		ContainerID:      id.ContainerID,
		WorkloadKind:     id.WorkloadKind,
		WorkloadName:     id.WorkloadName,
		WorkloadUID:      id.WorkloadUID,
		ReplicaSet:       id.ReplicaSet,
		ServiceAccount:   id.ServiceAccount,
		ImageDigest:      id.ImageDigest,
		External:         id.External,
		Confidence:       id.Confidence,
		Method:           id.Method,
		ResolutionStatus: id.ResolutionStatus,
	}
	if snapshot.CgroupID == 0 {
		snapshot.CgroupID = req.CgroupID
	}
	if pod != nil {
		// Pod-scoped rollout binding: the pod's own template hash and the
		// revision of the rollout that created THIS pod.
		snapshot.PodTemplateHash = pod.Labels["pod-template-hash"]
		if snapshot.PodTemplateHash == "" {
			snapshot.PodTemplateHash = id.PodTemplateHash
		}
		snapshot.Revision, snapshot.RevisionSource = r.cache.PodRolloutRevision(pod)
	}
	if snapshot.PodUID == "" {
		snapshot.MissingReason = missingReasonForStatus(id.ResolutionStatus, id.Reason)
	}

	switch id.ResolutionStatus {
	case ResolutionStatusInformerMiss, ResolutionStatusUnknown, ResolutionStatusServiceOnly:
		return snapshot, false
	default:
		return snapshot, true
	}
}

// missingReasonForStatus maps a no-pod-identity outcome to an explicit
// missing reason. Identity is never silently substituted with IP/name.
func missingReasonForStatus(status, reason string) string {
	switch status {
	case ResolutionStatusHostNetwork:
		return "host_network"
	case ResolutionStatusExternal:
		return "external_source"
	case ResolutionStatusInformerMiss:
		if reason != "" {
			return reason
		}
		return "informer_miss"
	case ResolutionStatusKubeSystem:
		return "kube_system_without_pod"
	default:
		return "unknown_source"
	}
}

// endpointFromSourceSnapshot materializes a frozen (or in-progress)
// generation snapshot as the record's source identity. No cache access
// happens here: emission-time state can never leak into the identity.
func endpointFromSourceSnapshot(snapshot sessionizer.SourceIdentity) EndpointIdentity {
	return EndpointIdentity{
		Namespace:        snapshot.Namespace,
		PodName:          snapshot.PodName,
		PodUID:           snapshot.PodUID,
		NodeName:         snapshot.NodeName,
		ContainerName:    snapshot.ContainerName,
		ContainerID:      snapshot.ContainerID,
		CgroupID:         snapshot.CgroupID,
		WorkloadKind:     snapshot.WorkloadKind,
		WorkloadName:     snapshot.WorkloadName,
		WorkloadUID:      snapshot.WorkloadUID,
		ReplicaSet:       snapshot.ReplicaSet,
		PodTemplateHash:  snapshot.PodTemplateHash,
		ImageDigest:      snapshot.ImageDigest,
		ServiceAccount:   snapshot.ServiceAccount,
		Revision:         snapshot.Revision,
		External:         snapshot.External,
		Confidence:       snapshot.Confidence,
		Method:           snapshot.Method,
		Reason:           snapshot.MissingReason,
		ResolutionStatus: snapshot.ResolutionStatus,
	}
}

var netnsLinkRE = regexp.MustCompile(`net:\[(\d+)\]`)

func HostNetnsIno() uint64 {
	raw, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return 0
	}
	match := netnsLinkRE.FindStringSubmatch(raw)
	if len(match) != 2 {
		return 0
	}
	v, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func (r *Resolver) resolveDestination(session sessionizer.FlowSession) EndpointIdentity {
	if r.cache == nil {
		id := unknown("unknown")
		id.ResolutionStatus = ResolutionStatusUnknown
		return id
	}
	if pod, ok := r.cache.PodByIP(session.DstIP); ok {
		id := identityFromPod(pod, session.StartTime, "pod_ip")
		if ep, ok := r.cache.EndpointByIPPort(session.DstIP, session.DstPort); ok && ep.Service != nil {
			applyServiceContext(&id, ep.Service)
			id.Method = "endpoint_slice"
		}
		id.ResolutionStatus = classifyResolutionStatus(id, pod.HostNetwork)
		return id
	}
	if svc, ok := r.cache.ServiceByClusterIPPort(session.DstIP, session.DstPort); ok {
		id := EndpointIdentity{
			Namespace:        svc.Namespace,
			ServiceName:      svc.Name,
			ServiceUID:       string(svc.UID),
			ServiceNamespace: svc.Namespace,
			ServicePortName:  svc.PortName,
			AppProtocol:      svc.AppProtocol,
			Confidence:       "medium",
			Method:           "service_cluster_ip",
		}
		id.ResolutionStatus = classifyResolutionStatus(id, false)
		return id
	}
	if ep, ok := r.cache.EndpointByIPPort(session.DstIP, session.DstPort); ok {
		id := EndpointIdentity{Confidence: "medium", Method: "endpoint_slice"}
		if ep.Service != nil {
			id.Namespace = ep.Service.Namespace
			applyServiceContext(&id, ep.Service)
		}
		if ep.Backend != nil {
			id = identityFromPod(ep.Backend, session.StartTime, "endpoint_slice")
			if ep.Service != nil {
				applyServiceContext(&id, ep.Service)
			}
		}
		hostNet := false
		if ep.Backend != nil {
			hostNet = ep.Backend.HostNetwork
		}
		id.ResolutionStatus = classifyResolutionStatus(id, hostNet)
		return id
	}
	if isLoopback(session.DstIP) {
		id := unknown("host_netns")
		id.Reason = "loopback_dst"
		id.ResolutionStatus = ResolutionStatusHostNetwork
		return id
	}
	if isProbablyExternal(session.DstIP) {
		id := unknown("external")
		id.External = true
		id.Confidence = "low"
		id.ResolutionStatus = ResolutionStatusExternal
		return id
	}
	id := unknown("unknown")
	id.ResolutionStatus = ResolutionStatusUnknown
	return id
}

func isLoopback(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func identityFromPod(pod *k8smeta.PodInfo, flowStart time.Time, method string) EndpointIdentity {
	id := EndpointIdentity{
		Namespace:      pod.Namespace,
		PodName:        pod.Name,
		PodUID:         string(pod.UID),
		NodeName:       pod.NodeName,
		ContainerName:  pod.ContainerName,
		ContainerID:    pod.ContainerID,
		ImageDigest:    pod.ImageDigest,
		ServiceAccount: pod.ServiceAccount,
		Confidence:     "high",
		Method:         method,
	}
	if pod.Workload != nil {
		id.WorkloadKind = pod.Workload.Kind
		id.WorkloadName = pod.Workload.Name
		id.WorkloadUID = string(pod.Workload.UID)
		id.Revision = pod.Workload.Revision
		id.PodTemplateHash = pod.Workload.PodTemplateHash
		id.ImageDigest = firstNonEmpty(id.ImageDigest, pod.Workload.ImageID)
		if pod.Workload.Kind == "Deployment" {
			for _, owner := range pod.OwnerReferences {
				if owner.Kind == "ReplicaSet" {
					id.ReplicaSet = owner.Name
					break
				}
			}
		}
	}
	if !pod.CreationTimestamp.IsZero() && flowStart.Before(pod.CreationTimestamp) {
		id.Confidence = "low"
		id.Reason = "flow_start_before_pod_creation"
	}
	if pod.DeletionTimestamp != nil {
		if flowStart.After(pod.DeletionTimestamp.Add(-5*time.Minute)) && flowStart.Before(pod.DeletionTimestamp.Add(5*time.Minute)) {
			id.Confidence = "low"
			id.Reason = "pod_deletion_window"
		}
	}
	return id
}

func unknown(method string) EndpointIdentity {
	return EndpointIdentity{Confidence: "unknown", Method: method}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func applyServiceContext(id *EndpointIdentity, svc *k8smeta.ServiceInfo) {
	id.ServiceName = svc.Name
	id.ServiceUID = string(svc.UID)
	id.ServiceNamespace = svc.Namespace
	id.ServicePortName = svc.PortName
	id.AppProtocol = svc.AppProtocol
}

func pickMappingMethod(src, dst EndpointIdentity) string {
	if src.Method == "cgroup_id" {
		return src.Method
	}
	if dst.Method != "" && dst.Method != "unknown" {
		return dst.Method
	}
	if src.Method != "" {
		return src.Method
	}
	return "unknown"
}

func isProbablyExternal(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast()
}
