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
}

func NewResolver(cache *k8smeta.Cache) *Resolver {
	return NewResolverWithCgroups(cache, nil)
}

func NewResolverWithCgroups(cache *k8smeta.Cache, cgroups CgroupLookup) *Resolver {
	return &Resolver{cache: cache, cgroups: cgroups, hostNetnsIno: HostNetnsIno()}
}

func (r *Resolver) Resolve(session sessionizer.FlowSession) ResolvedFlow {
	src := r.resolveSource(session)
	dst := r.resolveDestination(session)
	return ResolvedFlow{
		Src:              src,
		Dst:              dst,
		MappingMethod:    pickMappingMethod(src, dst),
		PodRestartWindow: src.Confidence == "low" || dst.Confidence == "low",
	}
}

func (r *Resolver) resolveSource(session sessionizer.FlowSession) EndpointIdentity {
	if r.cache == nil {
		return unknown("unknown")
	}
	if session.CgroupID != 0 && r.cgroups != nil {
		if podUID, containerID, ok := r.cgroups.Resolve(session.CgroupID); ok {
			if pod, podOK := r.cache.PodByUID(podUID); podOK {
				id := identityFromPod(pod, session.StartTime, "cgroup_id")
				id.CgroupID = session.CgroupID
				if containerID != "" {
					id.ContainerID = containerID
					if name, nameOK := r.cache.ContainerNameByID(podUID, containerID); nameOK {
						id.ContainerName = name
					}
				}
				return id
			}
		}
	}
	if pod, ok := r.cache.PodByIP(session.SrcIP); ok {
		id := identityFromPod(pod, session.StartTime, "pod_ip")
		id.CgroupID = 0
		if session.NetnsIno != 0 && r.hostNetnsIno != 0 && session.NetnsIno == r.hostNetnsIno {
			id.Confidence = "medium"
			id.Reason = "host_netns"
		}
		if pod.HostNetwork {
			id.Method = "pod_ip"
			id.Reason = "hostNetwork"
		}
		return id
	}
	if isProbablyExternal(session.SrcIP) {
		id := unknown("external")
		id.External = true
		id.Confidence = "low"
		return id
	}
	return unknown("unknown")
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
		return unknown("unknown")
	}
	if pod, ok := r.cache.PodByIP(session.DstIP); ok {
		id := identityFromPod(pod, session.StartTime, "pod_ip")
		if ep, ok := r.cache.EndpointByIPPort(session.DstIP, session.DstPort); ok && ep.Service != nil {
			applyServiceContext(&id, ep.Service)
			id.Method = "endpoint_slice"
		}
		return id
	}
	if svc, ok := r.cache.ServiceByClusterIPPort(session.DstIP, session.DstPort); ok {
		return EndpointIdentity{
			Namespace:        svc.Namespace,
			ServiceName:      svc.Name,
			ServiceUID:       string(svc.UID),
			ServiceNamespace: svc.Namespace,
			ServicePortName:  svc.PortName,
			AppProtocol:      svc.AppProtocol,
			Confidence:       "medium",
			Method:           "service_cluster_ip",
		}
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
		return id
	}
	if isProbablyExternal(session.DstIP) {
		id := unknown("external")
		id.External = true
		id.Confidence = "low"
		return id
	}
	return unknown("unknown")
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
