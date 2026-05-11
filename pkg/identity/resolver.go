package identity

import (
	"net/netip"
	"time"

	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/sessionizer"
)

type EndpointIdentity struct {
	Namespace      string
	PodName        string
	PodUID         string
	WorkloadKind   string
	WorkloadName   string
	WorkloadUID    string
	ServiceAccount string
	Revision       string
	ServiceName    string
	External       bool
	Confidence     string
	Method         string
	Reason         string
}

type ResolvedFlow struct {
	Src              EndpointIdentity
	Dst              EndpointIdentity
	MappingMethod    string
	PodRestartWindow bool
}

type Resolver struct {
	cache *k8smeta.Cache
}

func NewResolver(cache *k8smeta.Cache) *Resolver {
	return &Resolver{cache: cache}
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
	if pod, ok := r.cache.PodByIP(session.SrcIP); ok {
		id := identityFromPod(pod, session.StartTime, "pod_ip")
		if pod.HostNetwork {
			id.Method = "pod_ip"
			id.Reason = "hostNetwork"
		}
		return id
	}
	if isProbablyExternal(session.SrcIP) {
		id := unknown("external_ip")
		id.External = true
		id.Confidence = "low"
		return id
	}
	return unknown("unknown")
}

func (r *Resolver) resolveDestination(session sessionizer.FlowSession) EndpointIdentity {
	if r.cache == nil {
		return unknown("unknown")
	}
	if pod, ok := r.cache.PodByIP(session.DstIP); ok {
		return identityFromPod(pod, session.StartTime, "pod_ip")
	}
	if svc, ok := r.cache.ServiceByClusterIPPort(session.DstIP, session.DstPort); ok {
		return EndpointIdentity{
			Namespace:   svc.Namespace,
			ServiceName: svc.Name,
			Confidence:  "medium",
			Method:      "service_cluster_ip",
		}
	}
	if ep, ok := r.cache.EndpointByIPPort(session.DstIP, session.DstPort); ok {
		id := EndpointIdentity{Confidence: "medium", Method: "endpoint_slice"}
		if ep.Service != nil {
			id.Namespace = ep.Service.Namespace
			id.ServiceName = ep.Service.Name
		}
		if ep.Backend != nil {
			id = identityFromPod(ep.Backend, session.StartTime, "endpoint_slice")
			if ep.Service != nil {
				id.ServiceName = ep.Service.Name
			}
		}
		return id
	}
	if isProbablyExternal(session.DstIP) {
		id := unknown("external_ip")
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
		ServiceAccount: pod.ServiceAccount,
		Confidence:     "high",
		Method:         method,
	}
	if pod.Workload != nil {
		id.WorkloadKind = pod.Workload.Kind
		id.WorkloadName = pod.Workload.Name
		id.WorkloadUID = string(pod.Workload.UID)
		id.Revision = pod.Workload.Revision
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

func pickMappingMethod(src, dst EndpointIdentity) string {
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
