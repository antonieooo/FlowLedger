package k8smeta

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const TombstoneTTL = 5 * time.Minute

type Cache struct {
	mu sync.RWMutex

	podByIP        map[string]*PodInfo
	podByUID       map[types.UID]*PodInfo
	podTombstones  map[types.UID]tombstone
	podIPTombstone map[string]tombstone

	serviceByClusterIPPort  map[string]*ServiceInfo
	endpointByIPPort        map[string]*EndpointInfo
	endpointAliasesByIPPort map[string][]endpointServiceAlias
	endpointOwnerByIPPort   map[string]string
	endpointKeysBySlice     map[string][]string
	endpointSlicesByKey     map[string]struct{}

	workloads           map[types.UID]*WorkloadInfo
	replicaSetToDeploy  map[types.UID]*WorkloadInfo
	replicaSetDeployUID map[types.UID]types.UID
	replicaSets         map[types.UID]*WorkloadInfo
	jobsToCronJobs      map[types.UID]*WorkloadInfo
	pods, services      int
	endpointSlices      int
	serviceAccounts     int
}

type tombstone struct {
	pod       *PodInfo
	expiresAt time.Time
}

type endpointServiceAlias struct {
	owner            string
	namespace        string
	serviceName      string
	endpointPort     int32
	endpointPortName string
	service          *ServiceInfo
	protocol         string
}

func NewCache() *Cache {
	return &Cache{
		podByIP:                 map[string]*PodInfo{},
		podByUID:                map[types.UID]*PodInfo{},
		podTombstones:           map[types.UID]tombstone{},
		podIPTombstone:          map[string]tombstone{},
		serviceByClusterIPPort:  map[string]*ServiceInfo{},
		endpointByIPPort:        map[string]*EndpointInfo{},
		endpointAliasesByIPPort: map[string][]endpointServiceAlias{},
		endpointOwnerByIPPort:   map[string]string{},
		endpointKeysBySlice:     map[string][]string{},
		endpointSlicesByKey:     map[string]struct{}{},
		workloads:               map[types.UID]*WorkloadInfo{},
		replicaSetToDeploy:      map[types.UID]*WorkloadInfo{},
		replicaSetDeployUID:     map[types.UID]types.UID{},
		replicaSets:             map[types.UID]*WorkloadInfo{},
		jobsToCronJobs:          map[types.UID]*WorkloadInfo{},
	}
}

func ServiceKey(ip string, port int32) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func (c *Cache) UpsertPod(pod *corev1.Pod) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := podInfoFromPod(pod)
	info.Workload = c.resolvePodLocked(&info)
	c.podByUID[info.UID] = &info
	if info.IP != "" {
		c.podByIP[info.IP] = &info
	}
	c.pods = len(c.podByUID)
}

func (c *Cache) DeletePod(pod *corev1.Pod) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := podInfoFromPod(pod)
	if existing := c.podByUID[pod.UID]; existing != nil {
		info = *existing
		now := time.Now()
		info.DeletionTimestamp = &now
	}
	delete(c.podByUID, pod.UID)
	if info.IP != "" {
		delete(c.podByIP, info.IP)
	}
	ts := tombstone{pod: &info, expiresAt: time.Now().Add(TombstoneTTL)}
	c.podTombstones[pod.UID] = ts
	if info.IP != "" {
		c.podIPTombstone[info.IP] = ts
	}
	c.pods = len(c.podByUID)
}

func (c *Cache) UpsertService(svc *corev1.Service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, existing := range c.serviceByClusterIPPort {
		if existing.UID == svc.UID {
			delete(c.serviceByClusterIPPort, k)
		}
	}
	ips := svc.Spec.ClusterIPs
	if len(ips) == 0 && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
		ips = []string{svc.Spec.ClusterIP}
	}
	for _, ip := range ips {
		if ip == "" || ip == corev1.ClusterIPNone {
			continue
		}
		for _, p := range svc.Spec.Ports {
			info := &ServiceInfo{
				Namespace:   svc.Namespace,
				Name:        svc.Name,
				UID:         svc.UID,
				ClusterIP:   ip,
				ClusterIPs:  append([]string{}, ips...),
				Port:        p.Port,
				TargetPort:  p.TargetPort.IntVal,
				TargetName:  p.TargetPort.StrVal,
				PortName:    p.Name,
				AppProtocol: serviceAppProtocol(p.AppProtocol, p.Name),
				Protocol:    string(p.Protocol),
			}
			c.serviceByClusterIPPort[ServiceKey(ip, p.Port)] = info
		}
	}
	c.services = c.countServicesLocked()
}

func (c *Cache) DeleteService(svc *corev1.Service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, existing := range c.serviceByClusterIPPort {
		if existing.UID == svc.UID {
			delete(c.serviceByClusterIPPort, k)
		}
	}
	c.services = c.countServicesLocked()
}

func (c *Cache) UpsertEndpointSlice(slice *discoveryv1.EndpointSlice) {
	c.mu.Lock()
	defer c.mu.Unlock()
	serviceName := slice.Labels[discoveryv1.LabelServiceName]
	sKey := endpointSliceKey(slice)
	c.deleteEndpointSliceEndpointsLocked(sKey)
	keys := []string{}
	for _, ep := range slice.Endpoints {
		var backend *PodInfo
		if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
			backend = c.podByUID[types.UID(ep.TargetRef.UID)]
		}
		for _, addr := range ep.Addresses {
			for _, port := range slice.Ports {
				if port.Port == nil {
					continue
				}
				svc := c.findServiceForEndpointSlicePortLocked(slice.Namespace, serviceName, addr, port)
				info := &EndpointInfo{
					Service: svc,
					Backend: backend,
					IP:      addr,
					Port:    *port.Port,
				}
				key := ServiceKey(addr, *port.Port)
				c.endpointByIPPort[key] = info
				c.endpointAliasesByIPPort[key] = append(c.endpointAliasesByIPPort[key], endpointServiceAlias{
					owner:            sKey,
					namespace:        slice.Namespace,
					serviceName:      serviceName,
					endpointPort:     *port.Port,
					endpointPortName: endpointSlicePortName(port),
					service:          svc,
					protocol:         endpointSlicePortProtocol(port),
				})
				c.endpointOwnerByIPPort[key] = sKey
				keys = append(keys, key)
			}
		}
	}
	c.endpointKeysBySlice[sKey] = keys
	c.endpointSlicesByKey[sKey] = struct{}{}
	c.endpointSlices = len(c.endpointSlicesByKey)
}

func (c *Cache) DeleteEndpointSlice(slice *discoveryv1.EndpointSlice) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sKey := endpointSliceKey(slice)
	c.deleteEndpointSliceEndpointsLocked(sKey)
	delete(c.endpointKeysBySlice, sKey)
	delete(c.endpointSlicesByKey, sKey)
	c.endpointSlices = len(c.endpointSlicesByKey)
}

func (c *Cache) UpsertReplicaSet(rs *appsv1.ReplicaSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wl := workloadFromObject("ReplicaSet", rs.Namespace, rs.Name, rs.UID, rs.Labels, rs.Annotations, rs.Spec.Template.Spec.Containers)
	c.replicaSets[rs.UID] = wl
	c.workloads[rs.UID] = wl
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" {
			depUID := types.UID(owner.UID)
			c.replicaSetDeployUID[rs.UID] = depUID
			if dep := c.workloads[depUID]; dep != nil {
				c.replicaSetToDeploy[rs.UID] = dep
			}
		}
	}
}

func (c *Cache) UpsertDeployment(dep *appsv1.Deployment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wl := workloadFromObject("Deployment", dep.Namespace, dep.Name, dep.UID, dep.Spec.Template.Labels, dep.Annotations, dep.Spec.Template.Spec.Containers)
	c.workloads[dep.UID] = wl
	for rsUID := range c.replicaSets {
		if c.replicaSetDeployUID[rsUID] == dep.UID {
			c.replicaSetToDeploy[rsUID] = wl
		}
	}
}

func (c *Cache) UpsertStatefulSet(sts *appsv1.StatefulSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.workloads[sts.UID] = workloadFromObject("StatefulSet", sts.Namespace, sts.Name, sts.UID, sts.Spec.Template.Labels, sts.Annotations, sts.Spec.Template.Spec.Containers)
}

func (c *Cache) UpsertDaemonSet(ds *appsv1.DaemonSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.workloads[ds.UID] = workloadFromObject("DaemonSet", ds.Namespace, ds.Name, ds.UID, ds.Spec.Template.Labels, ds.Annotations, ds.Spec.Template.Spec.Containers)
}

func (c *Cache) UpsertJob(job *batchv1.Job) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wl := workloadFromObject("Job", job.Namespace, job.Name, job.UID, job.Spec.Template.Labels, job.Annotations, job.Spec.Template.Spec.Containers)
	c.workloads[job.UID] = wl
	for _, owner := range job.OwnerReferences {
		if owner.Kind == "CronJob" {
			if cj := c.workloads[types.UID(owner.UID)]; cj != nil {
				c.jobsToCronJobs[job.UID] = cj
			}
		}
	}
}

func (c *Cache) UpsertCronJob(cj *batchv1.CronJob) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.workloads[cj.UID] = &WorkloadInfo{Kind: "CronJob", Name: cj.Name, UID: cj.UID, Namespace: cj.Namespace}
}

func (c *Cache) UpsertServiceAccount() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serviceAccounts++
}

func (c *Cache) PodByIP(ip string) (*PodInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pod, ok := c.podByIP[ip]
	if !ok {
		if ts, tombstoneOK := c.podIPTombstone[ip]; tombstoneOK && time.Now().Before(ts.expiresAt) {
			pod = ts.pod
			ok = true
		}
	}
	cp := clonePod(pod)
	if cp != nil {
		cp.Workload = c.resolvePodLocked(pod)
	}
	return cp, ok
}

// ContainerNameByID returns the container name within the given Pod whose
// container ID matches. Returns ("", false) if the Pod is unknown, the
// container ID is empty, or no matching container exists.
//
// The container ID may arrive in raw form (e.g., "abc123...") or with a
// runtime prefix (e.g., "containerd://abc123..."). The lookup matches either
// form against either form.
func (c *Cache) ContainerNameByID(podUID, containerID string) (string, bool) {
	if containerID == "" {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	pod, ok := c.podByUID[types.UID(podUID)]
	if !ok || pod == nil {
		return "", false
	}
	want := normalizeContainerID(containerID)
	for storedID, name := range pod.Containers {
		if normalizeContainerID(storedID) == want {
			return name, true
		}
	}
	return "", false
}

func normalizeContainerID(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}

func (c *Cache) PodByUID(uid string) (*PodInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pod, ok := c.podByUID[types.UID(uid)]
	cp := clonePod(pod)
	if cp != nil {
		cp.Workload = c.resolvePodLocked(pod)
	}
	return cp, ok
}

func (c *Cache) ServiceByClusterIPPort(ip string, port uint16) (*ServiceInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	svc, ok := c.serviceByClusterIPPort[ServiceKey(ip, int32(port))]
	return cloneService(svc), ok
}

func (c *Cache) EndpointByIPPort(ip string, port uint16) (*EndpointInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ep, ok := c.endpointByIPPort[ServiceKey(ip, int32(port))]
	if ep == nil {
		return nil, ok
	}
	cp := *ep
	cp.Service = cloneService(ep.Service)
	cp.Backend = clonePod(ep.Backend)
	return &cp, ok
}

func (c *Cache) ResolveServiceForEndpoint(endpointIP string, endpointPort int, protocol string) (string, int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	aliases := c.endpointAliasesByIPPort[ServiceKey(endpointIP, int32(endpointPort))]
	if len(aliases) == 0 {
		return "", 0, false
	}
	protocol = normalizeProtocol(protocol)
	matches := make([]*ServiceInfo, 0, len(aliases))
	for _, alias := range aliases {
		if normalizeProtocol(alias.protocol) != protocol {
			continue
		}
		svc := c.findServiceForAliasLocked(endpointIP, alias)
		if svc == nil {
			svc = alias.service
		}
		if svc == nil {
			continue
		}
		matches = append(matches, svc)
	}
	if len(matches) == 0 {
		return "", 0, false
	}
	if len(matches) > 1 {
		log.Printf("debug: endpoint %s:%d/%s is backed by %d Services; using %s/%s",
			endpointIP, endpointPort, protocol, len(matches), matches[0].Namespace, matches[0].Name)
	}
	svc := matches[0]
	return svc.ClusterIP, int(svc.Port), true
}

func (c *Cache) Stats() (pods, services int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pods, c.services
}

func (c *Cache) EndpointSliceCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.endpointSlices
}

func podInfoFromPod(pod *corev1.Pod) PodInfo {
	var deleted *time.Time
	if pod.DeletionTimestamp != nil {
		t := pod.DeletionTimestamp.Time
		deleted = &t
	}
	containerName := ""
	if len(pod.Spec.Containers) > 0 {
		containerName = pod.Spec.Containers[0].Name
	}
	containerID := ""
	imageDigest := ""
	if len(pod.Status.ContainerStatuses) > 0 {
		containerID = pod.Status.ContainerStatuses[0].ContainerID
		imageDigest = imageDigestFromImageID(pod.Status.ContainerStatuses[0].ImageID)
	}
	containers := map[string]string{}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ContainerID == "" {
			continue
		}
		containers[cs.ContainerID] = cs.Name
	}
	return PodInfo{
		Namespace:         pod.Namespace,
		Name:              pod.Name,
		UID:               pod.UID,
		IP:                pod.Status.PodIP,
		NodeName:          pod.Spec.NodeName,
		ContainerName:     containerName,
		ContainerID:       containerID,
		Containers:        containers,
		ImageDigest:       imageDigest,
		ServiceAccount:    pod.Spec.ServiceAccountName,
		OwnerReferences:   append([]metav1.OwnerReference{}, pod.OwnerReferences...),
		Labels:            copyStringMap(pod.Labels),
		CreationTimestamp: pod.CreationTimestamp.Time,
		DeletionTimestamp: deleted,
		HostNetwork:       pod.Spec.HostNetwork,
	}
}

func workloadFromObject(kind, namespace, name string, uid types.UID, labels, annotations map[string]string, containers []corev1.Container) *WorkloadInfo {
	w := &WorkloadInfo{Kind: kind, Namespace: namespace, Name: name, UID: uid}
	if labels != nil {
		w.PodTemplateHash = labels["pod-template-hash"]
	}
	if annotations != nil {
		w.Revision = annotations["deployment.kubernetes.io/revision"]
		if w.Revision == "" {
			w.Revision = annotations["controller-revision-hash"]
		}
	}
	if len(containers) > 0 {
		w.Image = containers[0].Image
	}
	return w
}

func serviceAppProtocol(appProtocol *string, portName string) string {
	if appProtocol != nil {
		return *appProtocol
	}
	switch portName {
	case "http", "http2", "https", "grpc", "grpc-web":
		return portName
	default:
		return ""
	}
}

func imageDigestFromImageID(imageID string) string {
	for i := len(imageID) - 1; i >= 0; i-- {
		if imageID[i] == '@' {
			return imageID[i+1:]
		}
	}
	return ""
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func clonePod(p *PodInfo) *PodInfo {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Labels = copyStringMap(p.Labels)
	cp.Containers = copyStringMap(p.Containers)
	cp.OwnerReferences = append([]metav1.OwnerReference{}, p.OwnerReferences...)
	if p.Workload != nil {
		w := *p.Workload
		cp.Workload = &w
	}
	return &cp
}

func cloneService(s *ServiceInfo) *ServiceInfo {
	if s == nil {
		return nil
	}
	cp := *s
	cp.ClusterIPs = append([]string{}, s.ClusterIPs...)
	return &cp
}

func (c *Cache) countServicesLocked() int {
	seen := map[types.UID]struct{}{}
	for _, svc := range c.serviceByClusterIPPort {
		seen[svc.UID] = struct{}{}
	}
	return len(seen)
}

func (c *Cache) findServiceByNamePortLocked(namespace, name string, port int32) *ServiceInfo {
	for _, svc := range c.serviceByClusterIPPort {
		if svc.Namespace == namespace && svc.Name == name && svc.Port == port {
			return svc
		}
	}
	return nil
}

func (c *Cache) findServiceForEndpointSlicePortLocked(namespace, name, endpointIP string, port discoveryv1.EndpointPort) *ServiceInfo {
	endpointPort := int32(0)
	if port.Port != nil {
		endpointPort = *port.Port
	}
	return c.findServiceForAliasLocked(endpointIP, endpointServiceAlias{
		namespace:        namespace,
		serviceName:      name,
		endpointPort:     endpointPort,
		endpointPortName: endpointSlicePortName(port),
		protocol:         endpointSlicePortProtocol(port),
	})
}

func (c *Cache) findServiceForAliasLocked(endpointIP string, alias endpointServiceAlias) *ServiceInfo {
	var first *ServiceInfo
	for _, svc := range c.serviceByClusterIPPort {
		if svc.Namespace != alias.namespace || svc.Name != alias.serviceName || normalizeProtocol(svc.Protocol) != normalizeProtocol(alias.protocol) {
			continue
		}
		if !clusterIPFamilyMatches(endpointIP, svc.ClusterIP) {
			continue
		}
		if servicePortMatchesEndpoint(svc, alias.endpointPortName, alias.endpointPort) {
			if first == nil || svc.ClusterIP < first.ClusterIP {
				first = svc
			}
		}
	}
	return first
}

func servicePortMatchesEndpoint(svc *ServiceInfo, endpointPortName string, endpointPort int32) bool {
	if endpointPortName != "" && (svc.PortName == endpointPortName || svc.TargetName == endpointPortName) {
		return true
	}
	if endpointPort == 0 {
		return false
	}
	if svc.TargetPort != 0 {
		return svc.TargetPort == endpointPort
	}
	if svc.TargetName == "" {
		return svc.Port == endpointPort
	}
	return false
}

func endpointSlicePortProtocol(port discoveryv1.EndpointPort) string {
	if port.Protocol == nil {
		return "tcp"
	}
	return string(*port.Protocol)
}

func endpointSlicePortName(port discoveryv1.EndpointPort) string {
	if port.Name == nil {
		return ""
	}
	return *port.Name
}

func normalizeProtocol(protocol string) string {
	if protocol == "" {
		return "tcp"
	}
	return strings.ToLower(protocol)
}

func clusterIPFamilyMatches(endpointIP, clusterIP string) bool {
	endpointAddr, err := netip.ParseAddr(endpointIP)
	if err != nil {
		return true
	}
	clusterAddr, err := netip.ParseAddr(clusterIP)
	if err != nil {
		return true
	}
	return endpointAddr.Is4() == clusterAddr.Is4()
}

func (c *Cache) deleteEndpointSliceEndpointsLocked(sliceKey string) {
	for _, key := range c.endpointKeysBySlice[sliceKey] {
		c.endpointAliasesByIPPort[key] = removeEndpointAliasesForOwner(c.endpointAliasesByIPPort[key], sliceKey)
		if len(c.endpointAliasesByIPPort[key]) == 0 {
			delete(c.endpointAliasesByIPPort, key)
		}
		if c.endpointOwnerByIPPort[key] == sliceKey {
			delete(c.endpointByIPPort, key)
			delete(c.endpointOwnerByIPPort, key)
		}
	}
	delete(c.endpointKeysBySlice, sliceKey)
}

func removeEndpointAliasesForOwner(aliases []endpointServiceAlias, owner string) []endpointServiceAlias {
	out := aliases[:0]
	for _, alias := range aliases {
		if alias.owner != owner {
			out = append(out, alias)
		}
	}
	return out
}

func endpointSliceKey(slice *discoveryv1.EndpointSlice) string {
	if slice.UID != "" {
		return fmt.Sprintf("%s/%s/%s", slice.Namespace, slice.UID, slice.Name)
	}
	return fmt.Sprintf("%s/%s", slice.Namespace, slice.Name)
}
