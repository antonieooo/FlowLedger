package k8smeta

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type PodInfo struct {
	Namespace         string
	Name              string
	UID               types.UID
	IP                string
	NodeName          string
	ContainerName     string
	ContainerID       string
	ImageDigest       string
	ServiceAccount    string
	OwnerReferences   []metav1.OwnerReference
	Labels            map[string]string
	CreationTimestamp time.Time
	DeletionTimestamp *time.Time
	HostNetwork       bool
	Workload          *WorkloadInfo
}

type ServiceInfo struct {
	Namespace   string
	Name        string
	UID         types.UID
	ClusterIP   string
	ClusterIPs  []string
	Port        int32
	TargetPort  int32
	TargetName  string
	PortName    string
	AppProtocol string
	Protocol    string
}

type EndpointInfo struct {
	Service *ServiceInfo
	Backend *PodInfo
	IP      string
	Port    int32
}

type WorkloadInfo struct {
	Kind            string
	Name            string
	UID             types.UID
	Namespace       string
	Revision        string
	PodTemplateHash string
	Image           string
	ImageID         string
}

type Resolver interface {
	ResolveServiceForEndpoint(endpointIP string, endpointPort int, protocol string) (serviceClusterIP string, servicePort int, ok bool)
}
