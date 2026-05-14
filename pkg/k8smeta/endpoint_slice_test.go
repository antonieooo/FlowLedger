package k8smeta

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestEndpointSliceUpsertDoesNotDeleteSiblingSlice(t *testing.T) {
	cache := NewCache()
	cache.UpsertService(service("api", "10.96.0.10", 443))

	sliceA := endpointSlice("api-a", "slice-a-uid", "api", []string{"10.1.1.10"}, 443)
	sliceB := endpointSlice("api-b", "slice-b-uid", "api", []string{"10.1.1.20"}, 443)
	cache.UpsertEndpointSlice(sliceA)
	cache.UpsertEndpointSlice(sliceB)

	updatedA := endpointSlice("api-a", "slice-a-uid", "api", []string{"10.1.1.11"}, 443)
	cache.UpsertEndpointSlice(updatedA)

	if _, ok := cache.EndpointByIPPort("10.1.1.10", 443); ok {
		t.Fatal("old slice A endpoint still exists after update")
	}
	if _, ok := cache.EndpointByIPPort("10.1.1.11", 443); !ok {
		t.Fatal("updated slice A endpoint is missing")
	}
	if _, ok := cache.EndpointByIPPort("10.1.1.20", 443); !ok {
		t.Fatal("slice B endpoint was removed by slice A update")
	}
	if got := cache.EndpointSliceCount(); got != 2 {
		t.Fatalf("EndpointSliceCount() = %d, want 2", got)
	}
}

func TestEndpointSliceDeleteDoesNotDeleteSiblingSlice(t *testing.T) {
	cache := NewCache()
	cache.UpsertService(service("api", "10.96.0.10", 443))

	sliceA := endpointSlice("api-a", "slice-a-uid", "api", []string{"10.1.1.10"}, 443)
	sliceB := endpointSlice("api-b", "slice-b-uid", "api", []string{"10.1.1.20"}, 443)
	cache.UpsertEndpointSlice(sliceA)
	cache.UpsertEndpointSlice(sliceB)
	cache.DeleteEndpointSlice(sliceA)

	if _, ok := cache.EndpointByIPPort("10.1.1.10", 443); ok {
		t.Fatal("deleted slice A endpoint still exists")
	}
	if _, ok := cache.EndpointByIPPort("10.1.1.20", 443); !ok {
		t.Fatal("slice B endpoint was removed by slice A delete")
	}
	if got := cache.EndpointSliceCount(); got != 1 {
		t.Fatalf("EndpointSliceCount() = %d, want 1", got)
	}
}

func TestEndpointSliceDeleteWithoutCachedServiceRemovesEndpoints(t *testing.T) {
	cache := NewCache()
	slice := endpointSlice("api-a", "slice-a-uid", "api", []string{"10.1.1.10"}, 443)

	cache.UpsertEndpointSlice(slice)
	if _, ok := cache.EndpointByIPPort("10.1.1.10", 443); !ok {
		t.Fatal("endpoint missing after upsert without cached service")
	}

	cache.DeleteEndpointSlice(slice)
	if _, ok := cache.EndpointByIPPort("10.1.1.10", 443); ok {
		t.Fatal("endpoint left behind after delete without cached service")
	}
	if got := cache.EndpointSliceCount(); got != 0 {
		t.Fatalf("EndpointSliceCount() = %d, want 0", got)
	}
}

func TestResolveServiceForEndpointUsesEndpointSliceAlias(t *testing.T) {
	cache := NewCache()
	cache.UpsertEndpointSlice(endpointSlice("api-a", "slice-a-uid", "api", []string{"10.1.1.10"}, 8443))
	cache.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api",
			Namespace: "default",
			UID:       types.UID("api-uid"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromInt32(8443),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	})

	clusterIP, servicePort, ok := cache.ResolveServiceForEndpoint("10.1.1.10", 8443, "tcp")
	if !ok {
		t.Fatal("ResolveServiceForEndpoint did not resolve endpoint")
	}
	if clusterIP != "10.96.0.10" || servicePort != 443 {
		t.Fatalf("ResolveServiceForEndpoint = %s:%d, want 10.96.0.10:443", clusterIP, servicePort)
	}
}

func service(name, clusterIP string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			UID:       types.UID(name + "-uid"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: clusterIP,
			Ports: []corev1.ServicePort{{
				Port:     port,
				Protocol: corev1.ProtocolTCP,
			}},
		},
	}
}

func endpointSlice(name, uid, serviceName string, addresses []string, port int32) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			UID:       types.UID(uid),
			Labels: map[string]string{
				discoveryv1.LabelServiceName: serviceName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: addresses,
		}},
		Ports: []discoveryv1.EndpointPort{{
			Port: &port,
		}},
	}
}
