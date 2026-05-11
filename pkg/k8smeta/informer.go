package k8smeta

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type WatchErrorFunc func()

type InformerRunner struct {
	client       kubernetes.Interface
	metaCache    *Cache
	resyncPeriod time.Duration
	onWatchError WatchErrorFunc
}

func NewInformerRunner(client kubernetes.Interface, metaCache *Cache, onWatchError WatchErrorFunc) *InformerRunner {
	return &InformerRunner{
		client:       client,
		metaCache:    metaCache,
		resyncPeriod: 10 * time.Minute,
		onWatchError: onWatchError,
	}
}

func (r *InformerRunner) Run(ctx context.Context) error {
	if r.client == nil || r.metaCache == nil {
		return fmt.Errorf("kubernetes client and cache are required")
	}
	runtime.ErrorHandlers = append(runtime.ErrorHandlers, func(_ context.Context, err error, _ string, _ ...interface{}) {
		if err != nil && r.onWatchError != nil {
			r.onWatchError()
		}
	})

	factory := informers.NewSharedInformerFactory(r.client, r.resyncPeriod)

	pods := factory.Core().V1().Pods().Informer()
	services := factory.Core().V1().Services().Informer()
	serviceAccounts := factory.Core().V1().ServiceAccounts().Informer()
	endpointSlices := factory.Discovery().V1().EndpointSlices().Informer()
	replicaSets := factory.Apps().V1().ReplicaSets().Informer()
	deployments := factory.Apps().V1().Deployments().Informer()
	statefulSets := factory.Apps().V1().StatefulSets().Informer()
	daemonSets := factory.Apps().V1().DaemonSets().Informer()
	jobs := factory.Batch().V1().Jobs().Informer()
	cronJobs := factory.Batch().V1().CronJobs().Informer()

	_, _ = pods.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if pod, ok := obj.(*corev1.Pod); ok {
				r.metaCache.UpsertPod(pod)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if pod, ok := obj.(*corev1.Pod); ok {
				r.metaCache.UpsertPod(pod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if pod := podFromDelete(obj); pod != nil {
				r.metaCache.DeletePod(pod)
			}
		},
	})
	_, _ = services.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if svc, ok := obj.(*corev1.Service); ok {
				r.metaCache.UpsertService(svc)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if svc, ok := obj.(*corev1.Service); ok {
				r.metaCache.UpsertService(svc)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if svc, ok := obj.(*corev1.Service); ok {
				r.metaCache.DeleteService(svc)
			}
		},
	})
	_, _ = serviceAccounts.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(interface{}) { r.metaCache.UpsertServiceAccount() },
	})
	_, _ = endpointSlices.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if slice, ok := obj.(*discoveryv1.EndpointSlice); ok {
				r.metaCache.UpsertEndpointSlice(slice)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if slice, ok := obj.(*discoveryv1.EndpointSlice); ok {
				r.metaCache.UpsertEndpointSlice(slice)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if slice, ok := obj.(*discoveryv1.EndpointSlice); ok {
				r.metaCache.DeleteEndpointSlice(slice)
			}
		},
	})
	_, _ = replicaSets.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if rs, ok := obj.(*appsv1.ReplicaSet); ok {
				r.metaCache.UpsertReplicaSet(rs)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if rs, ok := obj.(*appsv1.ReplicaSet); ok {
				r.metaCache.UpsertReplicaSet(rs)
			}
		},
	})
	_, _ = deployments.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if dep, ok := obj.(*appsv1.Deployment); ok {
				r.metaCache.UpsertDeployment(dep)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if dep, ok := obj.(*appsv1.Deployment); ok {
				r.metaCache.UpsertDeployment(dep)
			}
		},
	})
	_, _ = statefulSets.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if sts, ok := obj.(*appsv1.StatefulSet); ok {
				r.metaCache.UpsertStatefulSet(sts)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if sts, ok := obj.(*appsv1.StatefulSet); ok {
				r.metaCache.UpsertStatefulSet(sts)
			}
		},
	})
	_, _ = daemonSets.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if ds, ok := obj.(*appsv1.DaemonSet); ok {
				r.metaCache.UpsertDaemonSet(ds)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if ds, ok := obj.(*appsv1.DaemonSet); ok {
				r.metaCache.UpsertDaemonSet(ds)
			}
		},
	})
	_, _ = jobs.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if job, ok := obj.(*batchv1.Job); ok {
				r.metaCache.UpsertJob(job)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if job, ok := obj.(*batchv1.Job); ok {
				r.metaCache.UpsertJob(job)
			}
		},
	})
	_, _ = cronJobs.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if cj, ok := obj.(*batchv1.CronJob); ok {
				r.metaCache.UpsertCronJob(cj)
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if cj, ok := obj.(*batchv1.CronJob); ok {
				r.metaCache.UpsertCronJob(cj)
			}
		},
	})

	factory.Start(ctx.Done())
	if ok := cache.WaitForCacheSync(ctx.Done(),
		pods.HasSynced,
		services.HasSynced,
		serviceAccounts.HasSynced,
		endpointSlices.HasSynced,
		replicaSets.HasSynced,
		deployments.HasSynced,
		statefulSets.HasSynced,
		daemonSets.HasSynced,
		jobs.HasSynced,
		cronJobs.HasSynced,
	); !ok {
		return fmt.Errorf("timed out waiting for Kubernetes metadata cache sync")
	}
	<-ctx.Done()
	return ctx.Err()
}

func podFromDelete(obj interface{}) *corev1.Pod {
	if pod, ok := obj.(*corev1.Pod); ok {
		return pod
	}
	if deleted, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if pod, ok := deleted.Obj.(*corev1.Pod); ok {
			return pod
		}
	}
	return nil
}
