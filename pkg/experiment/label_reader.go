package experiment

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Labels struct {
	ExperimentID  string
	ScenarioLabel string
	ScenarioPhase string
	AttackEnabled string
	LoadLevel     string
}

func DefaultLabels() Labels {
	return Labels{ExperimentID: "unknown", ScenarioLabel: "unlabeled"}
}

type Reader struct {
	getter     configMapGetter
	namespace  string
	name       string
	current    Labels
	hasCurrent bool
}

type configMapGetter interface {
	Get(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error)
}

type kubernetesConfigMapGetter struct {
	client kubernetes.Interface
}

func NewReader(client kubernetes.Interface, namespace, name string) *Reader {
	var getter configMapGetter
	if client != nil {
		getter = kubernetesConfigMapGetter{client: client}
	}
	return &Reader{getter: getter, namespace: namespace, name: name, current: DefaultLabels()}
}

func (r *Reader) Read(ctx context.Context) Labels {
	labels, _ := r.ReadWithStatus(ctx)
	return labels
}

func (r *Reader) ReadWithStatus(ctx context.Context) (Labels, error) {
	if r == nil || r.getter == nil {
		return DefaultLabels(), nil
	}
	cm, err := r.getter.Get(ctx, r.namespace, r.name)
	if err != nil {
		if r.hasCurrent {
			return r.current, err
		}
		return DefaultLabels(), err
	}
	r.current = labelsFromConfigMap(cm)
	r.hasCurrent = true
	return r.current, nil
}

func (g kubernetesConfigMapGetter) Get(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return g.client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
}

func labelsFromConfigMap(cm *corev1.ConfigMap) Labels {
	labels := DefaultLabels()
	if v := cm.Data["experiment_id"]; v != "" {
		labels.ExperimentID = v
	}
	if v := cm.Data["scenario_label"]; v != "" {
		labels.ScenarioLabel = v
	}
	labels.ScenarioPhase = cm.Data["scenario_phase"]
	labels.AttackEnabled = cm.Data["attack_enabled"]
	labels.LoadLevel = cm.Data["load_level"]
	return labels
}
