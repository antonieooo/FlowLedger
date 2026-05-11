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
	client    kubernetes.Interface
	namespace string
	name      string
	current   Labels
}

func NewReader(client kubernetes.Interface, namespace, name string) *Reader {
	return &Reader{client: client, namespace: namespace, name: name, current: DefaultLabels()}
}

func (r *Reader) Read(ctx context.Context) Labels {
	if r == nil || r.client == nil {
		return DefaultLabels()
	}
	cm, err := r.client.CoreV1().ConfigMaps(r.namespace).Get(ctx, r.name, metav1.GetOptions{})
	if err != nil {
		r.current = DefaultLabels()
		return r.current
	}
	r.current = labelsFromConfigMap(cm)
	return r.current
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
