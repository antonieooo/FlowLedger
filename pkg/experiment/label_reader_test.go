package experiment

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestReaderNoClientReturnsDefault(t *testing.T) {
	labels, err := NewReader(nil, "default", "labels").ReadWithStatus(context.Background())
	if err != nil {
		t.Fatalf("ReadWithStatus: %v", err)
	}
	if labels != DefaultLabels() {
		t.Fatalf("labels = %#v, want default", labels)
	}
}

func TestReaderSuccessReturnsConfigMapLabels(t *testing.T) {
	reader := testReader(&stubConfigMapGetter{responses: []configMapResponse{{
		cm: configMap("labels", map[string]string{
			"experiment_id":  "exp-1",
			"scenario_label": "baseline",
			"scenario_phase": "warmup",
			"attack_enabled": "false",
			"load_level":     "low",
		}),
	}}})

	labels, err := reader.ReadWithStatus(context.Background())
	if err != nil {
		t.Fatalf("ReadWithStatus: %v", err)
	}
	if labels.ExperimentID != "exp-1" || labels.ScenarioLabel != "baseline" || labels.ScenarioPhase != "warmup" {
		t.Fatalf("unexpected labels: %#v", labels)
	}
}

func TestReaderKeepsLastKnownGoodAfterFailure(t *testing.T) {
	ctx := context.Background()
	reader := testReader(&stubConfigMapGetter{responses: []configMapResponse{
		{
			cm: configMap("labels", map[string]string{
				"experiment_id":  "exp-1",
				"scenario_label": "attack",
			}),
		},
		{err: errors.New("temporary api failure")},
	}})

	want, err := reader.ReadWithStatus(ctx)
	if err != nil {
		t.Fatalf("initial ReadWithStatus: %v", err)
	}

	got, err := reader.ReadWithStatus(ctx)
	if err == nil {
		t.Fatal("expected read error")
	}
	if got != want {
		t.Fatalf("labels = %#v, want last known %#v", got, want)
	}
}

func TestReaderFailureBeforeSuccessReturnsDefault(t *testing.T) {
	reader := testReader(&stubConfigMapGetter{responses: []configMapResponse{{
		err: errors.New("not found"),
	}}})

	labels, err := reader.ReadWithStatus(context.Background())
	if err == nil {
		t.Fatal("expected read error")
	}
	if labels != DefaultLabels() {
		t.Fatalf("labels = %#v, want default", labels)
	}
}

func configMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Data: data,
	}
}

func testReader(getter configMapGetter) *Reader {
	return &Reader{
		getter:    getter,
		namespace: "default",
		name:      "labels",
		current:   DefaultLabels(),
	}
}

type configMapResponse struct {
	cm  *corev1.ConfigMap
	err error
}

type stubConfigMapGetter struct {
	responses []configMapResponse
}

func (g *stubConfigMapGetter) Get(context.Context, string, string) (*corev1.ConfigMap, error) {
	if len(g.responses) == 0 {
		return nil, errors.New("unexpected get")
	}
	next := g.responses[0]
	g.responses = g.responses[1:]
	return next.cm, next.err
}
