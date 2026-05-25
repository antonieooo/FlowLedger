// Package iforest implements an inference-only Isolation Forest evaluator
// that loads a model exported from sklearn as JSON.
//
// Why this exists (per design § H1 "Isolation Forest Go inference path"):
// option D — Python trains via sklearn → exports tree structures to JSON →
// Go interpreter walks the trees. ~100 lines of inference code, zero binary
// dependencies, fully testable, and avoids ONNX / Python sidecar plumbing.
//
// Export schema (matches scripts/train_iforest.py output):
//
//	{
//	  "n_features": <int>,
//	  "feature_names": [<string>, ...],
//	  "max_samples": <int>,           // sklearn IsolationForest._max_samples
//	  "trees": [
//	    {
//	      "feature":   [<int>, ...],   // per-node feature index; -1 if leaf
//	      "threshold": [<float>, ...], // per-node split threshold
//	      "left":      [<int>, ...],   // left child index; -1 if leaf
//	      "right":     [<int>, ...],   // right child index; -1 if leaf
//	      "n_samples": [<int>, ...]    // sklearn `n_node_samples` per node
//	    },
//	    ...
//	  ]
//	}
//
// Anomaly score follows the original Liu et al. (2008) formula and sklearn's
// `decision_function` sign convention: higher means MORE anomalous.
//
//	score(x) = 2 ** (-E[path_length(x)] / c(n))
//
// where E[path_length(x)] is the average path length across all trees plus
// the c(node_size) adjustment for early-stopped (still-internal) leaves, and
// c(n) is the harmonic-number-based expected path length for the
// max_samples used at training time. Scores are in [0, 1]; ~0.5 = normal,
// closer to 1 = stronger anomaly.
package iforest

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
)

// Tree is a flat representation of a single sklearn ExtraTreeRegressor used
// inside an IsolationForest. All slices have the same length = number of
// nodes in the tree.
type Tree struct {
	Feature   []int     `json:"feature"`
	Threshold []float64 `json:"threshold"`
	Left      []int     `json:"left"`
	Right     []int     `json:"right"`
	NSamples  []int     `json:"n_samples"`
}

// Model is the deserialized Isolation Forest.
type Model struct {
	NFeatures    int      `json:"n_features"`
	FeatureNames []string `json:"feature_names"`
	MaxSamples   int      `json:"max_samples"`
	Trees        []Tree   `json:"trees"`

	// cached: c(max_samples) — the normalization constant; computed lazily.
	cN float64
}

// LoadFromFile reads and parses a JSON-encoded Isolation Forest.
func LoadFromFile(path string) (*Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("iforest open: %w", err)
	}
	defer f.Close()
	return LoadFromReader(f)
}

// LoadFromReader parses a JSON-encoded Isolation Forest from an io.Reader.
func LoadFromReader(r io.Reader) (*Model, error) {
	var m Model
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, fmt.Errorf("iforest decode: %w", err)
	}
	if len(m.Trees) == 0 {
		return nil, fmt.Errorf("iforest: zero trees")
	}
	if m.NFeatures <= 0 {
		return nil, fmt.Errorf("iforest: invalid n_features %d", m.NFeatures)
	}
	if m.MaxSamples < 2 {
		// sklearn IsolationForest forces max_samples >= 2; treat lower as bug.
		return nil, fmt.Errorf("iforest: max_samples=%d must be >= 2", m.MaxSamples)
	}
	m.cN = expectedPathLength(float64(m.MaxSamples))
	return &m, nil
}

// AnomalyScore returns a value in [0, 1]. Higher → more anomalous.
//
// The input `features` must have length == m.NFeatures. The features are
// interpreted in the same order as Model.FeatureNames; the caller is
// responsible for matching the training-time feature schema.
func (m *Model) AnomalyScore(features []float64) (float64, error) {
	if len(features) != m.NFeatures {
		return 0, fmt.Errorf("iforest: got %d features, model expects %d", len(features), m.NFeatures)
	}
	var sum float64
	for i := range m.Trees {
		sum += pathLength(&m.Trees[i], features, 0, 0)
	}
	avg := sum / float64(len(m.Trees))
	return math.Pow(2, -avg/m.cN), nil
}

// pathLength returns the path length to the leaf containing `features` in
// `tree`, starting from node `idx` at depth `depth`. When a leaf has more
// than one sample (sklearn stops splitting before fully isolating to keep
// trees bounded), we add c(n_samples) to approximate the path length we
// would have seen had the tree continued (this matches the original Liu
// et al. paper and sklearn's `_average_path_length`).
func pathLength(tree *Tree, features []float64, idx, depth int) float64 {
	left := tree.Left[idx]
	right := tree.Right[idx]
	if left == -1 && right == -1 {
		// Leaf. Add the adjustment for early-stopped trees.
		return float64(depth) + expectedPathLength(float64(tree.NSamples[idx]))
	}
	feat := tree.Feature[idx]
	if features[feat] <= tree.Threshold[idx] {
		return pathLength(tree, features, left, depth+1)
	}
	return pathLength(tree, features, right, depth+1)
}

// expectedPathLength is sklearn's `_average_path_length(n)`:
//
//	c(n) = 2·H(n−1) − 2(n−1)/n
//
// where H(k) is the k-th harmonic number, well-approximated by
// ln(k) + Euler-Mascheroni. For n ≤ 1 the function returns 0 (singleton).
func expectedPathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	const euler = 0.5772156649
	h := math.Log(n-1) + euler
	return 2*h - 2*(n-1)/n
}

// Predict returns 1 (anomaly) or 0 (normal) using a threshold on the
// anomaly score. A default threshold of 0.55 roughly matches sklearn's
// contamination='auto' decision boundary; callers should tune via the
// validation-set ROC curve.
func (m *Model) Predict(features []float64, threshold float64) (int, float64, error) {
	score, err := m.AnomalyScore(features)
	if err != nil {
		return 0, 0, err
	}
	if score >= threshold {
		return 1, score, nil
	}
	return 0, score, nil
}
