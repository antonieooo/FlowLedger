package cache

import (
	"sync"
	"time"

	"github.com/axiomhq/hyperloglog"
	"github.com/influxdata/tdigest"
)

// BaselineEntry holds the per (image_digest, dst_edge_class) summary state.
//
// All probabilistic substructures use small, fixed memory budgets so that an
// agent observing up to ~100 unique images × 5 edge classes = 500 entries
// per node stays under the ~256 MB Node SLO with comfortable headroom.
//
// Per design doc §3.1: each entry is ~7-8 KB (3 CMS-CU + 2 HLL + 3 t-digest
// + scalars). LRU at the manager layer caps total entries at 256 to bound
// memory regardless of churn.
type BaselineEntry struct {
	// Frequency sketches for high-cardinality discrete features. Used to
	// derive "surprise" scores for novel JA4 / SNI / ALPN values.
	JA4Freq  *CountMinSketchCU
	SNIFreq  *CountMinSketchCU
	ALPNFreq *CountMinSketchCU

	// Distinct-count sketches. Used to detect cardinality blowups in dst
	// pods / SNI hosts inside a sliding window.
	UniqueDstPods *hyperloglog.Sketch
	UniqueSNI     *hyperloglog.Sketch

	// Continuous distribution sketches. Used as the reference distribution
	// for Wasserstein-1 / KL divergence vs the current flow's stats.
	PktLenDist   *tdigest.TDigest
	IATDist      *tdigest.TDigest
	DurationDist *tdigest.TDigest

	// EWMA scalars — light-touch summary stats that don't justify a full
	// sketch but feed into the LightGBM downstream.
	BytesUpDownRatioMean float64
	BytesUpDownRatioVar  float64
	FlowFreqPerMinute    float64

	// Metadata.
	SampleCount   uint64
	FirstSeenTS   time.Time
	LastUpdateTS  time.Time
	IsInColdstart bool

	// EntropyHistory holds the last few histogram-entropy snapshots, used
	// by the coldstart exit predicate ("baseline distribution has converged").
	// Bounded length (3 by default) so it doesn't grow.
	EntropyHistory []float64

	// Internal: bytes summary state used by EWMA updates (avoid lock-free
	// races on the public fields above; manager.go locks at entry level).
	mu sync.Mutex
}

// NewBaselineEntry constructs an entry with the design-doc default sketch
// sizes. Memory footprint ≈ 7-8 KB.
func NewBaselineEntry() *BaselineEntry {
	now := time.Now()
	return &BaselineEntry{
		JA4Freq:        NewCountMinSketchCU(128, 4),
		SNIFreq:        NewCountMinSketchCU(128, 4),
		ALPNFreq:       NewCountMinSketchCU(32, 4),
		UniqueDstPods:  hyperloglog.New16(), // precision=14 default; New16 → ~2KB
		UniqueSNI:      hyperloglog.New16(),
		PktLenDist:     tdigest.NewWithCompression(50),
		IATDist:        tdigest.NewWithCompression(50),
		DurationDist:   tdigest.NewWithCompression(50),
		FirstSeenTS:    now,
		LastUpdateTS:   now,
		IsInColdstart:  true,
		EntropyHistory: make([]float64, 0, 4),
	}
}

// Lock / Unlock are exposed so the manager can hold the entry across
// multi-step updates (multiple sketches + EWMA scalars) consistently.
func (e *BaselineEntry) Lock()   { e.mu.Lock() }
func (e *BaselineEntry) Unlock() { e.mu.Unlock() }
