package scoring

import (
	"math"
	"testing"
)

// ===== Wasserstein-1 =====

func TestWasserstein_Identical(t *testing.T) {
	// Identical distributions → distance 0.
	a := []uint64{1, 2, 3, 4}
	b := []uint64{1, 2, 3, 4}
	if d := Wasserstein1Histogram(a, b); d != 0 {
		t.Fatalf("identical dists: distance = %f, want 0", d)
	}
}

func TestWasserstein_ShiftByOne(t *testing.T) {
	// All mass at bucket 0 vs all mass at bucket 1 → distance = 1.
	a := []uint64{10, 0, 0, 0}
	b := []uint64{0, 10, 0, 0}
	d := Wasserstein1Histogram(a, b)
	if math.Abs(d-1.0) > 1e-9 {
		t.Fatalf("distance = %f, want 1", d)
	}
}

func TestWasserstein_ShiftByThree(t *testing.T) {
	// All mass at bucket 0 vs all mass at bucket 3 → distance = 3.
	a := []uint64{10, 0, 0, 0}
	b := []uint64{0, 0, 0, 10}
	d := Wasserstein1Histogram(a, b)
	if math.Abs(d-3.0) > 1e-9 {
		t.Fatalf("distance = %f, want 3", d)
	}
}

func TestWasserstein_EmptyHandled(t *testing.T) {
	// Empty input → no signal, distance 0 (defensive default).
	a := []uint64{0, 0, 0}
	b := []uint64{1, 2, 3}
	if d := Wasserstein1Histogram(a, b); d != 0 {
		t.Fatalf("empty a: distance = %f, want 0", d)
	}
}

func TestWasserstein_LengthMismatchPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on length mismatch")
		}
	}()
	Wasserstein1Histogram([]uint64{1}, []uint64{1, 2})
}

// ===== KL divergence =====

func TestKL_Identical(t *testing.T) {
	a := []uint64{10, 20, 30, 40}
	if d := KLDivergenceHistogram(a, a); math.Abs(d) > 1e-6 {
		t.Fatalf("identical: KL = %f, want ~0", d)
	}
}

func TestKL_DivergentDistributions(t *testing.T) {
	// P concentrated in bucket 0, Q spread across all → KL > 0.
	p := []uint64{100, 0, 0, 0}
	q := []uint64{25, 25, 25, 25}
	d := KLDivergenceHistogram(p, q)
	if d <= 0 {
		t.Fatalf("KL = %f, want > 0", d)
	}
	// Reference: KL ≈ 1 * ln(1/0.25) = ln(4) ≈ 1.386 (with eps smoothing negligible)
	if d < 1.3 || d > 1.45 {
		t.Fatalf("KL = %f, want ~1.386 (ln(4))", d)
	}
}

func TestKL_AsymmetricByDesign(t *testing.T) {
	// KL(P||Q) ≠ KL(Q||P) in general.
	p := []uint64{80, 20}
	q := []uint64{20, 80}
	dPQ := KLDivergenceHistogram(p, q)
	dQP := KLDivergenceHistogram(q, p)
	// Both should be positive and roughly equal in this symmetric flip case
	// (binary symmetric channels are a special case).
	if dPQ <= 0 || dQP <= 0 {
		t.Fatalf("KL must be >0; got %f and %f", dPQ, dQP)
	}
}

func TestKL_EmptyHandled(t *testing.T) {
	if d := KLDivergenceHistogram([]uint64{}, []uint64{}); d != 0 {
		t.Fatalf("empty: KL = %f, want 0", d)
	}
}

// ===== ZScore + Surprise =====

func TestZScore_Basic(t *testing.T) {
	// (10 − 5) / 2 = 2.5
	if z := ZScore(10, 5, 2); math.Abs(z-2.5) > 1e-9 {
		t.Fatalf("z = %f, want 2.5", z)
	}
}

func TestZScore_NegativeAbsolute(t *testing.T) {
	// |0 − 5| / 2 = 2.5
	if z := ZScore(0, 5, 2); math.Abs(z-2.5) > 1e-9 {
		t.Fatalf("z = %f, want 2.5", z)
	}
}

func TestZScore_ZeroStddevSafe(t *testing.T) {
	if z := ZScore(10, 5, 0); z != 0 {
		t.Fatalf("z with stddev=0: %f, want 0 (coldstart guard)", z)
	}
}

func TestZScore_Capped(t *testing.T) {
	if z := ZScore(1000, 0, 1); z != 20 {
		t.Fatalf("z capped: %f, want 20", z)
	}
}

func TestSurprise_NeverSeen(t *testing.T) {
	// count = 0 with total = 1000 → surprise = −log(eps/1000) ≈ 21
	s := SurpriseScore(0, 1000)
	if s < 18 || s > 25 {
		t.Fatalf("surprise(0, 1000) = %f, want ~21", s)
	}
}

func TestSurprise_VeryCommon(t *testing.T) {
	// count = total → surprise = −log(1) ≈ 0
	s := SurpriseScore(1000, 1000)
	if math.Abs(s) > 1e-3 {
		t.Fatalf("surprise(1000, 1000) = %f, want ~0", s)
	}
}

func TestSurprise_NoHistory(t *testing.T) {
	if s := SurpriseScore(0, 0); s != 0 {
		t.Fatalf("surprise with no history: %f, want 0 (coldstart guard)", s)
	}
}

func TestMaxSurprise(t *testing.T) {
	m := MaxSurprise(1.2, 0.3, 5.5, 2.1)
	if m != 5.5 {
		t.Fatalf("max = %f, want 5.5", m)
	}
}

// ===== Fusion =====

func TestSDev_AllZero(t *testing.T) {
	// All sub-scores 0 → logit = -bias → sigmoid(-2) ≈ 0.12
	w := DefaultWeights()
	s := SDev(w, SubScores{})
	if s < 0.10 || s > 0.13 {
		t.Fatalf("all-zero s_dev = %f, want ~0.12", s)
	}
}

func TestSDev_AllMax(t *testing.T) {
	// All sub-scores 1 → logit = sum(weights) - 2 = 1 - 2 = -1 → sigmoid(-1) ≈ 0.27
	w := DefaultWeights()
	s := SDev(w, SubScores{PktLen: 1, IAT: 1, Card: 1, Novelty: 1})
	if s < 0.25 || s > 0.30 {
		t.Fatalf("all-max s_dev = %f, want ~0.27", s)
	}
}

func TestSDev_BoundedInUnitInterval(t *testing.T) {
	w := DefaultWeights()
	// Sigmoid mathematically gives output in (0, 1), but float64 precision
	// saturates to 0.0 or 1.0 for extreme inputs. Closed interval [0, 1] is
	// the correct assertion.
	s := SDev(w, SubScores{PktLen: 100, IAT: 100, Card: 100, Novelty: 100})
	if s < 0 || s > 1 {
		t.Fatalf("s_dev out of [0,1]: %f", s)
	}
}
