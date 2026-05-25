package scoring

import "math"

// KLDivergenceHistogram computes the (smoothed) KL divergence D_KL(P || Q)
// between two count histograms on identical bucket boundaries.
//
// Both inputs are normalized into probability masses; small epsilon smoothing
// is applied to avoid log(0) when Q has empty buckets. The smoothing constant
// follows the design doc: ε = 1e-6 added to each bucket before renormalizing.
//
// D_KL returns 0 when either side is empty (no signal). It is asymmetric:
// `current` should be the FRESH distribution (the test flow's IAT counts)
// and `baseline` should be the historical distribution (from the entry's
// t-digest sampled into the same buckets, or from an aggregated history).
//
// Range is theoretically [0, ∞) but in practice bounded by ~10 with our
// 6-bucket IAT histogram + epsilon smoothing. Caller normalizes by an
// EWMA tracker (or fixed scale of e.g. 5.0) to map to [0, 1].
func KLDivergenceHistogram(current, baseline []uint64) float64 {
	if len(current) != len(baseline) {
		panic("kl: length mismatch")
	}
	if len(current) == 0 {
		return 0
	}
	const eps = 1e-6
	var sumP, sumQ float64
	pProb := make([]float64, len(current))
	qProb := make([]float64, len(baseline))
	for i := range current {
		pProb[i] = float64(current[i]) + eps
		qProb[i] = float64(baseline[i]) + eps
		sumP += pProb[i]
		sumQ += qProb[i]
	}
	if sumP <= 0 || sumQ <= 0 {
		return 0
	}
	var kl float64
	for i := range pProb {
		p := pProb[i] / sumP
		q := qProb[i] / sumQ
		kl += p * math.Log(p/q)
	}
	if kl < 0 || math.IsNaN(kl) {
		// Numerical pathology guard (shouldn't happen with the eps smoothing
		// but keeping a safety net).
		return 0
	}
	return kl
}
