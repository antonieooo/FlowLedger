// Package scoring implements behavior-deviation scoring algorithms used by the
// Node-level model. All functions operate on small histograms / scalars and
// are designed to complete in single-digit microseconds (well under the
// per-flow 500 µs budget).
package scoring

// Wasserstein1Histogram computes the Wasserstein-1 (earth-mover) distance
// between two discrete distributions defined on the same ordered support.
//
// Both `p` and `q` are bucket-count slices of the same length, representing
// histograms over identical bucket boundaries (so we can use bucket index as
// the support coordinate). The function normalizes each into a probability
// mass and returns the L1 norm of the CDF difference, which equals the
// Wasserstein-1 distance on a 1-D ordered support.
//
// Returns 0 when either input is empty (defensible default: "no signal" → not
// anomalous). For our packet-size 7-bucket histogram this is bounded above by
// 6 (max possible CDF difference summed across 6 internal boundaries), so the
// caller normalizes by an EWMA-tracked 95th percentile to map to [0, 1].
func Wasserstein1Histogram(p, q []uint64) float64 {
	if len(p) != len(q) {
		panic("wasserstein1: length mismatch")
	}
	if len(p) == 0 {
		return 0
	}
	var sumP, sumQ uint64
	for i := range p {
		sumP += p[i]
		sumQ += q[i]
	}
	if sumP == 0 || sumQ == 0 {
		return 0
	}
	var dist, cdfDiff float64
	fP := float64(sumP)
	fQ := float64(sumQ)
	for i := range p {
		cdfDiff += float64(p[i])/fP - float64(q[i])/fQ
		if cdfDiff < 0 {
			dist += -cdfDiff
		} else {
			dist += cdfDiff
		}
	}
	return dist
}
