package scoring

import "math"

// ZScore returns the standardized score |value − mean| / stddev, clamped to
// avoid div-by-zero and bounded to a large but finite cap (20) so a single
// pathological flow can't dominate downstream sums.
//
// This is used for the cardinality-window sub-score: "current unique dst
// count in the last 5 min vs HLL-estimated historical mean/stddev". Per
// design §3.2, |z| > 3 is treated as a strong signal.
func ZScore(value, mean, stddev float64) float64 {
	if stddev <= 0 {
		// No variance signal yet — return 0 instead of ±Inf. Coldstart period.
		return 0
	}
	z := (value - mean) / stddev
	if z < 0 {
		z = -z
	}
	if z > 20 {
		return 20
	}
	return z
}

// SurpriseScore returns the self-information −log(freq / total) of a discrete
// observation, given its observed count and the total count of all
// observations. A key that has never been seen (count=0) gets a high but
// finite surprise (capped via `epsilon` smoothing).
//
// Use this for "is this JA4 / SNI value novel for this baseline entry?".
// Range is roughly [0, 25] in practice (depends on total; for total = 10⁹,
// max surprise ≈ −log(1e-6 / 1e9) ≈ 14).
func SurpriseScore(count uint32, total uint64) float64 {
	if total == 0 {
		// No history yet → return moderate surprise (coldstart conservative).
		return 0
	}
	const eps = 1e-6
	p := (float64(count) + eps) / float64(total)
	return -math.Log(p)
}

// MaxSurprise returns the maximum of multiple SurpriseScore results, used
// to combine surprise across (JA4, SNI, ALPN) into one novelty sub-score
// per the design fusion formula §3.2.
func MaxSurprise(scores ...float64) float64 {
	if len(scores) == 0 {
		return 0
	}
	m := scores[0]
	for _, s := range scores[1:] {
		if s > m {
			m = s
		}
	}
	return m
}
