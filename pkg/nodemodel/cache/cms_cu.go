// Package cache implements the LocalCache layer of the Node-level model:
// per (image_digest, dst_edge_class) baseline summaries built from small,
// fixed-memory probabilistic data structures.
//
// CMS-CU = Count-Min Sketch with Conservative Update. Conservative Update only
// increments the minimum of the d hashed cells, which Ben Mazziane et al.
// (Computer Networks 2022) proved strictly tightens the over-estimation bound
// versus vanilla CMS — especially valuable in the long-tail key space we see
// (rare JA4 variants would otherwise produce inflated counts).
//
// Memory footprint per sketch ≈ width * depth * 4 bytes. Default
// width=128, depth=4 → 2 KB per sketch, with relative error roughly
// 1/width = ~0.8% on the total observed count and failure probability
// e^-depth ≈ 1.8%.
package cache

import (
	"encoding/binary"
	"hash/fnv"
)

// CountMinSketchCU is a CMS with the conservative-update increment rule.
type CountMinSketchCU struct {
	width uint32
	depth uint32
	rows  [][]uint32 // depth rows × width counters
	total uint64     // exact total count of inserts (cheap to maintain)
	seeds []uint32   // per-row hash seeds
}

// NewCountMinSketchCU creates an empty sketch.
func NewCountMinSketchCU(width, depth uint32) *CountMinSketchCU {
	if width == 0 || depth == 0 {
		panic("cms-cu: width and depth must be > 0")
	}
	rows := make([][]uint32, depth)
	seeds := make([]uint32, depth)
	for i := uint32(0); i < depth; i++ {
		rows[i] = make([]uint32, width)
		// Cheap, fixed seeds — sketch is not adversarial, just well-spread.
		seeds[i] = 0x9E3779B9 * (i + 1)
	}
	return &CountMinSketchCU{width: width, depth: depth, rows: rows, seeds: seeds}
}

// indices returns the d cell positions for `key` across the d rows.
func (c *CountMinSketchCU) indices(key string) []uint32 {
	out := make([]uint32, c.depth)
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	base := h.Sum64()
	for i := uint32(0); i < c.depth; i++ {
		// Mix base hash with per-row seed; equivalent to double hashing.
		mix := base ^ uint64(c.seeds[i])*0x100000001B3
		buf := [8]byte{}
		binary.LittleEndian.PutUint64(buf[:], mix)
		hh := fnv.New32a()
		_, _ = hh.Write(buf[:])
		out[i] = hh.Sum32() % c.width
	}
	return out
}

// Update increments `key` by 1 using the conservative-update rule:
// only cells whose value equals the current min get incremented.
func (c *CountMinSketchCU) Update(key string) {
	c.UpdateBy(key, 1)
}

// UpdateBy increments `key` by `n`.
func (c *CountMinSketchCU) UpdateBy(key string, n uint32) {
	if n == 0 {
		return
	}
	idx := c.indices(key)
	// Current estimate is min across the d cells.
	cur := c.rows[0][idx[0]]
	for i := uint32(1); i < c.depth; i++ {
		if v := c.rows[i][idx[i]]; v < cur {
			cur = v
		}
	}
	target := cur + n
	for i := uint32(0); i < c.depth; i++ {
		// Only raise cells that would otherwise stay below the new estimate;
		// cells already above the target are not touched. This is the CU
		// invariant.
		if c.rows[i][idx[i]] < target {
			c.rows[i][idx[i]] = target
		}
	}
	c.total += uint64(n)
}

// Estimate returns the conservative count for `key`.
// Result is the min across the d hashed cells — guaranteed ≥ true count,
// with bounded over-estimation per the CMS error guarantee.
func (c *CountMinSketchCU) Estimate(key string) uint32 {
	idx := c.indices(key)
	cur := c.rows[0][idx[0]]
	for i := uint32(1); i < c.depth; i++ {
		if v := c.rows[i][idx[i]]; v < cur {
			cur = v
		}
	}
	return cur
}

// Total returns the exact number of Update calls made.
func (c *CountMinSketchCU) Total() uint64 { return c.total }

// SizeBytes returns approximate memory footprint.
func (c *CountMinSketchCU) SizeBytes() int { return int(c.width*c.depth*4) + 64 }
