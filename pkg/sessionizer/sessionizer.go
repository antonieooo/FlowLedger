package sessionizer

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"FlowLedger/pkg/collector"
	"FlowLedger/pkg/features"
	"FlowLedger/pkg/k8smeta"
)

// Window-invalidity reasons carried by window_summary records
// (window_invalid_reason). An invalid window carries ZERO delta counters and
// empty delta histograms: an unattributable cumulative mass must never be
// presented as a window increment.
const (
	// WindowInvalidUnknownBaseline: the session's first observed event was a
	// mid-flight cumulative snapshot (no EVENT_CONNECT proving counters
	// started at zero — e.g. agent restart), so the first differencing
	// baseline is unknown.
	WindowInvalidUnknownBaseline = "unknown_baseline"
	// WindowInvalidCounterReset: a cumulative counter or histogram bucket
	// regressed since the previous baseline (kernel map entry evicted and
	// re-created, or accumulator otherwise reset). The current snapshot
	// becomes the new baseline and counter_epoch increments.
	WindowInvalidCounterReset = "counter_reset"
)

// maxSourceIdentityAttempts bounds resolution retries per connection
// generation: attempt 1 happens when the generation is created (ideally on
// EVENT_CONNECT), later events retry while the snapshot is not frozen. After
// the cap the last (unresolved) snapshot freezes permanently — identity that
// never resolved stays missing with its reason; it is never substituted.
const maxSourceIdentityAttempts = 5

// SourceIdentity is the frozen source-identity bundle of ONE connection
// generation. Every field comes from the SAME resolution attempt (atomic
// snapshot): an attempt REPLACES the whole struct, fields from different
// resolution moments are never mixed. Once Frozen is set the bundle is
// immutable for the generation's lifetime — later cache updates, pod
// deletion, rollouts, or emission-time changes must not rewrite it.
type SourceIdentity struct {
	// Attempted: at least one resolution attempt ran (the zero value means
	// no snapshotter is wired — emission falls back to legacy resolution).
	Attempted bool
	// Frozen: this bundle is final for the generation — either identity
	// resolution reached a terminal outcome, or the retry budget is spent.
	Frozen bool
	// ObservedAt is when THIS resolution was performed (all fields date from
	// this single instant).
	ObservedAt time.Time
	// Attempts is the number of resolution attempts so far (diagnostics).
	Attempts uint64
	// MissingReason explains an absent pod identity ("informer_miss",
	// "unknown_source", "host_network", "external_source", ...). Empty when
	// the pod identity resolved.
	MissingReason string

	CgroupID        uint64
	SrcIP           string
	Namespace       string
	PodName         string
	PodUID          string
	NodeName        string
	ContainerName   string
	ContainerID     string
	WorkloadKind    string
	WorkloadName    string
	WorkloadUID     string
	ReplicaSet      string
	PodTemplateHash string
	// Revision is the rollout revision of the POD this connection belongs
	// to (owner-ReplicaSet / controller-revision-hash scoped), never the
	// controller's current latest revision. RevisionSource says how it was
	// derived ("replicaset_revision", "controller_revision_hash",
	// "pod_template_hash", "not_applicable", "unavailable").
	Revision       string
	RevisionSource string
	ServiceAccount string
	ImageDigest    string
	External       bool
	Confidence     string
	Method         string
	// ResolutionStatus mirrors the identity package's status enum
	// (resolved / informer_miss / host_network / ...).
	ResolutionStatus string
}

// SourceIdentityRequest is the input of one atomic source resolution attempt.
type SourceIdentityRequest struct {
	CgroupID  uint64
	SrcIP     string
	NetnsIno  uint64
	ConnStart time.Time
}

// SourceIdentityResolver performs ONE atomic resolution attempt. terminal
// reports whether the outcome is final for this generation: true freezes the
// snapshot immediately (resolved identity, or by-design-no-identity such as
// host-network/external); false means a transient state (informer/cgroup
// cache not ready yet) that may be retried until frozen.
type SourceIdentityResolver interface {
	ResolveSourceIdentity(req SourceIdentityRequest) (snapshot SourceIdentity, terminal bool)
}

// rawCounters tracks the LATEST raw cumulative counter values seen from the
// kernel, as opposed to the session's monotonic-max lifetime merges. Window
// differencing must use raw-latest: after a kernel reset the monotonic maxima
// stay pinned at the stale pre-reset values and would silently zero out every
// subsequent window delta instead of recovering from a fresh baseline.
// For delta-semantics (mock) events the fields accumulate by summation, which
// yields the same running-cumulative meaning.
type rawCounters struct {
	bytesOut, bytesIn                    uint64
	packetsOut, packetsIn                uint64
	skbOut, skbIn                        uint64
	idleGap, burst                       uint64
	syn, fin, rst                        uint64
	retrans                              uint64
	directionChanges                     uint64
	localRetransCount, localRetransBytes uint64
}

// windowBaseline is the previous accepted cumulative snapshot of one
// connection generation; window deltas are current-minus-baseline. Histogram
// maps are private copies taken at the previous window emission.
type windowBaseline struct {
	at       time.Time
	counters rawCounters
	pktHist  map[string]uint64
	iatHist  map[string]uint64
	nfHist   map[string]uint64
}

type FlowSession struct {
	RecordType           string
	FlowID               string
	WindowID             uint64
	NodeName             string
	StartTime            time.Time
	EndTime              time.Time
	DurationMS           int64
	SrcIP                string
	SrcPort              uint16
	DstIP                string
	DstPort              uint16
	Protocol             string
	CgroupID             uint64
	NetnsIno             uint64
	Direction            string
	IPFamily             string
	TCPState             string
	BytesOut             uint64
	BytesIn              uint64
	PacketsOut           uint64
	PacketsIn            uint64
	EventCount           uint64
	CloseReason          string
	HandshakeSeen        bool
	TLSVersion           string
	SNIHash              string
	ALPN                 string
	JA4                  string
	TLSParseStatus       string
	ServerHelloSeen      bool
	TLSVersionNegotiated string
	ALPNNegotiated       string
	JA4S                 string
	TLSServerParseStatus string
	SamplingApplied      bool
	SamplingRate         float64
	SamplingReason       string
	HistogramTruncated   bool
	IATOverflow          bool
	LastUpdated          time.Time
	LastEmitted          time.Time
	FeatureSnapshot      features.Snapshot

	// v1alpha3: cgroup_skb-observed skb counts (from FlowEvent
	// RealPacketsSent/Recv). Cumulative per flow; merged as the latest
	// monotonic value. skb granularity (post-GSO/GRO), NOT wire packets.
	ObservedSKBPacketsOut       uint64
	ObservedSKBPacketsIn        uint64
	ObservedSKBPacketsAvailable bool
	ObservedSKBPacketsSource    string

	// v1alpha3: a cumulative event's counter regressed against this session's
	// stored value (kernel accumulator reset). Pre-reset maxima are kept.
	CounterResetDetected bool
	CounterResetCount    uint64

	// v1alpha3 P1: TCP/IP header aggregates from cgroup_skb. All merges are
	// idempotent under repeated cumulative snapshots (min/max envelopes,
	// bitwise OR, monotone max) so re-delivered snapshots never re-accumulate.
	// "Out" = local egress, "In" = local ingress — NOT client/server.
	IPTTLMin    *uint32
	IPTTLMax    *uint32
	TCPFlagsOut uint32
	TCPFlagsIn  uint32
	// Monotonic per-direction witness that a TCP header was successfully
	// read (kernel-set, never value-inferred). Drives tcp_flags/window
	// availability: observed=true with flags==0/window==0 is a genuine 0.
	TCPHeaderObservedOut         bool
	TCPHeaderObservedIn          bool
	TCPWindowMaxOut              *uint32
	TCPWindowMaxIn               *uint32
	DirectionDurationOutNS       uint64
	DirectionDurationInNS        uint64
	DirectionDurationOutObserved bool
	DirectionDurationInObserved  bool
	IPPktLenMin                  *uint32
	IPPktLenMax                  *uint32

	// v1alpha3 P2: LOCAL egress retransmissions (tcp/tcp_retransmit_skb),
	// cumulative; merged as the latest monotonic value. skb granularity, not
	// wire packets. Peer-direction retransmissions are unobservable and have
	// no session state.
	LocalRetransSKBCount  uint64
	LocalRetransSKBBytes  uint64
	LocalRetransAvailable bool
	LocalRetransSource    string

	// v1alpha4 window-delta contract. On window_summary records: WindowValid
	// says whether the delta counters are a trustworthy fixed-window
	// increment; when false WindowInvalidReason explains why and every delta
	// counter is zeroed. CounterEpoch increments after each counter_reset
	// window so consumers can group windows differenced over one continuous
	// kernel counter lineage. FinalWindow marks the partial window flushed at
	// connection end. WindowStartTime is the delta interval's start (the
	// previous baseline snapshot time). On session_summary records these
	// stay at their zero values (WindowValid=false) — a lifetime record is
	// never a window sample.
	WindowValid         bool
	WindowInvalidReason string
	CounterEpoch        uint64
	FinalWindow         bool
	WindowStartTime     time.Time

	// SourceIdentity is this connection generation's source-identity
	// snapshot (see the type doc). It lives and dies with the session: a new
	// generation, a reused 5-tuple, or an agent restart always starts from a
	// zero snapshot — inheritance is structurally impossible.
	SourceIdentity SourceIdentity

	windowSeq   uint64
	accumulator features.Accumulator

	raw          rawCounters
	baseline     windowBaseline
	baselineKnown bool // true iff this generation began with CONNECT/ACCEPT (counters provably from zero)
	pendingReset  bool // a raw cumulative counter regressed since the last accepted baseline
	epoch         uint64
}

type Sessionizer struct {
	nodeName           string
	timeout            time.Duration
	windowSize         time.Duration
	longLivedThreshold time.Duration
	sessions           map[string]*FlowSession
	k8sMeta            k8smeta.Resolver
	natAliasMetrics    NATAliasMetrics
	srcIdentity        SourceIdentityResolver
}

type NATAliasMetrics interface {
	IncTLSServerHelloNATAliasHit()
	IncTLSServerHelloNATAliasMiss()
}

func New(nodeName string, timeout, windowSize time.Duration) *Sessionizer {
	return NewWithLongLivedThreshold(nodeName, timeout, windowSize, features.DefaultLongLivedThreshold)
}

func (s *Sessionizer) SetK8sMeta(resolver k8smeta.Resolver) {
	s.k8sMeta = resolver
}

func (s *Sessionizer) SetNATAliasMetrics(metrics NATAliasMetrics) {
	s.natAliasMetrics = metrics
}

// SetSourceIdentityResolver wires the per-generation source-identity
// snapshotter. Without one, sessions carry a zero (Attempted=false) snapshot
// and emission falls back to the legacy resolve-at-output path.
func (s *Sessionizer) SetSourceIdentityResolver(resolver SourceIdentityResolver) {
	s.srcIdentity = resolver
}

// attemptSourceIdentity runs one resolution attempt for the session's
// generation unless the snapshot is already frozen or the retry budget is
// spent. Each attempt atomically REPLACES the snapshot. Freezing happens on
// a terminal outcome or when the budget runs out — after that the identity
// (present or missing) is immutable for the generation.
func (s *Sessionizer) attemptSourceIdentity(session *FlowSession) {
	if s.srcIdentity == nil || session.SourceIdentity.Frozen {
		return
	}
	if session.SourceIdentity.Attempts >= maxSourceIdentityAttempts {
		session.SourceIdentity.Frozen = true
		return
	}
	snapshot, terminal := s.srcIdentity.ResolveSourceIdentity(SourceIdentityRequest{
		CgroupID:  session.CgroupID,
		SrcIP:     session.SrcIP,
		NetnsIno:  session.NetnsIno,
		ConnStart: session.StartTime,
	})
	snapshot.Attempted = true
	snapshot.Attempts = session.SourceIdentity.Attempts + 1
	snapshot.Frozen = terminal || snapshot.Attempts >= maxSourceIdentityAttempts
	session.SourceIdentity = snapshot
}

func NewWithLongLivedThreshold(nodeName string, timeout, windowSize, longLivedThreshold time.Duration) *Sessionizer {
	if longLivedThreshold <= 0 {
		longLivedThreshold = features.DefaultLongLivedThreshold
	}
	return &Sessionizer{
		nodeName:           nodeName,
		timeout:            timeout,
		windowSize:         windowSize,
		longLivedThreshold: longLivedThreshold,
		sessions:           map[string]*FlowSession{},
	}
}

func (s *Sessionizer) Process(ev collector.FlowEvent) []FlowSession {
	evType := strings.ToUpper(ev.EventType)
	if evType == "TLS_HANDSHAKE" {
		s.ProcessTLSHandshake(ev)
		return nil
	}
	key := flowKey(ev)
	now := eventTime(ev)
	if ev.Protocol == "" {
		ev.Protocol = "tcp"
	}

	var out []FlowSession
	session := s.sessions[key]
	if session != nil && (evType == "CONNECT" || evType == "ACCEPT") {
		// The kernel creates a fresh accumulator entry on every TCP
		// establishment, so a CONNECT for a live session key means the
		// previous connection on this 5-tuple ended without an observed CLOSE
		// (lost event / tuple reuse). Finalize the old generation now — the
		// new connection must never inherit its baseline or flow_id.
		out = append(out, s.closeOut(session, key, now, "unknown")...)
		session = nil
	}
	if session == nil {
		session = &FlowSession{
			FlowID:      flowID(key, now),
			NodeName:    s.nodeName,
			StartTime:   now,
			EndTime:     now,
			SrcIP:       ev.SrcIP,
			SrcPort:     ev.SrcPort,
			DstIP:       ev.DstIP,
			DstPort:     ev.DstPort,
			Protocol:    strings.ToLower(ev.Protocol),
			CgroupID:    ev.CgroupID,
			NetnsIno:    ev.NetnsIno,
			Direction:   features.BaseDirection(ev.SrcIP, ev.DstIP),
			IPFamily:    features.IPFamily(ev.SrcIP, ev.DstIP),
			TCPState:    ev.TCPState,
			LastEmitted: now,
			// A generation that begins with CONNECT/ACCEPT provably starts
			// with zero counters: the zero baseline is trustworthy and the
			// first window is a genuine increment. Any other first event is a
			// mid-flight cumulative snapshot: baseline unknown until the
			// first (invalid) window establishes one.
			baselineKnown: evType == "CONNECT" || evType == "ACCEPT",
			baseline:      windowBaseline{at: now},
		}
		s.sessions[key] = session
	}

	session.EventCount++
	if session.SamplingRate == 0 {
		session.SamplingRate = 1.0
	}
	if session.SamplingReason == "" {
		session.SamplingReason = "none"
	}
	session.LastUpdated = now
	session.EndTime = now
	session.DurationMS = session.EndTime.Sub(session.StartTime).Milliseconds()
	if ev.TCPState != "" {
		session.TCPState = ev.TCPState
	}
	if ev.CounterSemantics == collector.CounterSemanticsCumulative {
		session.noteCounterResets(ev)
	}
	session.mergeRaw(ev, evType)
	if ev.BytesSent > session.BytesOut {
		session.BytesOut = ev.BytesSent
	}
	if ev.BytesRecv > session.BytesIn {
		session.BytesIn = ev.BytesRecv
	}
	if ev.PacketsSent > session.PacketsOut {
		session.PacketsOut = ev.PacketsSent
	}
	if ev.PacketsRecv > session.PacketsIn {
		session.PacketsIn = ev.PacketsRecv
	}
	session.mergeObservedSKBPackets(ev)
	session.mergeHeaderAggregates(ev)
	session.mergeLocalRetrans(ev)
	session.accumulator.AddEvent(ev)
	s.updateFeatureSnapshot(session)
	// Resolve-and-freeze source identity near connection establishment:
	// attempt 1 runs on the generation's first event (EVENT_CONNECT when
	// observed), transient misses retry on later events until frozen.
	s.attemptSourceIdentity(session)

	switch evType {
	case "CLOSE":
		out = append(out, s.closeOut(session, key, now, ev.CloseReason)...)
	case "CONNECT", "ACCEPT", "STATS":
		if s.windowSize > 0 && now.Sub(session.LastEmitted) >= s.windowSize {
			out = append(out, s.buildWindow(session, now, false))
		}
	}
	return out
}

// closeOut ends one connection generation: it flushes the not-yet-emitted
// final partial window exactly once (final_window=true), then emits the
// lifetime session_summary diagnostic record, and removes the session — which
// also clears its baseline, so a reused 5-tuple can never inherit it.
func (s *Sessionizer) closeOut(session *FlowSession, key string, now time.Time, closeReason string) []FlowSession {
	var out []FlowSession
	// Boundary fix: when the connection ends exactly on the previous window
	// boundary (zero data span since the last emitted window), everything is
	// already flushed — no extra window. A positive-span final window is
	// still emitted even when its traffic delta is zero. A generation that
	// never emitted a window always flushes its one final window.
	if session.windowSeq == 0 || session.EndTime.After(session.baseline.at) {
		out = append(out, s.buildWindow(session, now, true))
	}
	session.CloseReason = normalizeCloseReason(closeReason, "unknown")
	session.RecordType = "session_summary"
	session.WindowID = 0
	session.WindowValid = false
	session.WindowInvalidReason = ""
	session.FinalWindow = false
	session.WindowStartTime = time.Time{}
	session.CounterEpoch = session.epoch
	s.updateFeatureSnapshot(session)
	out = append(out, *session)
	delete(s.sessions, key)
	return out
}

// buildWindow emits one fixed-window record: delta = current cumulative
// snapshot minus the previous accepted baseline, then the current snapshot
// becomes the new baseline (carryover — a normal emission never clears it).
// The window is invalid (zeroed deltas) when the baseline is unknown or a
// cumulative counter/bucket regressed; either way the current snapshot is
// accepted as the next baseline so the following window recovers.
func (s *Sessionizer) buildWindow(session *FlowSession, now time.Time, final bool) FlowSession {
	s.updateFeatureSnapshot(session)
	cum := session.FeatureSnapshot

	pktDelta, pktRegressed := features.SubtractHistogram(cum.PktSizeHistogram, session.baseline.pktHist)
	iatDelta, iatRegressed := features.SubtractHistogram(cum.IATHistogram, session.baseline.iatHist)
	var nfDelta map[string]uint64
	nfRegressed := false
	if cum.NetFlowV2IPSizeHistogram != nil {
		nfDelta, nfRegressed = features.SubtractHistogram(cum.NetFlowV2IPSizeHistogram, session.baseline.nfHist)
	} else if histogramHasCounts(session.baseline.nfHist) {
		nfRegressed = true
	}

	invalidReason := ""
	if !session.baselineKnown {
		invalidReason = WindowInvalidUnknownBaseline
	} else if session.pendingReset || pktRegressed || iatRegressed || nfRegressed {
		invalidReason = WindowInvalidCounterReset
	}

	windowDuration := session.EndTime.Sub(session.baseline.at)

	summary := *session
	summary.RecordType = "window_summary"
	summary.CloseReason = ""
	session.windowSeq++
	summary.WindowID = session.windowSeq
	summary.FinalWindow = final
	summary.WindowStartTime = session.baseline.at
	summary.CounterEpoch = session.epoch

	if invalidReason != "" {
		summary.WindowValid = false
		summary.WindowInvalidReason = invalidReason
		summary.BytesOut, summary.BytesIn = 0, 0
		summary.PacketsOut, summary.PacketsIn = 0, 0
		summary.ObservedSKBPacketsOut, summary.ObservedSKBPacketsIn = 0, 0
		summary.LocalRetransSKBCount, summary.LocalRetransSKBBytes = 0, 0
		summary.FeatureSnapshot = features.WindowSnapshot(cum, features.WindowCounterDeltas{}, windowDuration)
	} else {
		base := session.baseline.counters
		d := features.WindowCounterDeltas{
			BytesOut:                 session.raw.bytesOut - base.bytesOut,
			BytesIn:                  session.raw.bytesIn - base.bytesIn,
			PacketsOut:               session.raw.packetsOut - base.packetsOut,
			PacketsIn:                session.raw.packetsIn - base.packetsIn,
			IdleGapCount:             session.raw.idleGap - base.idleGap,
			BurstCount:               session.raw.burst - base.burst,
			SYNCount:                 session.raw.syn - base.syn,
			FINCount:                 session.raw.fin - base.fin,
			RSTCount:                 session.raw.rst - base.rst,
			RetransCount:             session.raw.retrans - base.retrans,
			DirectionChanges:         session.raw.directionChanges - base.directionChanges,
			PktSizeHistogram:         pktDelta,
			IATHistogram:             iatDelta,
			NetFlowV2IPSizeHistogram: nfDelta,
		}
		summary.WindowValid = true
		summary.WindowInvalidReason = ""
		summary.BytesOut, summary.BytesIn = d.BytesOut, d.BytesIn
		summary.PacketsOut, summary.PacketsIn = d.PacketsOut, d.PacketsIn
		summary.ObservedSKBPacketsOut = session.raw.skbOut - base.skbOut
		summary.ObservedSKBPacketsIn = session.raw.skbIn - base.skbIn
		summary.LocalRetransSKBCount = session.raw.localRetransCount - base.localRetransCount
		summary.LocalRetransSKBBytes = session.raw.localRetransBytes - base.localRetransBytes
		summary.FeatureSnapshot = features.WindowSnapshot(cum, d, windowDuration)
	}

	// The invalid window records the transition under the OLD epoch; windows
	// after a reset carry the incremented epoch of the new counter lineage.
	if invalidReason == WindowInvalidCounterReset {
		session.epoch++
	}
	session.baseline = windowBaseline{
		at:       now,
		counters: session.raw,
		pktHist:  copyBuckets(cum.PktSizeHistogram),
		iatHist:  copyBuckets(cum.IATHistogram),
		nfHist:   copyBuckets(cum.NetFlowV2IPSizeHistogram),
	}
	session.baselineKnown = true
	session.pendingReset = false
	session.LastEmitted = now
	return summary
}

// mergeRaw tracks the latest raw cumulative counters (see rawCounters).
// Cumulative (eBPF) events: zero means "not provided" (existing convention —
// e.g. a CLOSE after the kernel map entry vanished) and is ignored; a
// non-zero regression marks a pending reset. Delta (mock) events mirror the
// established lifetime-merge semantics field by field: bytes/packets/skb/
// local-retrans carry running totals (monotonic max), while histogram-side
// counters (idle/burst/SYN/FIN/RST/retrans/direction-changes) are per-event
// increments that sum — including the legacy implied SYN/FIN on lifecycle
// events — so the raw view always matches the accumulator's lifetime view.
func (session *FlowSession) mergeRaw(ev collector.FlowEvent, evType string) {
	cumulative := ev.CounterSemantics == collector.CounterSemanticsCumulative
	latest := func(cur *uint64, next uint64) {
		if next == 0 {
			return
		}
		if cumulative && next < *cur {
			session.pendingReset = true
			*cur = next
			return
		}
		if next > *cur || cumulative {
			*cur = next
		}
	}
	additive := func(cur *uint64, next uint64) {
		if cumulative {
			latest(cur, next)
			return
		}
		*cur += next
	}
	latest(&session.raw.bytesOut, ev.BytesSent)
	latest(&session.raw.bytesIn, ev.BytesRecv)
	latest(&session.raw.packetsOut, ev.PacketsSent)
	latest(&session.raw.packetsIn, ev.PacketsRecv)
	latest(&session.raw.skbOut, ev.RealPacketsSent)
	latest(&session.raw.skbIn, ev.RealPacketsRecv)
	latest(&session.raw.localRetransCount, ev.LocalRetransSKBCount)
	latest(&session.raw.localRetransBytes, ev.LocalRetransSKBBytes)
	additive(&session.raw.idleGap, ev.IdleGapCount)
	additive(&session.raw.burst, ev.BurstCount)
	additive(&session.raw.syn, ev.SYNCount)
	additive(&session.raw.fin, ev.FINCount)
	additive(&session.raw.rst, ev.RSTCount)
	additive(&session.raw.retrans, ev.RetransCount)
	additive(&session.raw.directionChanges, ev.DirectionChanges)
	if !cumulative {
		switch evType {
		case "CONNECT", "ACCEPT":
			session.raw.syn++
		case "CLOSE":
			session.raw.fin++
		}
	}
}

func copyBuckets(src map[string]uint64) map[string]uint64 {
	if src == nil {
		return nil
	}
	out := make(map[string]uint64, len(src))
	for bucket, count := range src {
		out[bucket] = count
	}
	return out
}

func histogramHasCounts(h map[string]uint64) bool {
	for _, count := range h {
		if count > 0 {
			return true
		}
	}
	return false
}

func (s *Sessionizer) ProcessTLSHandshake(ev collector.FlowEvent) bool {
	key := flowKey(ev)
	session := s.sessions[key]
	if session == nil && (ev.ServerHelloSeen || ev.JA4S != "") {
		if altKey, ok := s.serviceAliasKey(ev); ok {
			session = s.sessions[altKey]
			if session != nil {
				s.incrementNATAliasHit()
			} else {
				s.incrementNATAliasMiss()
			}
		} else {
			s.incrementNATAliasMiss()
		}
	}
	if session == nil {
		return false
	}
	if ev.JA4 != "" || ev.HandshakeSeen {
		session.HandshakeSeen = ev.HandshakeSeen
		session.TLSVersion = ev.TLSVersion
		session.SNIHash = ev.SNIHash
		session.ALPN = ev.ALPN
		session.JA4 = ev.JA4
		session.TLSParseStatus = ev.TLSParseStatus
	}
	if ev.JA4S != "" || ev.ServerHelloSeen {
		session.ServerHelloSeen = ev.ServerHelloSeen
		session.TLSVersionNegotiated = ev.TLSVersionNegotiated
		session.ALPNNegotiated = ev.ALPNNegotiated
		session.JA4S = ev.JA4S
		session.TLSServerParseStatus = ev.TLSServerParseStatus
	}
	session.LastUpdated = eventTime(ev)
	return true
}

func (s *Sessionizer) serviceAliasKey(ev collector.FlowEvent) (string, bool) {
	if s.k8sMeta == nil {
		return "", false
	}
	clusterIP, servicePort, ok := s.k8sMeta.ResolveServiceForEndpoint(ev.DstIP, int(ev.DstPort), ev.Protocol)
	if !ok {
		return "", false
	}
	aliased := ev
	aliased.DstIP = clusterIP
	aliased.DstPort = uint16(servicePort)
	return flowKey(aliased), true
}

func (s *Sessionizer) incrementNATAliasHit() {
	if s.natAliasMetrics != nil {
		s.natAliasMetrics.IncTLSServerHelloNATAliasHit()
	}
}

func (s *Sessionizer) incrementNATAliasMiss() {
	if s.natAliasMetrics != nil {
		s.natAliasMetrics.IncTLSServerHelloNATAliasMiss()
	}
}

// Sweep distinguishes the two timer paths: an inactivity timeout ENDS the
// session (final window flush + session_summary + baseline destroyed with the
// session), while a periodic window emission only advances the baseline and
// keeps the session alive.
func (s *Sessionizer) Sweep(now time.Time) []FlowSession {
	var out []FlowSession
	for key, session := range s.sessions {
		if s.timeout > 0 && now.Sub(session.LastUpdated) > s.timeout {
			session.EndTime = session.LastUpdated
			session.DurationMS = session.EndTime.Sub(session.StartTime).Milliseconds()
			out = append(out, s.closeOut(session, key, now, "timeout")...)
			continue
		}
		if s.windowSize > 0 && now.Sub(session.LastEmitted) >= s.windowSize {
			out = append(out, s.buildWindow(session, now, false))
		}
	}
	return out
}

func (s *Sessionizer) ActiveCount() int {
	return len(s.sessions)
}

func (s *Sessionizer) CloseAll(reason string, now time.Time) []FlowSession {
	if reason == "" {
		reason = "timeout"
	}
	var out []FlowSession
	for key, session := range s.sessions {
		session.EndTime = now
		session.DurationMS = session.EndTime.Sub(session.StartTime).Milliseconds()
		out = append(out, s.closeOut(session, key, now, reason)...)
	}
	return out
}

func eventTime(ev collector.FlowEvent) time.Time {
	if ev.TimestampNS == 0 {
		return time.Now()
	}
	return time.Unix(0, int64(ev.TimestampNS)).UTC()
}

func flowKey(ev collector.FlowEvent) string {
	proto := strings.ToLower(ev.Protocol)
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%s|%s|%d|%s|%d", proto, ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
}

func flowID(key string, start time.Time) string {
	sum := sha1.Sum([]byte(fmt.Sprintf("%s|%d", key, start.UnixNano())))
	return hex.EncodeToString(sum[:])
}

// noteCounterResets flags a cumulative event whose counters regressed against
// the session's stored monotonic values: the kernel-side accumulator was reset
// (LRU eviction + re-create, agent restart). The stored maxima are kept by the
// subsequent merges — pre- and post-reset values are never summed — and the
// reset is recorded so downstream consumers know the totals are a lower bound.
// A zero counter means "not provided" (e.g. CLOSE after the map entry
// vanished) and is not a reset.
func (session *FlowSession) noteCounterResets(ev collector.FlowEvent) {
	regressed := func(next, prev uint64) bool { return next > 0 && next < prev }
	if regressed(ev.BytesSent, session.BytesOut) ||
		regressed(ev.BytesRecv, session.BytesIn) ||
		regressed(ev.PacketsSent, session.PacketsOut) ||
		regressed(ev.PacketsRecv, session.PacketsIn) ||
		regressed(ev.RealPacketsSent, session.ObservedSKBPacketsOut) ||
		regressed(ev.RealPacketsRecv, session.ObservedSKBPacketsIn) ||
		regressed(ev.LocalRetransSKBCount, session.LocalRetransSKBCount) ||
		regressed(ev.LocalRetransSKBBytes, session.LocalRetransSKBBytes) {
		session.CounterResetDetected = true
		session.CounterResetCount++
	}
}

// mergeObservedSKBPackets folds the event's cgroup_skb-observed skb counts
// (FlowEvent.RealPacketsSent/Recv) into the session as the latest monotonic
// value. The legacy PacketsOut/In syscall-count semantics are untouched.
func (session *FlowSession) mergeObservedSKBPackets(ev collector.FlowEvent) {
	if ev.RealPacketsSent == 0 && ev.RealPacketsRecv == 0 {
		return
	}
	if ev.RealPacketsSent > session.ObservedSKBPacketsOut {
		session.ObservedSKBPacketsOut = ev.RealPacketsSent
	}
	if ev.RealPacketsRecv > session.ObservedSKBPacketsIn {
		session.ObservedSKBPacketsIn = ev.RealPacketsRecv
	}
	session.ObservedSKBPacketsAvailable = true
	if session.ObservedSKBPacketsSource == "" && ev.ObservedSKBPacketsSource != "" {
		session.ObservedSKBPacketsSource = ev.ObservedSKBPacketsSource
	}
}

// mergeHeaderAggregates folds one event's TCP/IP header aggregates into the
// session. Every operation is idempotent (min/max envelope, bitwise OR,
// monotone max, boolean OR), so repeated cumulative snapshots never
// re-accumulate and event reordering cannot regress the values.
func (session *FlowSession) mergeHeaderAggregates(ev collector.FlowEvent) {
	session.IPTTLMin = minU32Ptr(session.IPTTLMin, ev.IPTTLMin)
	session.IPTTLMax = maxU32Ptr(session.IPTTLMax, ev.IPTTLMax)
	session.TCPFlagsOut |= ev.TCPFlagsOut
	session.TCPFlagsIn |= ev.TCPFlagsIn
	session.TCPHeaderObservedOut = session.TCPHeaderObservedOut || ev.TCPHeaderObservedOut
	session.TCPHeaderObservedIn = session.TCPHeaderObservedIn || ev.TCPHeaderObservedIn
	session.TCPWindowMaxOut = maxU32Ptr(session.TCPWindowMaxOut, ev.TCPWindowMaxOut)
	session.TCPWindowMaxIn = maxU32Ptr(session.TCPWindowMaxIn, ev.TCPWindowMaxIn)
	if ev.DirectionDurationOutNS > session.DirectionDurationOutNS {
		session.DirectionDurationOutNS = ev.DirectionDurationOutNS
	}
	if ev.DirectionDurationInNS > session.DirectionDurationInNS {
		session.DirectionDurationInNS = ev.DirectionDurationInNS
	}
	session.DirectionDurationOutObserved = session.DirectionDurationOutObserved || ev.DirectionDurationOutObserved
	session.DirectionDurationInObserved = session.DirectionDurationInObserved || ev.DirectionDurationInObserved
	session.IPPktLenMin = minU32Ptr(session.IPPktLenMin, ev.IPPktLenMin)
	session.IPPktLenMax = maxU32Ptr(session.IPPktLenMax, ev.IPPktLenMax)
}

// mergeLocalRetrans folds the event's local retransmission counters into the
// session as the latest monotonic value. Availability comes exclusively from
// the event's attach-status flag — never inferred from a zero counter — so an
// attached hook with no retransmissions yields a genuine 0 and an unattached
// hook yields unavailable.
func (session *FlowSession) mergeLocalRetrans(ev collector.FlowEvent) {
	if ev.LocalRetransSKBCount > session.LocalRetransSKBCount {
		session.LocalRetransSKBCount = ev.LocalRetransSKBCount
	}
	if ev.LocalRetransSKBBytes > session.LocalRetransSKBBytes {
		session.LocalRetransSKBBytes = ev.LocalRetransSKBBytes
	}
	session.LocalRetransAvailable = session.LocalRetransAvailable || ev.LocalRetransAvailable
	if session.LocalRetransSource == "" && ev.LocalRetransSource != "" {
		session.LocalRetransSource = ev.LocalRetransSource
	}
}

func minU32Ptr(current, candidate *uint32) *uint32 {
	if candidate == nil {
		return current
	}
	if current == nil || *candidate < *current {
		v := *candidate
		return &v
	}
	return current
}

func maxU32Ptr(current, candidate *uint32) *uint32 {
	if candidate == nil {
		return current
	}
	if current == nil || *candidate > *current {
		v := *candidate
		return &v
	}
	return current
}

func (s *Sessionizer) updateFeatureSnapshot(session *FlowSession) {
	session.FeatureSnapshot = session.accumulator.Snapshot(session.BytesOut, session.BytesIn, session.PacketsOut, session.PacketsIn, session.EndTime.Sub(session.StartTime), s.longLivedThreshold)
}

func normalizeCloseReason(reason, fallback string) string {
	switch strings.ToLower(reason) {
	case "fin", "rst", "timeout", "unknown":
		return strings.ToLower(reason)
	case "":
		return fallback
	default:
		return "unknown"
	}
}
