package sessionizer

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"FlowLedger/pkg/collector"
	"FlowLedger/pkg/features"
)

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

	windowSeq   uint64
	accumulator features.Accumulator
}

type Sessionizer struct {
	nodeName           string
	timeout            time.Duration
	windowSize         time.Duration
	longLivedThreshold time.Duration
	sessions           map[string]*FlowSession
}

func New(nodeName string, timeout, windowSize time.Duration) *Sessionizer {
	return NewWithLongLivedThreshold(nodeName, timeout, windowSize, features.DefaultLongLivedThreshold)
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
	if strings.ToUpper(ev.EventType) == "TLS_HANDSHAKE" {
		s.ProcessTLSHandshake(ev)
		return nil
	}
	key := flowKey(ev)
	now := eventTime(ev)
	if ev.Protocol == "" {
		ev.Protocol = "tcp"
	}

	session := s.sessions[key]
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
	session.accumulator.AddEvent(ev)
	s.updateFeatureSnapshot(session)

	var out []FlowSession
	switch strings.ToUpper(ev.EventType) {
	case "CLOSE":
		session.CloseReason = normalizeCloseReason(ev.CloseReason, "unknown")
		session.RecordType = "session_summary"
		session.WindowID = 0
		s.updateFeatureSnapshot(session)
		out = append(out, *session)
		delete(s.sessions, key)
	case "CONNECT", "ACCEPT", "STATS":
		if s.windowSize > 0 && now.Sub(session.LastEmitted) >= s.windowSize {
			summary := *session
			summary.RecordType = "window_summary"
			summary.CloseReason = ""
			session.windowSeq++
			summary.WindowID = session.windowSeq
			s.updateFeatureSnapshot(&summary)
			out = append(out, summary)
			session.LastEmitted = now
		}
	}
	return out
}

func (s *Sessionizer) ProcessTLSHandshake(ev collector.FlowEvent) bool {
	key := flowKey(ev)
	session := s.sessions[key]
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

func (s *Sessionizer) Sweep(now time.Time) []FlowSession {
	var out []FlowSession
	for key, session := range s.sessions {
		if s.timeout > 0 && now.Sub(session.LastUpdated) > s.timeout {
			session.EndTime = session.LastUpdated
			session.DurationMS = session.EndTime.Sub(session.StartTime).Milliseconds()
			session.CloseReason = "timeout"
			session.RecordType = "session_summary"
			session.WindowID = 0
			s.updateFeatureSnapshot(session)
			out = append(out, *session)
			delete(s.sessions, key)
			continue
		}
		if s.windowSize > 0 && now.Sub(session.LastEmitted) >= s.windowSize {
			summary := *session
			summary.RecordType = "window_summary"
			summary.CloseReason = ""
			session.windowSeq++
			summary.WindowID = session.windowSeq
			s.updateFeatureSnapshot(&summary)
			out = append(out, summary)
			session.LastEmitted = now
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
		session.CloseReason = normalizeCloseReason(reason, "timeout")
		session.RecordType = "session_summary"
		session.WindowID = 0
		s.updateFeatureSnapshot(session)
		out = append(out, *session)
		delete(s.sessions, key)
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
