package sessionizer

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"FlowLedger/pkg/collector"
)

type FlowSession struct {
	RecordType  string
	FlowID      string
	NodeName    string
	StartTime   time.Time
	EndTime     time.Time
	DurationMS  int64
	SrcIP       string
	SrcPort     uint16
	DstIP       string
	DstPort     uint16
	Protocol    string
	BytesOut    uint64
	BytesIn     uint64
	PacketsOut  uint64
	PacketsIn   uint64
	EventCount  uint64
	CloseReason string
	LastUpdated time.Time
	LastEmitted time.Time
}

type Sessionizer struct {
	nodeName   string
	timeout    time.Duration
	windowSize time.Duration
	sessions   map[string]*FlowSession
}

func New(nodeName string, timeout, windowSize time.Duration) *Sessionizer {
	return &Sessionizer{
		nodeName:   nodeName,
		timeout:    timeout,
		windowSize: windowSize,
		sessions:   map[string]*FlowSession{},
	}
}

func (s *Sessionizer) Process(ev collector.FlowEvent) []FlowSession {
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
			SrcIP:       ev.SrcIP,
			SrcPort:     ev.SrcPort,
			DstIP:       ev.DstIP,
			DstPort:     ev.DstPort,
			Protocol:    strings.ToLower(ev.Protocol),
			LastEmitted: now,
		}
		s.sessions[key] = session
	}

	session.EventCount++
	session.LastUpdated = now
	session.EndTime = now
	session.DurationMS = session.EndTime.Sub(session.StartTime).Milliseconds()
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

	var out []FlowSession
	switch strings.ToUpper(ev.EventType) {
	case "CLOSE":
		session.CloseReason = "closed"
		session.RecordType = "session_summary"
		out = append(out, *session)
		delete(s.sessions, key)
	case "CONNECT", "ACCEPT", "STATS":
		if s.windowSize > 0 && now.Sub(session.LastEmitted) >= s.windowSize {
			summary := *session
			summary.RecordType = "window_summary"
			summary.CloseReason = ""
			out = append(out, summary)
			session.LastEmitted = now
		}
	}
	return out
}

func (s *Sessionizer) Sweep(now time.Time) []FlowSession {
	var out []FlowSession
	for key, session := range s.sessions {
		if s.timeout > 0 && now.Sub(session.LastUpdated) > s.timeout {
			session.EndTime = session.LastUpdated
			session.DurationMS = session.EndTime.Sub(session.StartTime).Milliseconds()
			session.CloseReason = "expired"
			session.RecordType = "session_summary"
			out = append(out, *session)
			delete(s.sessions, key)
			continue
		}
		if s.windowSize > 0 && now.Sub(session.LastEmitted) >= s.windowSize {
			summary := *session
			summary.RecordType = "window_summary"
			summary.CloseReason = ""
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
		session.CloseReason = reason
		session.RecordType = "session_summary"
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
