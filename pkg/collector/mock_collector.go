package collector

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

type MockCollector struct {
	Path string
}

func NewMockCollector(path string) *MockCollector {
	return &MockCollector{Path: path}
}

func (c *MockCollector) Run(ctx context.Context) (<-chan FlowEvent, <-chan error) {
	events := make(chan FlowEvent)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		if c.Path == "" {
			errs <- errors.New("mock events path is required")
			return
		}

		f, err := os.Open(c.Path)
		if err != nil {
			errs <- err
			return
		}
		defer f.Close()

		reader := bufio.NewReader(f)
		for {
			select {
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			default:
			}

			line, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				errs <- err
				return
			}

			line = strings.TrimSpace(line)
			if line != "" {
				var ev FlowEvent
				if decErr := json.Unmarshal([]byte(line), &ev); decErr != nil {
					errs <- decErr
					return
				}
				if ev.Protocol == "" {
					ev.Protocol = "tcp"
				}
				if ev.EventType == "TLS_HANDSHAKE" && ev.TLSHandshakePayloadHex != "" {
					raw, err := hex.DecodeString(ev.TLSHandshakePayloadHex)
					if err != nil {
						errs <- err
						return
					}
					applyParsedTLSHandshake(&ev, raw)
					ev.TLSHandshakePayloadHex = ""
				}
				if ev.BytesSent > 0 || ev.BytesRecv > 0 || ev.PacketsSent > 0 || ev.PacketsRecv > 0 {
					ev.TrafficAccountingAvailable = true
				}
				if len(ev.PacketSizes) > 0 || len(ev.IATMicros) > 0 || len(ev.PacketSizeHistogram) > 0 || len(ev.IATHistogram) > 0 {
					ev.PacketTimingAvailable = true
				}
				if ev.SYNCount > 0 || ev.FINCount > 0 || ev.RSTCount > 0 || ev.RetransCount > 0 || ev.RTTEstimateUS > 0 {
					ev.TCPMetricsAvailable = true
				}
				// TCP header observation (tcp_header_observed_out/in) is
				// never inferred from flag/window values: fixtures that
				// model observed TCP headers must set the witness fields
				// explicitly, exactly like the kernel path does.
				// Mock fixtures default to the legacy per-event delta
				// semantics; a fixture may opt into "cumulative" explicitly
				// to exercise the eBPF aggregation path.
				if ev.CounterSemantics == "" {
					ev.CounterSemantics = CounterSemanticsDelta
				}
				if (ev.RealPacketsSent > 0 || ev.RealPacketsRecv > 0) && ev.ObservedSKBPacketsSource == "" {
					ev.ObservedSKBPacketsSource = "mock"
				}
				// Retransmission fixtures: non-zero counters imply the fixture
				// modelled an attached hook; a fixture may also set
				// local_retrans_available explicitly (with zero counters) to
				// model "hook attached, no retransmissions".
				if ev.LocalRetransSKBCount > 0 || ev.LocalRetransSKBBytes > 0 {
					ev.LocalRetransAvailable = true
				}
				if ev.LocalRetransAvailable && ev.LocalRetransSource == "" {
					ev.LocalRetransSource = "mock"
				}

				select {
				case <-ctx.Done():
					errs <- ctx.Err()
					return
				case events <- ev:
				}
			}

			if errors.Is(err, io.EOF) {
				return
			}
		}
	}()

	return events, errs
}

func applyParsedTLSHandshake(ev *FlowEvent, raw []byte) {
	switch ev.TLSHandshakeDirection {
	case tlsDirectionServerHello:
		info := ParseTLSServerHello(raw)
		ev.ServerHelloSeen = info.HandshakeSeen
		ev.TLSVersionNegotiated = info.TLSVersion
		ev.ALPNNegotiated = info.ALPN
		ev.JA4S = info.JA4S
		ev.TLSServerParseStatus = info.Status
	default:
		info := ParseTLSClientHello(raw)
		ev.HandshakeSeen = info.HandshakeSeen
		ev.TLSVersion = info.TLSVersion
		ev.SNIHash = info.SNIHash
		ev.ALPN = info.ALPN
		ev.JA4 = info.JA4
		ev.TLSParseStatus = info.Status
	}
}
