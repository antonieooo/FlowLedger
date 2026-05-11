package collector

import (
	"bufio"
	"context"
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
