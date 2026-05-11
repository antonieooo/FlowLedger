.PHONY: generate generate-ebpf test build run-mock

generate: generate-ebpf

generate-ebpf:
	go generate ./pkg/collector

test:
	go test ./...

build:
	go build ./cmd/node-agent

run-mock:
	go run ./cmd/node-agent --mode mock --mock-events-path ./testdata/mock_flow_events.jsonl --ledger-path ./flows.jsonl --node-name local-test
