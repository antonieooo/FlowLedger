FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/node-agent \
    ./cmd/node-agent

FROM gcr.io/distroless/static-debian12:latest

WORKDIR /
COPY --from=builder /out/node-agent /node-agent

USER 0:0
ENTRYPOINT ["/node-agent"]
