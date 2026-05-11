package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitForMetadataSyncSuccess(t *testing.T) {
	ready := make(chan error, 1)
	ready <- nil

	if err := waitForMetadataSync(context.Background(), ready, time.Second, false); err != nil {
		t.Fatalf("waitForMetadataSync: %v", err)
	}
}

func TestWaitForMetadataSyncErrorRequiresOptIn(t *testing.T) {
	ready := make(chan error, 1)
	ready <- errors.New("sync failed")

	if err := waitForMetadataSync(context.Background(), ready, time.Second, false); err == nil {
		t.Fatal("expected sync error")
	}
}

func TestWaitForMetadataSyncErrorAllowed(t *testing.T) {
	ready := make(chan error, 1)
	ready <- errors.New("sync failed")

	if err := waitForMetadataSync(context.Background(), ready, time.Second, true); err != nil {
		t.Fatalf("waitForMetadataSync: %v", err)
	}
}

func TestWaitForMetadataSyncTimeout(t *testing.T) {
	ready := make(chan error)

	if err := waitForMetadataSync(context.Background(), ready, time.Millisecond, false); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestWaitForMetadataSyncTimeoutAllowed(t *testing.T) {
	ready := make(chan error)

	if err := waitForMetadataSync(context.Background(), ready, time.Millisecond, true); err != nil {
		t.Fatalf("waitForMetadataSync: %v", err)
	}
}
