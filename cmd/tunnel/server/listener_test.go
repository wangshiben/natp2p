package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type controlledTunnelListener struct {
	calls       chan string
	release     chan struct{}
	active      atomic.Int32
	overlapping atomic.Bool
}

func (listener *controlledTunnelListener) Listen(ctx context.Context, relay string) error {
	if listener.active.Add(1) != 1 {
		listener.overlapping.Store(true)
	}
	defer listener.active.Add(-1)
	select {
	case listener.calls <- relay:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-listener.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestServeTunnelSessionsReregistersSequentially(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listener := &controlledTunnelListener{
		calls:   make(chan string, 2),
		release: make(chan struct{}, 1),
	}
	done := make(chan struct{})
	go func() {
		serveTunnelSessions(ctx, listener, "relay04:9000")
		close(done)
	}()

	expectListenCall(t, listener.calls, "relay04:9000")
	select {
	case relay := <-listener.calls:
		t.Fatalf("next registration started before the current session ended: %s", relay)
	case <-time.After(50 * time.Millisecond):
	}

	listener.release <- struct{}{}
	expectListenCall(t, listener.calls, "relay04:9000")
	if listener.overlapping.Load() {
		t.Fatal("Listen calls overlapped")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener loop did not stop after cancellation")
	}
}

func TestServeTunnelSessionsRetriesAfterListenFailure(t *testing.T) {
	expected := errors.New("registration failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	listener := tunnelListenerFunc(func(ctx context.Context, _ string) error {
		if calls.Add(1) == 1 {
			return expected
		}
		<-ctx.Done()
		return ctx.Err()
	})
	done := make(chan struct{})
	go func() {
		serveTunnelSessions(ctx, listener, "relay04:9000")
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatal("listener did not retry a transient registration failure")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener loop did not stop after cancellation")
	}
}

type tunnelListenerFunc func(context.Context, string) error

func (listen tunnelListenerFunc) Listen(ctx context.Context, relay string) error {
	return listen(ctx, relay)
}

func expectListenCall(t *testing.T, calls <-chan string, expected string) {
	t.Helper()
	select {
	case actual := <-calls:
		if actual != expected {
			t.Fatalf("Listen relay = %q, want %q", actual, expected)
		}
	case <-time.After(time.Second):
		t.Fatal("Listen was not called")
	}
}
