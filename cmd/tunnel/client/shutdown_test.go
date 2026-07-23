package main

import (
	"context"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type controlledTunnelSession struct {
	ctx          context.Context
	cancel       context.CancelFunc
	closeStarted chan struct{}
	closeRelease chan struct{}
	closeDone    chan struct{}
	closeOnce    sync.Once
}

func newControlledTunnelSession() *controlledTunnelSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &controlledTunnelSession{
		ctx: ctx, cancel: cancel,
		closeStarted: make(chan struct{}), closeRelease: make(chan struct{}), closeDone: make(chan struct{}),
	}
}

func (session *controlledTunnelSession) Context() context.Context {
	return session.ctx
}

func (session *controlledTunnelSession) Close() error {
	session.closeOnce.Do(func() {
		close(session.closeStarted)
		<-session.closeRelease
		session.cancel()
		close(session.closeDone)
	})
	return nil
}

type recordingCloser struct {
	closed chan struct{}
}

func (closer *recordingCloser) Close() error {
	close(closer.closed)
	return nil
}

func TestShutdownTunnelWaitsForSessionCloseBeforeListener(t *testing.T) {
	signals := make(chan os.Signal, 1)
	session := newControlledTunnelSession()
	listener := &recordingCloser{closed: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		shutdownTunnel(signals, session, listener)
		close(done)
	}()

	signals <- syscall.SIGTERM
	waitForTestSignal(t, session.closeStarted, "session Close start")
	select {
	case <-listener.closed:
		t.Fatal("listener closed before session Close completed")
	default:
	}
	close(session.closeRelease)
	waitForTestSignal(t, session.closeDone, "session Close completion")
	waitForTestSignal(t, listener.closed, "listener Close")
	waitForTestSignal(t, done, "shutdown helper completion")
}

func TestShutdownTunnelClosesListenerWhenSessionEnds(t *testing.T) {
	signals := make(chan os.Signal)
	session := newControlledTunnelSession()
	listener := &recordingCloser{closed: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		shutdownTunnel(signals, session, listener)
		close(done)
	}()

	session.cancel()
	waitForTestSignal(t, listener.closed, "listener Close")
	waitForTestSignal(t, done, "shutdown helper completion")
	select {
	case <-session.closeStarted:
		t.Fatal("remote session end invoked local Session.Close")
	default:
	}
}

func waitForTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}
