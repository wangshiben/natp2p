package networkFrameWork

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"bnfs_p2p/network"
)

type billingControlHandlerResult struct {
	payload string
	err     error
}

func TestBillingControlHandlerOutlivesHandshakeDispatch(t *testing.T) {
	cover := NewTransportCover()
	handlerEntered := make(chan struct{})
	handlerResult := make(chan billingControlHandlerResult, 1)
	handlerRelease := make(chan struct{})
	defer close(handlerRelease)
	cover.SetMissingGroupHandler(func(stream network.Stream, firstMessage *network.Message) error {
		defer stream.Close()
		if firstMessage == nil || firstMessage.Header == nil ||
			firstMessage.Header.RouteName != billingControlRouteHint {
			return fmt.Errorf("unexpected billing control first message")
		}
		close(handlerEntered)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for {
			message, err := stream.NextMessage(ctx)
			if err != nil {
				handlerResult <- billingControlHandlerResult{err: err}
				return err
			}
			if string(message.Payload) != "control-stream-still-open" {
				continue
			}
			handlerResult <- billingControlHandlerResult{payload: string(message.Payload)}
			<-handlerRelease
			return nil
		}
	})

	clientConnection, relayConnection := net.Pipe()
	client := startTcpStream("billing-relay", "billing-control-lifecycle", clientConnection)
	t.Cleanup(func() {
		_ = client.Close()
		_ = relayConnection.Close()
	})

	listenDone := make(chan error, 1)
	go func() {
		listenDone <- cover.ListenTCPConnection(relayConnection)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err := client.SendMessage(ctx, &network.Message{
		Header: &network.Header{
			RouteName:     billingControlRouteHint,
			NodeId:        "billing-relay",
			NodeIdVersion: 1,
			ConnectionId:  "billing-control-lifecycle",
		},
		Payload: []byte("billing-payer-public-key"),
	})
	cancel()
	if err != nil {
		t.Fatalf("send billing control first message: %v", err)
	}

	select {
	case <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("billing control handler did not start")
	}
	select {
	case err := <-listenDone:
		if err != nil {
			t.Fatalf("billing control handshake dispatch failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("billing control handler retained handshake timeout ownership")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	err = client.SendMessage(ctx, &network.Message{
		Header: &network.Header{
			RouteName:     billingControlRouteHint,
			NodeId:        "billing-relay",
			NodeIdVersion: 1,
			ConnectionId:  "billing-control-lifecycle",
		},
		Payload: []byte("control-stream-still-open"),
	})
	cancel()
	if err != nil {
		t.Fatalf("send billing control follow-up after dispatch return: %v", err)
	}

	select {
	case result := <-handlerResult:
		if result.err != nil {
			t.Fatalf("billing control handler failed after handoff: %v", result.err)
		}
		if result.payload != "control-stream-still-open" {
			t.Fatalf("billing control follow-up payload = %q", result.payload)
		}
	case <-time.After(time.Second):
		t.Fatal("billing control handler did not receive follow-up after handoff")
	}
}
