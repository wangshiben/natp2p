package natnode

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
)

var errControlledTransportClosed = errors.New("controlled transport stream closed")

type billingCascadeReproStream struct {
	connectionID string
	entered      chan<- struct{}
	fail         <-chan struct{}
	sendCalls    atomic.Int32
	closeCalls   atomic.Int32
	observerMu   sync.Mutex
	observer     network.OutboundRecordObserver
}

func (stream *billingCascadeReproStream) Close() error {
	stream.closeCalls.Add(1)
	return nil
}

func (*billingCascadeReproStream) NextMessage(context.Context) (*network.Message, error) {
	return nil, errors.New("billing cascade regression does not receive messages")
}

func (stream *billingCascadeReproStream) SendMessage(ctx context.Context, message *network.Message) error {
	stream.sendCalls.Add(1)
	if stream.entered != nil {
		select {
		case stream.entered <- struct{}{}:
		default:
		}
	}
	if stream.fail != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stream.fail:
			return errControlledTransportClosed
		}
	}

	stream.observerMu.Lock()
	observer := stream.observer
	stream.observerMu.Unlock()
	if observer == nil || message == nil || message.Header == nil {
		return nil
	}
	record := natBillingTestE2ERecord(message.Header.BillingBytes, message.Header.BillingSequence)
	sealed := *message
	header := *message.Header
	sealed.Header = &header
	sealed.Payload = record
	metadata, err := crypoto.InspectE2ERecord(record)
	if err != nil {
		return err
	}
	return observer(&sealed, metadata.MessageID)
}

func (*billingCascadeReproStream) SendMessageAsync(
	context.Context,
	*network.Message,
	network.MessageResultCallback,
) error {
	return errors.New("billing cascade regression does not use async sends")
}

func (stream *billingCascadeReproStream) NodeId() string       { return "peer-" + stream.connectionID }
func (stream *billingCascadeReproStream) ConnectionId() string { return stream.connectionID }
func (*billingCascadeReproStream) SetCryptoSuite(network.EncrypSuite) {
}
func (stream *billingCascadeReproStream) SetOutboundRecordObserver(observer network.OutboundRecordObserver) {
	stream.observerMu.Lock()
	stream.observer = observer
	stream.observerMu.Unlock()
}

type billingCascadeReproResult struct {
	connectionID string
	err          error
}

func TestSharedBillingInvalidationDoesNotCloseQueuedConnections(t *testing.T) {
	const (
		preInvalidationConnections  = 156
		queuedConnections           = preInvalidationConnections - 1
		postInvalidationConnections = 10
		totalConnections            = preInvalidationConnections + postInvalidationConnections
	)

	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	relayAddress := "controlled-relay:9000"
	sessionID := billingvoucher.Identifier{0x15, 0x6, 0x30}
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}

	var closedConnections atomic.Int32
	newServiceConnection := func(
		index int,
		entered chan<- struct{},
		fail <-chan struct{},
	) (*serviceConnection, *billingCascadeReproStream) {
		connectionID := fmt.Sprintf("regression-%03d", index)
		stream := &billingCascadeReproStream{
			connectionID: connectionID,
			entered:      entered,
			fail:         fail,
		}
		natConnection := newNATConnection(
			p2pnode.PeerInfo{ID: p2pnode.NodeID("peer-" + connectionID)},
			stream,
			nil,
			meter,
			func() string { return relayAddress },
			nil,
		)
		return &serviceConnection{
			Connection: natConnection,
			closeFn: func() {
				closedConnections.Add(1)
			},
		}, stream
	}

	testContext, cancelTest := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelTest()
	transportFailure := make(chan struct{})
	firstEntered := make(chan struct{}, 1)
	results := make(chan billingCascadeReproResult, totalConnections)
	firstConnection, firstStream := newServiceConnection(0, firstEntered, transportFailure)
	go func() {
		results <- billingCascadeReproResult{
			connectionID: firstStream.connectionID,
			err: firstConnection.Send(
				testContext,
				&p2pnode.Message{Payload: []byte("controlled-first-send")},
			),
		}
	}()
	select {
	case <-firstEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("first connection did not enter the controlled transport")
	}

	queuedStreams := make([]*billingCascadeReproStream, 0, queuedConnections)
	for index := 1; index < preInvalidationConnections; index++ {
		connection, stream := newServiceConnection(index, nil, nil)
		queuedStreams = append(queuedStreams, stream)
		go func(connectionID string, connection *serviceConnection) {
			results <- billingCascadeReproResult{
				connectionID: connectionID,
				err: connection.Send(
					testContext,
					&p2pnode.Message{Payload: []byte("queued-before-invalidation")},
				),
			}
		}(stream.connectionID, connection)
	}

	waitForBillingCascadeDiagnostics(t, meter, relayAddress, func(diagnostics natBillingRelayDiagnostics) bool {
		return diagnostics.sendOrderWaiters == queuedConnections &&
			diagnostics.activeSends == 1 &&
			!diagnostics.invalid
	}, "155 sends queued behind one active send")
	close(transportFailure)

	select {
	case result := <-results:
		if result.connectionID != firstStream.connectionID || !errors.Is(result.err, errControlledTransportClosed) {
			t.Fatalf("first result=%+v, want controlled transport failure", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first transport failure did not return")
	}
	waitForBillingCascadeDiagnostics(t, meter, relayAddress, func(diagnostics natBillingRelayDiagnostics) bool {
		return diagnostics.sendOrderWaiters == 0 &&
			diagnostics.relaySessionWaiters == queuedConnections &&
			diagnostics.activeSends == 0 &&
			diagnostics.invalid
	}, "155 stale send-order waiters moved to reconciliation")

	postInvalidationStreams := make([]*billingCascadeReproStream, 0, postInvalidationConnections)
	for index := preInvalidationConnections; index < totalConnections; index++ {
		connection, stream := newServiceConnection(index, nil, nil)
		postInvalidationStreams = append(postInvalidationStreams, stream)
		go func(connectionID string, connection *serviceConnection) {
			results <- billingCascadeReproResult{
				connectionID: connectionID,
				err: connection.Send(
					testContext,
					&p2pnode.Message{Payload: []byte("started-after-invalidation")},
				),
			}
		}(stream.connectionID, connection)
	}
	waitForBillingCascadeDiagnostics(t, meter, relayAddress, func(diagnostics natBillingRelayDiagnostics) bool {
		return diagnostics.relaySessionWaiters == queuedConnections+postInvalidationConnections
	}, "all non-triggering sends waiting for reconciliation")

	if got := closedConnections.Load(); got != 1 {
		t.Fatalf("connections closed before reconciliation=%d, want only the trigger connection", got)
	}
	select {
	case result := <-results:
		t.Fatalf("non-triggering connection returned before reconciliation: %+v", result)
	default:
	}
	for _, stream := range append(queuedStreams, postInvalidationStreams...) {
		if stream.sendCalls.Load() != 0 || stream.closeCalls.Load() != 0 {
			t.Fatalf(
				"%s reached transport or closed before reconciliation: sendCalls=%d closeCalls=%d",
				stream.connectionID, stream.sendCalls.Load(), stream.closeCalls.Load(),
			)
		}
	}

	emptyRelayState := natBillingSnapshot{}
	status, err := meter.activateRelaySessionWithState(
		relayAddress,
		sessionID.String(),
		relayPublicKey,
		&emptyRelayState,
	)
	if err != nil {
		t.Fatal(err)
	}
	if status.preexisting || !status.resetRequired || status.draining {
		t.Fatalf("ambiguous session did not require rotation: %+v", status)
	}
	rotatedSessionID := billingvoucher.Identifier{22, 7, 1}
	status, err = meter.activateRelaySessionWithState(
		relayAddress,
		rotatedSessionID.String(),
		relayPublicKey,
		&emptyRelayState,
	)
	if err != nil || status.resetRequired {
		t.Fatalf("activate rotated session = (%+v, %v)", status, err)
	}

	for received := 0; received < queuedConnections+postInvalidationConnections; received++ {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("%s failed after reconciliation: %v", result.connectionID, result.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out after %d recovered sends", received)
		}
	}
	if got := closedConnections.Load(); got != 1 {
		t.Fatalf("connections closed after reconciliation=%d, want only the trigger connection", got)
	}
	if firstStream.closeCalls.Load() != 1 {
		t.Fatalf("trigger stream close calls=%d, want 1", firstStream.closeCalls.Load())
	}
	for _, stream := range append(queuedStreams, postInvalidationStreams...) {
		if stream.sendCalls.Load() != 1 || stream.closeCalls.Load() != 0 {
			t.Fatalf(
				"%s recovery calls: send=%d close=%d, want 1/0",
				stream.connectionID, stream.sendCalls.Load(), stream.closeCalls.Load(),
			)
		}
	}
	finalDiagnostics := meter.relayDiagnostics(relayAddress)
	if finalDiagnostics.invalid || finalDiagnostics.sendOrderWaiters != 0 ||
		finalDiagnostics.relaySessionWaiters != 0 || finalDiagnostics.activeSends != 0 {
		t.Fatalf("unexpected final diagnostics: %+v", finalDiagnostics)
	}
	if finalDiagnostics.nextAssigned != totalConnections ||
		finalDiagnostics.nextAdvance != totalConnections {
		t.Fatalf(
			"billing sequence after recovery assigned=%d advance=%d, want %d",
			finalDiagnostics.nextAssigned,
			finalDiagnostics.nextAdvance,
			totalConnections,
		)
	}
}

func waitForBillingCascadeDiagnostics(
	t *testing.T,
	meter *natBillingMeter,
	relayAddress string,
	condition func(natBillingRelayDiagnostics) bool,
	description string,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		diagnostics := meter.relayDiagnostics(relayAddress)
		if condition(diagnostics) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %+v", description, diagnostics)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
