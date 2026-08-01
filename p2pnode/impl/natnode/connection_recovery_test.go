package natnode

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
)

type billingRotationRecoveryStream struct {
	mu         sync.Mutex
	observer   network.OutboundRecordObserver
	sendCalls  int
	closeCalls int
	sessions   [][32]byte
	sequences  []uint64
	firstSend  chan<- struct{}
	release    <-chan struct{}
}

func (stream *billingRotationRecoveryStream) Close() error {
	stream.mu.Lock()
	stream.closeCalls++
	stream.mu.Unlock()
	return nil
}

func (*billingRotationRecoveryStream) NextMessage(context.Context) (*network.Message, error) {
	return nil, errors.New("unused")
}

func (stream *billingRotationRecoveryStream) SendMessage(ctx context.Context, message *network.Message) error {
	return stream.SendMessageWithInitialWrite(ctx, message, nil)
}

func (stream *billingRotationRecoveryStream) SendMessageWithInitialWrite(
	_ context.Context,
	message *network.Message,
	onInitialWrite func(),
) error {
	stream.mu.Lock()
	stream.sendCalls++
	call := stream.sendCalls
	stream.sessions = append(stream.sessions, message.Header.BillingSessionID)
	stream.sequences = append(stream.sequences, message.Header.BillingSequence)
	observer := stream.observer
	stream.mu.Unlock()

	record := natBillingTestE2ERecord(message.Header.BillingBytes, message.Header.BillingSequence)
	sealed := *message
	header := *message.Header
	sealed.Header = &header
	sealed.Payload = record
	if observer != nil {
		metadata, err := crypoto.InspectE2ERecord(record)
		if err != nil {
			return err
		}
		if err := observer(&sealed, metadata.MessageID); err != nil {
			return err
		}
	}
	if onInitialWrite != nil {
		onInitialWrite()
	}
	if call == 1 {
		if stream.firstSend != nil {
			stream.firstSend <- struct{}{}
		}
		if stream.release != nil {
			<-stream.release
		}
		return networkFrameWork.ErrMessageMaxRetransmits
	}
	return nil
}

func (*billingRotationRecoveryStream) SendMessageAsync(
	context.Context,
	*network.Message,
	network.MessageResultCallback,
) error {
	return errors.New("unused")
}

func (*billingRotationRecoveryStream) NodeId() string       { return "peer" }
func (*billingRotationRecoveryStream) ConnectionId() string { return "billing-recovery" }
func (*billingRotationRecoveryStream) SetCryptoSuite(network.EncrypSuite) {
}

func (stream *billingRotationRecoveryStream) SetOutboundRecordObserver(observer network.OutboundRecordObserver) {
	stream.mu.Lock()
	stream.observer = observer
	stream.mu.Unlock()
}

func TestMaxRetransmitsRotatesBillingSessionAndRetriesWithoutClosingConnection(t *testing.T) {
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
	relayAddress := "relay-recovery:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	oldSessionID := billingvoucher.Identifier{61, 62, 63}
	newSessionID := billingvoucher.Identifier{71, 72, 73}
	if _, err := meter.activateRelaySession(relayAddress, oldSessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}

	stream := &billingRotationRecoveryStream{}
	resetCalls := 0
	var resetErr error
	connection := &serviceConnection{Connection: newNATConnection(
		p2pnode.PeerInfo{ID: "peer"}, stream, nil, meter,
		func() string { return relayAddress },
		func(string) {
			resetCalls++
			status, err := meter.activateRelaySessionWithState(
				relayAddress, oldSessionID.String(), relayPublicKey, &natBillingSnapshot{},
			)
			if err != nil {
				resetErr = err
				return
			}
			if !status.resetRequired {
				resetErr = errors.New("old session did not require rotation")
				return
			}
			_, resetErr = meter.activateRelaySessionWithState(
				relayAddress, newSessionID.String(), relayPublicKey, &natBillingSnapshot{},
			)
		},
	)}

	if err := connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("retry-after-rotation")}); err != nil {
		t.Fatalf("Send after recoverable retransmit exhaustion: %v", err)
	}
	if resetErr != nil {
		t.Fatal(resetErr)
	}
	if resetCalls != 1 {
		t.Fatalf("billing reset calls=%d, want 1", resetCalls)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.sendCalls != 2 {
		t.Fatalf("transport sends=%d, want failed old session plus successful retry", stream.sendCalls)
	}
	if stream.closeCalls != 0 {
		t.Fatalf("connection close calls=%d, want 0", stream.closeCalls)
	}
	if stream.sessions[0] != [32]byte(oldSessionID) || stream.sessions[1] != [32]byte(newSessionID) {
		t.Fatalf("billing sessions=%x then %x, want old then rotated", stream.sessions[0], stream.sessions[1])
	}
	if stream.sequences[0] != 1 || stream.sequences[1] != 1 {
		t.Fatalf("billing sequences=%v, want fresh sequence 1 after rotation", stream.sequences)
	}
}

func TestConcurrentMaxRetransmitsRecoverAfterOneBillingRotation(t *testing.T) {
	const connectionCount = 128
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
	relayAddress := "relay-concurrent-recovery:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	oldSessionID := billingvoucher.Identifier{81, 82, 83}
	newSessionID := billingvoucher.Identifier{91, 92, 93}
	if _, err := meter.activateRelaySession(relayAddress, oldSessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}

	firstSends := make(chan struct{}, connectionCount)
	release := make(chan struct{})
	streams := make([]*billingRotationRecoveryStream, 0, connectionCount)
	results := make(chan error, connectionCount)
	resetCalls := 0
	var resetErr error
	var resetMu sync.Mutex
	reset := func(string) {
		resetMu.Lock()
		defer resetMu.Unlock()
		resetCalls++
		status, err := meter.activateRelaySessionWithState(
			relayAddress, oldSessionID.String(), relayPublicKey, &natBillingSnapshot{},
		)
		if err != nil {
			resetErr = err
			return
		}
		if !status.resetRequired {
			resetErr = errors.New("old concurrent session did not require rotation")
			return
		}
		_, resetErr = meter.activateRelaySessionWithState(
			relayAddress, newSessionID.String(), relayPublicKey, &natBillingSnapshot{},
		)
	}
	for index := 0; index < connectionCount; index++ {
		stream := &billingRotationRecoveryStream{firstSend: firstSends, release: release}
		streams = append(streams, stream)
		connection := &serviceConnection{Connection: newNATConnection(
			p2pnode.PeerInfo{ID: p2pnode.NodeID("peer-concurrent")}, stream, nil, meter,
			func() string { return relayAddress }, reset,
		)}
		go func() {
			results <- connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("concurrent-retry")})
		}()
	}

	for entered := 0; entered < connectionCount; entered++ {
		select {
		case <-firstSends:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d/%d first sends became active", entered, connectionCount)
		}
	}
	diagnostics := meter.relayDiagnostics(relayAddress)
	if diagnostics.activeSends != connectionCount || diagnostics.nextAssigned != connectionCount+1 {
		t.Fatalf("pre-failure diagnostics=%+v", diagnostics)
	}
	close(release)
	for completed := 0; completed < connectionCount; completed++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("recovered send %d failed: %v", completed, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/%d sends recovered", completed, connectionCount)
		}
	}
	resetMu.Lock()
	defer resetMu.Unlock()
	if resetErr != nil {
		t.Fatal(resetErr)
	}
	if resetCalls != 1 {
		t.Fatalf("billing reset calls=%d, want 1", resetCalls)
	}
	for index, stream := range streams {
		stream.mu.Lock()
		if stream.sendCalls != 2 || stream.closeCalls != 0 {
			t.Fatalf("stream %d sends=%d closes=%d, want 2/0", index, stream.sendCalls, stream.closeCalls)
		}
		stream.mu.Unlock()
	}
	finalDiagnostics := meter.relayDiagnostics(relayAddress)
	if finalDiagnostics.sessionID != newSessionID || finalDiagnostics.invalid ||
		finalDiagnostics.activeSends != 0 || finalDiagnostics.nextAssigned != connectionCount+1 {
		t.Fatalf("post-recovery diagnostics=%+v", finalDiagnostics)
	}
}
