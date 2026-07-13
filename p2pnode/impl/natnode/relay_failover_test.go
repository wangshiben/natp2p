package natnode

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRelayFailoverRetriesEachAddressFiveTimes(t *testing.T) {
	state := newRelayFailoverState("relay-a:9000")
	state.setCandidates([]string{"relay-a:9000", "relay-b:9000", "relay-c:9000"})

	for addressIndex, expected := range []string{"relay-a:9000", "relay-b:9000", "relay-c:9000"} {
		for attempt := 1; attempt <= relayReconnectAttemptsPerAddress; attempt++ {
			target, err := state.currentTarget()
			if err != nil || target.address != expected {
				t.Fatalf("address %d attempt %d: target=%+v err=%v", addressIndex, attempt, target, err)
			}
			state.reportResult(target, errors.New("dial failed"))
			if attempt < relayReconnectAttemptsPerAddress {
				current, currentErr := state.currentTarget()
				if currentErr != nil || current.address != expected {
					t.Fatalf("第 %d 次失败不应切换: target=%+v err=%v", attempt, current, currentErr)
				}
			}
		}
	}

	if _, err := state.currentTarget(); !errors.Is(err, errRelayCandidatesExhausted) {
		t.Fatalf("候选耗尽后应返回明确错误，实际 %v", err)
	}
}

func TestRelayFailoverSuccessResetsFailureCount(t *testing.T) {
	state := newRelayFailoverState("relay-a:9000")
	for attempt := 0; attempt < 4; attempt++ {
		target, _ := state.currentTarget()
		state.reportResult(target, errors.New("dial failed"))
	}
	target, _ := state.currentTarget()
	state.reportResult(target, nil)

	for attempt := 0; attempt < 4; attempt++ {
		target, err := state.currentTarget()
		if err != nil || target.address != "relay-a:9000" {
			t.Fatalf("成功后失败计数应重置: target=%+v err=%v", target, err)
		}
		state.reportResult(target, errors.New("dial failed"))
	}
}

func TestRelayFailoverConcurrentFailuresAdvanceOnlyOnce(t *testing.T) {
	state := newRelayFailoverState("relay-a:9000")
	state.setCandidates([]string{"relay-a:9000", "relay-b:9000", "relay-c:9000"})
	target, _ := state.currentTarget()

	var waitGroup sync.WaitGroup
	for attempt := 0; attempt < 20; attempt++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			state.reportResult(target, errors.New("dial failed"))
		}()
	}
	waitGroup.Wait()

	current, err := state.currentTarget()
	if err != nil || current.address != "relay-b:9000" {
		t.Fatalf("同一代并发失败只能推进一次: target=%+v err=%v", current, err)
	}
}

func TestRelayFailoverActivationCallbackRunsOnce(t *testing.T) {
	state := newRelayFailoverState("relay-a:9000")
	state.setCandidates([]string{"relay-a:9000", "relay-b:9000"})
	var activations atomic.Int32
	state.onActivated = func(address string) {
		if address != "relay-b:9000" {
			t.Errorf("unexpected activated relay %s", address)
		}
		activations.Add(1)
	}
	for attempt := 0; attempt < relayReconnectAttemptsPerAddress; attempt++ {
		target, _ := state.currentTarget()
		state.reportResult(target, errors.New("dial failed"))
	}
	target, _ := state.currentTarget()
	state.reportResult(target, nil)
	state.reportResult(target, nil)
	if activations.Load() != 1 {
		t.Fatalf("激活回调应只执行一次，实际 %d", activations.Load())
	}
}

func TestRelayFailoverSignalsGenerationChangeAfterFifthFailure(t *testing.T) {
	state := newRelayFailoverState("relay-a:9000")
	state.setCandidates([]string{"relay-a:9000", "relay-b:9000"})
	signal := state.relayChangeSignal()
	for attempt := 1; attempt <= relayReconnectAttemptsPerAddress; attempt++ {
		target, _ := state.currentTarget()
		state.reportResult(target, errors.New("dial failed"))
		select {
		case <-signal:
			if attempt != relayReconnectAttemptsPerAddress {
				t.Fatalf("第 %d 次失败时过早广播切换", attempt)
			}
		default:
			if attempt == relayReconnectAttemptsPerAddress {
				t.Fatal("第 5 次失败后没有广播切换")
			}
		}
	}
}
