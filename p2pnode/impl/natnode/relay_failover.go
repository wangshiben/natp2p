package natnode

import (
	"errors"
	"sync"
)

const relayReconnectAttemptsPerAddress = 5

var errRelayCandidatesExhausted = errors.New("natnode: relay candidates exhausted")

type relayDialTarget struct {
	address    string
	generation uint64
}

type relayFailoverState struct {
	mu                  sync.Mutex
	candidates          []string
	current             int
	failures            int
	generation          uint64
	activatedGeneration uint64
	onActivated         func(string)
	changeSignal        chan struct{}
}

func newRelayFailoverState(initial string) *relayFailoverState {
	state := &relayFailoverState{generation: 1, activatedGeneration: 1, changeSignal: make(chan struct{})}
	state.setCandidates([]string{initial})
	return state
}

func (s *relayFailoverState) setCandidates(candidates []string) {
	unique := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		unique = append(unique, candidate)
	}

	s.mu.Lock()
	oldSignal := s.changeSignal
	s.changeSignal = make(chan struct{})
	s.candidates = unique
	s.current = 0
	s.failures = 0
	s.generation++
	s.activatedGeneration = s.generation
	if oldSignal != nil {
		close(oldSignal)
	}
	s.mu.Unlock()
}

func (s *relayFailoverState) currentTarget() (relayDialTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current >= len(s.candidates) {
		return relayDialTarget{}, errRelayCandidatesExhausted
	}
	return relayDialTarget{address: s.candidates[s.current], generation: s.generation}, nil
}

func (s *relayFailoverState) reportResult(target relayDialTarget, dialErr error) {
	var activated string
	s.mu.Lock()
	if target.generation != s.generation || s.current >= len(s.candidates) || s.candidates[s.current] != target.address {
		s.mu.Unlock()
		return
	}
	if dialErr == nil {
		s.failures = 0
		if s.activatedGeneration != s.generation {
			s.activatedGeneration = s.generation
			activated = target.address
		}
		s.mu.Unlock()
		if activated != "" && s.onActivated != nil {
			s.onActivated(activated)
		}
		return
	}

	s.failures++
	if s.failures >= relayReconnectAttemptsPerAddress {
		s.current++
		s.failures = 0
		s.generation++
		oldSignal := s.changeSignal
		s.changeSignal = make(chan struct{})
		close(oldSignal)
	}
	s.mu.Unlock()
}

func (s *relayFailoverState) relayChangeSignal() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changeSignal
}

func (s *relayFailoverState) snapshot() ([]string, int, int, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.candidates...), s.current, s.failures, s.generation
}
