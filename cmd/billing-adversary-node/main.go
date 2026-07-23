package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
)

const (
	schemaVersion         = 1
	defaultCreditBytes    = int64(64 << 30)
	maximumRequestBody    = 64 << 10
	peerRetryDelay        = 250 * time.Millisecond
	natBaselineAttempts   = 3
	relayBaselineAttempts = 3
	provisionTimeout      = 15 * time.Minute
)

var scenariosByRole = map[string][]string{
	"natserver": {
		"nat_stale_watermark",
		"nat_same_sequence_fork",
		"nat_signature_refusal",
		"nat_identity_forgery",
	},
	"relay": {
		"relay_usage_inflation",
		"relay_request_replay",
		"relay_fee_override",
		"relay_window_overrun",
		"relay_voucher_tamper",
	},
}

type configuration struct {
	role       string
	listen     string
	caURL      string
	peerURL    string
	stateDir   string
	seed       string
	interval   time.Duration
	runOnce    bool
	httpClient *http.Client
}

type attackerNode struct {
	config    configuration
	private   *ecdh.PrivateKey
	identity  identityWire
	caClient  *admission.CAClient
	http      *http.Client
	statusMu  sync.Mutex
	fixtureMu sync.Mutex
	snapshot  statusSnapshot
	random    *mathrand.Rand
	server    *http.Server
	ready     chan struct{}
	readyOnce sync.Once
}

type enrollmentRequest struct {
	SchemaVersion int            `json:"schemaVersion"`
	Role          admission.Role `json:"role"`
	PublicKey     string         `json:"publicKey"`
	NodeID        string         `json:"nodeID"`
}

type identityWire struct {
	Role      admission.Role       `json:"role"`
	PublicKey string               `json:"publicKey"`
	NodeID    string               `json:"nodeID"`
	Cert      admission.SignedCert `json:"cert"`
}

type signRequest struct {
	Scenario       string                     `json:"scenario"`
	Nonce          string                     `json:"nonce"`
	Body           billingvoucher.VoucherBody `json:"body"`
	RelaySignature []byte                     `json:"relaySignature"`
	RelayIdentity  identityWire               `json:"relayIdentity"`
}

type signResponse struct {
	PayerSignature []byte       `json:"payerSignature,omitempty"`
	PayerIdentity  identityWire `json:"payerIdentity,omitempty"`
	ErrorCode      string       `json:"errorCode,omitempty"`
}

type payerProposal struct {
	Body           billingvoucher.VoucherBody `json:"body"`
	PayerSignature []byte                     `json:"payerSignature"`
	PayerIdentity  identityWire               `json:"payerIdentity"`
}

type baselineResponse struct {
	CanonicalVoucher []byte `json:"canonicalVoucher,omitempty"`
	VoucherID        string `json:"voucherID,omitempty"`
	HTTPStatus       int    `json:"httpStatus"`
	Delta            int64  `json:"delta"`
	Replayed         bool   `json:"replayed,omitempty"`
	ErrorCode        string `json:"errorCode,omitempty"`
}

type evaluateRequest struct {
	Scenario          string        `json:"scenario"`
	Nonce             string        `json:"nonce"`
	BaselineCanonical []byte        `json:"baselineCanonical,omitempty"`
	Candidate         payerProposal `json:"candidate"`
}

type refusalRequest struct {
	Scenario string `json:"scenario"`
	Nonce    string `json:"nonce"`
}

type peerResult struct {
	Passed       bool   `json:"passed"`
	FailureCode  string `json:"failureCode,omitempty"`
	Defense      string `json:"defense,omitempty"`
	RequestCount int    `json:"requestCount"`
	HTTPStatuses []int  `json:"httpStatuses,omitempty"`
	BalanceDelta int64  `json:"balanceDelta"`
	StateChanged bool   `json:"stateChanged"`
}

type voucherHTTPResponse struct {
	Status int
	Body   admission.VoucherSettleResponse
}

type coverageCounter struct {
	Executed   int `json:"executed"`
	Contained  int `json:"contained"`
	Violations int `json:"violations"`
}

type statusSummary struct {
	ExecutedChecks    int `json:"executedChecks"`
	ContainedChecks   int `json:"containedChecks"`
	FailedChecks      int `json:"failedChecks"`
	CoveredScenarios  int `json:"coveredScenarios"`
	RequiredScenarios int `json:"requiredScenarios"`
}

type statusEvent struct {
	Sequence     uint64 `json:"sequence"`
	ObservedAt   string `json:"observedAt"`
	Scenario     string `json:"scenario"`
	Actor        string `json:"actor"`
	Passed       bool   `json:"passed"`
	Verdict      string `json:"verdict"`
	FailureCode  string `json:"failureCode,omitempty"`
	Defense      string `json:"defense,omitempty"`
	RequestCount int    `json:"requestCount"`
	HTTPStatuses []int  `json:"httpStatuses,omitempty"`
	BalanceDelta int64  `json:"balanceDelta"`
	StateChanged bool   `json:"stateChanged"`
	Path         string `json:"path"`
}

type statusSnapshot struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Status        string                     `json:"status"`
	Role          string                     `json:"role"`
	Mode          string                     `json:"mode"`
	HeartbeatAt   string                     `json:"heartbeatAt"`
	Sequence      uint64                     `json:"sequence"`
	SeedDigest    string                     `json:"seedDigest"`
	Coverage      map[string]coverageCounter `json:"coverage"`
	Summary       statusSummary              `json:"summary"`
	Recent        []statusEvent              `json:"recent"`
	Transport     []string                   `json:"transport"`
	Limitations   []string                   `json:"limitations"`
	LastError     string                     `json:"lastError,omitempty"`
}

func main() {
	config, err := parseConfiguration()
	if err != nil {
		log.Fatalf("billing adversary configuration: %v", err)
	}
	runContext, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	node, err := newAttackerNode(config)
	if err != nil {
		log.Fatalf("billing adversary startup: %v", err)
	}
	if err := node.run(runContext); err != nil && !errors.Is(err, context.Canceled) {
		node.fail("container_probe_runtime_failed")
		log.Fatalf("billing adversary runtime: %v", err)
	}
}

func parseConfiguration() (configuration, error) {
	role := flag.String("role", "", "natserver or relay")
	listen := flag.String("listen", ":9200", "peer protocol listen address")
	caURL := flag.String("ca", "http://ca:9100", "CA base URL")
	peerURL := flag.String("peer", "", "peer adversary base URL")
	stateDir := flag.String("state-dir", "/state", "private persistent state directory")
	seed := flag.String("seed", "bnfs-container-adversary-v1", "deterministic scheduling seed")
	interval := flag.Duration("interval", 15*time.Second, "random attack interval")
	runOnce := flag.Bool("once", false, "run initial coverage and exit")
	flag.Parse()

	config := configuration{
		role: *role, listen: *listen, caURL: strings.TrimRight(*caURL, "/"),
		peerURL: strings.TrimRight(*peerURL, "/"), stateDir: *stateDir,
		seed: *seed, interval: *interval, runOnce: *runOnce,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	if _, ok := scenariosByRole[config.role]; !ok {
		return configuration{}, errors.New("role must be natserver or relay")
	}
	if config.listen == "" || config.peerURL == "" || config.caURL == "" || config.seed == "" {
		return configuration{}, errors.New("listen, peer, CA and seed are required")
	}
	if config.interval < time.Second || config.interval > time.Hour {
		return configuration{}, errors.New("interval must be between 1s and 1h")
	}
	if err := validateHTTPServiceURL(config.caURL); err != nil {
		return configuration{}, fmt.Errorf("CA URL: %w", err)
	}
	if err := validateHTTPServiceURL(config.peerURL); err != nil {
		return configuration{}, fmt.Errorf("peer URL: %w", err)
	}
	if config.stateDir == "" || filepath.Clean(config.stateDir) == string(filepath.Separator) {
		return configuration{}, errors.New("invalid state directory")
	}
	return config, nil
}

func validateHTTPServiceURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must be a plain HTTP service URL without credentials, query or fragment")
	}
	return nil
}

func newAttackerNode(config configuration) (*attackerNode, error) {
	if err := os.MkdirAll(config.stateDir, 0o700); err != nil {
		return nil, err
	}
	privateKey, err := loadOrCreateIdentity(filepath.Join(config.stateDir, "identity.key"))
	if err != nil {
		return nil, err
	}
	nodeID, err := billingvoucher.NodeIDFromPublicKey(privateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	publicKey := hex.EncodeToString(privateKey.PublicKey().Bytes())
	role := admission.RoleServer
	if config.role == "relay" {
		role = admission.RoleRelay
	}
	enrollment := enrollmentRequest{
		SchemaVersion: schemaVersion,
		Role:          role,
		PublicKey:     publicKey,
		NodeID:        nodeID.String(),
	}
	if err := writeJSONAtomic(filepath.Join(config.stateDir, "enrollment.json"), enrollment); err != nil {
		return nil, err
	}

	seedHash := sha256.Sum256([]byte(config.seed + ":" + config.role))
	seedValue := int64(0)
	for _, value := range seedHash[:8] {
		seedValue = seedValue<<8 | int64(value)
	}
	coverage := make(map[string]coverageCounter)
	for _, scenario := range scenariosByRole[config.role] {
		coverage[scenario] = coverageCounter{}
	}
	node := &attackerNode{
		config:   config,
		private:  privateKey,
		caClient: admission.NewCAClient(config.caURL),
		http:     config.httpClient,
		random:   mathrand.New(mathrand.NewSource(seedValue)),
		ready:    make(chan struct{}),
		snapshot: statusSnapshot{
			SchemaVersion: schemaVersion,
			Status:        "STARTING",
			Role:          config.role,
			Mode:          "container_network_protocol",
			HeartbeatAt:   time.Now().UTC().Format(time.RFC3339Nano),
			SeedDigest:    hex.EncodeToString(seedHash[:8]),
			Coverage:      coverage,
			Summary:       statusSummary{RequiredScenarios: len(coverage)},
			Recent:        []statusEvent{},
			Transport:     []string{"container_http_peer", "container_http_ca"},
			Limitations: []string{
				"isolated_from_production_nat_and_relay_accounts",
				"does_not_instantiate_full_p2p_payload_socket",
				"nat_meter_uses_deterministic_attack_fixture",
			},
		},
	}
	_ = node.restoreSequence()
	return node, nil
}

func (node *attackerNode) run(context context.Context) error {
	if err := node.startServer(); err != nil {
		return err
	}
	defer node.stopServer()
	if err := node.publish(); err != nil {
		return err
	}

	identity, err := node.waitForProvisioning(context)
	if err != nil {
		return err
	}
	node.identity = identity
	node.readyOnce.Do(func() { close(node.ready) })

	for _, scenario := range deterministicInitialOrder(scenariosByRole[node.config.role], node.random) {
		if err := node.execute(context, scenario); err != nil {
			return err
		}
	}
	if node.config.runOnce {
		node.statusMu.Lock()
		if node.snapshot.Status != "FAILED" {
			node.snapshot.Status = "STOPPED"
		}
		node.statusMu.Unlock()
		return node.publish()
	}

	attackTicker := time.NewTicker(node.config.interval)
	heartbeatTicker := time.NewTicker(2 * time.Second)
	defer attackTicker.Stop()
	defer heartbeatTicker.Stop()
	for {
		select {
		case <-context.Done():
			node.statusMu.Lock()
			if node.snapshot.Status != "FAILED" {
				node.snapshot.Status = "STOPPED"
			}
			node.statusMu.Unlock()
			_ = node.publish()
			return context.Err()
		case <-heartbeatTicker.C:
			if err := node.publish(); err != nil {
				return err
			}
		case <-attackTicker.C:
			scenarios := scenariosByRole[node.config.role]
			if err := node.execute(context, scenarios[node.random.Intn(len(scenarios))]); err != nil {
				return err
			}
		}
	}
}

func (node *attackerNode) startServer() error {
	listener, err := net.Listen("tcp", node.config.listen)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", node.handleHealth)
	mux.HandleFunc("/identity", node.handleIdentity)
	if node.config.role == "natserver" {
		mux.HandleFunc("/nat/sign", node.handleNatSign)
	} else {
		mux.HandleFunc("/relay/baseline", node.serializeRelayFixture(node.handleRelayBaseline))
		mux.HandleFunc("/relay/evaluate", node.serializeRelayFixture(node.handleRelayEvaluate))
		mux.HandleFunc("/relay/refusal", node.serializeRelayFixture(node.handleRelayRefusal))
	}
	node.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	go func() {
		if err := node.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("peer protocol server failed: %v", err)
		}
	}()
	return nil
}

func (node *attackerNode) stopServer() {
	if node.server == nil {
		return
	}
	context, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = node.server.Shutdown(context)
}

func (node *attackerNode) waitForProvisioning(context context.Context) (identityWire, error) {
	deadline := time.Now().Add(provisionTimeout)
	certPath := filepath.Join(node.config.stateDir, "certificate.json")
	for {
		if err := context.Err(); err != nil {
			return identityWire{}, err
		}
		if time.Now().After(deadline) {
			return identityWire{}, errors.New("provisioned certificate was not supplied")
		}
		if err := node.caClient.RefreshPubKey(context); err == nil {
			var certificate admission.SignedCert
			if err := readJSONFile(certPath, &certificate); err == nil {
				nodeID, _ := billingvoucher.NodeIDFromPublicKey(node.private.PublicKey())
				role := admission.RoleServer
				if node.config.role == "relay" {
					role = admission.RoleRelay
				}
				if err := node.caClient.Verify(&certificate, admission.VerifyOptions{
					ExpectNodeID: nodeID.String(), ExpectRole: role,
				}); err == nil && certificate.Cert.SubjectPubKey == hex.EncodeToString(node.private.PublicKey().Bytes()) {
					identity := identityWire{
						Role:      role,
						PublicKey: certificate.Cert.SubjectPubKey,
						NodeID:    nodeID.String(),
						Cert:      certificate,
					}
					if node.config.role != "natserver" {
						return identity, nil
					}
					balance, _, balanceErr := node.balance(context, identity.NodeID)
					if balanceErr == nil && balance >= defaultCreditBytes {
						return identity, nil
					}
				}
			}
		}
		if err := sleepContext(context, peerRetryDelay); err != nil {
			return identityWire{}, err
		}
	}
}

func (node *attackerNode) execute(context context.Context, scenario string) error {
	releaseFixture := node.lockRelayFixture()
	defer releaseFixture()

	node.statusMu.Lock()
	node.snapshot.Sequence++
	sequence := node.snapshot.Sequence
	node.statusMu.Unlock()
	nonce := fmt.Sprintf("%s-%d", node.config.role, sequence)
	var event statusEvent
	if node.config.role == "relay" {
		event = node.runRelayScenario(context, scenario, nonce)
	} else {
		event = node.runNatScenario(context, scenario, nonce)
	}
	event.Sequence = sequence
	event.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	event.Scenario = scenario
	event.Actor = node.config.role
	if event.Passed {
		event.Verdict = "CONTAINED"
	} else {
		event.Verdict = "VIOLATION"
		if event.FailureCode == "" {
			event.FailureCode = "container_attack_not_contained"
		}
	}
	if event.Path == "" {
		event.Path = "container_peer_protocol"
	}
	node.record(event)
	return node.publish()
}

func (node *attackerNode) lockRelayFixture() func() {
	if node.config.role != "relay" {
		return func() {}
	}
	node.fixtureMu.Lock()
	return node.fixtureMu.Unlock
}

func (node *attackerNode) serializeRelayFixture(handler http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		releaseFixture := node.lockRelayFixture()
		defer releaseFixture()
		handler(writer, request)
	}
}

func (node *attackerNode) runRelayScenario(context context.Context, scenario, nonce string) statusEvent {
	peer, err := node.fetchPeerIdentity(context, admission.RoleServer)
	if err != nil {
		return failedEvent("malicious_nat_peer_unavailable")
	}
	switch scenario {
	case "relay_usage_inflation":
		honest := fixtureBody(nonce, peer.nodeIdentifier(), node.identity.nodeIdentifier(), 1, 512<<10, billingvoucher.Identifier{}, "main")
		candidate := honest
		candidate.CumulativeUniqueBytes += 64 << 10
		candidate.LastRecordID = identifier(nonce + ":inflated-record")
		candidate.RecordSetDigest = digest(nonce + ":inflated-root")
		return node.expectNatRefusal(context, scenario, nonce, candidate, peer, "nat_meter_rejected_usage_inflation")
	case "relay_fee_override":
		candidate := fixtureBody(nonce, peer.nodeIdentifier(), node.identity.nodeIdentifier(), 1, 512<<10, billingvoucher.Identifier{}, "main")
		candidate.PolicyDigest[0] ^= 1
		return node.expectNatRefusal(context, scenario, nonce, candidate, peer, "nat_rejected_policy_override")
	case "relay_window_overrun":
		candidate := fixtureBody(nonce, peer.nodeIdentifier(), node.identity.nodeIdentifier(), 1, billingvoucher.CumulativeWindowBytes+1, billingvoucher.Identifier{}, "overrun")
		valid := fixtureBody(nonce+"-signature", peer.nodeIdentifier(), node.identity.nodeIdentifier(), 1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, "valid")
		relaySignature, err := billingvoucher.SignRelay(valid, node.private)
		if err != nil {
			return failedEvent("relay_signature_fixture_failed")
		}
		request := signRequest{Scenario: scenario, Nonce: nonce, Body: candidate, RelaySignature: relaySignature, RelayIdentity: node.identity}
		var response signResponse
		status, err := node.postPeer(context, "/nat/sign", request, &response)
		if err != nil {
			return failedEvent("nat_sign_protocol_unavailable")
		}
		if status != http.StatusConflict || response.ErrorCode != "voucher_body_invalid" {
			return failedEventWithStatus("one_mib_window_overrun_not_rejected", status)
		}
		return containedEvent("nat_rejected_one_mib_window_overrun", 1, []int{status}, "malicious-relay->malicious-natserver")
	case "relay_request_replay":
		return node.runReplay(context, scenario, nonce, peer)
	case "relay_voucher_tamper":
		return node.runTamper(context, scenario, nonce, peer)
	default:
		return failedEvent("unknown_relay_container_scenario")
	}
}

func (node *attackerNode) expectNatRefusal(context context.Context, scenario, nonce string, body billingvoucher.VoucherBody, payer identityWire, defense string) statusEvent {
	relaySignature, err := billingvoucher.SignRelay(body, node.private)
	if err != nil {
		return failedEvent("relay_attack_signature_failed")
	}
	before, _, err := node.balance(context, payer.NodeID)
	if err != nil {
		return failedEvent("payer_balance_unavailable")
	}
	request := signRequest{Scenario: scenario, Nonce: nonce, Body: body, RelaySignature: relaySignature, RelayIdentity: node.identity}
	var response signResponse
	status, err := node.postPeer(context, "/nat/sign", request, &response)
	if err != nil {
		return failedEvent("nat_sign_protocol_unavailable")
	}
	after, _, err := node.balance(context, payer.NodeID)
	if err != nil {
		return failedEvent("payer_balance_unavailable")
	}
	delta := before - after
	if status != http.StatusConflict || response.ErrorCode == "" || delta != 0 {
		return statusEvent{Passed: false, FailureCode: "malicious_relay_claim_not_contained", RequestCount: 1, HTTPStatuses: []int{status}, BalanceDelta: delta, StateChanged: delta != 0}
	}
	return containedEvent(defense, 1, []int{status}, "malicious-relay->malicious-natserver")
}

func (node *attackerNode) runReplay(context context.Context, scenario, nonce string, payer identityWire) statusEvent {
	body := fixtureBody(nonce, payer.nodeIdentifier(), node.identity.nodeIdentifier(), 1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, "main")
	voucher, signStatus, err := node.requestMutualVoucher(context, scenario, nonce, body, payer)
	if err != nil {
		return failedEventWithStatus("mutual_voucher_handshake_failed", signStatus)
	}
	request, err := node.voucherRequest(voucher, payer, node.identity)
	if err != nil {
		return failedEvent("voucher_request_build_failed")
	}
	_, baselineStatuses, baselineRequests, err := node.establishRelayReplayBaseline(
		context, request, int64(billingvoucher.CumulativeWindowBytes),
	)
	if err != nil {
		event := failedEvent("valid_voucher_rejected")
		if errors.Is(err, errRelayReplayBaselineUnavailable) {
			event.FailureCode = "relay_replay_baseline_unavailable"
		}
		event.RequestCount = 1 + baselineRequests
		event.HTTPStatuses = append([]int{signStatus}, baselineStatuses...)
		return event
	}
	before, _, err := node.balance(context, payer.NodeID)
	if err != nil {
		return failedEvent("payer_balance_unavailable")
	}
	replay, err := node.submitVoucher(context, request)
	if err != nil {
		event := failedEvent("voucher_replay_request_failed")
		event.RequestCount = 2 + baselineRequests
		event.HTTPStatuses = append([]int{signStatus}, baselineStatuses...)
		return event
	}
	after, _, err := node.balance(context, payer.NodeID)
	if err != nil {
		return failedEvent("payer_balance_unavailable")
	}
	delta := before - after
	statuses := append([]int{signStatus}, baselineStatuses...)
	statuses = append(statuses, replay.Status)
	if replay.Status != http.StatusOK || replay.Body.Delta != 0 || !replay.Body.Replayed || delta != 0 {
		return statusEvent{Passed: false, FailureCode: "duplicate_deduction_detected", RequestCount: 2 + baselineRequests, HTTPStatuses: statuses, BalanceDelta: delta, StateChanged: delta != 0}
	}
	return containedEvent("ca_idempotent_replay", 2+baselineRequests, statuses, "malicious-relay->malicious-natserver->ca")
}

var errRelayReplayBaselineUnavailable = errors.New("Relay replay baseline unavailable")

func (node *attackerNode) establishRelayReplayBaseline(
	context context.Context,
	request admission.VoucherSettleRequest,
	expectedDelta int64,
) (voucherHTTPResponse, []int, int, error) {
	statuses := make([]int, 0, relayBaselineAttempts)
	for attempt := 1; attempt <= relayBaselineAttempts; attempt++ {
		response, err := node.submitVoucher(context, request)
		if response.Status >= 100 && response.Status <= 599 {
			statuses = append(statuses, response.Status)
		}
		if err == nil && response.Status == http.StatusOK &&
			(response.Body.Delta == expectedDelta || (response.Body.Delta == 0 && response.Body.Replayed)) {
			return response, statuses, attempt, nil
		}
		if !retryableRelayReplayBaseline(response.Status, err) {
			return voucherHTTPResponse{}, statuses, attempt, errors.New("Relay replay baseline rejected")
		}
		if attempt == relayBaselineAttempts {
			return voucherHTTPResponse{}, statuses, attempt, errRelayReplayBaselineUnavailable
		}
		if node.config.stateDir != "" {
			if publishErr := node.publish(); publishErr != nil {
				return voucherHTTPResponse{}, statuses, attempt, publishErr
			}
		}
		if err := sleepContext(context, peerRetryDelay); err != nil {
			return voucherHTTPResponse{}, statuses, attempt, err
		}
	}
	return voucherHTTPResponse{}, statuses, relayBaselineAttempts, errRelayReplayBaselineUnavailable
}

func retryableRelayReplayBaseline(status int, err error) bool {
	if status == 0 {
		return err != nil
	}
	return status >= http.StatusInternalServerError
}

func (node *attackerNode) runTamper(context context.Context, scenario, nonce string, payer identityWire) statusEvent {
	honest := fixtureBody(nonce, payer.nodeIdentifier(), node.identity.nodeIdentifier(), 1, 512<<10, billingvoucher.Identifier{}, "main")
	voucher, signStatus, err := node.requestMutualVoucher(context, scenario, nonce, honest, payer)
	if err != nil {
		return failedEventWithStatus("mutual_voucher_handshake_failed", signStatus)
	}
	tampered := voucher.Body
	tampered.LastRecordID[0] ^= 1
	tampered.RecordSetDigest[0] ^= 1
	relaySignature, err := billingvoucher.SignRelay(tampered, node.private)
	if err != nil {
		return failedEvent("tampered_relay_signature_failed")
	}
	malicious, err := billingvoucher.NewMutualVoucher(tampered, voucher.PayerSignature, relaySignature)
	if err != nil {
		return failedEvent("tampered_voucher_assembly_failed")
	}
	request, err := node.voucherRequest(malicious, payer, node.identity)
	if err != nil {
		return failedEvent("voucher_request_build_failed")
	}
	before, _, err := node.balance(context, payer.NodeID)
	if err != nil {
		return failedEvent("payer_balance_unavailable")
	}
	response, err := node.submitVoucher(context, request)
	if err != nil {
		return failedEvent("tampered_voucher_request_failed")
	}
	after, _, err := node.balance(context, payer.NodeID)
	if err != nil {
		return failedEvent("payer_balance_unavailable")
	}
	delta := before - after
	statuses := []int{signStatus, response.Status}
	if response.Status < 400 || response.Status >= 500 || delta != 0 {
		return statusEvent{Passed: false, FailureCode: "tampered_voucher_accepted", RequestCount: 2, HTTPStatuses: statuses, BalanceDelta: delta, StateChanged: delta != 0}
	}
	return containedEvent("ca_rejected_tampered_double_signature", 2, statuses, "malicious-relay->malicious-natserver->ca")
}

func (node *attackerNode) requestMutualVoucher(context context.Context, scenario, nonce string, body billingvoucher.VoucherBody, payer identityWire) (billingvoucher.MutualVoucher, int, error) {
	relaySignature, err := billingvoucher.SignRelay(body, node.private)
	if err != nil {
		return billingvoucher.MutualVoucher{}, 0, err
	}
	request := signRequest{Scenario: scenario, Nonce: nonce, Body: body, RelaySignature: relaySignature, RelayIdentity: node.identity}
	var response signResponse
	status, err := node.postPeer(context, "/nat/sign", request, &response)
	if err != nil || status != http.StatusOK || response.PayerIdentity.NodeID != payer.NodeID {
		return billingvoucher.MutualVoucher{}, status, errors.New("Nat co-sign failed")
	}
	voucher, err := billingvoucher.NewMutualVoucher(body, response.PayerSignature, relaySignature)
	if err != nil {
		return billingvoucher.MutualVoucher{}, status, err
	}
	if err := voucher.Verify(payer.public(), node.private.PublicKey()); err != nil {
		return billingvoucher.MutualVoucher{}, status, err
	}
	return voucher, status, nil
}

func (node *attackerNode) runNatScenario(context context.Context, scenario, nonce string) statusEvent {
	peer, err := node.fetchPeerIdentity(context, admission.RoleRelay)
	if err != nil {
		return failedEvent("malicious_relay_peer_unavailable")
	}
	switch scenario {
	case "nat_stale_watermark", "nat_same_sequence_fork":
		return node.runNatChainAttack(context, scenario, nonce, peer)
	case "nat_signature_refusal":
		var result peerResult
		status, err := node.postPeer(context, "/relay/refusal", refusalRequest{Scenario: scenario, Nonce: nonce}, &result)
		if err != nil {
			return failedEvent("relay_refusal_probe_unavailable")
		}
		return eventFromPeerResult(status, result, "malicious-natserver->malicious-relay->malicious-natserver")
	case "nat_identity_forgery":
		return node.runIdentityForgery(context, scenario, nonce, peer)
	default:
		return failedEvent("unknown_nat_container_scenario")
	}
}

func (node *attackerNode) runNatChainAttack(context context.Context, scenario, nonce string, relay identityWire) statusEvent {
	baselineBytes := uint64(512 << 10)
	if scenario == "nat_stale_watermark" {
		baselineBytes = 768 << 10
	}
	baselineBody := fixtureBody(nonce, node.identity.nodeIdentifier(), relay.nodeIdentifier(), 1, baselineBytes, billingvoucher.Identifier{}, "baseline")
	payerSignature, err := billingvoucher.SignPayer(baselineBody, node.private)
	if err != nil {
		return failedEvent("nat_baseline_signature_failed")
	}
	proposal := payerProposal{Body: baselineBody, PayerSignature: payerSignature, PayerIdentity: node.identity}
	baseline, baselineStatuses, baselineRequests, err := node.establishNatAttackBaseline(context, proposal, int64(baselineBytes))
	if err != nil {
		event := failedEvent("nat_attack_baseline_rejected")
		if errors.Is(err, errNatAttackBaselineUnavailable) {
			event.FailureCode = "nat_attack_baseline_unavailable"
		}
		event.RequestCount = baselineRequests
		event.HTTPStatuses = baselineStatuses
		return event
	}
	baselineID, err := billingvoucher.ParseIdentifierHex(baseline.VoucherID)
	if err != nil {
		return failedEvent("baseline_voucher_id_invalid")
	}
	var candidateBody billingvoucher.VoucherBody
	if scenario == "nat_stale_watermark" {
		candidateBody = fixtureBody(nonce, node.identity.nodeIdentifier(), relay.nodeIdentifier(), 2, baselineBytes, baselineID, "stale")
	} else {
		candidateBody = fixtureBody(nonce, node.identity.nodeIdentifier(), relay.nodeIdentifier(), 1, 640<<10, billingvoucher.Identifier{}, "fork")
	}
	candidateSignature, err := billingvoucher.SignPayer(candidateBody, node.private)
	if err != nil {
		return failedEvent("nat_candidate_signature_failed")
	}
	request := evaluateRequest{
		Scenario:          scenario,
		Nonce:             nonce,
		BaselineCanonical: baseline.CanonicalVoucher,
		Candidate:         payerProposal{Body: candidateBody, PayerSignature: candidateSignature, PayerIdentity: node.identity},
	}
	var result peerResult
	status, err := node.postPeer(context, "/relay/evaluate", request, &result)
	if err != nil {
		return failedEvent("relay_chain_probe_unavailable")
	}
	event := eventFromPeerResult(status, result, "malicious-natserver->malicious-relay->ca")
	event.RequestCount += baselineRequests
	event.HTTPStatuses = append(baselineStatuses, event.HTTPStatuses...)
	return event
}

var errNatAttackBaselineUnavailable = errors.New("Nat attack baseline unavailable")

func (node *attackerNode) establishNatAttackBaseline(
	context context.Context,
	proposal payerProposal,
	expectedDelta int64,
) (baselineResponse, []int, int, error) {
	statuses := make([]int, 0, 2*natBaselineAttempts)
	for attempt := 1; attempt <= natBaselineAttempts; attempt++ {
		var baseline baselineResponse
		peerStatus, err := node.postPeer(context, "/relay/baseline", proposal, &baseline)
		if peerStatus >= 100 && peerStatus <= 599 {
			statuses = append(statuses, peerStatus)
		}
		if err == nil && baseline.HTTPStatus >= 100 && baseline.HTTPStatus <= 599 {
			statuses = append(statuses, baseline.HTTPStatus)
		}
		if err == nil && peerStatus == http.StatusOK && baseline.HTTPStatus == http.StatusOK &&
			(baseline.Delta == expectedDelta || (baseline.Delta == 0 && baseline.Replayed)) {
			return baseline, statuses, attempt, nil
		}
		if !retryableNatAttackBaseline(peerStatus, baseline.HTTPStatus, err) {
			return baselineResponse{}, statuses, attempt, errors.New("Nat attack baseline rejected")
		}
		if attempt == natBaselineAttempts {
			return baselineResponse{}, statuses, attempt, errNatAttackBaselineUnavailable
		}
		if node.config.stateDir != "" {
			if publishErr := node.publish(); publishErr != nil {
				return baselineResponse{}, statuses, attempt, publishErr
			}
		}
		if err := sleepContext(context, peerRetryDelay); err != nil {
			return baselineResponse{}, statuses, attempt, err
		}
	}
	return baselineResponse{}, statuses, natBaselineAttempts, errNatAttackBaselineUnavailable
}

func retryableNatAttackBaseline(peerStatus, caStatus int, err error) bool {
	if err != nil {
		return true
	}
	if peerStatus == http.StatusBadGateway || peerStatus == http.StatusServiceUnavailable || peerStatus == http.StatusGatewayTimeout {
		return true
	}
	return peerStatus == http.StatusOK && caStatus >= http.StatusInternalServerError
}

func (node *attackerNode) runIdentityForgery(context context.Context, scenario, nonce string, relay identityWire) statusEvent {
	rogue, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return failedEvent("rogue_identity_generation_failed")
	}
	rogueID, err := billingvoucher.NodeIDFromPublicKey(rogue.PublicKey())
	if err != nil {
		return failedEvent("rogue_identity_generation_failed")
	}
	body := fixtureBody(nonce, rogueID, relay.nodeIdentifier(), 1, 512<<10, billingvoucher.Identifier{}, "forged")
	signature, err := billingvoucher.SignPayer(body, rogue)
	if err != nil {
		return failedEvent("rogue_identity_signature_failed")
	}
	forgedIdentity := node.identity
	forgedIdentity.PublicKey = hex.EncodeToString(rogue.PublicKey().Bytes())
	forgedIdentity.NodeID = rogueID.String()
	request := evaluateRequest{
		Scenario:  scenario,
		Nonce:     nonce,
		Candidate: payerProposal{Body: body, PayerSignature: signature, PayerIdentity: forgedIdentity},
	}
	var result peerResult
	status, err := node.postPeer(context, "/relay/evaluate", request, &result)
	if err != nil {
		return failedEvent("relay_identity_probe_unavailable")
	}
	return eventFromPeerResult(status, result, "malicious-natserver->malicious-relay")
}

func (node *attackerNode) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := "starting"
	select {
	case <-node.ready:
		status = "ready"
	default:
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": status})
}

func (node *attackerNode) handleIdentity(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	select {
	case <-node.ready:
		writeJSON(writer, http.StatusOK, node.identity)
	default:
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"errorCode": "not_provisioned"})
	}
}

func (node *attackerNode) handleNatSign(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input signRequest
	if err := decodeRequest(request, &input); err != nil {
		writeJSON(writer, http.StatusBadRequest, signResponse{ErrorCode: "request_invalid"})
		return
	}
	if input.Scenario == "nat_signature_refusal" {
		writeJSON(writer, http.StatusConflict, signResponse{ErrorCode: "nat_signature_refused"})
		return
	}
	if !contains(scenariosByRole["relay"], input.Scenario) || !safeNonce(input.Nonce) {
		writeJSON(writer, http.StatusBadRequest, signResponse{ErrorCode: "scenario_invalid"})
		return
	}
	if err := input.Body.Validate(); err != nil {
		writeJSON(writer, http.StatusConflict, signResponse{ErrorCode: "voucher_body_invalid"})
		return
	}
	if err := node.verifyPeerIdentity(input.RelayIdentity, admission.RoleRelay, input.Body.PayeeRelayID); err != nil {
		writeJSON(writer, http.StatusForbidden, signResponse{ErrorCode: "relay_identity_invalid"})
		return
	}
	if err := billingvoucher.VerifyRelaySignature(input.Body, input.RelaySignature, input.RelayIdentity.public()); err != nil {
		writeJSON(writer, http.StatusForbidden, signResponse{ErrorCode: "relay_signature_invalid"})
		return
	}
	expectedBytes := uint64(512 << 10)
	if input.Scenario == "relay_request_replay" {
		expectedBytes = billingvoucher.CumulativeWindowBytes
	}
	expected := fixtureBody(input.Nonce, node.identity.nodeIdentifier(), input.RelayIdentity.nodeIdentifier(), 1, expectedBytes, billingvoucher.Identifier{}, "main")
	if input.Body != expected {
		writeJSON(writer, http.StatusConflict, signResponse{ErrorCode: "nat_meter_mismatch"})
		return
	}
	signature, err := billingvoucher.SignPayer(input.Body, node.private)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, signResponse{ErrorCode: "payer_signature_failed"})
		return
	}
	writeJSON(writer, http.StatusOK, signResponse{PayerSignature: signature, PayerIdentity: node.identity})
}

func (node *attackerNode) handleRelayBaseline(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var proposal payerProposal
	if err := decodeRequest(request, &proposal); err != nil {
		writeJSON(writer, http.StatusBadRequest, baselineResponse{ErrorCode: "request_invalid"})
		return
	}
	if err := node.verifyPayerProposal(proposal); err != nil {
		writeJSON(writer, http.StatusForbidden, baselineResponse{ErrorCode: "payer_proposal_invalid"})
		return
	}
	relaySignature, err := billingvoucher.SignRelay(proposal.Body, node.private)
	if err != nil {
		writeJSON(writer, http.StatusConflict, baselineResponse{ErrorCode: "relay_signature_refused"})
		return
	}
	voucher, err := billingvoucher.NewMutualVoucher(proposal.Body, proposal.PayerSignature, relaySignature)
	if err != nil {
		writeJSON(writer, http.StatusConflict, baselineResponse{ErrorCode: "voucher_invalid"})
		return
	}
	settleRequest, err := node.voucherRequest(voucher, proposal.PayerIdentity, node.identity)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, baselineResponse{ErrorCode: "voucher_request_failed"})
		return
	}
	settled, err := node.submitVoucher(request.Context(), settleRequest)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, baselineResponse{ErrorCode: "ca_unavailable"})
		return
	}
	canonical, _ := voucher.CanonicalBytes()
	voucherID, _ := voucher.ID()
	writeJSON(writer, http.StatusOK, baselineResponse{
		CanonicalVoucher: canonical,
		VoucherID:        voucherID.String(),
		HTTPStatus:       settled.Status,
		Delta:            settled.Body.Delta,
		Replayed:         settled.Body.Replayed,
	})
}

func (node *attackerNode) handleRelayEvaluate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input evaluateRequest
	if err := decodeRequest(request, &input); err != nil || !safeNonce(input.Nonce) {
		writeJSON(writer, http.StatusBadRequest, peerResult{Passed: false, FailureCode: "request_invalid"})
		return
	}
	if input.Scenario == "nat_identity_forgery" {
		err := node.verifyPayerProposal(input.Candidate)
		if err == nil {
			writeJSON(writer, http.StatusOK, peerResult{Passed: false, FailureCode: "forged_identity_accepted", StateChanged: false})
			return
		}
		writeJSON(writer, http.StatusOK, peerResult{Passed: true, Defense: "relay_rejected_forged_nat_identity", RequestCount: 1})
		return
	}
	if input.Scenario != "nat_stale_watermark" && input.Scenario != "nat_same_sequence_fork" {
		writeJSON(writer, http.StatusBadRequest, peerResult{Passed: false, FailureCode: "scenario_invalid"})
		return
	}
	baseline, err := billingvoucher.ParseCanonicalVoucher(input.BaselineCanonical)
	if err != nil || baseline.Body.PayeeRelayID != node.identity.nodeIdentifier() {
		writeJSON(writer, http.StatusBadRequest, peerResult{Passed: false, FailureCode: "baseline_invalid"})
		return
	}
	if err := baseline.Verify(input.Candidate.PayerIdentity.public(), node.private.PublicKey()); err != nil {
		writeJSON(writer, http.StatusForbidden, peerResult{Passed: false, FailureCode: "baseline_signature_invalid"})
		return
	}
	if err := node.verifyPayerProposal(input.Candidate); err != nil {
		writeJSON(writer, http.StatusForbidden, peerResult{Passed: false, FailureCode: "candidate_identity_invalid"})
		return
	}
	before, _, err := node.balance(request.Context(), input.Candidate.PayerIdentity.NodeID)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, peerResult{Passed: false, FailureCode: "payer_balance_unavailable"})
		return
	}
	relaySignature, err := billingvoucher.SignRelay(input.Candidate.Body, node.private)
	if err != nil {
		writeJSON(writer, http.StatusOK, peerResult{Passed: true, Defense: "relay_rejected_invalid_nat_candidate", RequestCount: 1})
		return
	}
	candidate, err := billingvoucher.NewMutualVoucher(input.Candidate.Body, input.Candidate.PayerSignature, relaySignature)
	if err != nil {
		writeJSON(writer, http.StatusOK, peerResult{Passed: true, Defense: "relay_rejected_invalid_nat_candidate", RequestCount: 1})
		return
	}
	chainErr := billingvoucher.ValidateSuccessor(baseline, candidate)
	after, _, balanceErr := node.balance(request.Context(), input.Candidate.PayerIdentity.NodeID)
	if balanceErr != nil {
		writeJSON(writer, http.StatusBadGateway, peerResult{Passed: false, FailureCode: "payer_balance_unavailable"})
		return
	}
	delta := before - after
	if chainErr == nil || delta != 0 {
		writeJSON(writer, http.StatusOK, peerResult{Passed: false, FailureCode: "malicious_nat_chain_accepted", RequestCount: 1, BalanceDelta: delta, StateChanged: delta != 0})
		return
	}
	defense := "relay_rejected_stale_nat_watermark"
	if input.Scenario == "nat_same_sequence_fork" {
		defense = "relay_rejected_same_sequence_fork"
	}
	writeJSON(writer, http.StatusOK, peerResult{Passed: true, Defense: defense, RequestCount: 1})
}

func (node *attackerNode) handleRelayRefusal(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input refusalRequest
	if err := decodeRequest(request, &input); err != nil || input.Scenario != "nat_signature_refusal" || !safeNonce(input.Nonce) {
		writeJSON(writer, http.StatusBadRequest, peerResult{Passed: false, FailureCode: "request_invalid"})
		return
	}
	payer, err := node.fetchPeerIdentity(request.Context(), admission.RoleServer)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, peerResult{Passed: false, FailureCode: "nat_peer_unavailable"})
		return
	}
	body := fixtureBody(input.Nonce, payer.nodeIdentifier(), node.identity.nodeIdentifier(), 1, 512<<10, billingvoucher.Identifier{}, "main")
	relaySignature, err := billingvoucher.SignRelay(body, node.private)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, peerResult{Passed: false, FailureCode: "relay_signature_failed"})
		return
	}
	before, _, err := node.balance(request.Context(), payer.NodeID)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, peerResult{Passed: false, FailureCode: "payer_balance_unavailable"})
		return
	}
	var response signResponse
	status, err := node.postPeer(request.Context(), "/nat/sign", signRequest{
		Scenario: input.Scenario, Nonce: input.Nonce, Body: body,
		RelaySignature: relaySignature, RelayIdentity: node.identity,
	}, &response)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, peerResult{Passed: false, FailureCode: "nat_refusal_protocol_unavailable"})
		return
	}
	after, _, err := node.balance(request.Context(), payer.NodeID)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, peerResult{Passed: false, FailureCode: "payer_balance_unavailable"})
		return
	}
	delta := before - after
	if status != http.StatusConflict || response.ErrorCode != "nat_signature_refused" || delta != 0 {
		writeJSON(writer, http.StatusOK, peerResult{Passed: false, FailureCode: "nat_refusal_bypassed", RequestCount: 1, HTTPStatuses: []int{status}, BalanceDelta: delta, StateChanged: delta != 0})
		return
	}
	writeJSON(writer, http.StatusOK, peerResult{Passed: true, Defense: "relay_never_submitted_unsigned_bill", RequestCount: 1, HTTPStatuses: []int{status}})
}

func (node *attackerNode) verifyPayerProposal(proposal payerProposal) error {
	if err := proposal.Body.Validate(); err != nil {
		return err
	}
	if proposal.Body.PayeeRelayID != node.identity.nodeIdentifier() {
		return errors.New("proposal targets another Relay")
	}
	if err := node.verifyPeerIdentity(proposal.PayerIdentity, admission.RoleServer, proposal.Body.PayerNatID); err != nil {
		return err
	}
	return billingvoucher.VerifyPayerSignature(proposal.Body, proposal.PayerSignature, proposal.PayerIdentity.public())
}

func (node *attackerNode) verifyPeerIdentity(identity identityWire, role admission.Role, expected billingvoucher.Identifier) error {
	if identity.Role != role || identity.NodeID != expected.String() || identity.Cert.Cert.SubjectPubKey != identity.PublicKey {
		return errors.New("peer identity binding mismatch")
	}
	public := identity.public()
	if public == nil {
		return errors.New("peer public key invalid")
	}
	derived, err := billingvoucher.NodeIDFromPublicKey(public)
	if err != nil || derived != expected {
		return errors.New("peer node ID mismatch")
	}
	return node.caClient.Verify(&identity.Cert, admission.VerifyOptions{ExpectNodeID: expected.String(), ExpectRole: role})
}

func (node *attackerNode) fetchPeerIdentity(context context.Context, role admission.Role) (identityWire, error) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		var identity identityWire
		status, err := node.getPeer(context, "/identity", &identity)
		if err == nil && status == http.StatusOK && identity.Role == role {
			if node.config.role == "relay" {
				if err := node.verifyPeerIdentity(identity, role, identity.nodeIdentifier()); err == nil {
					return identity, nil
				}
			} else if err := node.verifyPeerIdentity(identity, role, identity.nodeIdentifier()); err == nil {
				return identity, nil
			}
		}
		if time.Now().After(deadline) {
			return identityWire{}, errors.New("peer identity timeout")
		}
		if err := sleepContext(context, peerRetryDelay); err != nil {
			return identityWire{}, err
		}
	}
}

func (node *attackerNode) voucherRequest(voucher billingvoucher.MutualVoucher, payer, relay identityWire) (admission.VoucherSettleRequest, error) {
	canonical, err := voucher.CanonicalBytes()
	if err != nil {
		return admission.VoucherSettleRequest{}, err
	}
	return admission.VoucherSettleRequest{
		CanonicalVoucher: canonical,
		PayerPublicKey:   payer.PublicKey,
		RelayPublicKey:   relay.PublicKey,
		PayerCert:        &payer.Cert,
		RelayCert:        &relay.Cert,
	}, nil
}

func (node *attackerNode) submitVoucher(context context.Context, request admission.VoucherSettleRequest) (voucherHTTPResponse, error) {
	var response admission.VoucherSettleResponse
	status, err := node.postCA(context, admission.PathVoucherSettle, request, &response)
	return voucherHTTPResponse{Status: status, Body: response}, err
}

func (node *attackerNode) balance(context context.Context, nodeID string) (int64, int, error) {
	request, err := http.NewRequestWithContext(context, http.MethodGet, node.config.caURL+admission.PathBalance+"?node="+url.QueryEscape(nodeID), nil)
	if err != nil {
		return 0, 0, err
	}
	response, err := node.http.Do(request)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	var body struct {
		Balance int64 `json:"balance"`
	}
	if err := decodeResponse(response.Body, &body); err != nil {
		return 0, response.StatusCode, err
	}
	if response.StatusCode != http.StatusOK {
		return 0, response.StatusCode, errors.New("balance request rejected")
	}
	return body.Balance, response.StatusCode, nil
}

func (node *attackerNode) postPeer(context context.Context, path string, input, output any) (int, error) {
	return node.postJSON(context, node.config.peerURL+path, input, output)
}

func (node *attackerNode) getPeer(context context.Context, path string, output any) (int, error) {
	request, err := http.NewRequestWithContext(context, http.MethodGet, node.config.peerURL+path, nil)
	if err != nil {
		return 0, err
	}
	response, err := node.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeResponse(response.Body, output); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func (node *attackerNode) postCA(context context.Context, path string, input, output any) (int, error) {
	return node.postJSON(context, node.config.caURL+path, input, output)
}

func (node *attackerNode) postJSON(context context.Context, target string, input, output any) (int, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(context, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := node.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeResponse(response.Body, output); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func (node *attackerNode) record(event statusEvent) {
	node.statusMu.Lock()
	defer node.statusMu.Unlock()
	counter := node.snapshot.Coverage[event.Scenario]
	counter.Executed++
	if event.Passed {
		counter.Contained++
	} else {
		counter.Violations++
		node.snapshot.Status = "FAILED"
		node.snapshot.LastError = event.FailureCode
	}
	node.snapshot.Coverage[event.Scenario] = counter
	node.snapshot.Summary.ExecutedChecks++
	if event.Passed {
		node.snapshot.Summary.ContainedChecks++
	} else {
		node.snapshot.Summary.FailedChecks++
	}
	covered := 0
	for _, value := range node.snapshot.Coverage {
		if value.Executed > 0 {
			covered++
		}
	}
	node.snapshot.Summary.CoveredScenarios = covered
	if node.snapshot.Status != "FAILED" {
		if covered == len(node.snapshot.Coverage) {
			node.snapshot.Status = "RUNNING"
		} else {
			node.snapshot.Status = "STARTING"
		}
	}
	node.snapshot.Recent = append([]statusEvent{event}, node.snapshot.Recent...)
	if len(node.snapshot.Recent) > 16 {
		node.snapshot.Recent = node.snapshot.Recent[:16]
	}
}

func (node *attackerNode) publish() error {
	node.statusMu.Lock()
	node.snapshot.HeartbeatAt = time.Now().UTC().Format(time.RFC3339Nano)
	snapshot := node.snapshot
	snapshot.Coverage = cloneCoverage(node.snapshot.Coverage)
	snapshot.Recent = append([]statusEvent(nil), node.snapshot.Recent...)
	node.statusMu.Unlock()
	return writeJSONAtomic(filepath.Join(node.config.stateDir, "status.json"), snapshot)
}

func (node *attackerNode) fail(code string) {
	node.statusMu.Lock()
	node.snapshot.Status = "FAILED"
	node.snapshot.LastError = safeCode(code)
	node.statusMu.Unlock()
	_ = node.publish()
}

func (node *attackerNode) restoreSequence() error {
	var previous statusSnapshot
	if err := readJSONFile(filepath.Join(node.config.stateDir, "status.json"), &previous); err != nil {
		return err
	}
	if previous.SchemaVersion == schemaVersion && previous.Role == node.config.role {
		node.snapshot.Sequence = previous.Sequence
	}
	return nil
}

func (identity identityWire) public() *ecdh.PublicKey {
	encoded, err := hex.DecodeString(identity.PublicKey)
	if err != nil || hex.EncodeToString(encoded) != identity.PublicKey {
		return nil
	}
	public, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil
	}
	return public
}

func (identity identityWire) nodeIdentifier() billingvoucher.Identifier {
	identifier, _ := billingvoucher.ParseIdentifierHex(identity.NodeID)
	return identifier
}

func fixtureBody(nonce string, payer, relay billingvoucher.Identifier, sequence, cumulative uint64, previous billingvoucher.Identifier, label string) billingvoucher.VoucherBody {
	return billingvoucher.VoucherBody{
		Version:                 billingvoucher.CurrentVersion,
		SessionID:               identifier(nonce + ":session"),
		PayerNatID:              payer,
		PayeeRelayID:            relay,
		Direction:               billingvoucher.DirectionPayerOutbound,
		Sequence:                sequence,
		PreviousMutualVoucherID: previous,
		CumulativeUniqueBytes:   cumulative,
		LastRecordID:            identifier(fmt.Sprintf("%s:%s:record:%d", nonce, label, sequence)),
		LastRecordSequence:      sequence,
		RecordSetDigest:         digest(fmt.Sprintf("%s:%s:root:%d", nonce, label, sequence)),
		PolicyDigest:            billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes:  billingvoucher.MaxBillableBytes,
	}
}

func identifier(value string) billingvoucher.Identifier { return sha256.Sum256([]byte(value)) }
func digest(value string) billingvoucher.Digest         { return sha256.Sum256([]byte(value)) }

func deterministicInitialOrder(values []string, random *mathrand.Rand) []string {
	result := append([]string(nil), values...)
	random.Shuffle(len(result), func(left, right int) { result[left], result[right] = result[right], result[left] })
	return result
}

func loadOrCreateIdentity(path string) (*ecdh.PrivateKey, error) {
	if encoded, err := os.ReadFile(path); err == nil {
		if len(encoded) != 32 {
			return nil, errors.New("persisted identity key has invalid length")
		}
		return ecdh.P256().NewPrivateKey(encoded)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, privateKey.Bytes(), 0o600); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func decodeRequest(request *http.Request, output any) error {
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumRequestBody+1))
	if err != nil || len(body) > maximumRequestBody {
		return errors.New("request too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing request data")
	}
	return nil
}

func decodeResponse(reader io.Reader, output any) error {
	body, err := io.ReadAll(io.LimitReader(reader, maximumRequestBody+1))
	if err != nil || len(body) > maximumRequestBody {
		return errors.New("response too large")
	}
	return json.Unmarshal(body, output)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func readJSONFile(path string, output any) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func writeJSONAtomic(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeFileAtomic(path, encoded, 0o600)
}

func writeFileAtomic(path string, value []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	defer cleanup()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func containedEvent(defense string, requests int, statuses []int, path string) statusEvent {
	return statusEvent{Passed: true, Defense: defense, RequestCount: requests, HTTPStatuses: statuses, Path: path}
}

func failedEvent(code string) statusEvent {
	return statusEvent{Passed: false, FailureCode: safeCode(code)}
}

func failedEventWithStatus(code string, status int) statusEvent {
	statuses := []int{}
	if status >= 100 && status <= 599 {
		statuses = append(statuses, status)
	}
	return statusEvent{Passed: false, FailureCode: safeCode(code), HTTPStatuses: statuses}
}

func eventFromPeerResult(status int, result peerResult, path string) statusEvent {
	statuses := append([]int(nil), result.HTTPStatuses...)
	if status >= 100 && status <= 599 {
		statuses = append([]int{status}, statuses...)
	}
	return statusEvent{
		Passed:       result.Passed,
		FailureCode:  safeCode(result.FailureCode),
		Defense:      safeCode(result.Defense),
		RequestCount: result.RequestCount,
		HTTPStatuses: statuses,
		BalanceDelta: result.BalanceDelta,
		StateChanged: result.StateChanged,
		Path:         path,
	}
}

func statusOrZero(response voucherHTTPResponse, err error) int {
	if err != nil {
		return 0
	}
	return response.Status
}

func safeNonce(value string) bool {
	if value == "" || len(value) > 160 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func safeCode(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
		if builder.Len() == 64 {
			break
		}
	}
	return builder.String()
}

func cloneCoverage(source map[string]coverageCounter) map[string]coverageCounter {
	result := make(map[string]coverageCounter, len(source))
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result[key] = source[key]
	}
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sleepContext(context context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-context.Done():
		return context.Err()
	case <-timer.C:
		return nil
	}
}
