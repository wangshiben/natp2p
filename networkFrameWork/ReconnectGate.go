package networkFrameWork

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type ReconnectGateRequest struct {
	RelayAddress string `json:"relayAddress"`
	Transport    string `json:"transport"`
	NodeID       string `json:"nodeId,omitempty"`
	ConnectionID string `json:"connectionId,omitempty"`
	Attempt      int    `json:"attempt,omitempty"`
	Role         string `json:"role,omitempty"`
}

type ReconnectGate interface {
	Wait(context.Context, ReconnectGateRequest) error
}

type RelayReconnectGateProvider interface {
	ReconnectGate() ReconnectGate
}

type RelayReconnectRoleProvider interface {
	ReconnectRole() string
}

type HTTPReconnectGate struct {
	endpoint   string
	token      string
	httpClient *http.Client
}

type reconnectAttemptContextKey struct{}

type reconnectGateDecision struct {
	Granted          bool `json:"granted"`
	DelaySeconds     int  `json:"delaySeconds"`
	RetryAfterSecond int  `json:"retryAfterSeconds"`
}

func NewHTTPReconnectGate(endpoint, token string) *HTTPReconnectGate {
	return &HTTPReconnectGate{
		endpoint:   strings.TrimRight(strings.TrimSpace(endpoint), "/"),
		token:      token,
		httpClient: &http.Client{},
	}
}

func NewReconnectGateFromEnvironment() ReconnectGate {
	endpoint := strings.TrimSpace(os.Getenv("BNFS_RECONNECT_GATE_URL"))
	if endpoint == "" {
		return nil
	}
	return NewHTTPReconnectGate(endpoint, os.Getenv("BNFS_RECONNECT_GATE_TOKEN"))
}

func withReconnectAttempt(ctx context.Context, attempt int) context.Context {
	return context.WithValue(ctx, reconnectAttemptContextKey{}, attempt)
}

func reconnectAttempt(ctx context.Context) int {
	attempt, _ := ctx.Value(reconnectAttemptContextKey{}).(int)
	return attempt
}

func (gate *HTTPReconnectGate) Wait(ctx context.Context, request ReconnectGateRequest) error {
	if gate == nil || gate.endpoint == "" {
		return waitReconnectFallback(ctx)
	}
	for {
		decision, err := gate.requestDecision(ctx, request)
		if err != nil {
			return waitReconnectFallback(ctx)
		}
		if decision.Granted {
			return waitReconnectDuration(ctx, time.Duration(decision.DelaySeconds)*time.Second)
		}
		retryAfter := time.Duration(decision.RetryAfterSecond) * time.Second
		if retryAfter <= 0 {
			retryAfter = 30 * time.Second
		}
		if err := waitReconnectDuration(ctx, retryAfter); err != nil {
			return err
		}
	}
}

func (gate *HTTPReconnectGate) requestDecision(ctx context.Context, request ReconnectGateRequest) (reconnectGateDecision, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return reconnectGateDecision{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodPost,
		gate.endpoint+"/v1/reconnect-delay",
		bytes.NewReader(body),
	)
	if err != nil {
		return reconnectGateDecision{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if gate.token != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+gate.token)
	}
	response, err := gate.httpClient.Do(httpRequest)
	if err != nil {
		return reconnectGateDecision{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return reconnectGateDecision{}, fmt.Errorf("reconnect gate status %s", response.Status)
	}
	var decision reconnectGateDecision
	if err := json.NewDecoder(response.Body).Decode(&decision); err != nil {
		return reconnectGateDecision{}, err
	}
	if decision.DelaySeconds < 0 || decision.DelaySeconds > 60 ||
		decision.RetryAfterSecond < 0 || decision.RetryAfterSecond > 60 {
		return reconnectGateDecision{}, fmt.Errorf("reconnect gate returned invalid delay")
	}
	return decision, nil
}

func waitReconnectFallback(ctx context.Context) error {
	const (
		minimum = 30 * time.Second
		maximum = 60 * time.Second
	)
	delay, err := randomReconnectDuration(minimum, maximum)
	if err != nil {
		delay = maximum
	}
	return waitReconnectDuration(ctx, delay)
}

func randomReconnectDuration(minimum, maximum time.Duration) (time.Duration, error) {
	if maximum <= minimum {
		return minimum, nil
	}
	var randomBytes [8]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return 0, err
	}
	value := binary.BigEndian.Uint64(randomBytes[:])
	span := uint64(maximum - minimum)
	return minimum + time.Duration(value%(span+1)), nil
}

func waitReconnectDuration(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
