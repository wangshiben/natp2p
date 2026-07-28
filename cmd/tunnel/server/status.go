package main

import (
	"bnfs_p2p/p2pnode/impl/natnode"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type serviceStatusSource interface {
	Snapshot() natnode.ServiceListenerSnapshot
}

type publicServiceSession struct {
	ConnectionID string `json:"connectionId"`
	PeerID       string `json:"peerId"`
	RelayAddress string `json:"relayAddress,omitempty"`
}

type publicServiceCarrier struct {
	RelayAddress      string `json:"relayAddress"`
	Connected         bool   `json:"connected"`
	CarrierGeneration uint64 `json:"carrierGeneration"`
	ActiveSessions    int    `json:"activeSessions"`
}

type serviceListenerStatus struct {
	SchemaVersion     int                    `json:"schemaVersion"`
	ObservedAt        string                 `json:"observedAt"`
	Service           string                 `json:"service"`
	NodeID            string                 `json:"nodeId"`
	RelayAddress      string                 `json:"relayAddress"`
	CarrierConnected  bool                   `json:"carrierConnected"`
	CarrierGeneration uint64                 `json:"carrierGeneration"`
	ActiveSessions    int                    `json:"activeSessions"`
	MaxSessions       int                    `json:"maxSessions"`
	AcceptQueueDepth  int                    `json:"acceptQueueDepth"`
	AcceptQueue       int                    `json:"acceptQueue"`
	AcceptedTotal     uint64                 `json:"acceptedTotal"`
	RejectedTotal     uint64                 `json:"rejectedTotal"`
	Carriers          []publicServiceCarrier `json:"carriers,omitempty"`
	Sessions          []publicServiceSession `json:"sessions"`
}

func startServiceStatusReporter(ctx context.Context, file, service, nodeID string, source serviceStatusSource) error {
	if file == "" {
		return nil
	}
	if source == nil {
		return errors.New("service status source is required")
	}
	if err := writeServiceListenerStatus(file, service, nodeID, source.Snapshot()); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = writeServiceListenerStatus(file, service, nodeID, source.Snapshot())
			}
		}
	}()
	return nil
}

func writeServiceListenerStatus(file, service, nodeID string, snapshot natnode.ServiceListenerSnapshot) error {
	if file == "" {
		return errors.New("service status file is required")
	}
	status := serviceListenerStatus{
		SchemaVersion:     1,
		ObservedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		Service:           service,
		NodeID:            prefix(nodeID, 16),
		RelayAddress:      snapshot.RelayAddress,
		CarrierConnected:  snapshot.CarrierConnected,
		CarrierGeneration: snapshot.CarrierGeneration,
		ActiveSessions:    snapshot.ActiveSessions,
		MaxSessions:       snapshot.MaxSessions,
		AcceptQueueDepth:  snapshot.AcceptQueueDepth,
		AcceptQueue:       snapshot.AcceptQueue,
		AcceptedTotal:     snapshot.AcceptedTotal,
		RejectedTotal:     snapshot.RejectedTotal,
		Carriers:          make([]publicServiceCarrier, 0, len(snapshot.Carriers)),
		Sessions:          make([]publicServiceSession, 0, len(snapshot.Sessions)),
	}
	for _, carrier := range snapshot.Carriers {
		status.Carriers = append(status.Carriers, publicServiceCarrier{
			RelayAddress: carrier.RelayAddress, Connected: carrier.Connected,
			CarrierGeneration: carrier.CarrierGeneration, ActiveSessions: carrier.ActiveSessions,
		})
	}
	for _, session := range snapshot.Sessions {
		status.Sessions = append(status.Sessions, publicServiceSession{
			ConnectionID: prefix(session.ConnectionID, 8),
			PeerID:       prefix(session.PeerID, 16),
			RelayAddress: session.RelayAddress,
		})
	}
	body, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("encode service status: %w", err)
	}
	body = append(body, '\n')
	directory := filepath.Dir(file)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create service status directory: %w", err)
	}
	temporary := file + fmt.Sprintf(".tmp-%d", os.Getpid())
	if err := os.WriteFile(temporary, body, 0o600); err != nil {
		return fmt.Errorf("write service status: %w", err)
	}
	if err := os.Rename(temporary, file); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("publish service status: %w", err)
	}
	return nil
}

func prefix(value string, length int) string {
	value = strings.TrimSpace(value)
	if length <= 0 || len(value) <= length {
		return value
	}
	return value[:length]
}
