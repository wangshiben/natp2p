package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bnfs_p2p/billingqueue"
	"bnfs_p2p/billingvoucher"
)

func TestRunOutputsOnlyRedactedAggregateJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-node-name", "wait-submit.queue")
	queue, err := billingqueue.Open(path, billingqueue.Limits{
		MaxItems: defaultMaxItems,
		MaxBytes: defaultMaxBytes,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if status := run([]string{"-path", path}, &stdout, &stderr); status != 0 {
		t.Fatalf("run status = %d, stderr = %q", status, stderr.String())
	}
	want := "{\"schema\":\"billingqueue-wal/v3\",\"depth\":0,\"payload_bytes\":0,\"incomplete_tail\":false,\"channel_depth\":0,\"authorized_bytes\":0,\"session_count\":0}\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 || strings.Contains(stdout.String(), path) {
		t.Fatalf("output leaked path or wrote stderr: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunTargetUsesPrivateKeyFilesWithoutLeakingThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-node-name", "wait-submit.queue")
	queue, err := billingqueue.Open(path, billingqueue.Limits{MaxItems: defaultMaxItems, MaxBytes: defaultMaxBytes})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	payer := generateCommandIdentity(t)
	relay := generateCommandIdentity(t)
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	payerKeyPath := writeCommandIdentity(t, "payer-secret.key", payer)
	relayKeyPath := writeCommandIdentity(t, "relay-secret.key", relay)
	privateKeyHex := hex.EncodeToString(relay.Bytes())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run([]string{
		"-path", path, "-payer-id", payerID.String(), "-payer-key", payerKeyPath, "-relay-key", relayKeyPath,
	}, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("run status = %d, stderr = %q", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"channel_depth":0`) ||
		strings.Contains(stdout.String(), payerKeyPath) || strings.Contains(stdout.String(), relayKeyPath) ||
		strings.Contains(stdout.String(), privateKeyHex) || stderr.Len() != 0 {
		t.Fatalf("target output was not redacted: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunTargetRejectsMissingOrInvalidIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := billingqueue.Open(path, billingqueue.Limits{MaxItems: defaultMaxItems, MaxBytes: defaultMaxBytes})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	payer := generateCommandIdentity(t)
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	for name, arguments := range map[string][]string{
		"missing Relay key":      {"-path", path, "-payer-id", payerID.String()},
		"non-canonical payer ID": {"-path", path, "-payer-id", strings.ToUpper(payerID.String()), "-relay-key", path},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if status := run(arguments, &stdout, &stderr); status != 2 {
				t.Fatalf("run status = %d, want 2", status)
			}
			if stdout.Len() != 0 || stderr.String() != "billingqueue-inspect: target_invalid\n" {
				t.Fatalf("output = stdout %q stderr %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunCorruptionErrorIsRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-node-name", "wait-submit.queue")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if status := run([]string{"-path", path}, &stdout, &stderr); status != 1 {
		t.Fatalf("run status = %d, want 1", status)
	}
	if stdout.Len() != 0 || stderr.String() != "billingqueue-inspect: queue_corrupt\n" {
		t.Fatalf("redacted output = stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), path) {
		t.Fatalf("stderr leaked queue path: %q", stderr.String())
	}
}

func generateCommandIdentity(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return identity
}

func writeCommandIdentity(t *testing.T, name string, identity *ecdh.PrivateKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(identity.Bytes())), 0o600); err != nil {
		t.Fatalf("WriteFile identity: %v", err)
	}
	return path
}
