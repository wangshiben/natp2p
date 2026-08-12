import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  buildMaliciousRelayCommand,
  buildSignedNodeAuthorization,
  createSerialHeartbeatPublisher,
  generateEphemeralServerIdentity,
  mixedPathNodes,
  normalPartitionForRelay,
  pendingTriggers,
  publicTrigger,
  recordControllerFailure,
  selectRandomNormalRelay,
  waitForFilePattern,
} from "./mixed-path-controller.mjs";

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

test("mixed path starts with normal probe on malicious relay and malicious NAT on normal relay", () => {
  assert.deepEqual(mixedPathNodes("malicious-relay", "relay03"), [
    "mixed-path-probe",
    "malicious-relay",
    "relay03",
    "malicious-natserver",
  ]);
  assert.deepEqual(mixedPathNodes("relay05", "relay05"), [
    "mixed-path-probe",
    "relay05",
    "malicious-natserver",
  ]);
});

test("random migration always chooses a different normal relay", () => {
  assert.equal(selectRandomNormalRelay("relay03", [], () => 0), "relay04");
  assert.equal(selectRandomNormalRelay("relay01", [], () => 4), "relay07");
  assert.match(selectRandomNormalRelay("malicious-relay", [], () => 2), /^relay0[3-7]$/);
  assert.equal(selectRandomNormalRelay("relay06", ["relay03"], () => 0), "relay04");
});

test("mixed-path NatServer identities rotate without exposing enrollment credentials", () => {
  const first = generateEphemeralServerIdentity();
  const second = generateEphemeralServerIdentity();
  for (const identity of [first, second]) {
    assert.match(identity.privateKey, /^[0-9a-f]{64}$/);
    assert.match(identity.publicKey, /^04[0-9a-f]{128}$/);
    assert.match(identity.nodeID, /^[0-9a-f]{64}$/);
  }
  assert.notEqual(first.nodeID, second.nodeID);
  assert.deepEqual(Object.keys(first).sort(), ["nodeID", "privateKey", "publicKey"]);
});

test("mixed-path NatServer rotates through a billing-bound double-signed authorization", () => {
  const identity = generateEphemeralServerIdentity();
  const billing = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateJWK = billing.privateKey.export({ format: "jwk" });
  const billingPublicKey = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(privateJWK.x, "base64url"),
    Buffer.from(privateJWK.y, "base64url"),
  ]);
  const bundle = {
    version: 1,
    key_id: crypto.createHash("sha256").update(billingPublicKey).digest("hex"),
    algorithm: "ECDSA_P256_SHA256",
    private_key_jwk: privateJWK,
    public_key_hex: billingPublicKey.toString("hex"),
    registration_status: "active",
  };
  const request = buildSignedNodeAuthorization(identity, bundle, 1785811200);
  const canonical = [
    "CA-NODE-AUTHORIZATION-V1",
    request.subject_pubkey,
    request.role,
    request.billing_key_id,
    String(request.timestamp),
    request.nonce,
    String(request.ttl_seconds),
  ].join("\n");
  const identityPublicKey = crypto.createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(identity.publicKey.slice(2, 66), "hex").toString("base64url"),
      y: Buffer.from(identity.publicKey.slice(66), "hex").toString("base64url"),
    },
    format: "jwk",
  });

  assert.equal(request.role, "server");
  assert.equal(request.billing_key_id, bundle.key_id);
  assert.equal(request.timestamp, 1785811200);
  assert.equal(crypto.verify(
    "sha256", Buffer.from(canonical), identityPublicKey, Buffer.from(request.node_signature, "base64url"),
  ), true);
  assert.equal(crypto.verify(
    "sha256", Buffer.from(canonical), billing.publicKey, Buffer.from(request.billing_signature, "base64url"),
  ), true);
});

test("normal Relay attachments map only to real control partitions", () => {
  assert.equal(normalPartitionForRelay("relay03"), "control_partition_a");
  assert.equal(normalPartitionForRelay("relay05"), "control_partition_a");
  assert.equal(normalPartitionForRelay("relay06"), "control_partition_b");
  assert.equal(normalPartitionForRelay("relay07"), "control_partition_b");
  assert.equal(normalPartitionForRelay("relay01"), "");
  assert.equal(normalPartitionForRelay("malicious-relay"), "");
});

test("dynamic production Relay persists an isolated revocation state", () => {
  const command = buildMaliciousRelayCommand("relay04");
  assert.match(command, /BNFS_CA_CERT_FILE=\/state\/certificate\.json/);
  assert.match(command, /BNFS_REVOCATION_STATE_FILE=\/state\/mixed-revocations\.json/);
  assert.match(command, /-peer relay04:9000/);
  assert.throws(() => buildMaliciousRelayCommand("malicious-relay"), /mixed_path_relay_invalid/);
});

test("mixed path trigger rejects untrusted fields and scenarios", () => {
  assert.deepEqual(publicTrigger("relay", {
    sequence: 9,
    scenario: "relay_usage_inflation",
    observedAt: "2026-07-20T12:00:00Z",
    passed: true,
    defense: "nat_meter_rejected_usage_inflation",
    requestCount: 1,
    httpStatuses: [409, 999],
    nodeID: "secret",
    path: "untrusted",
  }), {
    actor: "relay",
    sequence: 9,
    scenario: "relay_usage_inflation",
    observedAt: "2026-07-20T12:00:00.000Z",
    contained: true,
    defense: "nat_meter_rejected_usage_inflation",
    requestCount: 1,
    httpStatuses: [409],
  });
  assert.equal(publicTrigger("natserver", { sequence: 1, scenario: "relay_usage_inflation" }), null);
  assert.equal(publicTrigger("relay", { sequence: -1, scenario: "relay_usage_inflation" }), null);
});

test("mixed path queues every unseen random event in observation order", () => {
  const events = {
    natserver: [
      { sequence: 3, scenario: "nat_signature_refusal", observedAt: "2026-07-20T12:00:03Z", passed: true },
      { sequence: 2, scenario: "nat_same_sequence_fork", observedAt: "2026-07-20T12:00:02Z", passed: true },
      { sequence: 1, scenario: "nat_stale_watermark", observedAt: "2026-07-20T12:00:01Z", passed: true },
    ],
    relay: [
      { sequence: 2, scenario: "relay_request_replay", observedAt: "2026-07-20T12:00:04Z", passed: true },
      { sequence: 1, scenario: "relay_usage_inflation", observedAt: "2026-07-20T12:00:00Z", passed: true },
    ],
  };
  assert.deepEqual(
    pendingTriggers(events, { natserver: 1, relay: 0 }).map(({ actor, sequence, scenario }) => ({ actor, sequence, scenario })),
    [
      { actor: "relay", sequence: 1, scenario: "relay_usage_inflation" },
      { actor: "natserver", sequence: 2, scenario: "nat_same_sequence_fork" },
      { actor: "natserver", sequence: 3, scenario: "nat_signature_refusal" },
      { actor: "relay", sequence: 2, scenario: "relay_request_replay" },
    ],
  );
});

test("heartbeat publication continues independently and remains serialized", async () => {
  const state = { heartbeatAt: "", generation: 0 };
  const snapshots = [];
  let active = 0;
  let maximumActive = 0;
  const publisher = createSerialHeartbeatPublisher(state, async (snapshot) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await delay(12);
    snapshots.push(snapshot);
    active -= 1;
  }, 5);

  await publisher.publish();
  state.generation = 1;
  await delay(28);
  await publisher.stop();

  assert.equal(maximumActive, 1);
  assert.ok(snapshots.length >= 3);
  assert.equal(snapshots.at(-1).generation, 1);
  assert.ok(snapshots.every((snapshot) => Number.isFinite(Date.parse(snapshot.heartbeatAt))));
});

test("process waits retain a stage-specific timeout code", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-mixed-path-timeout-"));
  context.after(() => fs.rm(directory, { recursive: true, force: true }));
  await assert.rejects(
    waitForFilePattern(
      path.join(directory, "missing.log"),
      /ready/,
      5,
      { shouldStop: () => false },
      "mixed_path_relay_control_timeout",
    ),
    (error) => error?.code === "mixed_path_relay_control_timeout",
  );
});

test("controller failure preserves accumulated migration evidence", () => {
  const state = {
    status: "MIGRATING",
    generation: 11,
    migrations: [{ generation: 11 }],
    networkCoverage: [{ scenario: "relay_fee_override", executed: 2, contained: 2, violations: 0 }],
  };
  const result = recordControllerFailure(
    state,
    Object.assign(new Error("timeout"), { code: "mixed_path_relay_control_timeout" }),
  );

  assert.equal(result, state);
  assert.equal(result.status, "FAILED");
  assert.equal(result.errorCode, "mixed_path_relay_control_timeout");
  assert.equal(result.generation, 11);
  assert.deepEqual(result.migrations, [{ generation: 11 }]);
  assert.equal(result.networkCoverage[0].executed, 2);
});
