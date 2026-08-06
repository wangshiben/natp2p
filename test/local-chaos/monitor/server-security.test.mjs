import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const dashboardPath = fileURLToPath(new URL("./server.mjs", import.meta.url));
const scenarios = [
  "relay_usage_inflation",
  "relay_request_replay",
  "relay_fee_override",
  "relay_window_overrun",
  "nat_stale_watermark",
  "nat_same_sequence_fork",
  "nat_signature_refusal",
  "relay_voucher_tamper",
  "index_disconnect_backlog_recovery",
];
const containerScenarios = [
  ["nat_stale_watermark", "natserver"],
  ["nat_same_sequence_fork", "natserver"],
  ["nat_signature_refusal", "natserver"],
  ["nat_identity_forgery", "natserver"],
  ["relay_usage_inflation", "relay"],
  ["relay_request_replay", "relay"],
  ["relay_fee_override", "relay"],
  ["relay_window_overrun", "relay"],
  ["relay_voucher_tamper", "relay"],
];
const productionGateEvidenceDetails = [
  "billing_production_gate_nat_snapshot_unavailable",
  "billing_production_gate_nat_snapshot_invalid",
  "billing_production_gate_nat_snapshot_unstable",
  "billing_production_gate_authorization_invalid",
  "billing_production_gate_authorized_amount_mismatch",
  "billing_production_gate_payer_debit_mismatch",
  "billing_production_gate_channel_accounting_mismatch",
  "billing_production_gate_recovery_server_restart_failed",
  "billing_production_gate_recovery_queue_timeout",
];

test("Dashboard publishes only aggregate reconnect gate metrics", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-reconnect-gate-"));
  const secretRelay = "private-relay.internal:9000";
  const secretToken = "private-reconnect-gate-token";
  let authenticated = false;
  const gateServer = http.createServer((request, response) => {
    authenticated = request.headers.authorization === `Bearer ${secretToken}`;
    const body = JSON.stringify({
      status: "ok",
      startedAt: "2026-07-29T00:00:00Z",
      observedAt: "2026-07-29T00:01:00Z",
      safeRate: 10,
      windowSeconds: 10,
      scopes: [
        {
          scope: `${secretRelay}|tcp`,
          granted: 12,
          denied: 2,
          futureSlots: 7,
          scheduledPerSecondPeak: 4,
          windowRequests: 9,
          pressure: 0.09,
        },
        {
          scope: `${secretRelay}|carrier`,
          granted: 3,
          denied: 0,
          futureSlots: 2,
          scheduledPerSecondPeak: 2,
          windowRequests: 3,
          pressure: 0.03,
        },
      ],
    });
    response.writeHead(authenticated && request.url === "/metrics" ? 200 : 401, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
      Connection: "close",
    });
    response.end(body);
  });
  await new Promise((resolve) => gateServer.listen(0, "127.0.0.1", resolve));
  const gateAddress = gateServer.address();
  try {
    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const reconnectGate = JSON.parse(encoded).reconnectGate;
      assert.equal(authenticated, true);
      assert.equal(reconnectGate.status, "RUNNING");
      assert.equal(reconnectGate.healthy, true);
      assert.equal(reconnectGate.scopeCount, 2);
      assert.equal(reconnectGate.granted, 15);
      assert.equal(reconnectGate.denied, 2);
      assert.equal(reconnectGate.queued, 9);
      assert.equal(reconnectGate.scheduledPerSecondPeak, 4);
      assert.equal(reconnectGate.pressurePct, 9);
      assert.deepEqual(reconnectGate.transports, [
        { transport: "carrier", granted: 3, denied: 0, queued: 2, windowRequests: 3 },
        { transport: "tcp", granted: 12, denied: 2, queued: 7, windowRequests: 9 },
      ]);
      assert.equal(encoded.includes(secretRelay), false);
      assert.equal(encoded.includes(secretToken), false);

      const page = await dashboardFetch(`http://127.0.0.1:${port}/`);
      const html = await page.text();
      assert.equal(html.includes('id="reconnectGateStatus"'), true);
      assert.equal(html.includes("NAT 重连随机退避 Gate"), true);
    }, {
      env: {
        BNFS_RECONNECT_GATE_MONITOR_URL: `http://127.0.0.1:${gateAddress.port}`,
        BNFS_RECONNECT_GATE_TOKEN: secretToken,
      },
    });
  } finally {
    await new Promise((resolve) => gateServer.close(resolve));
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard reads the completed capacity reconnect gate snapshot", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-capacity-gate-"));
  const capacityDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-capacity-gate-"));
  const capacityPointer = path.join(runDir, "capacity-pointer");
  try {
    await fs.writeFile(capacityPointer, `${capacityDir}\n`);
    await fs.writeFile(path.join(capacityDir, "client.log"), "CAPACITY_PLAN clients=1 transfer_mib=1 targets=1\n");
    await fs.writeFile(path.join(capacityDir, "reconnect-gate-final.json"), JSON.stringify({
      status: "ok",
      startedAt: "2026-07-29T00:00:00Z",
      observedAt: "2026-07-29T00:01:00Z",
      safeRate: 10,
      windowSeconds: 10,
      scopes: [{
        scope: "private-relay.internal:9000|tcp",
        granted: 3,
        denied: 0,
        futureSlots: 1,
        scheduledPerSecondPeak: 1,
        windowRequests: 2,
        pressure: 0.02,
      }],
    }));
    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      const encoded = await response.text();
      const reconnectGate = JSON.parse(encoded).reconnectGate;
      assert.equal(reconnectGate.status, "STOPPED");
      assert.equal(reconnectGate.live, false);
      assert.equal(reconnectGate.granted, 3);
      assert.equal(encoded.includes("private-relay.internal"), false);
    }, {
      env: { CAPACITY_RUN_POINTER: capacityPointer },
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
    await fs.rm(capacityDir, { recursive: true, force: true });
  }
});

test("Dashboard internal errors never expose filesystem details", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-redaction-"));
  try {
    await fs.mkdir(path.join(runDir, "transfers.tsv"));
    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      const encoded = await response.text();
      assert.equal(response.status, 500);
      assert.deepEqual(JSON.parse(encoded), { error: "dashboard_error" });
      assert.equal(encoded.includes(runDir), false);
      assert.equal(encoded.includes("transfers.tsv"), false);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard rejects monitor heartbeats over five seconds in the future", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-heartbeat-"));
  try {
    await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
    await fs.writeFile(path.join(runDir, "metadata.env"), "billing_adversary_mode=enforce\n");
    await fs.writeFile(path.join(runDir, "transfers.tsv"), [
      "timestamp",
      "transfer_id",
      "client",
      "ingress_relay",
      "server",
      "requested_mib",
      "rc",
      "bytes",
      "seconds",
      "mib_per_second",
      "sha256_ok",
      "expected_sha",
      "actual_sha",
    ].join("\t") + "\n");
    await fs.writeFile(path.join(runDir, "billing-adversary.json"), JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      heartbeatAt: new Date(Date.now() + 60000).toISOString(),
      coverage: Object.fromEntries(scenarios.map((scenario) => [scenario, {
        executed: 1,
        contained: 1,
        violations: 0,
      }])),
      summary: { stateChanges: 0 },
      componentProbe: {
        schemaVersion: 1,
        status: "RUNNING",
        executed: scenarios.length,
        failed: 0,
        required: scenarios.length,
        covered: scenarios.length,
      },
      recent: [],
    }));
    await fs.writeFile(path.join(runDir, "failure-watcher.json"), JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      heartbeatAt: new Date(Date.now() + 60000).toISOString(),
      source: { available: true, sizeBytes: 0, offsetBytes: 0 },
      baseline: { transferRecords: 0, failureRecords: 0 },
      observed: { transferRecords: 0, failureRecords: 0, newFailureRecords: 0 },
      alerts: { limit: 100, total: 0, recent: [] },
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      assert.equal(status.billingAdversary.available, true);
      assert.equal(status.billingAdversary.status, "RUNNING");
      assert.equal(status.billingAdversary.summary.coveredScenarios, scenarios.length);
      assert.equal(status.billingAdversary.componentProbe.status, "RUNNING");
      assert.equal(status.billingAdversary.healthy, false);
      assert.equal(status.failureWatcher.available, true);
      assert.equal(status.failureWatcher.status, "RUNNING");
      assert.equal(status.failureWatcher.source.available, true);
      assert.equal(status.failureWatcher.healthy, false);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard strictly whitelists component and container probes and includes them in health", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-component-probe-"));
  const secretPath = "/private/component/probe/binary";
  const secretNodeID = "c".repeat(64);
  const secretContainerID = "private-component-container-id";
  try {
    await fs.writeFile(path.join(runDir, "billing-adversary.json"), JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      heartbeatAt: new Date().toISOString(),
      coverage: Object.fromEntries(scenarios.map((scenario) => [scenario, {
        executed: 1,
        contained: 1,
        violations: 0,
      }])),
      summary: { stateChanges: 0 },
      componentProbe: {
        schemaVersion: 1,
        status: "RUNNING",
        executed: scenarios.length,
        failed: 0,
        required: scenarios.length,
        covered: scenarios.length,
        binaryPath: secretPath,
        command: [secretPath, "-state-dir", secretPath],
        pid: 919191,
        nodeID: secretNodeID,
        containerID: secretContainerID,
        nested: { secretPath, secretNodeID },
      },
      containerProbe: runningContainerProbe({ secretPath, secretNodeID, secretContainerID }),
      recent: [],
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const status = JSON.parse(encoded);
      assert.deepEqual(status.billingAdversary.componentProbe, {
        schemaVersion: 1,
        status: "RUNNING",
        executed: scenarios.length,
        failed: 0,
        required: scenarios.length,
        covered: scenarios.length,
      });
      assert.deepEqual(Object.keys(status.billingAdversary.componentProbe).sort(), [
        "covered", "executed", "failed", "required", "schemaVersion", "status",
      ]);
      assert.equal(status.billingAdversary.containerProbe.status, "RUNNING");
      assert.equal(status.billingAdversary.containerProbe.covered, containerScenarios.length);
      assert.equal(status.billingAdversary.containerProbe.failed, 0);
      assert.deepEqual(status.billingAdversary.containerProbe.transport, ["container_http_peer", "container_http_ca"]);
      assert.equal(status.billingAdversary.containerProbe.scope, "isolated_container_http_ca_fixture");
      assert.deepEqual(Object.keys(status.billingAdversary.containerProbe).sort(), [
        "actors", "coverage", "covered", "errorCode", "executed", "failed", "limitations", "recent",
        "required", "schemaVersion", "scope", "status", "transport",
      ]);
      assert.equal(status.billingAdversary.healthy, true);
      for (const secret of [secretPath, secretNodeID, secretContainerID, "919191"]) {
        assert.equal(encoded.includes(secret), false, `component probe API leaked ${secret}`);
      }

      const page = await dashboardFetch(`http://127.0.0.1:${port}/`);
      const html = await page.text();
      assert.equal(html.includes('id="billingComponentProbe"'), true);
      assert.equal(html.includes("真实 Go 生产组件探针"), true);
      assert.equal(html.includes("不代表完整 Nat / Relay Socket"), true);
      assert.equal(html.includes("不代表完整 P2P Payload Socket"), true);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

function runningContainerProbe(secrets) {
  const heartbeatAt = new Date().toISOString();
  const coverage = containerScenarios.map(([scenario, actor]) => ({
    scenario,
    actor,
    executed: 1,
    contained: 1,
    violations: 0,
    rawPath: secrets.secretPath,
  }));
  return {
    schemaVersion: 1,
    status: "RUNNING",
    executed: coverage.length,
    failed: 0,
    covered: coverage.length,
    required: coverage.length,
    actors: {
      natserver: { status: "RUNNING", executed: 4, failed: 0, covered: 4, required: 4 },
      relay: { status: "RUNNING", executed: 5, failed: 0, covered: 5, required: 5 },
    },
    coverage,
    recent: [{
      sequence: 1,
      observedAt: heartbeatAt,
      scenario: "nat_identity_forgery",
      actor: "natserver",
      passed: true,
      verdict: "CONTAINED",
      defense: "relay_rejected_forged_nat_identity",
      requestCount: 1,
      httpStatuses: [200],
      balanceDelta: 0,
      stateChanged: false,
      path: "malicious-natserver->malicious-relay->ca",
      rawPath: secrets.secretPath,
      nodeID: secrets.secretNodeID,
      containerID: secrets.secretContainerID,
    }],
    transport: ["untrusted", secrets.secretPath],
    limitations: [secrets.secretNodeID],
    errorCode: "",
    rawPath: secrets.secretPath,
  };
}

test("Dashboard exposes only whitelisted malicious node runtime and activity", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-malicious-nodes-"));
  const fakeBin = path.join(runDir, "bin");
  const inspectFixture = path.join(runDir, "docker-inspect.json");
  const secretPath = "/private/adversary/runtime/state";
  const secretNodeID = "e".repeat(64);
  const secretContainerID = "private-malicious-container-id";
  const secretIP = "10.202.0.199";
  const secretHealth = "private_runtime_secret";
  try {
    const containerProbe = runningContainerProbe({ secretPath, secretNodeID, secretContainerID });
    containerProbe.recent.push({
      sequence: 2,
      observedAt: new Date().toISOString(),
      scenario: "relay_usage_inflation",
      actor: "relay",
      passed: true,
      verdict: "CONTAINED",
      defense: "attack_rejected",
      requestCount: 1,
      httpStatuses: [409],
      balanceDelta: 0,
      stateChanged: false,
      path: "malicious-relay->malicious-natserver->ca",
      rawPath: secretPath,
      nodeID: secretNodeID,
      containerID: secretContainerID,
    });
    await fs.writeFile(path.join(runDir, "billing-adversary.json"), JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      heartbeatAt: new Date().toISOString(),
      coverage: Object.fromEntries(scenarios.map((scenario) => [scenario, {
        executed: 1,
        contained: 1,
        violations: 0,
      }])),
      summary: { stateChanges: 0 },
      componentProbe: {
        schemaVersion: 1,
        status: "RUNNING",
        executed: scenarios.length,
        failed: 0,
        required: scenarios.length,
        covered: scenarios.length,
      },
      containerProbe,
      recent: [],
    }));
    await fs.writeFile(inspectFixture, JSON.stringify([
      inspectedContainer("malicious-natserver", {
        id: secretNodeID,
        name: `${secretPath}/malicious-natserver`,
        image: `${secretPath}/private-image:latest`,
        running: true,
        status: "running",
        health: "healthy",
        restartCount: 2,
        ip: secretIP,
      }),
      inspectedContainer("malicious-relay", {
        id: secretContainerID,
        name: `${secretPath}/malicious-relay`,
        image: `${secretPath}/private-image:latest`,
        running: false,
        status: "exited",
        health: secretHealth,
        restartCount: 7,
        ip: "10.202.0.200",
      }),
    ]));
    await fs.mkdir(fakeBin, { recursive: true });
    await fs.writeFile(path.join(fakeBin, "docker"), [
      "#!/bin/sh",
      "case \"$1\" in",
      "  ps) printf '%s\\n' malicious-natserver-id malicious-relay-id ;;",
      "  inspect) /bin/cat \"$DASHBOARD_DOCKER_INSPECT_FIXTURE\" ;;",
      "  *) exit 2 ;;",
      "esac",
      "",
    ].join("\n"), { mode: 0o700 });

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const status = JSON.parse(encoded);
      assert.deepEqual(status.maliciousNodes.map((node) => node.service), [
        "malicious-natserver",
        "malicious-relay",
      ]);
      assert.deepEqual(status.maliciousNodes.map((node) => node.actor), ["natserver", "relay"]);
      assert.deepEqual(Object.keys(status.maliciousNodes[0]).sort(), [
        "actor", "health", "ipFamily", "ipType", "latestActivity", "networkStack", "probe",
        "restartCount", "running", "service", "transportStack",
      ]);
      assert.deepEqual(status.maliciousNodes[0].probe, {
        status: "RUNNING",
        executed: 4,
        failed: 0,
        covered: 4,
        required: 4,
      });
      assert.equal(status.maliciousNodes[0].running, true);
      assert.equal(status.maliciousNodes[0].health, "healthy");
      assert.equal(status.maliciousNodes[0].restartCount, 2);
      assert.equal(status.maliciousNodes[0].latestActivity.scenario, "nat_identity_forgery");
      assert.equal(status.maliciousNodes[1].running, false);
      assert.equal(status.maliciousNodes[1].health, "unknown");
      assert.equal(status.maliciousNodes[1].restartCount, 7);
      assert.deepEqual(status.maliciousNodes[1].latestActivity, {
        observedAt: containerProbe.recent[1].observedAt,
        scenario: "relay_usage_inflation",
        passed: true,
        verdict: "CONTAINED",
        defense: "attack_rejected",
        failureCode: "",
      });
      for (const secret of [
        secretPath,
        secretNodeID,
        secretNodeID.slice(0, 12),
        secretContainerID,
        secretIP,
        secretHealth,
        "private-image",
      ]) {
        assert.equal(encoded.includes(secret), false, `malicious node API leaked ${secret}`);
      }
    }, {
      composeProject: "dashboard-malicious-node-test",
      env: {
        DASHBOARD_DOCKER_INSPECT_FIXTURE: inspectFixture,
        PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
      },
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard separates a manually stopped run from a healthy CA-only deployment", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-ca-only-"));
  const fakeBin = path.join(runDir, "bin");
  const inspectFixture = path.join(runDir, "docker-inspect.json");
  try {
    await fs.writeFile(path.join(runDir, "phase"), "STOPPED\n");
    await fs.writeFile(path.join(runDir, "status.env"), [
      "outcome=FAILED",
      "detail=resource_guard_identity_invalid",
      "finished_epoch=1785812909",
      "remaining_containers=0",
      "remaining_networks=0",
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "resource-guard.status"), "STOPPED_BY_SIGNAL timestamp=2026-08-04T11:08:20+08:00\n");
    await fs.writeFile(path.join(runDir, "metadata.env"), "duration_seconds=43200\ndeadline_epoch=1999999999\n");
    await fs.writeFile(inspectFixture, JSON.stringify([
      inspectedContainer("ca-postgres", {
        id: "a".repeat(64), name: "ca-postgres", image: "postgres:16",
        running: true, status: "running", health: "healthy", restartCount: 0, ip: "10.0.0.2",
      }),
      inspectedContainer("ca", {
        id: "b".repeat(64), name: "ca", image: "ca:test",
        running: true, status: "running", health: "healthy", restartCount: 1, ip: "10.0.0.3",
      }),
      inspectedContainer("ca-web", {
        id: "c".repeat(64), name: "ca-web", image: "ca-web:test",
        running: true, status: "running", health: "healthy", restartCount: 0, ip: "10.0.0.4",
      }),
    ]));
    await fs.mkdir(fakeBin, { recursive: true });
    await fs.writeFile(path.join(fakeBin, "docker"), [
      "#!/bin/sh",
      "case \"$1\" in",
      "  ps) printf '%s\\n' ca-postgres-id ca-id ca-web-id ;;",
      "  inspect) /bin/cat \"$DASHBOARD_DOCKER_INSPECT_FIXTURE\" ;;",
      "  *) exit 2 ;;",
      "esac",
      "",
    ].join("\n"), { mode: 0o700 });

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      assert.deepEqual(status.status, { outcome: "STOPPED", detail: "signal_requested" });
      assert.equal(status.runState.phase, "STOPPED");
      assert.equal(status.runState.manuallyStopped, true);
      assert.equal(status.runState.stopReason, "MANUAL_SIGNAL");
      assert.deepEqual(status.runState.cleanup, {
        complete: true,
        remainingContainers: 0,
        remainingNetworks: 0,
      });
      assert.deepEqual(status.runState.recordedStatus, {
        outcome: "FAILED",
        detail: "resource_guard_identity_invalid",
      });
      assert.equal(status.timing.remainingSeconds, 0);
      assert.equal(status.resources.mode, "HISTORICAL");
      assert.equal(status.deployment.mode, "CA_ONLY");
      assert.equal(status.deployment.status, "HEALTHY");
      assert.equal(status.deployment.healthy, true);
      assert.equal(status.deployment.running, 3);
      assert.equal(status.deployment.healthyCount, 3);
      assert.equal(status.deployment.workloadRunning, 0);
      assert.equal(status.deployment.totalRestarts, 1);
      assert.deepEqual(status.deployment.services.map((service) => service.service), [
        "ca-postgres", "ca", "ca-web",
      ]);
      assert.equal(status.summary.scope, "TEST_TOPOLOGY");
      assert.equal(status.summary.active, false);
      assert.equal(status.summary.coreHealthy, 0);
      assert.equal(status.summary.natRunning, 0);
      assert.equal(status.summary.totalRunning, 0);
      assert.equal(status.nodes.some((node) => node.service === "ca-postgres" || node.service === "ca-web"), false);

      const page = await dashboardFetch(`http://127.0.0.1:${port}/`);
      const html = await page.text();
      assert.equal(html.includes('id="deploymentPanel"'), true);
      assert.equal(html.includes('id="deploymentNodes"'), true);
      assert.equal(html.includes("冷切换后无压测业务节点残留"), true);
    }, {
      composeProject: "dashboard-ca-only-test",
      env: {
        DASHBOARD_DOCKER_INSPECT_FIXTURE: inspectFixture,
        PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
      },
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

for (const terminalPhase of ["COMPLETED", "FAILED", "RESOURCE_LIMIT", "STOPPED"]) test(`Dashboard force-refreshes ${terminalPhase} malicious nodes from pre-cleanup evidence`, async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-terminal-malicious-"));
  const secretPath = "/private/final/container/state";
  const secretNatContainerID = "a".repeat(64);
  const secretRelayContainerID = "b".repeat(64);
  try {
    const containerProbe = runningContainerProbe({
      secretPath,
      secretNodeID: "c".repeat(64),
      secretContainerID: secretNatContainerID,
    });
    await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
    await fs.writeFile(path.join(runDir, "metadata.env"), "billing_adversary_mode=enforce\n");
    await fs.writeFile(path.join(runDir, "billing-adversary.json"), JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      heartbeatAt: new Date().toISOString(),
      coverage: Object.fromEntries(scenarios.map((scenario) => [scenario, {
        executed: 1,
        contained: 1,
        violations: 0,
      }])),
      summary: { stateChanges: 0 },
      componentProbe: {
        schemaVersion: 1,
        status: "RUNNING",
        executed: scenarios.length,
        failed: 0,
        required: scenarios.length,
        covered: scenarios.length,
      },
      containerProbe,
      recent: [],
    }));
    await fs.writeFile(path.join(runDir, "containers-final.tsv"), [
      "service\tcontainer_id\tstatus\thealth\tstarted_at\trestart_count",
      `malicious-natserver\t${secretNatContainerID}\trunning\thealthy\t${secretPath}\t0`,
      `malicious-relay\t${secretRelayContainerID}\trunning\thealthy\t${secretPath}\t0`,
      "",
    ].join("\n"));

    await withDashboard(runDir, async (port) => {
      const running = await dashboardFetch(`http://127.0.0.1:${port}/api/status`).then((response) => response.json());
      assert.equal(running.phase, "RUNNING");
      assert.equal(running.maliciousNodes.every((node) => node.running === false), true);

      const detail = terminalPhase === "COMPLETED" ? "duration_complete" : "signal_requested";
      await fs.writeFile(path.join(runDir, "status.env"), `outcome=${terminalPhase}\ndetail=${detail}\n`);
      await fs.writeFile(path.join(runDir, "phase"), `${terminalPhase}\n`);
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status?fresh=1`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const terminal = JSON.parse(encoded);
      assert.equal(terminal.phase, terminalPhase);
      assert.deepEqual(terminal.maliciousNodes.map((node) => ({
        service: node.service,
        running: node.running,
        health: node.health,
        restartCount: node.restartCount,
        covered: node.probe.covered,
        required: node.probe.required,
      })), [{
        service: "malicious-natserver",
        running: true,
        health: "healthy",
        restartCount: 0,
        covered: 4,
        required: 4,
      }, {
        service: "malicious-relay",
        running: true,
        health: "healthy",
        restartCount: 0,
        covered: 5,
        required: 5,
      }]);
      for (const secret of [secretPath, secretNatContainerID, secretRelayContainerID]) {
        assert.equal(encoded.includes(secret), false, `terminal malicious evidence leaked ${secret}`);
      }
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard renders malicious node health and containment activity", async () => {
  const html = await fs.readFile(new URL("./index.html", import.meta.url), "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, "Dashboard inline script is missing");
  const maliciousNodes = { innerHTML: "", style: {} };
  const elements = new Map([["maliciousNodes", maliciousNodes]]);
  const context = vm.createContext({
    document: {
      getElementById(id) {
        if (!elements.has(id)) {
          elements.set(id, { className: "", innerHTML: "", style: {}, textContent: "" });
        }
        return elements.get(id);
      },
    },
    fetch: () => new Promise(() => {}),
    setInterval: () => 0,
    window: { addEventListener() {}, devicePixelRatio: 1 },
  });
  vm.runInContext(script, context, { filename: "dashboard-index.html" });
  context.nodes = [{
    service: "malicious-natserver",
    actor: "natserver",
    running: true,
    health: "healthy",
    restartCount: 0,
    probe: { status: "RUNNING", executed: 8, failed: 0, covered: 4, required: 4 },
    latestActivity: {
      observedAt: "2026-07-20T10:00:00Z",
      scenario: "nat_identity_forgery",
      passed: true,
      defense: "relay_rejected_forged_nat_identity",
      failureCode: "",
    },
  }, {
    service: "malicious-relay",
    actor: "relay",
    running: false,
    health: "<img src=x onerror=alert(1)>",
    restartCount: 3,
    probe: { status: "FAILED", executed: 5, failed: 1, covered: 5, required: 5 },
    latestActivity: {
      observedAt: "2026-07-20T10:01:00Z",
      scenario: "relay_usage_inflation",
      passed: false,
      defense: "",
      failureCode: "container_attack_not_contained",
    },
  }];
  vm.runInContext("renderMaliciousNodes(nodes)", context);

  assert.match(maliciousNodes.innerHTML, /malicious-node ok/);
  assert.match(maliciousNodes.innerHTML, /malicious-node bad/);
  assert.match(maliciousNodes.innerHTML, /覆盖 4 \/ 4/);
  assert.match(maliciousNodes.innerHTML, /最近已阻断 · NAT 身份伪造/);
  assert.match(maliciousNodes.innerHTML, /OFFLINE/);
  assert.match(maliciousNodes.innerHTML, /最近 FAIL · Relay 虚增用量/);
  assert.match(maliciousNodes.innerHTML, /container_attack_not_contained/);
  assert.equal(maliciousNodes.innerHTML.includes("<img"), false);
  assert.match(maliciousNodes.innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);

  vm.runInContext("nodes[0].restartCount = 2; renderMaliciousNodes(nodes)", context);
  assert.match(maliciousNodes.innerHTML,
    /<div class="malicious-node bad"><div class="malicious-node-head"><div><strong>malicious-natserver<\/strong>[\s\S]*?<span class="status bad">RESTARTED<\/span>/);
  assert.match(maliciousNodes.innerHTML, /Restart 2/);
});

test("Dashboard includes malicious activity in transfer cards and topology", async () => {
  const html = await fs.readFile(new URL("./index.html", import.meta.url), "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, "Dashboard inline script is missing");
  const elements = new Map();
  const context = vm.createContext({
    document: {
      getElementById(id) {
        if (!elements.has(id)) {
          elements.set(id, { className: "", innerHTML: "", style: {}, textContent: "" });
        }
        return elements.get(id);
      },
    },
    fetch: () => new Promise(() => {}),
    setInterval: () => 0,
    window: { addEventListener() {}, devicePixelRatio: 1 },
  });
  vm.runInContext(script, context, { filename: "dashboard-index.html" });
  context.transfers = {
    available: true,
    summary: { totalTransfers: 1, succeeded: 1, failed: 0, clientCount: 6, activeClients: 1 },
    byClient: {
      natclient01: {
        summary: { totalTransfers: 1, succeeded: 1, failed: 0 },
        ipType: "IPv6",
        transportStack: "KCP/UDP + TCP 故障切换",
        recent: [{
          timestamp: "2026-07-20T10:00:00Z",
          ingress_relay: "relay01",
          server: "natserver01",
          bytes: 1048576,
          seconds: 1,
          mib_per_second: 1,
          requested_mib: 1,
          rc: "0",
          sha256_ok: "yes",
          serverIPType: "IPv4 + IPv6 双栈",
          transportStack: "KCP/UDP + TCP 故障切换",
          networkStack: "IPv6 → IPv4 + IPv6 双栈 · KCP/UDP + TCP 故障切换",
        }],
      },
    },
    byServer: {
      natserver01: {
        summary: { totalTransfers: 2, succeeded: 2, failed: 0 },
        ipType: "IPv4 + IPv6 双栈",
        networkStack: "IPv4 + IPv6 双栈 · KCP/UDP + TCP 故障切换",
        distinctClients: 2,
        recentClients: ["natclient01", "natclient02"],
        lastTransferAt: "2026-07-20T10:00:00Z",
        lastClient: "natclient02",
        lastIngressRelay: "relay01",
      },
    },
  };
  context.maliciousNodes = [{
    service: "malicious-natserver",
    actor: "natserver",
    running: true,
    health: "healthy",
    restartCount: 0,
    probe: { status: "RUNNING", executed: 8, failed: 0, covered: 4, required: 4 },
  }, {
    service: "malicious-relay",
    actor: "relay",
    running: true,
    health: "healthy",
    restartCount: 0,
    probe: { status: "RUNNING", executed: 9, failed: 0, covered: 5, required: 5 },
  }];
  context.maliciousEvents = [{
    sequence: 9,
    observedAt: "2026-07-20T10:02:00Z",
    scenario: "relay_voucher_tamper",
    actor: "relay",
    passed: true,
    verdict: "CONTAINED",
    requestCount: 2,
    httpStatuses: [200, 400],
    defense: "ca_rejected_tampered_double_signature",
    path: "malicious-relay->malicious-natserver->ca",
  }, {
    sequence: 8,
    observedAt: "2026-07-20T10:01:00Z",
    scenario: "nat_identity_forgery",
    actor: "natserver",
    passed: true,
    verdict: "CONTAINED",
    requestCount: 1,
    httpStatuses: [200],
    defense: "relay_rejected_forged_nat_identity",
    path: "malicious-natserver->malicious-relay",
  }];
  context.mixedPath = {
    available: true,
    status: "RUNNING",
    healthy: true,
    generation: 2,
    path: {
      state: "active",
      nodes: ["mixed-path-probe", "relay05", "relay04", "malicious-natserver"],
      kind: "normal_partition_mixed_adversary",
      normalPartitions: ["control_partition_a"],
      containsNormalPartition: true,
      containsMaliciousNode: true,
    },
    attachments: {
      maliciousNatserver: { currentRelay: "relay04", normalPartition: "control_partition_a", basis: "live_relay_registration" },
      normalProbe: { currentRelay: "relay05", normalPartition: "control_partition_a", basis: "live_tunnel_registration" },
      maliciousRelay: { currentRelay: "relay03", normalPartition: "control_partition_a", basis: "live_control_hello" },
    },
    probe: { status: "PASS", successes: 7, bytes: 1048576, sha256Verified: true },
    lastTrigger: { scenario: "relay_voucher_tamper" },
    networkCoverage: [{
      scenario: "relay_voucher_tamper", actor: "relay", executed: 1, contained: 1, violations: 0,
    }],
    networkSummary: { executed: 1, contained: 1, violations: 0, covered: 1, required: 9 },
    migrations: [{
      generation: 2,
      endpoint: "malicious-relay",
      previousRelay: "relay03",
      currentRelay: "relay05",
      normalPartition: "control_partition_a",
      switchedAt: "2026-07-20T10:03:00Z",
      probePassed: true,
      isolationVerified: true,
      triggerContained: true,
      containmentVerified: true,
      trigger: {
        actor: "relay", scenario: "relay_voucher_tamper", contained: true,
        defense: "ca_rejected_tampered_double_signature",
      },
    }],
    containment: { status: "VERIFIED", verifiedMigrations: 2 },
  };

  vm.runInContext("renderClientTransfers(transfers, {}, maliciousNodes, maliciousEvents, mixedPath)", context);
  const transferMarkup = elements.get("clientTransfers").innerHTML;
  assert.match(transferMarkup, /natclient01/);
  assert.match(transferMarkup, /恶意 NAT Server/);
  assert.match(transferMarkup, /恶意 Relay/);
  assert.match(transferMarkup, /Relay 篡改记录根/);
  assert.doesNotMatch(transferMarkup, /malicious-relay → malicious-natserver/);
  assert.match(transferMarkup, /已阻断/);
  assert.match(transferMarkup, /对应防范措施/);
  assert.match(transferMarkup, /CA 双签验证拒绝被篡改的记录根/);
  assert.match(transferMarkup, /真实正常分区随机恶意行为/);
  assert.match(transferMarkup, /relay03 → 恶意 Relay → 隔离 → relay05 → 恶意 Relay/);
  assert.match(transferMarkup, /主网处置覆盖 1 \/ 9/);
  assert.match(transferMarkup, /SHA-256 PASS/);
  assert.match(transferMarkup, /真实正常分区接入/);
  assert.match(transferMarkup, /已阻断并隔离/);
  const serverTimelineMarkup = elements.get("serverTransferTimeline").innerHTML;
  assert.match(serverTimelineMarkup, /NatServer 被随机命中的时间线|natserver01/);
  assert.match(serverTimelineMarkup, /IPv4 \+ IPv6 双栈/);
  assert.match(serverTimelineMarkup, /natclient02 → relay01 → natserver01/);
  assert.match(serverTimelineMarkup, /不同 Client 2/);
  context.randomBatches = {
    policy: {
      multiClientProbabilityPct: 60,
      multiClientMin: 2,
      multiClientMax: 4,
      clientStartStaggerSeconds: 30,
      mixedPathQuietSamples: 3,
      mixedPathQuietTimeoutSeconds: 45,
      rateLimitsKiBps: [
        { clients: 1, kibps: 5120 },
        { clients: 2, kibps: 5120 },
        { clients: 3, kibps: 5120 },
        { clients: 4, kibps: 5120 },
      ],
    },
    summary: { totalBatches: 1, multiClientBatches: 1, maliciousSelectedBatches: 1, maliciousServerBatches: 1, failedBatches: 0 },
    recent: [{
      timestamp: "2026-07-20T10:04:00Z",
      batchID: "batch-1-1",
      selectedServer: "malicious-random-natserver",
      serverMalicious: true,
      mode: "multi",
      requestedClients: 2,
      selectedClients: ["natclient01", "malicious-natclient"],
      maliciousSelected: true,
      status: "PASS",
      targets: [{ client: "natclient01", server: "malicious-random-natserver" }, { client: "malicious-natclient", server: "malicious-random-natserver" }],
      succeeded: 2,
      failed: 0,
    }],
  };
  vm.runInContext("renderRandomBatches(randomBatches)", context);
  assert.match(elements.get("randomBatchSummary").innerHTML, /多 Client 概率<strong>60%/);
  assert.match(elements.get("randomBatchSummary").innerHTML, /建连错峰<strong>30 秒 \/ Client/);
  assert.match(elements.get("randomBatchSummary").innerHTML, /迁移静默窗<strong>连续 3 秒稳定/);
  assert.match(elements.get("randomBatchSummary").innerHTML, /4 Client × 5 MiB\/s/);
  assert.match(elements.get("randomBatchList").innerHTML, /malicious-natclient/);
  assert.match(elements.get("randomBatchList").innerHTML, /步骤 0 · 本批目标 Server/);
  assert.match(elements.get("randomBatchList").innerHTML, /malicious-random-natserver（恶意）/);
  assert.match(elements.get("randomBatchList").innerHTML, /含恶意节点/);

  context.sessionTopology = vm.runInContext(`normalizeTopology({nodes:[]}, [], [], [], {}, {
    sessions:[{connectionID:'1234abcd',client:'natclient02',clientRelay:'relay01',
      serverRelay:'relay03',server:'natserver03'}]
  })`, context);
  assert.equal(context.sessionTopology.links.some((link) => link.source === "natclient02"
    && link.target === "relay01" && link.kind === "service-session"), true);
  assert.equal(context.sessionTopology.links.some((link) => link.source === "relay01"
    && link.target === "relay03" && link.kind === "service-session"), true);
  assert.equal(context.sessionTopology.links.some((link) => link.source === "relay03"
    && link.target === "natserver03" && link.kind === "service-session"), true);

  context.topology = vm.runInContext(
    "normalizeTopology({nodes:[{id:'ca',role:'ca',running:true,health:'healthy'}]}, [], maliciousNodes, maliciousEvents, mixedPath)",
    context,
  );
  assert.equal(context.topology.links.some((link) => link.source === "relay04"
    && link.target === "malicious-natserver" && link.kind === "attack"), true);
  assert.equal(context.topology.links.some((link) => link.source === "relay03"
    && link.target === "malicious-relay" && link.kind === "control"), true);
  assert.equal(context.topology.links.some((link) => link.source.startsWith("malicious-")
    && link.target.startsWith("malicious-")), false);
  vm.runInContext("renderTopologyGraph(topology); renderMaliciousPath(topology.attackPath)", context);
  const topologyMarkup = elements.get("topologyGraph").innerHTML;
  assert.match(topologyMarkup, /topology-node malicious-natserver/);
  assert.match(topologyMarkup, /topology-node malicious-relay/);
  assert.match(topologyMarkup, /topology-edge attack-contained/);
  assert.match(topologyMarkup, /NORMAL PARTITIONS \+ MIXED ADVERSARY \(FIXTURE SEPARATE\)/);
  assert.match(topologyMarkup, /topology-node natclient active[^>]*mixed-path-probe|mixed-path-probe/);
  assert.match(topologyMarkup, /真实混合 P2P Payload/);
  assert.match(elements.get("maliciousPath").innerHTML, /Relay 篡改记录根/);
  assert.match(elements.get("maliciousPath").innerHTML, /已阻断/);
  assert.match(elements.get("maliciousPath").innerHTML, /SHA-256 PASS/);
  assert.match(elements.get("maliciousPath").innerHTML, /正常分区 A/);
});

test("Dashboard whitelists real mixed P2P attachments and migration evidence", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-mixed-path-"));
  const secretNodeID = "a".repeat(64);
  const secretPath = "/private/mixed/path";
  try {
    await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
    await fs.writeFile(path.join(runDir, "mixed-adversary-path.json"), JSON.stringify({
      schemaVersion: 1,
      status: "MIGRATING",
      heartbeatAt: new Date().toISOString(),
      generation: 2,
      observedTriggers: 4,
      nodeID: secretNodeID,
      privatePath: secretPath,
      attachments: {
        maliciousNatserver: {
          currentRelay: "relay04",
          previousRelay: "relay03",
          attachmentType: "registered_to_normal_relay",
          normalPartition: "control_partition_a",
          basis: "live_relay_registration",
          generation: 1,
          running: false,
          switchedAt: "2026-07-20T10:00:00Z",
          lastScenario: "nat_identity_forgery",
          nodeID: secretNodeID,
        },
        normalProbe: {
          currentRelay: "relay05",
          previousRelay: "malicious-relay",
          attachmentType: "connected_to_normal_relay",
          normalPartition: "control_partition_a",
          basis: "live_tunnel_registration",
          generation: 1,
          running: true,
          switchedAt: "2026-07-20T10:01:00Z",
          lastScenario: "relay_usage_inflation",
        },
        maliciousRelay: {
          currentRelay: "relay03",
          attachmentType: "control_peer_with_normal_relay",
          normalPartition: "control_partition_a",
          basis: "live_control_hello",
          peerDirection: "normal_relay_to_malicious_relay",
          generation: 0,
          running: true,
        },
      },
      path: {
        state: "active",
        nodes: ["mixed-path-probe", "relay05", "relay04", "malicious-natserver", secretNodeID],
        transport: "real_p2p_tunnel_http_payload",
        basis: "live_process_attachment_and_sha256_payload_probe",
        kind: "normal_partition_mixed_adversary",
        normalRelays: ["relay03", "relay04", "relay05"],
        normalPartitions: ["control_partition_a"],
        containsNormalPartition: true,
        containsMaliciousNode: true,
      },
      probe: {
        status: "PASS",
        observedAt: "2026-07-20T10:02:00Z",
        successes: 8,
        failures: 0,
        consecutiveFailures: 0,
        bytes: 1048576,
        sha256Verified: true,
      },
      lastTrigger: {
        actor: "relay",
        scenario: "relay_usage_inflation",
        sequence: 9,
        observedAt: "2026-07-20T10:01:00Z",
        contained: true,
        nodeID: secretNodeID,
      },
      migrations: [{
        generation: 2,
        endpoint: "malicious-relay",
        previousRelay: "relay03",
        currentRelay: "relay05",
        failureInjected: true,
        isolationVerified: true,
        triggerContained: true,
        containmentVerified: true,
        probePassed: true,
        normalPartition: "control_partition_a",
        postContainmentPath: ["mixed-path-probe", "relay05", "relay04", "malicious-natserver"],
        switchedAt: "2026-07-20T10:01:00Z",
        trigger: {
          actor: "relay",
          scenario: "relay_usage_inflation",
          sequence: 9,
          observedAt: "2026-07-20T10:01:00Z",
          contained: true,
          defense: "ca_rejected_tampered_double_signature",
          requestCount: 2,
          httpStatuses: [200, 400],
        },
      }],
      networkCoverage: [
        { scenario: "relay_voucher_tamper", actor: "relay", executed: 1, contained: 1, violations: 0 },
      ],
      containment: {
        status: "VERIFIED",
        verifiedMigrations: 2,
        lastScenario: "relay_usage_inflation",
        lastActor: "relay",
        lastAction: "isolate_malicious_relay_and_migrate_to_random_normal_relay",
        verifiedAt: "2026-07-20T10:02:00Z",
      },
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status?fresh=1`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const status = JSON.parse(encoded);
      assert.equal(status.mixedPath.available, true);
      assert.equal(status.mixedPath.healthy, true);
      assert.equal(status.mixedPath.generation, 2);
      assert.deepEqual(status.mixedPath.path.nodes, [
        "mixed-path-probe", "relay05", "relay04", "malicious-natserver",
      ]);
      assert.equal(status.mixedPath.attachments.maliciousNatserver.currentRelay, "relay04");
      assert.equal(status.mixedPath.attachments.normalProbe.previousRelay, "malicious-relay");
      assert.equal(status.mixedPath.attachments.maliciousNatserver.normalPartition, "control_partition_a");
      assert.equal(status.mixedPath.attachments.maliciousRelay.currentRelay, "relay03");
      assert.equal(status.mixedPath.diagnostics.attachmentEvidenceValid, true);
      assert.equal(status.mixedPath.diagnostics.requiredAttachmentsRunning, false);
      assert.equal(status.mixedPath.diagnostics.attachmentLifecycleReady, true);
      assert.equal(status.mixedPath.path.containsNormalPartition, true);
      assert.equal(status.mixedPath.probe.sha256Verified, true);
      assert.equal(status.mixedPath.migrations[0].failureInjected, true);
      assert.equal(status.mixedPath.migrations[0].containmentVerified, true);
      assert.equal(status.mixedPath.migrations[0].endpoint, "malicious-relay");
      assert.equal(status.mixedPath.migrations[0].trigger.defense, "ca_rejected_tampered_double_signature");
      assert.equal(status.mixedPath.networkSummary.covered, 1);
      assert.equal(status.mixedPath.containment.verifiedMigrations, 2);
      assert.equal(status.topology.links.some((link) => link.kind === "mixed-attack"), true);
      assert.equal(status.topology.links.some((link) => link.kind === "mixed-relay-control"
        && link.source === "relay03" && link.target === "malicious-relay"), true);
      assert.equal(encoded.includes(secretNodeID), false);
      assert.equal(encoded.includes(secretPath), false);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

function inspectedContainer(service, options) {
  return {
    Id: options.id,
    Name: options.name,
    Config: {
      Image: options.image,
      Labels: { "com.docker.compose.service": service },
    },
    State: {
      Status: options.status,
      Running: options.running,
      Health: { Status: options.health },
      StartedAt: options.name,
      FinishedAt: options.name,
      Pid: 4242,
    },
    RestartCount: options.restartCount,
    NetworkSettings: {
      Networks: {
        private_adversary_network: { IPAddress: options.ip },
      },
    },
  };
}

test("Dashboard fails closed and redacts malformed Go component probe values", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-component-probe-invalid-"));
  const secret = "/private/component/state/with-node-id-" + "d".repeat(64);
  try {
    await fs.writeFile(path.join(runDir, "billing-adversary.json"), JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      heartbeatAt: new Date().toISOString(),
      coverage: Object.fromEntries(scenarios.map((scenario) => [scenario, {
        executed: 1,
        contained: 1,
        violations: 0,
      }])),
      summary: { stateChanges: 0 },
      componentProbe: {
        schemaVersion: "1",
        status: secret,
        executed: "9",
        failed: -1,
        required: 9.5,
        covered: 10,
        rawError: secret,
        command: secret,
        pid: secret,
      },
      containerProbe: {
        schemaVersion: "1",
        status: secret,
        executed: "9",
        failed: -1,
        required: 9.5,
        covered: 10,
        rawPath: secret,
      },
      recent: [],
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const status = JSON.parse(encoded);
      assert.deepEqual(status.billingAdversary.componentProbe, {
        schemaVersion: 1,
        status: "FAILED",
        executed: 0,
        failed: 1,
        required: scenarios.length,
        covered: 0,
      });
      assert.equal(status.billingAdversary.healthy, false);
      assert.equal(status.billingAdversary.containerProbe.status, "FAILED");
      assert.equal(status.billingAdversary.containerProbe.required, containerScenarios.length);
      assert.deepEqual(status.maliciousNodes.map((node) => node.service), [
        "malicious-natserver",
        "malicious-relay",
      ]);
      assert.deepEqual(status.maliciousNodes.map((node) => node.probe.status), ["FAILED", "FAILED"]);
      assert.equal(status.maliciousNodes.every((node) => node.running === false), true);
      assert.equal(status.maliciousNodes.every((node) => node.health === "missing"), true);
      assert.equal(encoded.includes(secret), false);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard health rejects incomplete Go component scenario coverage", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-component-probe-incomplete-"));
  try {
    await fs.writeFile(path.join(runDir, "billing-adversary.json"), JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      heartbeatAt: new Date().toISOString(),
      coverage: Object.fromEntries(scenarios.map((scenario) => [scenario, {
        executed: 1,
        contained: 1,
        violations: 0,
      }])),
      summary: { stateChanges: 0 },
      componentProbe: {
        schemaVersion: 1,
        status: "RUNNING",
        executed: scenarios.length,
        failed: 0,
        required: scenarios.length,
        covered: scenarios.length - 1,
      },
      recent: [],
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      assert.equal(status.billingAdversary.componentProbe.status, "RUNNING");
      assert.equal(status.billingAdversary.componentProbe.failed, 0);
      assert.equal(status.billingAdversary.componentProbe.covered, scenarios.length - 1);
      assert.equal(status.billingAdversary.healthy, false);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard maps untrusted runtime strings to public aliases", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-aliases-"));
  const secretPath = "/sensitive/private/runtime/path";
  const secretNodeID = "a".repeat(64);
  const secretToken = "b".repeat(32);
  const secretContainerID = "c".repeat(64);
  const secretImage = "privateimage";
  try {
    await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
    await fs.writeFile(path.join(runDir, "metadata.env"), [
      "scenario=1",
      `scenario_name=${secretPath}`,
      "duration_seconds=43200",
      "billing_adversary_mode=enforce",
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "workload.env"), [
      `server=${secretPath}`,
      `client=${secretNodeID}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "resource-guard.status"), `RUNNING detail=${secretPath}\n`);
    await fs.writeFile(path.join(runDir, "status.env"), [
      `outcome=${secretContainerID}`,
      `detail=${secretNodeID}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "resources.tsv"), [
      "timestamp\tepoch\tcontainers\tstate",
      `2026-07-20T00:00:00Z\t1\t1\t${secretToken}`,
      `2026-07-20T00:00:01Z\t2\t1\t${secretImage}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "failure-watcher.json"), JSON.stringify({
      schemaVersion: 1,
      status: "FAILED",
      heartbeatAt: new Date().toISOString(),
      source: { available: false, sizeBytes: 0, offsetBytes: 0 },
      alerts: { recent: [] },
      lastError: { at: new Date().toISOString(), code: secretToken },
    }));
    await fs.writeFile(path.join(runDir, "billing-adversary.json"), JSON.stringify({
      schemaVersion: 1,
      status: "FAILED",
      heartbeatAt: new Date().toISOString(),
      componentProbe: { schemaVersion: 1, status: "FAILED", executed: 0, failed: 1, required: scenarios.length, covered: 0 },
      lastError: { at: new Date().toISOString(), code: secretContainerID },
    }));
    await fs.writeFile(path.join(runDir, "probes.tsv"), [
      "timestamp\tlabel\trc\tbytes\tseconds\tsha256_ok\tclient",
      `2026-07-20T00:00:00Z\t${secretPath}\t0\t1\t1\tyes\t${secretNodeID}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "transfers.tsv"), [
      "timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha",
      `2026-07-20T00:00:00Z\tprivate-transfer\tnatclient01\t${secretNodeID}\t${secretPath}\t1\t0\t1048576\t1\t1\tyes\t${secretNodeID}\t${secretNodeID}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "compose.json"), JSON.stringify({
      services: {
        [`relay${secretNodeID}`]: { networks: [secretPath] },
      },
      networks: {
        [secretPath]: { internal: true },
      },
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      const encoded = JSON.stringify(status);
      for (const secret of [secretPath, secretNodeID, secretToken, secretContainerID, secretImage]) {
        assert.equal(encoded.includes(secret), false, `generic API field leaked ${secret}`);
      }
      assert.equal(encoded.includes("transfers.tsv"), false);
      assert.equal(encoded.includes("transfer-logs/"), false);
      assert.deepEqual(status.status, { outcome: "", detail: "status_detail_redacted" });
      assert.equal(status.resources.latest.state, "UNKNOWN");
      assert.equal(status.resources.history[0].state, "UNKNOWN");
      assert.equal(status.failureWatcher.lastError.code, "watcher_error");
      assert.equal(status.billingAdversary.lastError.code, "billing_adversary_error");
      assert.equal(status.metadata.scenario_name, "partition_bridge");
      assert.equal(status.resourceGuard, "RUNNING");
      assert.equal(status.probes.latest.label, "probe");
      assert.equal(status.probes.latest.client, "unknown");
      assert.equal(status.clientTransfers.byClient.natclient01.recent[0].ingress_relay, "unknown");
      assert.equal(status.clientTransfers.byClient.natclient01.recent[0].server, "unknown");
      assert.equal(status.topology.activePath.client, "");
      assert.equal(status.topology.activePath.server, "");
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard rejects active paths that require multiple Relay control hops", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-relay-route-"));
  try {
    await fs.mkdir(path.join(runDir, "runtime", "stability"), { recursive: true });
    await fs.writeFile(path.join(runDir, "workload.env"), "client=natclient01\nserver=natserver01\n");
    await fs.writeFile(
      path.join(runDir, "runtime", "stability", "natclient01.log"),
      "使用指定 relay: relay04:9000\n",
    );
    await fs.writeFile(
      path.join(runDir, "runtime", "stability", "natserver01.log"),
      "注册到 relay: relay03:9000\n",
    );
    await fs.writeFile(path.join(runDir, "compose.json"), JSON.stringify({
      services: {
        relay01: { command: ["nodeserver", "-index", "index:9000"], networks: ["control_partition_a"] },
        relay03: { command: ["nodeserver", "-index", "relay01:9000"], networks: ["control_partition_a"] },
        relay04: { command: ["nodeserver", "-index", "relay01:9000"], networks: ["control_partition_a"] },
        natclient01: { networks: ["access_r4"] },
        natserver01: { networks: ["access_r3"] },
      },
      networks: {
        control_partition_a: { internal: true },
        access_r3: { internal: true },
        access_r4: { internal: true },
      },
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      assert.deepEqual(status.topology.relayControlLinks.map((link) => [link.source, link.target]), [
        ["relay01", "index"],
        ["relay03", "relay01"],
        ["relay04", "relay01"],
      ]);
      assert.equal(status.topology.activePath.state, "blocked");
      assert.equal(status.topology.activePath.label, "Relay 路由不可达：relay04 → relay03");
      assert.deepEqual(status.topology.activePath.nodes, [
        "natclient01",
        "relay04",
        "relay03",
        "natserver01",
      ]);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard strictly whitelists the production waitSubmit gate and public metrics", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-production-gate-"));
  const secret = "/private/production/relay/node-id";
  const observedAt = "2026-07-20T04:05:06Z";
  try {
    await fs.writeFile(path.join(runDir, "phase"), "VERIFYING_BILLING\n");
    await fs.writeFile(path.join(runDir, "metadata.env"), [
      "duration_seconds=43200",
      "started_epoch=1",
      "deadline_epoch=4102444800",
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "resources.tsv"), [
      "timestamp\tepoch\tcontainers\tstate\tproject_cpu_host_pct\tproject_memory_bytes\tproject_memory_host_pct\tprivate_node",
      `2026-07-20T04:05:06Z\t1\t27\tRUNNING\t1.5\t987654321\t2.5\t${secret}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "billing-production-gate.json"), JSON.stringify({
      schemaVersion: 2,
      status: "PASSED",
      detail: "verified",
      queueDepthBefore: 3,
      queueDepthAfterRestart: 3,
      queueDepthAfterRecovery: 0,
      transferBytes: 4194304,
      observedBillableBytes: 4899040,
      authorizedBillableBytes: 4811576,
      payerDebit: 4811576,
      unsettledTailBytes: 87464,
      relayCredit: 4570997,
      caCredit: 240579,
      amountVerified: true,
      splitVerified: true,
      observedAt,
      relayNodeID: secret,
      queuePath: secret,
      natSnapshotPath: secret,
      rawAuthorization: `private-key:${secret}`,
      nestedEvidence: { secret },
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      const encoded = JSON.stringify(status);
      assert.equal(status.phase, "VERIFYING_BILLING");
      assert.deepEqual(status.billingProductionGate, {
        schemaVersion: 2,
        status: "PASSED",
        detail: "verified",
        queueDepthBefore: 3,
        queueDepthAfterRestart: 3,
        queueDepthAfterRecovery: 0,
        transferBytes: 4194304,
        observedBillableBytes: 4899040,
        authorizedBillableBytes: 4811576,
        payerDebit: 4811576,
        unsettledTailBytes: 87464,
        relayCredit: 4570997,
        caCredit: 240579,
        amountVerified: true,
        splitVerified: true,
        observedAt,
      });
      assert.deepEqual(Object.keys(status.billingProductionGate), [
        "schemaVersion",
        "status",
        "detail",
        "queueDepthBefore",
        "queueDepthAfterRestart",
        "queueDepthAfterRecovery",
        "transferBytes",
        "observedBillableBytes",
        "authorizedBillableBytes",
        "payerDebit",
        "unsettledTailBytes",
        "relayCredit",
        "caCredit",
        "amountVerified",
        "splitVerified",
        "observedAt",
      ]);
      assert.equal(status.billingProductionGate.payerDebit > status.billingProductionGate.transferBytes, true);
      assert.equal(status.billingProductionGate.payerDebit, status.billingProductionGate.authorizedBillableBytes);
      assert.deepEqual(Object.keys(status.timing).sort(), ["durationSeconds", "remainingSeconds"]);
      assert.equal(status.nodes.every((node) => !Object.hasOwn(node, "startedAt")), true);
      assert.equal(Object.hasOwn(status.resources.latest, "project_memory_bytes"), false);
      assert.equal(status.resources.history.every((sample) => !Object.hasOwn(sample, "project_memory_bytes")), true);
      assert.equal(encoded.includes(secret), false);
      assert.equal(encoded.includes("987654321"), false);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard fails closed on malformed production waitSubmit gate values", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-production-gate-invalid-"));
  const secret = "/private/ledger/relay-node-id";
  try {
    await fs.writeFile(path.join(runDir, "billing-production-gate.json"), JSON.stringify({
      schemaVersion: 2,
      status: "FAILED",
      detail: secret,
      queueDepthBefore: "3",
      queueDepthAfterRestart: -1,
      queueDepthAfterRecovery: 1.5,
      transferBytes: Number.MAX_SAFE_INTEGER + 1,
      observedBillableBytes: "4194304",
      authorizedBillableBytes: -1,
      payerDebit: Number.MAX_SAFE_INTEGER + 1,
      unsettledTailBytes: 0.5,
      relayCredit: null,
      caCredit: -1,
      amountVerified: "true",
      splitVerified: "true",
      observedAt: "not-a-timestamp",
      rawError: `cannot read ${secret}`,
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      assert.deepEqual(status.billingProductionGate, {
        schemaVersion: 2,
        status: "FAILED",
        detail: "billing_production_gate_failed",
        queueDepthBefore: 0,
        queueDepthAfterRestart: 0,
        queueDepthAfterRecovery: 0,
        transferBytes: 0,
        observedBillableBytes: 0,
        authorizedBillableBytes: 0,
        payerDebit: 0,
        unsettledTailBytes: 0,
        relayCredit: 0,
        caCredit: 0,
        amountVerified: false,
        splitVerified: false,
        observedAt: "",
      });
      assert.equal(JSON.stringify(status).includes(secret), false);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard preserves and renders a whitelisted production gate root cause", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-production-gate-detail-"));
  const secret = "/private/ca/ledger.json";
  try {
    await fs.writeFile(path.join(runDir, "billing-production-gate.json"), JSON.stringify({
      schemaVersion: 2,
      status: "FAILED",
      detail: "billing_production_gate_payer_overcharged",
      queueDepthBefore: 3,
      queueDepthAfterRestart: 3,
      queueDepthAfterRecovery: 0,
      transferBytes: 4194304,
      observedBillableBytes: 4811576,
      authorizedBillableBytes: 4811576,
      payerDebit: 4811577,
      unsettledTailBytes: 0,
      relayCredit: 4570997,
      caCredit: 240579,
      amountVerified: false,
      splitVerified: false,
      observedAt: "2026-07-20T04:05:06Z",
      rawError: `accounting source ${secret}`,
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const status = JSON.parse(encoded);
      assert.equal(status.billingProductionGate.detail, "billing_production_gate_payer_overcharged");
      assert.equal(encoded.includes(secret), false);

      const page = await dashboardFetch(`http://127.0.0.1:${port}/`);
      const html = await page.text();
      assert.equal(page.status, 200);
      assert.equal(html.includes("失败原因"), true);
      assert.equal(html.includes("billing_production_gate_payer_overcharged"), true);
      assert.equal(html.includes("扣款超过双签授权量"), true);
      assert.equal(html.includes("HTTP 文件体"), true);
      assert.equal(html.includes("NAT 私有观测计费量"), true);
      assert.equal(html.includes("WAL 双签授权量"), true);
      assert.equal(html.includes("实际扣款"), true);
      assert.equal(html.includes("未结算尾量"), true);
      assert.equal(html.includes("billing_production_gate_recovery_transfer_failed"), true);
      assert.equal(html.includes("Relay 恢复后的真实传输失败"), true);
      assert.equal(html.includes("billing_production_gate_recovery_server_restart_failed"), true);
      assert.equal(html.includes("恢复验证前 NAT Server 重启失败"), true);
      assert.equal(html.includes("billing_production_gate_recovery_queue_timeout"), true);
      assert.equal(html.includes("恢复传输后计费队列未按时清空"), true);
      assert.equal(html.includes(secret), false);
      for (const detail of productionGateEvidenceDetails) assert.equal(html.includes(detail), true);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard whitelists schema2 production gate evidence failure codes", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-production-gate-codes-"));
  const secret = "raw-private-billing-evidence";
  try {
    for (const detail of productionGateEvidenceDetails) {
      await fs.writeFile(path.join(runDir, "billing-production-gate.json"), JSON.stringify({
        schemaVersion: 2,
        status: "FAILED",
        detail,
        queueDepthBefore: 1,
        queueDepthAfterRestart: 1,
        queueDepthAfterRecovery: 0,
        transferBytes: 4194304,
        observedBillableBytes: 4811576,
        authorizedBillableBytes: 4811576,
        payerDebit: 4811576,
        unsettledTailBytes: 0,
        relayCredit: 4570997,
        caCredit: 240579,
        amountVerified: false,
        splitVerified: false,
        observedAt: "2026-07-20T04:05:06Z",
        rawEvidence: { privateKey: secret, walPath: `/private/${secret}` },
      }));
      await withDashboard(runDir, async (port) => {
        const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
        assert.equal(response.status, 200);
        const encoded = await response.text();
        assert.equal(JSON.parse(encoded).billingProductionGate.detail, detail);
        assert.equal(encoded.includes(secret), false);
      });
    }
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard exposes time-based many-client random targets with IP and stack metadata", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-random-targets-"));
  const secretEndpoint = "private-relay-endpoint.example:9000";
  const secretNodeID = "e".repeat(64);
  try {
    await fs.writeFile(path.join(runDir, "server-pool.tsv"), [
      "server\tingress_relay\trelay_endpoint\tip_family\tnode_id",
      `natserver03\trelay03\t${secretEndpoint}\tdefault\t${secretNodeID}`,
      `natserver04\trelay04\t${secretEndpoint}\tipv6\t${secretNodeID}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "client-pool.tsv"), [
      "client\tingress_relay\trelay_endpoint\tip_family\tlisten_port\tnode_id",
      `natclient01\trelay03\t${secretEndpoint}\tdefault\t18101\t${secretNodeID}`,
      `natclient02\trelay03\t${secretEndpoint}\tdefault\t18102\t${secretNodeID}`,
      `natclient03\trelay04\t${secretEndpoint}\tipv6\t18103\t${secretNodeID}`,
      `malicious-natclient\trelay03\t${secretEndpoint}\tdefault\t18107\t${secretNodeID}`,
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "ip-family-plan.tsv"), [
      "family\trelay\tnatserver\tnatclient",
      "ipv4\trelay03\tnatserver05\tnatclient04",
      "ipv6\trelay04\tnatserver04\tnatclient03",
      "dual\trelay05\tnatserver06\tnatclient05",
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "transfers.tsv"), [
      "timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha",
      "2026-07-20T10:00:00Z\ttransfer-1\tnatclient01\trelay03\tnatserver03\t5\t0\t5242880\t1\t5\tyes\ta\ta",
      "2026-07-20T10:03:00Z\ttransfer-2\tnatclient02\trelay03\tnatserver03\t5\t0\t5242880\t1\t5\tyes\tb\tb",
      "2026-07-20T10:06:00Z\ttransfer-3\tnatclient03\trelay04\tnatserver04\t5\t0\t5242880\t1\t5\tyes\tc\tc",
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "random-batches.tsv"), [
      "timestamp\tbatch_id\tselected_server\tserver_pool_includes_malicious\tserver_malicious\tmode\trequested_clients\tselected_clients\tclient_pool_includes_malicious\tmalicious_client_selected\tstatus\ttarget_pairs\tsucceeded\tfailed",
      "2026-07-20T10:03:00Z\tbatch-100-1\tmalicious-random-natserver\ttrue\ttrue\tmulti\t2\tnatclient01,malicious-natclient\ttrue\ttrue\tRUNNING\tnatclient01→malicious-random-natserver,malicious-natclient→malicious-random-natserver\t0\t0",
      "2026-07-20T10:06:00Z\tbatch-100-1\tmalicious-random-natserver\ttrue\ttrue\tmulti\t2\tnatclient01,malicious-natclient\ttrue\ttrue\tPASS\tnatclient01→malicious-random-natserver,malicious-natclient→malicious-random-natserver\t2\t0",
      "",
    ].join("\n"));
    await fs.writeFile(path.join(runDir, "workload.env"), [
      "batch_limit_1_client_kibps=5120",
      "batch_limit_2_clients_kibps=5120",
      "batch_limit_3_clients_kibps=5120",
      "batch_limit_4_clients_kibps=5120",
      "batch_client_start_stagger_seconds=30",
      "batch_mixed_path_quiet_samples=3",
      "batch_mixed_path_quiet_timeout_seconds=45",
      "",
    ].join("\n"));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status?fresh=1`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const status = JSON.parse(encoded);
      const server = status.clientTransfers.byServer.natserver03;
      assert.equal(server.summary.totalTransfers, 2);
      assert.equal(server.summary.succeeded, 2);
      assert.equal(server.distinctClients, 2);
      assert.deepEqual(server.recentClients, ["natclient01", "natclient02"]);
      assert.equal(server.lastTransferAt, "2026-07-20T10:03:00Z");
      assert.equal(server.lastClient, "natclient02");
      assert.equal(server.lastIngressRelay, "relay03");
      assert.equal(server.ipType, "IPv4（默认网络）");
      assert.equal(server.transportStack, "KCP/UDP + TCP 故障切换");
      const ipv6Transfer = status.clientTransfers.byClient.natclient03.recent[0];
      assert.equal(ipv6Transfer.clientIPType, "IPv6");
      assert.equal(ipv6Transfer.serverIPType, "IPv6");
      assert.equal(ipv6Transfer.networkStack, "IPv6 · KCP/UDP + TCP 故障切换");
      assert.equal(status.nodes.find((node) => node.service === "relay04").ipType, "IPv6");
      assert.equal(status.topology.nodes.find((node) => node.service === "natserver04").networkStack,
        "IPv6 · KCP/UDP + TCP 故障切换");
      assert.equal(status.topology.nodes.find((node) => node.service === "malicious-random-natserver").role,
        "natserver");
      assert.equal(status.clientTransfers.byServer["malicious-random-natserver"].server,
        "malicious-random-natserver");
      assert.deepEqual(status.randomBatches.policy, {
        multiClientProbabilityPct: 60,
        multiClientMin: 2,
        multiClientMax: 4,
        clientStartStaggerSeconds: 30,
        mixedPathQuietSamples: 3,
        mixedPathQuietTimeoutSeconds: 45,
        rateLimitsKiBps: [
          { clients: 1, kibps: 5120 },
          { clients: 2, kibps: 5120 },
          { clients: 3, kibps: 5120 },
          { clients: 4, kibps: 5120 },
        ],
      });
      assert.equal(status.randomBatches.summary.multiClientBatches, 1);
      assert.equal(status.randomBatches.summary.maliciousSelectedBatches, 1);
      assert.equal(status.randomBatches.summary.maliciousServerBatches, 1);
      assert.equal(status.randomBatches.recent[0].selectedServer, "malicious-random-natserver");
      assert.equal(status.randomBatches.recent[0].serverMalicious, true);
      assert.deepEqual(status.randomBatches.recent[0].selectedClients,
        ["natclient01", "malicious-natclient"]);
      assert.equal(status.randomBatches.recent[0].targets[1].client, "malicious-natclient");
      assert.equal(encoded.includes(secretEndpoint), false);
      assert.equal(encoded.includes(secretNodeID), false);

      const page = await dashboardFetch(`http://127.0.0.1:${port}/`);
      const html = await page.text();
      assert.equal(html.includes('id="serverTransferTimeline"'), true);
      assert.equal(html.includes("NatServer 被随机命中的时间线"), true);
      assert.equal(html.includes("Server IP 类型"), true);
      assert.equal(html.includes("传输协议"), true);
      assert.equal(html.includes('id="randomBatchList"'), true);
      assert.equal(html.includes("多 Client 概率"), true);
    });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard exposes only whitelisted concurrent service sessions", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-service-sessions-"));
  const privateRoot = path.join(runDir, "private");
  const clientNodeID = "a".repeat(64);
  const serverNodeID = "b".repeat(64);
  const secret = "/private/service-listener.key";
  try {
    await fs.mkdir(path.join(privateRoot, "natserver03"), { recursive: true });
    await fs.writeFile(path.join(runDir, "nat-identities.tsv"), [
      "service\trole\tnode_id\tingress_relay\tcredited",
      `natclient02\tnatclient\t${clientNodeID}\trelay01\tyes`,
      `natserver03\tnatserver\t${serverNodeID}\trelay03\tyes`,
    ].join("\n") + "\n");
    await fs.writeFile(path.join(privateRoot, "natserver03", "service-listener.json"), JSON.stringify({
      schemaVersion: 1,
      observedAt: new Date().toISOString(),
      service: "natserver03",
      nodeId: serverNodeID.slice(0, 16),
      relayAddress: "10.253.41.250:9000",
      carrierConnected: true,
      carrierGeneration: 3,
      activeSessions: 1,
      maxSessions: 8,
      acceptQueueDepth: 0,
      acceptQueue: 8,
	      acceptedTotal: 11,
	      rejectedTotal: 2,
	      carriers: [{
	        relayAddress: "10.253.41.250:9000",
	        connected: true,
	        carrierGeneration: 3,
	        activeSessions: 1,
	        dataQueueDepth: 17,
	        dataQueueCapacity: 1024,
	        controlQueueDepth: 3,
	        controlQueueCapacity: 1024,
	      }],
      sessions: [{ connectionId: "1234abcd", peerId: clientNodeID.slice(0, 16), privateKey: secret }],
      privateKey: secret,
      fullNodeID: serverNodeID,
    }));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const encoded = await response.text();
      const status = JSON.parse(encoded).serviceSessions;
      assert.equal(status.available, true);
      assert.deepEqual(status.summary, {
        listeners: 1,
        freshListeners: 1,
        connectedCarriers: 1,
        activeSessions: 1,
        maxSessions: 8,
        acceptedTotal: 11,
        rejectedTotal: 2,
      });
	      assert.deepEqual(status.sessions, [{
        connectionID: "1234abcd",
        client: "natclient02",
        clientRelay: "relay01",
        server: "natserver03",
        relay: "relay03",
        serverRelay: "relay03",
	      }]);
	      assert.equal(status.listeners[0].muxDataQueueDepth, 17);
	      assert.equal(status.listeners[0].muxDataQueueCapacity, 1024);
	      assert.equal(status.listeners[0].muxControlQueueDepth, 3);
	      assert.equal(status.listeners[0].muxControlQueueCapacity, 1024);
      assert.equal(encoded.includes(secret), false);
      assert.equal(encoded.includes(clientNodeID), false);
      assert.equal(encoded.includes(serverNodeID), false);
    }, { env: { PRIVATE_RUNTIME_DIR: privateRoot } });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

test("Dashboard publishes the public Relay capacity result", async () => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-dashboard-capacity-"));
  const capacityDir = path.join(runDir, "capacity");
  const capacityPointer = path.join(runDir, "capacity-pointer");
  try {
    await fs.mkdir(capacityDir, { recursive: true });
    await fs.writeFile(capacityPointer, `${capacityDir}\n`);
    await fs.writeFile(path.join(capacityDir, "start-time.txt"), "2026-07-29T12:00:00+08:00\n");
    await fs.writeFile(path.join(capacityDir, "end-time.txt"), "2026-07-29T13:50:00+08:00\n");
    await fs.writeFile(path.join(capacityDir, "client.rc"), "0\n");
    await fs.writeFile(path.join(capacityDir, "client.pid"), "999999999\n");
    await fs.writeFile(path.join(capacityDir, "client.log"), [
      "CAPACITY_PLAN clients=100 transfer_mib=100 targets=3",
      "CONNECTED count=100 target=1ecbe57204ac5464 elapsed=1s at=2026-07-29T12:00:01+08:00",
      "CHECKSUM_WARMUP_COMPLETE clients=100 unique_checksums=100 elapsed=30s at=2026-07-29T12:00:31+08:00",
      "TARGET_DISTRIBUTION target=1ecbe57204ac5464 clients=34",
      "TARGET_DISTRIBUTION target=a8cea2806f6c997f clients=33",
      "TARGET_DISTRIBUTION target=bf0c600945127f4d clients=33",
      "TRANSFER_SUMMARY clients=100 successes=100 failures=0 bytes=10485760000 expected_bytes=10485760000 elapsed=1h50m0s mib_per_second=1.515 at=2026-07-29T13:50:00+08:00",
      "",
    ].join("\n"));
    await fs.writeFile(path.join(capacityDir, "resource-samples.tsv"), [
      [
        "epoch", "iso", "host_cpu_ticks",
        "client_cpu_ticks", "client_rss_kib", "client_threads", "client_fds", "client_read_bytes", "client_write_bytes",
        "nat1_cpu_ticks", "nat1_rss_kib", "nat1_threads", "nat1_fds", "nat1_read_bytes", "nat1_write_bytes",
        "http1_cpu_ticks", "http1_rss_kib", "http1_threads", "nat1_active_sessions",
        "nat2_cpu_ticks", "nat2_rss_kib", "nat2_threads", "nat2_fds", "nat2_read_bytes", "nat2_write_bytes",
        "http2_cpu_ticks", "http2_rss_kib", "http2_threads", "nat2_active_sessions",
        "nat3_cpu_ticks", "nat3_rss_kib", "nat3_threads", "nat3_fds", "nat3_read_bytes", "nat3_write_bytes",
        "http3_cpu_ticks", "http3_rss_kib", "http3_threads", "nat3_active_sessions",
        "local_net_rx_bytes", "local_net_tx_bytes",
        "relay_cpu_ticks", "relay_rss_kib", "relay_threads", "relay_fds", "relay_read_bytes", "relay_write_bytes",
        "relay_tcp_established", "relay_net_rx_bytes", "relay_net_tx_bytes", "relay_load1", "relay_restarts",
      ].join("\t"),
      [
        "1785297600", "2026-07-29T12:00:00+08:00", "1000",
        "100", "40960", "110", "220", "0", "0",
        "100", "20480", "45", "80", "0", "0", "100", "110592", "8", "34",
        "100", "20480", "45", "80", "0", "0", "100", "110592", "8", "33",
        "100", "20480", "45", "80", "0", "0", "100", "110592", "8", "33",
        "1000000", "2000000",
        "100", "245760", "16", "230", "0", "0", "216", "3000000", "4000000", "0.42", "0",
      ].join("\t"),
      "",
    ].join("\n"));

    await withDashboard(runDir, async (port) => {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/api/status`);
      assert.equal(response.status, 200);
      const status = await response.json();
      assert.equal(status.capacityTest.available, true);
      assert.equal(status.capacityTest.phase, "COMPLETED");
      assert.equal(status.capacityTest.plannedClients, 100);
      assert.equal(status.capacityTest.transferMiB, 100);
      assert.equal(status.capacityTest.connected, 100);
      assert.equal(status.capacityTest.checksumWarmup.uniqueChecksums, 100);
      assert.equal(status.capacityTest.transfer.successes, 100);
      assert.equal(status.capacityTest.transfer.failures, 0);
      assert.equal(status.capacityTest.transfer.bytes, 10485760000);
      assert.equal(status.capacityTest.targets.reduce((sum, target) => sum + target.clients, 0), 100);
      assert.equal(status.capacityTest.resources.client.threads, 110);
      assert.equal(status.capacityTest.resources.client.fds, 220);
      assert.equal(status.capacityTest.resources.natServers[0].activeSessions, 34);
      assert.equal(status.capacityTest.resources.relay.threads, 16);
      assert.equal(status.capacityTest.resources.relay.fds, 230);
      assert.equal(status.capacityTest.resources.relay.restarts, 0);
      assert.equal(status.capacityTest.resources.trends.tenMinutes.windowSeconds, 0);
      assert.equal(status.capacityTest.resources.trends.tenMinutes.localRSSDeltaMiB, 0);

      await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
      const activeResponse = await dashboardFetch(`http://127.0.0.1:${port}/api/status?fresh=1`);
      assert.equal(activeResponse.status, 200);
      const activeStatus = await activeResponse.json();
      assert.equal(activeStatus.phase, "RUNNING");
      assert.equal(activeStatus.capacityTest.available, false);
      assert.equal(activeStatus.resources.mode, "LIVE");
    }, { env: { CAPACITY_RUN_POINTER: capacityPointer } });
  } finally {
    await fs.rm(runDir, { recursive: true, force: true });
  }
});

async function withDashboard(runDir, callback, options = {}) {
  const port = await freePort();
  const child = spawn(process.execPath, [dashboardPath], {
    env: {
      ...process.env,
      ...(options.env ?? {}),
      HOST: "127.0.0.1",
      PORT: String(port),
      RUN_DIR: runDir,
      COMPOSE_PROJECT: options.composeProject ?? "",
      COMPOSE_FILE: path.join(runDir, "compose.json"),
      CA_PORT: "1",
      CAPACITY_RUN_POINTER: options.env?.CAPACITY_RUN_POINTER ?? path.join(runDir, "capacity-pointer"),
    },
    stdio: "ignore",
  });
  try {
    await waitForDashboard(port, child);
    await callback(port);
  } finally {
    await stopProcess(child);
  }
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  return address.port;
}

async function waitForDashboard(port, child) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Dashboard exited with ${child.exitCode}`);
    try {
      const response = await dashboardFetch(`http://127.0.0.1:${port}/healthz`);
      await response.arrayBuffer();
      if (response.ok) return;
    } catch {}
    await delay(50);
  }
  throw new Error("timed out waiting for Dashboard");
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  const gracefulExit = waitForExit(child);
  child.kill("SIGTERM");
  if (await Promise.race([gracefulExit.then(() => true), unrefDelay(3000).then(() => false)])) return;
  child.kill("SIGKILL");
  await waitForExit(child);
}

function waitForExit(child) {
  return child.exitCode !== null ? Promise.resolve() : once(child, "exit");
}

function dashboardFetch(url) {
  return fetch(url, { headers: { Connection: "close" } });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function unrefDelay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds).unref());
}
