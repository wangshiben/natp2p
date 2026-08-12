import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

import {
  attackScenarios,
  createAPIClient,
  runAttackCycle,
  runAttackScenario,
} from "../../../runtimeScript/local-chaos/monitor/billing-adversary-core.mjs";
import { createBillingComponentProbe } from "../../../runtimeScript/local-chaos/monitor/billing-component-probe.mjs";
import { containerScenariosByActor } from "../../../runtimeScript/local-chaos/monitor/billing-container-probe.mjs";
import { openDurableWaitSubmit } from "../../../runtimeScript/local-chaos/monitor/billing-adversary-outbox.mjs";

const execFileAsync = promisify(execFile);
const repositoryRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const runnerPath = fileURLToPath(new URL("../../../runtimeScript/local-chaos/monitor/billing-adversary.mjs", import.meta.url));
const dashboardPath = fileURLToPath(new URL("../../../runtimeScript/local-chaos/monitor/server.mjs", import.meta.url));

let insecureServer;
let insecureURL;
let hardenedProcess;
let hardenedURL;
let temporaryDirectory;
let componentProbeBinary;
let hardenedCredentials;

const passingComponentProbe = {
  async run(scenario) {
    return {
      schemaVersion: 1,
      scenario,
      status: "PASS",
      failureCode: "",
      checks: ["stub_component_check"],
      productionPackages: ["billingvoucher"],
      limitations: ["component_probe_not_full_p2p_socket_path"],
    };
  },
};

before(async () => {
  temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-billing-adversary-test-"));
  ({ server: insecureServer, url: insecureURL } = await startInsecureCA());
  insecureServer.unref();
  const hardenedPort = await freePort();
  const binary = path.join(temporaryDirectory, "caserver");
  componentProbeBinary = path.join(temporaryDirectory, "billing-adversary-probe");
  hardenedCredentials = {
    enrollmentTokens: {
      server: crypto.randomBytes(32).toString("base64url"),
      relay: crypto.randomBytes(32).toString("base64url"),
    },
    adminToken: crypto.randomBytes(32).toString("base64url"),
  };
  const relayTokenFile = path.join(temporaryDirectory, "relay-enrollment.token");
  const serverTokenFile = path.join(temporaryDirectory, "server-enrollment.token");
  const adminTokenFile = path.join(temporaryDirectory, "admin.token");
  await Promise.all([
    fs.writeFile(relayTokenFile, `${hardenedCredentials.enrollmentTokens.relay}\n`, { mode: 0o600 }),
    fs.writeFile(serverTokenFile, `${hardenedCredentials.enrollmentTokens.server}\n`, { mode: 0o600 }),
    fs.writeFile(adminTokenFile, `${hardenedCredentials.adminToken}\n`, { mode: 0o600 }),
  ]);
  await Promise.all([
    execFileAsync("go", ["build", "-o", binary, "./test/testCode/caserver"], {
      cwd: repositoryRoot,
      timeout: 120000,
      maxBuffer: 4 * 1024 * 1024,
    }),
    execFileAsync("go", ["build", "-o", componentProbeBinary, "./test/testCode/billing-adversary-probe"], {
      cwd: repositoryRoot,
      timeout: 120000,
      maxBuffer: 4 * 1024 * 1024,
    }),
  ]);
  hardenedProcess = spawn(binary, [
    "-listen", `127.0.0.1:${hardenedPort}`,
    "-key", path.join(temporaryDirectory, "ca.key"),
    "-ledger", path.join(temporaryDirectory, "ledger.json"),
    "-issuer", "local-adversary-test",
    "-relay-enrollment-token-file", relayTokenFile,
    "-server-enrollment-token-file", serverTokenFile,
    "-admin-token-file", adminTokenFile,
  ], { stdio: "ignore" });
  hardenedProcess.unref();
  hardenedURL = `http://127.0.0.1:${hardenedPort}`;
  await waitForCA(hardenedURL, hardenedProcess);
});

after(async () => {
  await closeServer(insecureServer);
  if (hardenedProcess?.exitCode === null) hardenedProcess.kill("SIGTERM");
  await waitForExit(hardenedProcess);
  if (temporaryDirectory) await fs.rm(temporaryDirectory, { recursive: true, force: true });
});

test("active malicious NAT and Relay probes flag an accepting ledger", async () => {
  const events = await runAttackCycle(createAPIClient(insecureURL), "insecure-cycle", {
    waitSubmitPath: path.join(temporaryDirectory, "insecure-waitsubmit.json"),
    componentProbe: passingComponentProbe,
  });
  assert.equal(events.length, attackScenarios.length);
  assert.deepEqual(events.map((event) => event.scenario), attackScenarios);
  assert.equal(events.every((event) => event.passed === false), true);
  assert.equal(events.every((event) => event.componentProbePassed === true), true);
  assert.equal(events.some((event) => event.stateChanged), true);
  assert.equal(events.every((event) => ["relay", "natserver", "network"].includes(event.actor)), true);
  assert.equal(JSON.stringify(events).includes("subject_node_id"), false);
});

test("hardened voucher API contains every malicious behavior", async () => {
  const waitSubmitPath = path.join(temporaryDirectory, "hardened-waitsubmit.json");
  const events = await runAttackCycle(createAPIClient(hardenedURL, 3000, hardenedCredentials), "hardened-cycle", {
    waitSubmitPath,
    componentProbe: passingComponentProbe,
  });
  assert.equal(events.length, attackScenarios.length);
  assert.equal(events.every((event) => event.passed === true), true, JSON.stringify(events));
  assert.equal(events.every((event) => event.stateChanged === false), true);
  assert.equal(events.every((event) => event.balanceDelta === 0), true);
  assert.equal(events.find((event) => event.scenario === "relay_request_replay")?.defense, "idempotent_replay");
  assert.equal(events.find((event) => event.scenario === "nat_same_sequence_fork")?.defense, "channel_frozen_on_fork");
  assert.equal(events.find((event) => event.scenario === "index_disconnect_backlog_recovery")?.defense, "fifo_recovered_exactly_once");
  const waitSubmit = JSON.parse(await fs.readFile(waitSubmitPath, "utf8"));
  assert.equal(waitSubmit.entries.length, 0);
  assert.equal(waitSubmit.revision, 6);
});

test("HTTP server errors never count as protocol containment", async () => {
  const client = createSyntheticClient(() => ({
    status: 500,
    body: { error: "internal_error" },
  }));
  const scenarios = [
    "relay_usage_inflation",
    "relay_fee_override",
    "relay_window_overrun",
    "nat_signature_refusal",
    "relay_voucher_tamper",
  ];
  for (const [index, scenario] of scenarios.entries()) {
    const event = await runAttackScenario(client, scenario, `server-error-${index + 1}`, {
      componentProbe: passingComponentProbe,
    });
    assert.equal(event.passed, false, scenario);
    assert.equal(event.failureCode, "voucher_api_unavailable", scenario);
    assert.equal(event.httpStatuses.includes(500), true, scenario);
  }
});

test("backlog recovery requires exact authoritative balance changes", async () => {
  const accepted = new Set();
  const client = createSyntheticClient((request) => {
    const replayed = accepted.has(request.canonical_voucher);
    accepted.add(request.canonical_voucher);
    return {
      status: 200,
      body: { delta: replayed ? 0 : 1048576, replayed },
    };
  });
  const event = await runAttackScenario(client, "index_disconnect_backlog_recovery", "lying-ledger", {
    waitSubmitPath: path.join(temporaryDirectory, "lying-ledger-waitsubmit.json"),
    componentProbe: passingComponentProbe,
  });
  assert.equal(event.passed, false);
  assert.equal(event.failureCode, "waitsubmit_balance_mismatch");
  assert.equal(event.stateChanged, false);
});

test("durable wait-submit preserves billing-bound voucher identities", async () => {
  const payer = createQueueIdentity("server");
  const relay = createQueueIdentity("relay");
  const request = {
    canonical_voucher: Buffer.from("billing-bound-voucher").toString("base64"),
    payer_public_key: payer.identityPublicKey,
    relay_public_key: relay.identityPublicKey,
    payer_billing_public_key: payer.billingPublicKey,
    relay_billing_public_key: relay.billingPublicKey,
    payer_cert: payer.certificate,
    relay_cert: relay.certificate,
  };
  const filename = path.join(temporaryDirectory, "billing-bound-waitsubmit.json");
  let queue = await openDurableWaitSubmit(filename);
  await queue.enqueue(request);
  queue = await openDurableWaitSubmit(filename);
  assert.deepEqual(queue.peek()?.request, request);

  const incomplete = { ...request };
  delete incomplete.relay_billing_public_key;
  await assert.rejects(queue.enqueue(incomplete), /waitsubmit_request_invalid/);
  await assert.rejects(queue.enqueue({
    ...request,
    payer_billing_public_key: relay.billingPublicKey,
  }), /waitsubmit_request_invalid/);
});

test("one-shot sidecar publishes bounded redacted coverage", async () => {
  const runDir = await fs.mkdtemp(path.join(temporaryDirectory, "run-"));
  const credentialDirectory = path.join(runDir, "runtime", ".private", "ca");
  await fs.mkdir(credentialDirectory, { recursive: true, mode: 0o700 });
  const serverTokenFile = path.join(credentialDirectory, "enroll-server.token");
  const relayTokenFile = path.join(credentialDirectory, "enroll-relay.token");
  const adminTokenFile = path.join(credentialDirectory, "admin.token");
  await Promise.all([
    fs.writeFile(serverTokenFile, `${hardenedCredentials.enrollmentTokens.server}\n`, { mode: 0o600 }),
    fs.writeFile(relayTokenFile, `${hardenedCredentials.enrollmentTokens.relay}\n`, { mode: 0o600 }),
    fs.writeFile(adminTokenFile, `${hardenedCredentials.adminToken}\n`, { mode: 0o600 }),
  ]);
  await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
  await writeContainerProbeFixtures(path.join(runDir, "runtime", ".private"));
  await fs.writeFile(path.join(runDir, "metadata.env"), [
    "run_id=private-run-identifier",
    "scenario=1",
    "scenario_name=partition_bridge",
    "duration_seconds=43200",
    "dashboard_host=private-dashboard-host",
    "dashboard_port=65530",
    "ca_port=65531",
    "compose_project=private-compose-project",
    "billing_adversary_mode=enforce",
    "started_epoch=100",
    "deadline_epoch=43300",
    "",
  ].join("\n"));
  const child = spawn(process.execPath, [runnerPath], {
    env: {
      ...process.env,
      RUN_DIR: runDir,
      CA_BASE_URL: hardenedURL,
      RUN_ONCE: "1",
      EVENT_LIMIT: "8",
      COMPONENT_PROBE_BIN: componentProbeBinary,
      COMPONENT_PROBE_STATE_DIR: path.join(runDir, "component-probe-state"),
      CONTAINER_ADVERSARY_STATE_ROOT: path.join(runDir, "runtime", ".private"),
      CONTAINER_PROBE_MODE: "enforce",
      CA_SERVER_ENROLLMENT_TOKEN_FILE: serverTokenFile,
      CA_RELAY_ENROLLMENT_TOKEN_FILE: relayTokenFile,
      CA_ADMIN_TOKEN_FILE: adminTokenFile,
    },
    stdio: "ignore",
  });
  const result = await waitForExit(child);
  assert.equal(result.code, 0);
  const snapshot = JSON.parse(await fs.readFile(path.join(runDir, "billing-adversary.json"), "utf8"));
  assert.equal(snapshot.status, "STOPPED");
  assert.equal(snapshot.summary.executedChecks, attackScenarios.length);
  assert.equal(snapshot.summary.failedChecks, 0);
  assert.equal(snapshot.summary.coveredScenarios, attackScenarios.length);
  assert.deepEqual(snapshot.componentProbe, {
    schemaVersion: 1,
    status: "STOPPED",
    executed: attackScenarios.length,
    failed: 0,
    required: attackScenarios.length,
    covered: attackScenarios.length,
  });
  assert.equal(snapshot.containerProbe.status, "RUNNING");
  assert.equal(snapshot.containerProbe.executed, 9);
  assert.equal(snapshot.containerProbe.failed, 0);
  assert.equal(snapshot.containerProbe.covered, 9);
  assert.equal(snapshot.containerProbe.required, 9);
  assert.equal(snapshot.recent.length, 8);
  const serialized = JSON.stringify(snapshot);
  assert.equal(serialized.includes(runDir), false);
  assert.equal(serialized.includes(hardenedURL), false);
  assert.equal(/[0-9a-f]{64}/.test(serialized), false);
  assert.equal(serialized.includes("private"), false);
  const events = await fs.readFile(path.join(runDir, "billing-adversary-events.tsv"), "utf8");
  assert.equal(/[0-9a-f]{64}/.test(events), false);

  const dashboardPort = await freePort();
  const dashboard = spawn(process.execPath, [dashboardPath], {
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(dashboardPort),
      RUN_DIR: runDir,
      COMPOSE_PROJECT: "",
      CA_PORT: "1",
    },
    stdio: "ignore",
  });
  try {
    const api = await waitForDashboard(dashboardPort, dashboard);
    assert.equal(api.billingAdversary.available, true);
    assert.equal(api.billingAdversary.summary.executedChecks, attackScenarios.length);
    assert.equal(api.billingAdversary.summary.preventedChecks, attackScenarios.length);
    assert.equal(api.billingAdversary.summary.missedChecks, 0);
    assert.equal(api.billingAdversary.coverage.length, attackScenarios.length);
    assert.deepEqual(api.billingAdversary.componentProbe, snapshot.componentProbe);
    assert.deepEqual(Object.keys(api.billingAdversary.componentProbe).sort(), [
      "covered", "executed", "failed", "required", "schemaVersion", "status",
    ]);
    assert.equal(api.billingAdversary.containerProbe.status, "RUNNING");
    assert.equal(api.billingAdversary.containerProbe.covered, 9);
    assert.equal(api.billingAdversary.containerProbe.required, 9);
    assert.equal(api.billingAdversary.containerProbe.coverage.length, 9);
    assert.deepEqual(api.billingAdversary.containerProbe.transport, ["container_http_peer", "container_http_ca"]);
    assert.equal(api.billingAdversary.containerProbe.scope, "isolated_container_http_ca_fixture");
    assert.deepEqual(api.maliciousNodes.map((node) => node.service), ["malicious-natserver", "malicious-relay"]);
    assert.deepEqual(api.maliciousNodes.map((node) => node.probe.status), ["RUNNING", "RUNNING"]);
    assert.deepEqual(api.maliciousNodes.map((node) => [node.probe.covered, node.probe.required]), [[4, 4], [5, 5]]);
    assert.deepEqual(api.maliciousNodes.map((node) => node.latestActivity?.scenario), [
      "nat_identity_forgery",
      "relay_voucher_tamper",
    ]);
    const publicAPI = JSON.stringify(api);
    for (const secret of [runDir, "private-run-identifier", "private-dashboard-host", "private-compose-project", "65530", "65531"]) {
      assert.equal(publicAPI.includes(secret), false, `Dashboard API leaked ${secret}`);
    }
    assert.equal(Object.hasOwn(api.metadata, "run_id"), false);
    assert.equal(Object.hasOwn(api.metadata, "started_epoch"), false);
    assert.equal(Object.hasOwn(api.metadata, "deadline_epoch"), false);
    const health = await fetch(`http://127.0.0.1:${dashboardPort}/healthz`).then((response) => response.json());
    assert.deepEqual(Object.keys(health).sort(), ["ok", "timestamp"]);
    const page = await fetch(`http://127.0.0.1:${dashboardPort}/`).then((response) => response.text());
    assert.match(page, /id="billingAdversaryCoverage"/);
    assert.match(page, /id="billingComponentProbe"/);
    assert.match(page, /id="billingContainerProbe"/);
    assert.match(page, /id="billingContainerCoverage"/);
    assert.match(page, /id="maliciousNodes"/);
    assert.match(page, /malicious-natserver/);
    assert.match(page, /malicious-relay/);
    assert.match(page, /不代表完整 Nat \/ Relay Socket/);
    assert.match(page, /不代表完整 P2P Payload Socket/);
    assert.match(page, /renderBillingAdversary\(data\.billingAdversary\)/);
    assert.match(page, /renderMaliciousNodes\(data\.maliciousNodes, data\.mixedPath\)/);
    assert.match(page, /NAT Client 随机传输与恶意节点活动/);
    assert.match(page, /隔离恶意 HTTP\/CA 路径/);
    assert.match(page, /renderMaliciousTransferCards/);
    assert.match(page, /malicious-natserver/);
    assert.match(page, /malicious-relay/);
  } finally {
    if (dashboard.exitCode === null) dashboard.kill("SIGTERM");
    await waitForExit(dashboard);
  }
});

async function writeContainerProbeFixtures(root) {
  const heartbeatAt = new Date().toISOString();
  for (const [actor, scenarios] of Object.entries(containerScenariosByActor)) {
    const service = actor === "relay" ? "malicious-relay" : "malicious-natserver";
    const directory = path.join(root, service);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const coverage = Object.fromEntries(scenarios.map((scenario) => [scenario, {
      executed: 1,
      contained: 1,
      violations: 0,
    }]));
    await fs.writeFile(path.join(directory, "status.json"), `${JSON.stringify({
      schemaVersion: 1,
      status: "RUNNING",
      role: actor,
      mode: "container_network_protocol",
      heartbeatAt,
      sequence: scenarios.length,
      seedDigest: "0123456789abcdef",
      coverage,
      summary: {
        executedChecks: scenarios.length,
        containedChecks: scenarios.length,
        failedChecks: 0,
        coveredScenarios: scenarios.length,
        requiredScenarios: scenarios.length,
      },
      recent: scenarios.map((scenario, index) => ({
        sequence: index + 1,
        observedAt: heartbeatAt,
        scenario,
        actor,
        passed: true,
        verdict: "CONTAINED",
        defense: "attack_rejected",
        requestCount: 1,
        httpStatuses: [200, 409],
        balanceDelta: 0,
        stateChanged: false,
        path: actor === "relay"
          ? "malicious-relay->malicious-natserver->ca"
          : "malicious-natserver->malicious-relay->ca",
      })),
      transport: ["container_http_peer", "container_http_ca"],
      limitations: [],
    })}\n`, { mode: 0o600 });
  }
}

test("sidecar heartbeat fails closed when a container fixture stops", async () => {
  const runDir = await fs.mkdtemp(path.join(temporaryDirectory, "container-heartbeat-run-"));
  const credentialDirectory = path.join(runDir, "runtime", ".private", "ca");
  const containerRoot = path.join(runDir, "runtime", ".private");
  await fs.mkdir(credentialDirectory, { recursive: true, mode: 0o700 });
  const serverTokenFile = path.join(credentialDirectory, "enroll-server.token");
  const relayTokenFile = path.join(credentialDirectory, "enroll-relay.token");
  const adminTokenFile = path.join(credentialDirectory, "admin.token");
  await Promise.all([
    fs.writeFile(serverTokenFile, `${hardenedCredentials.enrollmentTokens.server}\n`, { mode: 0o600 }),
    fs.writeFile(relayTokenFile, `${hardenedCredentials.enrollmentTokens.relay}\n`, { mode: 0o600 }),
    fs.writeFile(adminTokenFile, `${hardenedCredentials.adminToken}\n`, { mode: 0o600 }),
    fs.writeFile(path.join(runDir, "phase"), "RUNNING\n"),
  ]);
  await writeContainerProbeFixtures(containerRoot);
  const child = spawn(process.execPath, [runnerPath], {
    env: {
      ...process.env,
      RUN_DIR: runDir,
      CA_BASE_URL: hardenedURL,
      ATTACK_INTERVAL_MS: "3600000",
      HEARTBEAT_INTERVAL_MS: "250",
      COMPONENT_PROBE_BIN: componentProbeBinary,
      COMPONENT_PROBE_STATE_DIR: path.join(runDir, "component-probe-state"),
      CONTAINER_ADVERSARY_STATE_ROOT: containerRoot,
      CONTAINER_PROBE_MODE: "enforce",
      CA_SERVER_ENROLLMENT_TOKEN_FILE: serverTokenFile,
      CA_RELAY_ENROLLMENT_TOKEN_FILE: relayTokenFile,
      CA_ADMIN_TOKEN_FILE: adminTokenFile,
    },
    stdio: "ignore",
  });
  try {
    await waitForJSON(path.join(runDir, "billing-adversary.json"), child, (value) => (
      value.status === "RUNNING" && value.containerProbe?.covered === 9
    ));
    const actorFile = path.join(containerRoot, "malicious-natserver", "status.json");
    const actor = JSON.parse(await fs.readFile(actorFile, "utf8"));
    actor.status = "STOPPED";
    const temporary = `${actorFile}.tmp`;
    await fs.writeFile(temporary, `${JSON.stringify(actor)}\n`, { mode: 0o600 });
    await fs.rename(temporary, actorFile);
    const failed = await waitForJSON(path.join(runDir, "billing-adversary.json"), child, (value) => (
      value.status === "FAILED" && value.containerProbe?.errorCode === "container_probe_actor_stopped"
    ));
    assert.equal(failed.containerProbe.failed, 1);
    const alert = JSON.parse(await fs.readFile(path.join(runDir, "billing-adversary.alert"), "utf8"));
    assert.equal(alert.failureCode, "container_probe_actor_stopped");
  } finally {
    if (child.exitCode === null) child.kill("SIGTERM");
    await waitForExit(child);
  }
});

test("probe target is restricted to loopback HTTP", () => {
  assert.throws(() => createAPIClient("http://example.invalid:9000"), /loopback/);
  assert.throws(() => createAPIClient("file:///tmp/ca"), /loopback/);
  assert.throws(() => createAPIClient("http://user:password@127.0.0.1:9000"), /without credentials/);
});

test("billing-bound fixture authorizes nodes and probes user balances by authorization", async () => {
  const billingFixture = {
    payer: createBillingFixtureBundle("payer"),
    relay: createBillingFixtureBundle("relay"),
  };
  const requests = [];
  const authorized = new Map();
  let balanceReads = 0;
  const client = {
    async get(pathname) {
      const target = new URL(pathname, "http://fixture.invalid");
      requests.push({ method: "GET", pathname: target.pathname, search: target.searchParams });
      const nodeID = target.searchParams.get("node") ?? "";
      const authorization = target.searchParams.get("authorization_id") ?? "";
      if (authorized.get(nodeID) !== authorization) {
        return { status: 401, body: { error: "invalid_node_authorization" } };
      }
      balanceReads += 1;
      return {
        status: 200,
        body: {
          balance: 64 * 1024 * 1024 * 1024 - balanceReads * 4096,
          authorization_consumed_bytes: 0,
          authorization_earned_bytes: 0,
        },
      };
    },
    async post(pathname, body) {
      requests.push({ method: "POST", pathname, body });
      if (pathname === "/v1/node/authorize") {
        const bundle = body.role === "server" ? billingFixture.payer : billingFixture.relay;
        const nodeID = crypto.createHash("sha256").update(String(body.subject_pubkey)).digest("hex");
        const canonical = authorizationCanonicalForTest(body);
        assert.equal(crypto.verify(
          "sha256", Buffer.from(canonical), publicKeyFromHex(body.subject_pubkey),
          Buffer.from(body.node_signature, "base64url"),
        ), true);
        assert.equal(crypto.verify(
          "sha256", Buffer.from(canonical), crypto.createPublicKey({ key: bundle.private_key_jwk, format: "jwk" }),
          Buffer.from(body.billing_signature, "base64url"),
        ), true);
        const authorizationID = nodeAuthorizationIDForTest(nodeID, bundle.key_id);
        authorized.set(nodeID, authorizationID);
        return {
          status: 200,
          body: {
            node_id: nodeID,
            authorization_id: authorizationID,
            signed_cert: {
              cert: {
                subject_node_id: nodeID,
                subject_pubkey: body.subject_pubkey,
                role: body.role,
                billing_key_id: bundle.key_id,
                billing_public_key: bundle.public_key_hex,
                authorization_id: authorizationID,
              },
              sig: "fixture",
            },
          },
        };
      }
      if (pathname === "/v1/channel/voucher") {
        assert.match(body.payer_billing_public_key, /^04[0-9a-f]{128}$/);
        assert.match(body.relay_billing_public_key, /^04[0-9a-f]{128}$/);
        return { status: 409, body: { error: "cumulative window exceeded" } };
      }
      return { status: 404, body: { error: "not_found" } };
    },
  };

  const event = await runAttackScenario(client, "relay_window_overrun", "billing-bound", {
    componentProbe: passingComponentProbe,
    billingFixture,
  });
  assert.equal(event.passed, true, JSON.stringify(event));
  assert.equal(event.defense, "one_mib_window_enforced");
  assert.equal(requests.filter((request) => request.pathname === "/v1/node/authorize").length, 2);
  assert.equal(requests.some((request) => request.pathname === "/issue" || request.pathname === "/credit"), false);
  assert.ok(requests.filter((request) => request.method === "GET").every(
    (request) => /^[0-9a-f]{64}$/.test(request.search.get("authorization_id") ?? ""),
  ));
});

test("component helper faults are fail-closed", async () => {
  const scenario = "relay_usage_inflation";
  const fixtures = [
    {
      name: "missing",
      binary: path.join(temporaryDirectory, "missing-component-probe"),
      expected: "component_probe_unavailable",
    },
    {
      name: "exit",
      binary: await writeExecutable("component-exit.mjs", "process.stdin.once('data', () => process.exit(0));\n"),
      expected: "component_probe_exited",
    },
    {
      name: "timeout",
      binary: await writeExecutable("component-timeout.mjs", "process.stdin.resume();\nsetInterval(() => {}, 1000);\n"),
      expected: "component_probe_timeout",
      timeoutMs: 100,
    },
    {
      name: "malformed",
      binary: await writeExecutable("component-malformed.mjs", "process.stdin.once('data', () => process.stdout.write('{}\\n'));\n"),
      expected: "component_probe_output_invalid",
    },
  ];
  for (const fixture of fixtures) {
    const componentProbe = createBillingComponentProbe({
      binaryPath: fixture.binary,
      stateDir: path.join(temporaryDirectory, `component-state-${fixture.name}`),
      timeoutMs: fixture.timeoutMs ?? 1000,
    });
    try {
      const event = await runAttackScenario(createAPIClient(hardenedURL, 3000, hardenedCredentials), scenario, `fault-${fixture.name}`, {
        componentProbe,
      });
      assert.equal(event.passed, false, fixture.name);
      assert.equal(event.componentProbePassed, false, fixture.name);
      assert.equal(event.componentProbeCovered, false, fixture.name);
      assert.equal(event.failureCode, fixture.expected, fixture.name);
    } finally {
      await componentProbe.close();
    }
  }

  const failingBinary = await writeExecutable("component-fail.mjs", [
    "process.stdin.once('data', (chunk) => {",
    "  const request = JSON.parse(String(chunk).trim());",
    "  process.stdout.write(JSON.stringify({",
    "    schemaVersion: 1, scenario: request.scenario, status: 'FAIL',",
    "    failureCode: 'malicious_variant_accepted', checks: ['variant_checked'],",
    "    productionPackages: ['billingvoucher'],",
    "    limitations: ['component_probe_not_full_p2p_socket_path'],",
    "  }) + '\\n');",
    "});",
    "",
  ].join("\n"));
  const componentProbe = createBillingComponentProbe({
    binaryPath: failingBinary,
    stateDir: path.join(temporaryDirectory, "component-state-fail"),
  });
  try {
    const event = await runAttackScenario(createAPIClient(hardenedURL, 3000, hardenedCredentials), scenario, "fault-reported-fail", {
      componentProbe,
    });
    assert.equal(event.passed, false);
    assert.equal(event.componentProbeCovered, true);
    assert.equal(event.componentProbePassed, false);
    assert.equal(event.failureCode, "component_probe_malicious_variant_accepted");
    assert.equal(event.depth, "production_go_component_probe");
  } finally {
    await componentProbe.close();
  }
});

function createSyntheticClient(settleVoucher) {
  const balances = new Map();
  return {
    async get(pathname) {
      const target = new URL(pathname, "http://synthetic.invalid");
      return { status: 200, body: { balance: balances.get(target.searchParams.get("node") ?? "") ?? 0 } };
    },
    async post(pathname, body) {
      if (pathname === "/issue") {
        const publicKey = String(body.subject_pubkey ?? "");
        const nodeID = crypto.createHash("sha256").update(publicKey).digest("hex");
        return {
          status: 200,
          body: {
            signed_cert: {
              cert: {
                subject_node_id: nodeID,
                subject_pubkey: publicKey,
                role: String(body.role ?? ""),
                not_before: 0,
                not_after: 4102444800,
                nonce: "synthetic",
                issuer: "synthetic",
              },
              sig: "synthetic",
            },
          },
        };
      }
      if (pathname === "/credit") {
        const node = String(body.node_id ?? "");
        const balance = (balances.get(node) ?? 0) + Number(body.add_bytes ?? 0);
        balances.set(node, balance);
        return { status: 200, body: { balance } };
      }
      if (pathname === "/settle" || pathname === "/reserve") {
        return { status: 410, body: { error: "retired" } };
      }
      if (pathname === "/v1/channel/voucher") return settleVoucher(body, balances);
      return { status: 404, body: { error: "not_found" } };
    },
  };
}

function createBillingFixtureBundle(label) {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateJWK = privateKey.export({ format: "jwk" });
  const publicKey = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(privateJWK.x, "base64url"),
    Buffer.from(privateJWK.y, "base64url"),
  ]);
  return {
    version: 1,
    key_id: crypto.createHash("sha256").update(publicKey).digest("hex"),
    label,
    algorithm: "ECDSA_P256_SHA256",
    private_key_jwk: privateJWK,
    public_key_hex: publicKey.toString("hex"),
    registration_status: "active",
  };
}

function createQueueIdentity(role) {
  const identity = createBillingFixtureBundle(`${role}-identity`);
  const billing = createBillingFixtureBundle(`${role}-billing`);
  const nodeID = crypto.createHash("sha256")
    .update(Buffer.from(identity.public_key_hex, "hex"))
    .digest("hex");
  return {
    identityPublicKey: identity.public_key_hex,
    billingPublicKey: billing.public_key_hex,
    certificate: {
      cert: {
        subject_node_id: nodeID,
        subject_pubkey: identity.public_key_hex,
        role,
        not_before: 0,
        not_after: 4102444800,
        nonce: `${role}-queue-fixture`,
        issuer: "queue-test",
        billing_key_id: billing.key_id,
        billing_public_key: billing.public_key_hex,
        authorization_id: nodeAuthorizationIDForTest(nodeID, billing.key_id),
      },
      sig: "queue-fixture",
    },
  };
}

function publicKeyFromHex(value) {
  const encoded = Buffer.from(value, "hex");
  return crypto.createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: encoded.subarray(1, 33).toString("base64url"),
      y: encoded.subarray(33, 65).toString("base64url"),
    },
    format: "jwk",
  });
}

function authorizationCanonicalForTest(request) {
  return [
    "CA-NODE-AUTHORIZATION-V1",
    request.subject_pubkey,
    request.role,
    request.billing_key_id,
    String(request.timestamp),
    request.nonce,
    String(request.ttl_seconds),
  ].join("\n");
}

function nodeAuthorizationIDForTest(nodeID, billingKeyID) {
  return crypto.createHash("sha256")
    .update(`CA-NODE-AUTHORIZATION-ID-V1\0${nodeID}\0${billingKeyID}`)
    .digest("hex");
}

async function writeExecutable(name, source) {
  const filename = path.join(temporaryDirectory, name);
  await fs.writeFile(filename, `#!/usr/bin/env node\n${source}`, { mode: 0o700 });
  await fs.chmod(filename, 0o700);
  return filename;
}

async function startInsecureCA() {
  const balances = new Map();
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    if (request.method === "GET" && url.pathname === "/balance") {
      return json(response, 200, { balance: balances.get(url.searchParams.get("node") ?? "") ?? 0 });
    }
    if (request.method !== "POST") return json(response, 405, { error: "method_not_allowed" });
    const body = await readJSON(request);
    if (url.pathname === "/issue") {
      if (Number(body.ttl_seconds) < 86400) return json(response, 422, { error: "fixture_ttl_too_short" });
      const publicKey = String(body.subject_pubkey ?? "");
      const nodeID = crypto.createHash("sha256").update(publicKey).digest("hex");
      return json(response, 200, {
        signed_cert: {
          cert: {
            subject_node_id: nodeID,
            subject_pubkey: publicKey,
            role: String(body.role ?? ""),
            not_before: 0,
            not_after: 4102444800,
            nonce: "synthetic",
            issuer: "insecure-test",
          },
          sig: "insecure",
        },
      });
    }
    if (url.pathname === "/credit") {
      const node = String(body.node_id ?? "");
      const balance = (balances.get(node) ?? 0) + Number(body.add_bytes ?? 0);
      balances.set(node, balance);
      return json(response, 200, { balance });
    }
    if (url.pathname === "/v1/channel/voucher") {
      const payer = String(body.payer_cert?.cert?.subject_node_id ?? "");
      const relay = String(body.relay_cert?.cert?.subject_node_id ?? "");
      balances.set(payer, (balances.get(payer) ?? 0) - 1024);
      balances.set(relay, (balances.get(relay) ?? 0) + 1024);
      return json(response, 200, { delta: 1048576, replayed: false, frozen: false });
    }
    return json(response, 404, { error: "not_found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return { server, url: `http://127.0.0.1:${address.port}` };
}

async function readJSON(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function json(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { "Content-Type": "application/json", "Content-Length": body.length });
  response.end(body);
}

function closeServer(server) {
  if (!server) return Promise.resolve();
  return new Promise((resolve) => {
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      resolve();
    };
    const timeout = setTimeout(finish, 1000);
    server.close(finish);
    server.closeAllConnections?.();
  });
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  return address.port;
}

async function waitForCA(baseURL, child, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`caserver exited with ${child.exitCode}`);
    try {
      const response = await fetch(`${baseURL}/pubkey`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for local caserver");
}

async function waitForDashboard(port, child, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`dashboard exited with ${child.exitCode}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/status`);
      if (response.ok) return response.json();
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for Dashboard");
}

async function waitForJSON(filename, child, predicate, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`sidecar exited with ${child.exitCode}`);
    try {
      const value = JSON.parse(await fs.readFile(filename, "utf8"));
      if (predicate(value)) return value;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for sidecar snapshot");
}

function waitForExit(child) {
  if (!child || child.exitCode !== null) {
    return Promise.resolve({ code: child?.exitCode ?? 0, signal: child?.signalCode ?? null });
  }
  return new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
}
