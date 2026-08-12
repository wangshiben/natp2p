import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

import {
  containerScenariosByActor,
  readBillingContainerProbe,
  waitForBillingContainerProbe,
} from "../../../runtimeScript/local-chaos/monitor/billing-container-probe.mjs";

const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

test("aggregates fresh container-network Nat and Relay evidence", async () => {
  const root = await fixtureRoot();
  const probe = await readBillingContainerProbe(root);
  assert.equal(probe.status, "RUNNING");
  assert.equal(probe.failed, 0);
  assert.equal(probe.covered, 9);
  assert.equal(probe.required, 9);
  assert.equal(probe.coverage.every((item) => item.contained === 1), true);
  assert.deepEqual(probe.transport, ["container_http_peer", "container_http_ca"]);
  assert.equal(JSON.stringify(probe).includes(root), false);
  assert.equal(/[0-9a-f]{64}/.test(JSON.stringify(probe)), false);
});

test("fails closed on stale, malformed, or violating actor evidence", async () => {
  const staleRoot = await fixtureRoot({ heartbeatAt: "2020-01-01T00:00:00.000Z" });
  const stale = await readBillingContainerProbe(staleRoot);
  assert.equal(stale.status, "FAILED");
  assert.equal(stale.errorCode, "container_probe_heartbeat_stale");

  const malformedRoot = await fixtureRoot();
  const relayFile = path.join(malformedRoot, "malicious-relay", "status.json");
  const relay = JSON.parse(await fs.readFile(relayFile, "utf8"));
  relay.coverage.relay_request_replay.contained = 0;
  await fs.writeFile(relayFile, `${JSON.stringify(relay)}\n`);
  const malformed = await readBillingContainerProbe(malformedRoot);
  assert.equal(malformed.status, "FAILED");
  assert.equal(malformed.errorCode, "container_probe_counter_invalid");

  const violatedRoot = await fixtureRoot({ violation: "nat_identity_forgery" });
  const violated = await readBillingContainerProbe(violatedRoot);
  assert.equal(violated.status, "FAILED");
  assert.equal(violated.failed, 1);
  assert.equal(violated.coverage.find((item) => item.scenario === "nat_identity_forgery")?.violations, 1);

  const stoppedRoot = await fixtureRoot();
  const stoppedFile = path.join(stoppedRoot, "malicious-natserver", "status.json");
  const stoppedActor = JSON.parse(await fs.readFile(stoppedFile, "utf8"));
  stoppedActor.status = "STOPPED";
  await fs.writeFile(stoppedFile, `${JSON.stringify(stoppedActor)}\n`);
  const stopped = await readBillingContainerProbe(stoppedRoot);
  assert.equal(stopped.status, "FAILED");
  assert.equal(stopped.failed, 1);
  assert.equal(stopped.errorCode, "container_probe_actor_stopped");
});

test("startup wait tolerates absent snapshots until both fixtures reach 9/9", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-container-probe-wait-test-"));
  temporaryDirectories.push(root);
  const waiting = waitForBillingContainerProbe(root, { timeoutMs: 2000 });
  await new Promise((resolve) => setTimeout(resolve, 150));
  await writeFixtureSnapshots(root);
  const probe = await waiting;
  assert.equal(probe.status, "RUNNING");
  assert.equal(probe.covered, probe.required);
  assert.equal(probe.required, 9);
});

async function fixtureRoot(options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-container-probe-test-"));
  temporaryDirectories.push(root);
  await writeFixtureSnapshots(root, options);
  return root;
}

async function writeFixtureSnapshots(root, options = {}) {
  const heartbeatAt = options.heartbeatAt ?? new Date().toISOString();
  for (const [actor, scenarios] of Object.entries(containerScenariosByActor)) {
    const service = actor === "relay" ? "malicious-relay" : "malicious-natserver";
    const directory = path.join(root, service);
    await fs.mkdir(directory, { recursive: true });
    const coverage = Object.fromEntries(scenarios.map((scenario) => {
      const violated = options.violation === scenario;
      return [scenario, { executed: 1, contained: violated ? 0 : 1, violations: violated ? 1 : 0 }];
    }));
    const failed = Object.values(coverage).reduce((sum, item) => sum + item.violations, 0);
    await fs.writeFile(path.join(directory, "status.json"), `${JSON.stringify({
      schemaVersion: 1,
      status: failed > 0 ? "FAILED" : "RUNNING",
      role: actor,
      mode: "container_network_protocol",
      heartbeatAt,
      sequence: scenarios.length,
      seedDigest: "0123456789abcdef",
      coverage,
      summary: {
        executedChecks: scenarios.length,
        containedChecks: scenarios.length - failed,
        failedChecks: failed,
        coveredScenarios: scenarios.length,
        requiredScenarios: scenarios.length,
      },
      recent: scenarios.map((scenario, index) => ({
        sequence: index + 1,
        observedAt: heartbeatAt,
        scenario,
        actor,
        passed: options.violation !== scenario,
        verdict: options.violation === scenario ? "VIOLATION" : "CONTAINED",
        failureCode: options.violation === scenario ? "forged_identity_accepted" : "",
        defense: options.violation === scenario ? "" : "attack_rejected",
        requestCount: 2,
        httpStatuses: [200, 409],
        balanceDelta: 0,
        stateChanged: false,
        path: actor === "relay"
          ? "malicious-relay->malicious-natserver->ca"
          : "malicious-natserver->malicious-relay->ca",
      })),
      transport: ["container_http_peer", "container_http_ca"],
      limitations: [],
      lastError: failed > 0 ? "forged_identity_accepted" : "",
    })}\n`);
  }
}
