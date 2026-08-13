import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import {
  attackScenarios,
  createAPIClient,
  runAttackCycle,
  runAttackScenario,
} from "./billing-adversary-core.mjs";
import { createBillingComponentProbe } from "./billing-component-probe.mjs";
import {
  containerScenariosByActor,
  readBillingContainerProbe,
  waitForBillingContainerProbe,
} from "./billing-container-probe.mjs";

process.umask(0o077);

const runDir = path.resolve(process.env.RUN_DIR ?? "");
const baseURL = process.env.CA_BASE_URL ?? "";
const intervalMs = boundedInteger(process.env.ATTACK_INTERVAL_MS, 15000, 250, 3600000);
const heartbeatMs = boundedInteger(process.env.HEARTBEAT_INTERVAL_MS, 5000, 250, 60000);
const recentLimit = boundedInteger(process.env.EVENT_LIMIT, 24, 8, 100);
const watchPid = boundedInteger(process.env.WATCH_PID, 0, 0, Number.MAX_SAFE_INTEGER);
const once = process.env.RUN_ONCE === "1";
const componentProbeBinary = process.env.COMPONENT_PROBE_BIN ?? "";
const componentProbeTimeoutMs = boundedInteger(process.env.COMPONENT_PROBE_TIMEOUT_MS, 3000, 100, 60000);
const containerProbeMode = process.env.CONTAINER_PROBE_MODE ?? "off";
const containerProbeStateRoot = path.resolve(process.env.CONTAINER_ADVERSARY_STATE_ROOT ?? "");
const containerProbeStartTimeoutMs = boundedInteger(process.env.CONTAINER_PROBE_START_TIMEOUT_MS, 60000, 1000, 120000);
const billingFixtureFiles = Object.freeze({
  payer: process.env.CA_BILLING_PAYER_KEY_FILE ?? "",
  relay: process.env.CA_BILLING_RELAY_KEY_FILE ?? "",
});
const snapshotPath = path.join(runDir, "billing-adversary.json");
const statusPath = path.join(runDir, "billing-adversary.status");
const alertPath = path.join(runDir, "billing-adversary.alert");
const eventPath = path.join(runDir, "billing-adversary-events.tsv");
const waitSubmitPath = path.join(runDir, "billing-adversary-waitsubmit.json");
const componentProbeStateDir = path.resolve(process.env.COMPONENT_PROBE_STATE_DIR ?? path.join(runDir, "billing-component-probe"));
const lockPath = path.join(runDir, "billing-adversary.lock");
const phasePath = path.join(runDir, "phase");
const terminalPhases = new Set(["COMPLETED", "FAILED", "RESOURCE_LIMIT", "STOPPED"]);

let lockHandle;
let stopping = false;
let stopReason = "";
let lastPublish = 0;
let eventSequence = 0;
let wakeDelay = null;
let componentProbe;
const componentProbeCoverage = new Set();
const snapshot = emptySnapshot();

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    stopping = true;
    stopReason = signal.toLowerCase();
    wakeDelay?.();
  });
}

try {
  validateConfiguration();
  lockHandle = await acquireLock();
  await ensureEventLog();
  const client = createAPIClient(baseURL);
  componentProbe = createBillingComponentProbe({
    binaryPath: componentProbeBinary,
    stateDir: componentProbeStateDir,
    timeoutMs: componentProbeTimeoutMs,
  });
  const context = { waitSubmitPath, componentProbe, billingFixture: await loadBillingFixture() };
  const initial = await runAttackCycle(client, randomNonce(), context);
  for (const event of initial) await recordEvent(event);
  if (containerProbeMode !== "off") {
    snapshot.containerProbe = await waitForBillingContainerProbe(containerProbeStateRoot, {
      timeoutMs: containerProbeStartTimeoutMs,
    });
  }
  await publish(true);
  process.stdout.write(`BNFS billing adversary running for ${path.basename(runDir)}\n`);

  if (!once) {
    while (!stopping) {
      await delayWithHeartbeat(intervalMs);
      if (stopping) break;
      if (watchPid > 0 && !processAlive(watchPid)) {
        stopping = true;
        stopReason = "runner_exited";
        break;
      }
      const phase = (await readText(phasePath)).trim();
      if (terminalPhases.has(phase)) {
        stopping = true;
        stopReason = `phase_${phase.toLowerCase()}`;
        break;
      }
      const scenario = attackScenarios[crypto.randomInt(attackScenarios.length)];
      await recordEvent(await runAttackScenario(client, scenario, randomNonce(), context));
      await publish(false);
    }
  }

  snapshot.stopReason = once ? "run_once_complete" : stopReason || "requested";
  snapshot.status = snapshot.summary.failedChecks > 0 || snapshot.containerProbe.failed > 0 ? "FAILED" : "STOPPED";
  snapshot.componentProbe.status = snapshot.componentProbe.failed > 0 ? "FAILED" : "STOPPED";
  await publish(true);
} catch (error) {
  snapshot.status = "DEGRADED";
  snapshot.componentProbe.status = snapshot.componentProbe.failed > 0 ? "FAILED" : "DEGRADED";
  snapshot.lastError = {
    at: new Date().toISOString(),
    code: safeCode(error?.code || "billing_adversary_error"),
  };
  if (lockHandle) await publish(true).catch(() => {});
  process.stderr.write(`billing adversary failed: ${safeCode(error?.code || "billing_adversary_error")}\n`);
  process.exitCode = 1;
} finally {
  await componentProbe?.close().catch(() => {});
  if (lockHandle) {
    await lockHandle.close().catch(() => {});
    await fs.unlink(lockPath).catch(() => {});
  }
}

async function loadBillingFixture() {
  const filenames = Object.values(billingFixtureFiles);
  if (filenames.every((filename) => filename === "")) return null;
  if (filenames.some((filename) => filename === "")) {
    throw Object.assign(new Error("incomplete billing fixture"), { code: "billing_fixture_incomplete" });
  }
  const [payer, relay] = await Promise.all([
    readPrivateJSON(billingFixtureFiles.payer),
    readPrivateJSON(billingFixtureFiles.relay),
  ]);
  return { payer, relay };
}

async function readPrivateJSON(filename) {
  const resolved = path.resolve(filename);
  if (resolved === runDir || !resolved.startsWith(`${runDir}${path.sep}`)) {
    throw Object.assign(new Error("billing fixture outside run directory"), { code: "billing_fixture_path_invalid" });
  }
  const stat = await fs.lstat(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
    || stat.size <= 0 || stat.size > 65536) {
    throw Object.assign(new Error("invalid billing fixture file"), { code: "billing_fixture_file_invalid" });
  }
  try {
    return JSON.parse(await fs.readFile(resolved, "utf8"));
  } catch {
    throw Object.assign(new Error("invalid billing fixture JSON"), { code: "billing_fixture_json_invalid" });
  }
}

function emptySnapshot() {
  const now = new Date().toISOString();
  return {
    schemaVersion: 1,
    status: "STARTING",
    mode: "active_local_api",
    scope: "isolated_synthetic_accounts",
    startedAt: now,
    heartbeatAt: now,
    stopReason: "",
    requiredScenarios: [...attackScenarios],
    coverage: Object.fromEntries(attackScenarios.map((scenario) => [scenario, {
      actor: scenario.startsWith("nat_") ? "natserver" : scenario.startsWith("index_") ? "network" : "relay",
      executed: 0,
      contained: 0,
      violations: 0,
    }])),
    actors: {
      natserver: { executed: 0, contained: 0, violations: 0 },
      relay: { executed: 0, contained: 0, violations: 0 },
      network: { executed: 0, contained: 0, violations: 0 },
    },
    summary: {
      executedChecks: 0,
      containedChecks: 0,
      preventedChecks: 0,
      failedChecks: 0,
      missedChecks: 0,
      preventionRatePct: 0,
      stateChanges: 0,
      coveredScenarios: 0,
      requiredScenarioCount: attackScenarios.length,
    },
    componentProbe: {
      schemaVersion: 1,
      status: "STARTING",
      executed: 0,
      failed: 0,
      required: attackScenarios.length,
      covered: 0,
    },
    containerProbe: emptyContainerProbe(),
    recent: [],
    limitations: [
      "isolated_synthetic_nat_and_relay_identities",
      "index_disconnect_is_loopback_fault_injection",
      "go_component_probe_is_not_full_p2p_socket_path",
    ],
    lastError: null,
  };
}

async function recordEvent(event) {
  eventSequence += 1;
  const published = { sequence: eventSequence, ...event };
  const coverage = snapshot.coverage[event.scenario];
  coverage.executed += 1;
  coverage.contained += event.passed ? 1 : 0;
  coverage.violations += event.passed ? 0 : 1;
  const actor = snapshot.actors[event.actor];
  if (actor) {
    actor.executed += 1;
    actor.contained += event.passed ? 1 : 0;
    actor.violations += event.passed ? 0 : 1;
  }
  snapshot.summary.executedChecks += 1;
  snapshot.summary.containedChecks += event.passed ? 1 : 0;
  snapshot.summary.preventedChecks = snapshot.summary.containedChecks;
  snapshot.summary.failedChecks += event.passed ? 0 : 1;
  snapshot.summary.missedChecks = snapshot.summary.failedChecks;
  snapshot.summary.preventionRatePct = Math.round(
    snapshot.summary.containedChecks / snapshot.summary.executedChecks * 10000,
  ) / 100;
  snapshot.summary.stateChanges += event.stateChanged ? 1 : 0;
  snapshot.summary.coveredScenarios = Object.values(snapshot.coverage).filter((item) => item.executed > 0).length;
  snapshot.componentProbe.executed += 1;
  snapshot.componentProbe.failed += event.componentProbePassed ? 0 : 1;
  if (event.componentProbeCovered) componentProbeCoverage.add(event.scenario);
  snapshot.componentProbe.covered = componentProbeCoverage.size;
  snapshot.componentProbe.status = snapshot.componentProbe.failed > 0 ? "FAILED" : "RUNNING";
  snapshot.recent.unshift(published);
  snapshot.recent = snapshot.recent.slice(0, recentLimit);
  snapshot.status = snapshot.summary.failedChecks > 0 ? "FAILED" : "RUNNING";
  snapshot.lastError = null;
  await fs.appendFile(eventPath, [
    published.observedAt,
    published.sequence,
    published.scenario,
    published.actor,
    published.actorInstance,
    published.verdict,
    published.failureCode || "none",
    published.defense || "none",
    published.stateChanged ? "yes" : "no",
    published.balanceDelta,
    published.depth,
    published.httpStatuses.join(",") || "none",
  ].join("\t") + "\n", { mode: 0o600 });
  if (!event.passed) await publishAlert(published);
}

async function publish(force) {
  const now = Date.now();
  if (!force && now - lastPublish < heartbeatMs) return;
  if (containerProbeMode !== "off") {
    snapshot.containerProbe = await readBillingContainerProbe(containerProbeStateRoot, { now });
    if (snapshot.containerProbe.failed > 0) await publishContainerAlert(snapshot.containerProbe);
  }
  refreshOverallStatus();
  snapshot.heartbeatAt = new Date(now).toISOString();
  await writeJSONAtomic(snapshotPath, snapshot);
  const heartbeatEpoch = Math.floor(now / 1000);
  const lines = [
    "schema_version=1",
    `status=${safeCode(snapshot.status).toUpperCase()}`,
    `heartbeat_epoch=${heartbeatEpoch}`,
    `executed_checks=${snapshot.summary.executedChecks}`,
    `failed_checks=${snapshot.summary.failedChecks}`,
    `covered_scenarios=${snapshot.summary.coveredScenarios}`,
    `required_scenarios=${snapshot.summary.requiredScenarioCount}`,
    `container_status=${safeCode(snapshot.containerProbe.status).toUpperCase()}`,
    `container_executed_checks=${snapshot.containerProbe.executed}`,
    `container_failed_checks=${snapshot.containerProbe.failed}`,
    `container_covered_scenarios=${snapshot.containerProbe.covered}`,
    `container_required_scenarios=${snapshot.containerProbe.required}`,
    `container_error_code=${safeCode(snapshot.containerProbe.errorCode) || "none"}`,
  ];
  await writeTextAtomic(statusPath, `${lines.join("\n")}\n`);
  lastPublish = now;
}

function emptyContainerProbe() {
  const coverage = Object.entries(containerScenariosByActor).flatMap(([actor, scenarios]) => (
    scenarios.map((scenario) => ({ scenario, actor, executed: 0, contained: 0, violations: 0 }))
  ));
  return {
    schemaVersion: 1,
    status: "DISABLED",
    executed: 0,
    failed: 0,
    covered: 0,
    required: coverage.length,
    actors: {
      natserver: { status: "DISABLED", executed: 0, failed: 0, covered: 0, required: containerScenariosByActor.natserver.length },
      relay: { status: "DISABLED", executed: 0, failed: 0, covered: 0, required: containerScenariosByActor.relay.length },
    },
    coverage,
    recent: [],
    transport: ["container_http_peer", "container_http_ca"],
    limitations: [
      "isolated_from_production_nat_and_relay_accounts",
      "does_not_instantiate_full_p2p_payload_socket",
      "nat_meter_uses_deterministic_attack_fixture",
    ],
    errorCode: "",
  };
}

function refreshOverallStatus() {
  if (snapshot.status === "DEGRADED") return;
  const failed = snapshot.summary.failedChecks > 0 || snapshot.containerProbe.failed > 0;
  if (snapshot.stopReason) {
    snapshot.status = failed ? "FAILED" : "STOPPED";
    return;
  }
  if (failed) {
    snapshot.status = "FAILED";
    return;
  }
  const containerReady = containerProbeMode === "off" || (
    snapshot.containerProbe.status === "RUNNING"
    && snapshot.containerProbe.covered === snapshot.containerProbe.required
  );
  snapshot.status = containerReady ? "RUNNING" : "STARTING";
}

async function publishContainerAlert(probe) {
  const violation = probe.recent.find((event) => event.passed === false);
  await writeJSONAtomic(alertPath, {
    schemaVersion: 1,
    status: "SECURITY_INVARIANT_FAILED",
    detectedAt: violation?.observedAt || new Date().toISOString(),
    scenario: violation?.scenario || "container_probe",
    failureCode: safeCode(violation?.failureCode || probe.errorCode || "container_probe_failed"),
    stateChanged: violation?.stateChanged === true,
  });
}

async function publishAlert(event) {
  await writeJSONAtomic(alertPath, {
    schemaVersion: 1,
    status: "SECURITY_INVARIANT_FAILED",
    detectedAt: event.observedAt,
    scenario: event.scenario,
    failureCode: event.failureCode,
    stateChanged: event.stateChanged,
  });
}

function validateConfiguration() {
  if (!process.env.RUN_DIR || runDir === path.parse(runDir).root) {
    throw Object.assign(new Error("invalid run directory"), { code: "invalid_run_dir" });
  }
  if (!baseURL) throw Object.assign(new Error("missing CA base URL"), { code: "missing_ca_base_url" });
  if (watchPid === process.pid) throw Object.assign(new Error("invalid watch PID"), { code: "invalid_watch_pid" });
  if (!["off", "enforce", "report"].includes(containerProbeMode)) {
    throw Object.assign(new Error("invalid container probe mode"), { code: "container_probe_mode_invalid" });
  }
  if (containerProbeMode !== "off" && (!process.env.CONTAINER_ADVERSARY_STATE_ROOT
    || containerProbeStateRoot === path.parse(containerProbeStateRoot).root)) {
    throw Object.assign(new Error("invalid container probe state root"), { code: "container_probe_state_root_invalid" });
  }
}

async function acquireLock() {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const handle = await fs.open(lockPath, "wx", 0o600);
      await handle.writeFile(`${JSON.stringify({ pid: process.pid, startedAt: snapshot.startedAt })}\n`);
      return handle;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const owner = await readJSON(lockPath);
      if (processAlive(boundedInteger(owner.pid, 0, 0, Number.MAX_SAFE_INTEGER))) {
        throw Object.assign(new Error("billing adversary already running"), { code: "adversary_already_running" });
      }
      await fs.unlink(lockPath).catch(() => {});
    }
  }
  throw Object.assign(new Error("unable to acquire billing adversary lock"), { code: "adversary_lock_failed" });
}

async function ensureEventLog() {
  try {
    await fs.access(eventPath);
  } catch {
    await fs.writeFile(eventPath, "timestamp\tsequence\tscenario\tactor\tactor_instance\tverdict\tfailure_code\tdefense\tstate_changed\tbalance_delta\tdepth\thttp_statuses\n", { mode: 0o600 });
  }
}

async function writeJSONAtomic(file, value) {
  await writeTextAtomic(file, `${JSON.stringify(value)}\n`);
}

async function writeTextAtomic(file, value) {
  const temporary = `${file}.tmp-${process.pid}`;
  await fs.writeFile(temporary, value, { mode: 0o600 });
  await fs.rename(temporary, file);
}

async function readJSON(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return {};
  }
}

async function readText(file) {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return "";
  }
}

function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function randomNonce() {
  return crypto.randomBytes(8).toString("hex");
}

function safeCode(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 64);
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

function delay(milliseconds) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (wakeDelay === finish) wakeDelay = null;
      resolve();
    };
    const timer = setTimeout(finish, milliseconds);
    wakeDelay = finish;
  });
}

async function delayWithHeartbeat(milliseconds) {
  const deadline = Date.now() + milliseconds;
  while (!stopping && Date.now() < deadline) {
    await delay(Math.min(heartbeatMs, deadline - Date.now()));
    if (!stopping) await publish(true);
  }
}
