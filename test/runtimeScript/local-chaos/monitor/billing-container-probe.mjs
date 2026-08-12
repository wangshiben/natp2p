import fs from "node:fs/promises";
import path from "node:path";

export const containerScenariosByActor = Object.freeze({
  natserver: Object.freeze([
    "nat_stale_watermark",
    "nat_same_sequence_fork",
    "nat_signature_refusal",
    "nat_identity_forgery",
  ]),
  relay: Object.freeze([
    "relay_usage_inflation",
    "relay_request_replay",
    "relay_fee_override",
    "relay_window_overrun",
    "relay_voucher_tamper",
  ]),
});

const actorServices = Object.freeze({
  natserver: "malicious-natserver",
  relay: "malicious-relay",
});
const allowedStatuses = new Set(["STARTING", "RUNNING", "FAILED", "STOPPED"]);
const allowedPaths = new Set([
  "container_peer_protocol",
  "malicious-relay->malicious-natserver",
  "malicious-relay->malicious-natserver->ca",
  "malicious-natserver->malicious-relay",
  "malicious-natserver->malicious-relay->ca",
  "malicious-natserver->malicious-relay->malicious-natserver",
]);

export async function waitForBillingContainerProbe(stateRoot, options = {}) {
  const timeoutMs = boundedInteger(options.timeoutMs, 60000, 1000, 120000);
  const deadline = Date.now() + timeoutMs;
  let latest;
  while (Date.now() < deadline) {
    latest = await readBillingContainerProbe(stateRoot, options);
    if (latest.status === "RUNNING" && latest.failed === 0 && latest.covered === latest.required) return latest;
    if (latest.status === "FAILED" && !startupRetryable(latest)) return latest;
    await delay(100);
  }
  return failedProbe("container_probe_start_timeout");
}

export async function readBillingContainerProbe(stateRoot, options = {}) {
  const now = boundedInteger(options.now, Date.now(), 0, Number.MAX_SAFE_INTEGER);
  const freshnessMs = boundedInteger(options.freshnessMs, 10000, 1000, 60000);
  if (!stateRoot || path.resolve(stateRoot) === path.parse(path.resolve(stateRoot)).root) {
    return failedProbe("container_probe_state_root_invalid");
  }

  const actorResults = await Promise.all(Object.entries(actorServices).map(async ([actor, service]) => {
    const value = await readJSON(path.join(stateRoot, service, "status.json"));
    return validateActorSnapshot(actor, value, now, freshnessMs);
  }));
  const coverage = actorResults.flatMap((result) => result.coverage);
  const executed = coverage.reduce((sum, item) => sum + item.executed, 0);
  const failed = coverage.reduce((sum, item) => sum + item.violations, 0)
    + actorResults.filter((result) => !result.valid || (
      ["FAILED", "STOPPED"].includes(result.status)
      && result.coverage.every((item) => item.violations === 0)
    )).length;
  const covered = coverage.filter((item) => item.executed > 0).length;
  const required = Object.values(containerScenariosByActor).reduce((sum, scenarios) => sum + scenarios.length, 0);
  const allRunning = actorResults.every((result) => result.valid && result.status === "RUNNING");
  const anyFailed = actorResults.some((result) => ["FAILED", "STOPPED"].includes(result.status)) || failed > 0;
  const status = anyFailed ? "FAILED" : allRunning && covered === required ? "RUNNING" : "STARTING";
  const recent = actorResults.flatMap((result) => result.recent)
    .sort((left, right) => Date.parse(right.observedAt) - Date.parse(left.observedAt))
    .slice(0, 16);
  return {
    schemaVersion: 1,
    status,
    executed,
    failed,
    covered,
    required,
    actors: Object.fromEntries(actorResults.map((result) => [result.actor, {
      status: result.status,
      executed: result.coverage.reduce((sum, item) => sum + item.executed, 0),
      failed: result.coverage.reduce((sum, item) => sum + item.violations, 0)
        + (!result.valid || (["FAILED", "STOPPED"].includes(result.status)
          && result.coverage.every((item) => item.violations === 0)) ? 1 : 0),
      covered: result.coverage.filter((item) => item.executed > 0).length,
      required: result.coverage.length,
    }])),
    coverage,
    recent,
    transport: ["container_http_peer", "container_http_ca"],
    limitations: [
      "isolated_from_production_nat_and_relay_accounts",
      "does_not_instantiate_full_p2p_payload_socket",
      "nat_meter_uses_deterministic_attack_fixture",
    ],
    errorCode: firstError(actorResults)
      || (actorResults.some((result) => result.status === "STOPPED") ? "container_probe_actor_stopped" : ""),
  };
}

function validateActorSnapshot(actor, value, now, freshnessMs) {
  const expected = containerScenariosByActor[actor];
  const emptyCoverage = expected.map((scenario) => ({ scenario, actor, executed: 0, contained: 0, violations: 0 }));
  const fail = (errorCode, status = "FAILED") => ({
    actor, valid: false, status, coverage: emptyCoverage, recent: [], errorCode,
  });
  if (!value || value.schemaVersion !== 1 || value.role !== actor
    || value.mode !== "container_network_protocol" || !allowedStatuses.has(value.status)) {
    return fail("container_probe_snapshot_invalid");
  }
  const heartbeat = Date.parse(value.heartbeatAt);
  if (!Number.isFinite(heartbeat) || heartbeat > now + 5000 || now - heartbeat > freshnessMs) {
    return fail("container_probe_heartbeat_stale");
  }
  if (!value.coverage || typeof value.coverage !== "object" || Array.isArray(value.coverage)) {
    return fail("container_probe_coverage_invalid");
  }
  if (Object.keys(value.coverage).sort().join("\0") !== [...expected].sort().join("\0")) {
    return fail("container_probe_coverage_invalid");
  }
  const coverage = [];
  for (const scenario of expected) {
    const source = value.coverage[scenario];
    const counters = [source?.executed, source?.contained, source?.violations];
    if (counters.some((count) => !Number.isSafeInteger(count) || count < 0)
      || source.contained + source.violations !== source.executed) {
      return fail("container_probe_counter_invalid");
    }
    coverage.push({
      scenario,
      actor,
      executed: source.executed,
      contained: source.contained,
      violations: source.violations,
    });
  }
  const summary = {
    executed: coverage.reduce((sum, item) => sum + item.executed, 0),
    contained: coverage.reduce((sum, item) => sum + item.contained, 0),
    failed: coverage.reduce((sum, item) => sum + item.violations, 0),
    covered: coverage.filter((item) => item.executed > 0).length,
  };
  if (!value.summary || value.summary.executedChecks !== summary.executed
    || value.summary.containedChecks !== summary.contained
    || value.summary.failedChecks !== summary.failed
    || value.summary.coveredScenarios !== summary.covered
    || value.summary.requiredScenarios !== expected.length) {
    return fail("container_probe_summary_invalid");
  }
  if (value.status === "RUNNING" && (summary.failed !== 0 || summary.covered !== expected.length)) {
    return fail("container_probe_running_state_invalid");
  }
  if (value.status === "FAILED" && summary.failed === 0 && !safeCode(value.lastError)) {
    return fail("container_probe_failed_state_invalid");
  }
  const recent = Array.isArray(value.recent)
    ? value.recent.map((event) => publicEvent(event, actor, expected)).filter(Boolean).slice(0, 16)
    : [];
  return {
    actor,
    valid: true,
    status: value.status,
    coverage,
    recent,
    errorCode: safeCode(value.lastError),
  };
}

function publicEvent(value, actor, expected) {
  if (!value || !expected.includes(value.scenario) || value.actor !== actor
    || !Number.isSafeInteger(value.sequence) || value.sequence < 1) return null;
  const observedAt = publicTimestamp(value.observedAt);
  if (!observedAt) return null;
  const passed = value.passed === true;
  const verdict = passed ? "CONTAINED" : "VIOLATION";
  return {
    sequence: value.sequence,
    observedAt,
    scenario: value.scenario,
    actor,
    passed,
    verdict,
    failureCode: safeCode(value.failureCode),
    defense: safeCode(value.defense),
    requestCount: nonNegativeInteger(value.requestCount),
    httpStatuses: Array.isArray(value.httpStatuses)
      ? value.httpStatuses.map(nonNegativeInteger).filter((status) => status >= 100 && status <= 599).slice(0, 8)
      : [],
    balanceDelta: Number.isSafeInteger(value.balanceDelta) ? value.balanceDelta : 0,
    stateChanged: value.stateChanged === true,
    path: allowedPaths.has(value.path) ? value.path : "container_peer_protocol",
  };
}

function failedProbe(errorCode) {
  const coverage = Object.entries(containerScenariosByActor).flatMap(([actor, scenarios]) => (
    scenarios.map((scenario) => ({ scenario, actor, executed: 0, contained: 0, violations: 0 }))
  ));
  return {
    schemaVersion: 1,
    status: "FAILED",
    executed: 0,
    failed: 1,
    covered: 0,
    required: coverage.length,
    actors: {
      natserver: { status: "FAILED", executed: 0, failed: 1, covered: 0, required: containerScenariosByActor.natserver.length },
      relay: { status: "FAILED", executed: 0, failed: 1, covered: 0, required: containerScenariosByActor.relay.length },
    },
    coverage,
    recent: [],
    transport: ["container_http_peer", "container_http_ca"],
    limitations: [
      "isolated_from_production_nat_and_relay_accounts",
      "does_not_instantiate_full_p2p_payload_socket",
      "nat_meter_uses_deterministic_attack_fixture",
    ],
    errorCode,
  };
}

function firstError(results) {
  return results.map((result) => safeCode(result.errorCode)).find(Boolean) ?? "";
}

function startupRetryable(probe) {
  return probe.coverage.every((item) => item.violations === 0)
    && ["container_probe_snapshot_invalid", "container_probe_heartbeat_stale"].includes(probe.errorCode);
}

async function readJSON(filename) {
  try {
    const encoded = await fs.readFile(filename, "utf8");
    if (encoded.length > 1024 * 1024) return {};
    return JSON.parse(encoded);
  } catch {
    return {};
  }
}

function publicTimestamp(value) {
  const timestamp = Date.parse(String(value ?? ""));
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : "";
}

function safeCode(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 64);
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(Number(value)) && Number(value) >= 0 ? Number(value) : 0;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
