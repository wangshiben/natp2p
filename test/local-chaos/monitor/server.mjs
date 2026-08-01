import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import process from "node:process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const host = process.env.HOST ?? "0.0.0.0";
const port = integer(process.env.PORT, 8911);
const runDir = path.resolve(process.env.RUN_DIR ?? ".");
const privateRuntimeDir = path.resolve(process.env.PRIVATE_RUNTIME_DIR ?? path.join(runDir, "runtime", ".private"));
const composeProject = process.env.COMPOSE_PROJECT ?? "";
const composeFile = path.resolve(process.env.COMPOSE_FILE ?? path.join(runDir, "runtime", "compose.json"));
const caPort = integer(process.env.CA_PORT, 19100);
const reconnectGateURL = String(
  process.env.BNFS_RECONNECT_GATE_MONITOR_URL ?? process.env.BNFS_RECONNECT_GATE_URL ?? "",
).trim();
const reconnectGateToken = String(process.env.BNFS_RECONNECT_GATE_TOKEN ?? "");
const capacityRunPointer = path.resolve(
  process.env.CAPACITY_RUN_POINTER ?? "/tmp/natp2p-capacity.EVFZr6/latest-formal-run",
);
const htmlPath = new URL("./index.html", import.meta.url);
const relayCount = 7;
const natServerCount = 13;
const natClientCount = 6;
const maliciousNatClient = "malicious-natclient";
const maliciousRandomNatServer = "malicious-random-natserver";
const transferClients = [...numbered("natclient", natClientCount), maliciousNatClient];
const transferServers = [...numbered("natserver", natServerCount), maliciousRandomNatServer];
const failureRetentionLimit = 50;
const transferColumns = [
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
];
const expectedServices = [
  "ca",
  "index",
  ...numbered("relay", relayCount),
  ...numbered("natserver", natServerCount),
  ...numbered("natclient", natClientCount),
  maliciousRandomNatServer,
  maliciousNatClient,
];
const maliciousNodeCatalog = Object.freeze([
  Object.freeze({ service: "malicious-natserver", actor: "natserver" }),
  Object.freeze({ service: "malicious-relay", actor: "relay" }),
]);
const maliciousScenarioActors = new Map([
  ["nat_stale_watermark", "natserver"],
  ["nat_same_sequence_fork", "natserver"],
  ["nat_signature_refusal", "natserver"],
  ["nat_identity_forgery", "natserver"],
  ["relay_usage_inflation", "relay"],
  ["relay_request_replay", "relay"],
  ["relay_fee_override", "relay"],
  ["relay_window_overrun", "relay"],
  ["relay_voucher_tamper", "relay"],
]);
const maliciousScenarioNames = new Set(maliciousScenarioActors.keys());
const mixedPathNodes = new Set([
  "mixed-path-probe",
  "malicious-natserver",
  "malicious-relay",
  "index",
  ...numbered("relay", relayCount),
]);
const mixedPathStatuses = new Set(["STARTING", "RUNNING", "MIGRATING", "DEGRADED", "FAILED", "STOPPED"]);
const mixedPathPartitions = new Set(["control_partition_a", "control_partition_b"]);
const mixedPathAttachmentTypes = new Set([
  "registered_to_normal_relay",
  "connected_to_malicious_relay",
  "connected_to_normal_relay",
  "control_peer_with_normal_relay",
]);
const mixedPathAttachmentBases = new Set(["live_relay_registration", "live_tunnel_registration", "live_control_hello"]);
const publicRuntimeStatuses = new Set([
  "created",
  "dead",
  "error",
  "exited",
  "healthy",
  "missing",
  "paused",
  "removing",
  "restarting",
  "running",
  "starting",
  "unhealthy",
  "unknown",
]);
const expectedServiceSet = new Set(expectedServices);
const expectedNetworkSet = new Set([
  "control_index",
  "control_partition_a",
  "control_partition_b",
  "ca_host",
  "adversary_billing",
  "adversary_mixed_access",
  "ip_family_ipv4",
  "ip_family_ipv6",
  "ip_family_dual",
  ...numbered("access_r", relayCount),
]);
const billingProductionGateFailureDetails = new Set([
  "billing_production_gate_failed",
  "billing_production_gate_cleanup_failed",
  "billing_production_gate_actor_missing",
  "billing_production_gate_channel_not_fresh",
  "billing_production_gate_relay_identity_missing",
  "billing_production_gate_relay_registration_missing",
  "billing_production_gate_inspector_unavailable",
  "billing_production_gate_inspection_invalid",
  "billing_production_gate_queue_not_empty",
  "billing_production_gate_client_start_failed",
  "billing_production_gate_balance_read_failed",
  "billing_production_gate_accounting_read_failed",
  "billing_production_gate_ca_pause_failed",
  "billing_production_gate_ca_disconnect_not_observed",
  "billing_production_gate_transfer_failed",
  "billing_production_gate_producer_freeze_failed",
  "billing_production_gate_queue_depth_not_reached",
  "billing_production_gate_queue_digest_failed",
  "billing_production_gate_relay_crash_failed",
  "billing_production_gate_crash_inspection_failed",
  "billing_production_gate_queue_persistence_changed",
  "billing_production_gate_client_stop_failed",
  "billing_production_gate_ca_resume_failed",
  "billing_production_gate_relay_start_failed",
  "billing_production_gate_queue_recovery_timeout",
  "billing_production_gate_recovery_server_restart_failed",
  "billing_production_gate_recovery_client_start_failed",
  "billing_production_gate_recovery_transfer_failed",
  "billing_production_gate_recovery_client_stop_failed",
  "billing_production_gate_recovery_queue_timeout",
  "billing_production_gate_balance_delta_invalid",
  "billing_production_gate_nat_snapshot_unavailable",
  "billing_production_gate_nat_snapshot_invalid",
  "billing_production_gate_nat_snapshot_unstable",
  "billing_production_gate_authorization_invalid",
  "billing_production_gate_authorized_amount_mismatch",
  "billing_production_gate_payer_debit_mismatch",
  "billing_production_gate_channel_accounting_mismatch",
  "billing_production_gate_payer_overcharged",
  "billing_production_gate_unbilled_tail_invalid",
  "billing_production_gate_relay_income_mismatch",
  "billing_production_gate_split_mismatch",
  "billing_production_gate_ca_split_mismatch",
]);
const billingContainerProbeCodes = new Set([
  "",
  "attack_rejected",
  "baseline_invalid",
  "baseline_signature_invalid",
  "baseline_voucher_id_invalid",
  "ca_idempotent_replay",
  "ca_rejected_tampered_double_signature",
  "candidate_identity_invalid",
  "container_attack_not_contained",
  "container_probe_actor_stopped",
  "container_probe_counter_invalid",
  "container_probe_coverage_invalid",
  "container_probe_failed_state_invalid",
  "container_probe_heartbeat_stale",
  "container_probe_running_state_invalid",
  "container_probe_runtime_failed",
  "container_probe_snapshot_invalid",
  "container_probe_start_timeout",
  "container_probe_summary_invalid",
  "duplicate_deduction_detected",
  "forged_identity_accepted",
  "malicious_nat_chain_accepted",
  "malicious_nat_peer_unavailable",
  "malicious_relay_claim_not_contained",
  "malicious_relay_peer_unavailable",
  "mutual_voucher_handshake_failed",
  "nat_attack_baseline_rejected",
  "nat_baseline_signature_failed",
  "nat_candidate_signature_failed",
  "nat_meter_rejected_usage_inflation",
  "nat_peer_unavailable",
  "nat_refusal_bypassed",
  "nat_refusal_protocol_unavailable",
  "nat_rejected_one_mib_window_overrun",
  "nat_rejected_policy_override",
  "nat_sign_protocol_unavailable",
  "one_mib_window_overrun_not_rejected",
  "payer_balance_unavailable",
  "relay_attack_signature_failed",
  "relay_chain_probe_unavailable",
  "relay_identity_probe_unavailable",
  "relay_never_submitted_unsigned_bill",
  "relay_refusal_probe_unavailable",
  "relay_rejected_forged_nat_identity",
  "relay_rejected_invalid_nat_candidate",
  "relay_rejected_same_sequence_fork",
  "relay_rejected_stale_nat_watermark",
  "relay_signature_failed",
  "relay_signature_fixture_failed",
  "request_invalid",
  "rogue_identity_generation_failed",
  "rogue_identity_signature_failed",
  "scenario_invalid",
  "tampered_relay_signature_failed",
  "tampered_voucher_accepted",
  "tampered_voucher_assembly_failed",
  "tampered_voucher_request_failed",
  "valid_voucher_rejected",
  "voucher_replay_request_failed",
  "voucher_request_build_failed",
]);
const publicRunOutcomes = new Set(["COMPLETED", "FAILED", "RESOURCE_LIMIT", "STOPPED"]);
const publicRunDetails = new Set([
  "billing_adversary_coverage_incomplete",
  "billing_adversary_exited",
  "billing_adversary_final_status_invalid",
  "billing_adversary_heartbeat_stale",
  "billing_adversary_security_violation",
  "billing_adversary_start_failed",
  "billing_adversary_status_invalid",
  "billing_adversary_stop_timeout",
  "billing_adversary_unhealthy_status",
  "billing_container_probe_actor_stopped",
  "billing_container_probe_coverage_incomplete",
  "billing_container_probe_heartbeat_stale",
  "billing_container_probe_runtime_failed",
  "billing_container_probe_security_violation",
  "billing_container_probe_start_timeout",
  "billing_container_probe_status_invalid",
  "billing_container_probe_unhealthy_status",
  "billing_production_gate_core_unhealthy",
  "billing_production_gate_failed",
  "build_failed",
  "ca_port_busy",
  "cluster_start_failed",
  "container_adversary_provision_failed",
  "core_identity_capture_failed",
  "core_identity_recapture_failed",
  "core_service_recreated_or_restarted",
  "core_service_unhealthy",
  "dashboard_exited",
  "dashboard_port_busy",
  "dashboard_start_failed",
  "dashboard_status_api_http_invalid",
  "dashboard_status_api_json_invalid",
  "dashboard_status_api_malicious_nodes_invalid",
  "dashboard_status_api_mixed_path_invalid",
  "dashboard_status_api_phase_invalid",
  "dashboard_status_api_transport_failed",
  "duration_complete",
  "failure_watcher_degraded",
  "failure_watcher_exited",
  "failure_watcher_failed",
  "failure_watcher_heartbeat_stale",
  "failure_watcher_source_lag",
  "failure_watcher_source_lag_timeout",
  "failure_watcher_source_unavailable",
  "failure_watcher_start_failed",
  "failure_watcher_status_invalid",
  "failure_watcher_status_missing",
  "failure_watcher_unhealthy_status",
  "initializing",
  "ip_family_coverage_gate_failed",
  "mixed_path_controller_exited",
  "mixed_path_containment_unverified",
  "mixed_path_heartbeat_stale",
  "mixed_path_migration_incomplete",
  "mixed_path_network_containment_violation",
  "mixed_path_network_coverage_incomplete",
  "mixed_path_network_evidence_invalid",
  "mixed_path_normal_partition_attachment_invalid",
  "mixed_path_probe_failed",
  "mixed_path_start_failed",
  "mixed_path_status_invalid",
  "mixed_path_stop_timeout",
  "post_gate_server_pool_recovery_failed",
  "profile_setup_failed",
  "random_client_worker_failed",
  "random_transfer_reconciliation_failed",
  "random_worker_drain_timeout",
  "random_worker_group_leaked",
  "random_worker_group_stop_failed",
  "random_worker_identity_invalid",
  "random_worker_start_failed",
  "random_workload_coverage_failed",
  "project_cleanup_incomplete",
  "project_cleanup_inspection_failed",
  "resource_guard_cleanup_failed",
  "resource_guard_deadline_exceeded",
  "resource_guard_exited",
  "resource_guard_identity_invalid",
  "resource_guard_sample_invalid",
  "resource_guard_sample_missing",
  "resource_guard_sample_stale",
  "resource_guard_start_failed",
  "resource_guard_status_invalid",
  "resource_guard_stop_failed",
  "resource_guard_stop_timeout",
  "resource_threshold_exceeded",
  "runner_exited_unexpectedly",
  "signal_requested",
  "signal_requested_during_profile",
  "three_consecutive_large_probe_failures",
  "transfer_failure_detected",
  "worker_group_stop_failed",
  "worker_identity_invalid",
  "worker_registry_invalid",
  "worker_registry_lock_failed",
  ...billingProductionGateFailureDetails,
]);
const failureWatcherErrorCodes = new Set([
  "invalid_run_dir",
  "invalid_transfer_header",
  "invalid_watch_pid",
  "watcher_already_running",
  "watcher_error",
  "watcher_lock_failed",
]);
const billingAdversaryErrorCodes = new Set([
  "adversary_already_running",
  "adversary_lock_failed",
  "billing_adversary_error",
  "ca_credential_invalid",
  "ca_credential_path_invalid",
  "ca_credentials_incomplete",
  "container_probe_mode_invalid",
  "container_probe_state_root_invalid",
  "invalid_run_dir",
  "invalid_watch_pid",
  "missing_ca_base_url",
]);
const billingAdversaryEventCodes = new Set([
  "attack_probe_error",
  "backlog_replay_changed_balance",
  "balance_probe_unavailable",
  "channel_frozen_on_fork",
  "component_probe_malicious_variant_accepted",
  "component_probe_missing",
  "component_probe_output_invalid",
  "disconnect_fixture_not_isolated",
  "fee_and_legacy_api_rejection",
  "fifo_recovered_exactly_once",
  "fixed_policy_and_legacy_endpoints_rejected",
  "fixed_policy_rejected",
  "fork_changed_balance",
  "idempotent_replay",
  "legacy_billing_endpoint_not_retired",
  "malicious_voucher_accepted",
  "one_mib_window_enforced",
  "payer_signature_required",
  "recovered_tail_not_idempotent",
  "rejected_voucher_changed_balance",
  "replay_changed_balance",
  "same_sequence_fork_not_frozen",
  "signed_record_root_protected",
  "stale_watermark_rejected",
  "unauthorized_balance_change",
  "usage_inflation_rejected",
  "voucher_api_unavailable",
  "voucher_replay_not_idempotent",
  "waitsubmit_balance_mismatch",
  "waitsubmit_delete_persistence_failed",
  "waitsubmit_fifo_recovery_failed",
  "waitsubmit_path_missing",
  "waitsubmit_previous_recovery_failed",
  "waitsubmit_restart_restore_failed",
]);
const billingAdversaryDepths = new Set([
  "production_go_component_probe",
  "voucher_api",
  "voucher_api_rejection",
  "voucher_api_replay",
  "voucher_chain_validation",
  "voucher_fork_freeze",
  "waitsubmit_fifo_recovery",
]);
const resourceSampleStates = new Set(["LIMIT_EXCEEDED", "OK"]);

let cachedStatus = null;
let cachedAt = 0;
let refreshPromise = null;
let firewallCache = { key: "", cachedAt: 0, value: new Map() };
let failureEvidenceCache = new Map();
let transferLogCache = emptyTransferLogCache("");

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    if (request.method !== "GET") {
      return json(response, 405, { error: "method_not_allowed" });
    }
    if (url.pathname === "/healthz") {
      return json(response, 200, {
        ok: true,
        timestamp: new Date().toISOString(),
      });
    }
    if (url.pathname === "/api/status") {
      const status = await statusSnapshot(url.searchParams.get("fresh") === "1");
      return json(response, 200, status, { "Cache-Control": "no-store" });
    }
    if (url.pathname === "/" || url.pathname === "/index.html") {
      const body = await fs.readFile(htmlPath);
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": body.length,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
      });
      return response.end(body);
    }
    return json(response, 404, { error: "not_found" });
  } catch {
    return json(response, 500, { error: "dashboard_error" });
  }
});

server.listen(port, host, () => {
  process.stdout.write(`BNFS stability dashboard listening on http://${host}:${port}/\n`);
});

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}

async function statusSnapshot(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedStatus && now - cachedAt < 1800) return cachedStatus;
  if (refreshPromise) {
    if (!forceRefresh) return refreshPromise;
    await refreshPromise.catch(() => {});
  }
  refreshPromise = buildStatus()
    .then((value) => {
      cachedStatus = value;
      cachedAt = Date.now();
      return value;
    })
    .finally(() => {
      refreshPromise = null;
    });
  return refreshPromise;
}

async function buildStatus() {
  const [metadata, status, phase, guardStatus, resources, probes, largeProbes, rawClientTransfers, randomBatches, workers, workload, compose, containers, finalContainers, ca, serverPool, clientPool, failureWatcher, billingAdversary, billingProductionGate, mixedPath, ipFamilyPlan, ipFamilyEvidence, natIdentities, capacityTest, reconnectGate] = await Promise.all([
    readEnv(path.join(runDir, "metadata.env")),
    readEnv(path.join(runDir, "status.env")),
    readText(path.join(runDir, "phase")),
    readText(path.join(runDir, "resource-guard.status")),
    readTsv(path.join(runDir, "resources.tsv"), 240),
    readTsv(path.join(runDir, "probes.tsv"), 30),
    readTsv(path.join(runDir, "large-probes.tsv"), 30),
    readClientTransfers(path.join(runDir, "transfers.tsv")),
    readRandomBatches(path.join(runDir, "random-batches.tsv")),
    readWorkerStatus(path.join(runDir, "worker-pids.tsv")),
    readEnv(path.join(runDir, "workload.env")),
    readJson(composeFile),
    inspectProjectContainers(),
    readTsv(path.join(runDir, "containers-final.tsv"), 100),
    probeCA(),
    readTsv(path.join(runDir, "server-pool.tsv"), 100),
    readTsv(path.join(runDir, "client-pool.tsv"), 100),
    readFailureWatcher(path.join(runDir, "failure-watcher.json")),
    readBillingAdversary(path.join(runDir, "billing-adversary.json")),
    readBillingProductionGate(path.join(runDir, "billing-production-gate.json")),
    readMixedAdversaryPath(path.join(runDir, "mixed-adversary-path.json")),
    readTsv(path.join(runDir, "ip-family-plan.tsv"), 4),
    readTsv(path.join(runDir, "ip-family-coverage.tsv"), 12),
    readTsv(path.join(runDir, "nat-identities.tsv"), 64),
    readCapacityTest(capacityRunPointer),
    readReconnectGate(
      path.join(runDir, "reconnect-gate-final.json"),
      capacityRunPointer,
    ),
  ]);
  const serviceSessions = await readServiceSessions(privateRuntimeDir, natIdentities);
  const nodeProfiles = buildNodeProfiles(serverPool, clientPool, ipFamilyPlan);
  const clientTransfers = enrichClientTransfers(rawClientTransfers, nodeProfiles);
  randomBatches.policy.rateLimitsKiBps = [1, 2, 3, 4].map((clients) => ({
    clients,
    kibps: publicNonNegativeInteger(
      integer(workload[`batch_limit_${clients}_client${clients === 1 ? "" : "s"}_kibps`], 0),
    ),
  }));
  randomBatches.policy.clientStartStaggerSeconds = publicNonNegativeInteger(
    integer(workload.batch_client_start_stagger_seconds, 0),
  );
  randomBatches.policy.mixedPathQuietSamples = publicNonNegativeInteger(
    integer(workload.batch_mixed_path_quiet_samples, 0),
  );
  randomBatches.policy.mixedPathQuietTimeoutSeconds = publicNonNegativeInteger(
    integer(workload.batch_mixed_path_quiet_timeout_seconds, 0),
  );

  const containerMap = new Map(containers.map((item) => [item.service, item]));
  const nodes = expectedServices.map((service) => containerMap.get(service) ?? missingContainer(service));
  for (const item of containers) {
    if (!expectedServices.includes(item.service)) nodes.push(item);
  }

  const nowEpoch = Math.floor(Date.now() / 1000);
  const deadlineEpoch = integer(metadata.deadline_epoch, 0);
  const durationSeconds = integer(metadata.duration_seconds, 0);
  const remainingSeconds = deadlineEpoch > 0
    ? Math.max(0, deadlineEpoch - nowEpoch)
    : durationSeconds;
  const core = nodes.filter((item) => expectedServiceSet.has(item.service)
    && (item.role === "ca" || item.role === "index" || item.role === "relay"));
  const nat = nodes.filter((item) => expectedServiceSet.has(item.service)
    && (item.role === "natserver" || item.role === "natclient"));
  const topologyWorkload = {
    server: knownService(workload.server, "natserver"),
    client: knownService(workload.client, "natclient"),
  };
  const activeNatServices = [topologyWorkload.server, topologyWorkload.client].filter(Boolean);
  const firewalls = await inspectNatFirewalls(activeNatServices, containerMap);
  const ipFamilyCoverage = publicIPFamilyCoverage(ipFamilyPlan, ipFamilyEvidence);
  const topology = await buildTopology({
    compose,
    metadata,
    workload: topologyWorkload,
    nodes,
    firewalls,
    mixedPath,
    capacityTest,
    serviceSessions,
    nodeProfiles,
  });
  const failureAnalysis = await buildFailureAnalysis({
    failures: transferLogCache.failures,
    failureStats: transferLogCache.failureStats,
    ingressStats: transferLogCache.ingressStats,
    available: transferLogCache.available,
    updatedAt: transferLogCache.updatedAt,
    serverPool,
    compose,
  });
  const publicNodes = nodes.map((node) => publicRuntimeNode(node, nodeProfiles.get(node.service)));
  const publicPhaseValue = publicPhase(phase);
  const maliciousRuntimeMap = publicRunOutcomes.has(publicPhaseValue)
    ? finalMaliciousRuntimeMap(finalContainers)
    : containerMap;
  const maliciousNodes = publicMaliciousNodes(maliciousRuntimeMap, billingAdversary.containerProbe);

  return {
    generatedAt: new Date().toISOString(),
    phase: publicPhaseValue,
    metadata: publicMetadata(metadata),
    status: publicRunStatus(status),
    timing: { durationSeconds, remainingSeconds },
    thresholds: {
      cpu: number(metadata.cpu_limit_pct, 55),
      memory: number(metadata.memory_limit_pct, 40),
      disk: number(metadata.disk_limit_pct, 40),
    },
    resourceGuard: publicResourceGuard(guardStatus),
    resources: {
      latest: publicResourceSample(resources.at(-1)),
      history: resources.map(publicResourceSample),
    },
    probes: {
      latest: publicProbe(probes.at(-1)),
      history: probes.map(publicProbe),
    },
    largeProbes: {
      latest: publicProbe(largeProbes.at(-1)),
      history: largeProbes.map(publicProbe),
    },
    clientTransfers,
    randomBatches,
    workers,
    failureAnalysis,
    failureWatcher,
    billingAdversary,
    billingProductionGate,
    reconnectGate,
    mixedPath,
    serviceSessions,
    capacityTest,
    ipFamilyCoverage,
    ca,
    summary: {
      coreExpected: core.length,
      coreHealthy: core.filter(isHealthy).length,
      natExpected: nat.length,
      natRunning: nat.filter((item) => item.running).length,
      totalExpected: expectedServices.length,
      totalRunning: nodes.filter((item) => item.running).length,
      totalRestarts: nodes.reduce((sum, item) => sum + (item.restartCount ?? 0), 0),
    },
    nodes: publicNodes,
    maliciousNodes,
    topology,
  };
}

async function readCapacityTest(pointerFile) {
  const runDirectory = String(await readText(pointerFile)).trim();
  if (!path.isAbsolute(runDirectory)) return emptyCapacityTest();
  const clientLog = await readTail(path.join(runDirectory, "client.log"), 1024 * 1024);
  if (!clientLog) return emptyCapacityTest();
  // Five-second sampling makes 8192 rows cover more than eleven hours,
  // including the full 500 x 100 MiB capacity run without publishing raw rows.
  const resourceRows = await readTsv(path.join(runDirectory, "resource-samples.tsv"), 8192, 8 * 1024 * 1024);
  const startTime = publicTimestamp(String(await readText(path.join(runDirectory, "start-time.txt"))).trim());
  const endTime = publicTimestamp(String(await readText(path.join(runDirectory, "end-time.txt"))).trim());
  const clientRCText = String(await readText(path.join(runDirectory, "client.rc"))).trim();
  const clientRC = /^-?\d+$/.test(clientRCText) ? integer(clientRCText, -1) : null;
  const clientPID = integer(String(await readText(path.join(runDirectory, "client.pid"))).trim(), 0);
  const clientRunning = clientPID > 0 && await processExists(clientPID);
  const plan = lastMatch(clientLog, /CAPACITY_PLAN clients=(\d+) transfer_mib=(\d+) targets=(\d+)/g);
  const connected = Math.max(
    lastIntegerMatch(clientLog, /CONNECTED count=(\d+)/g),
    lastIntegerMatch(clientLog, /MILESTONE_REACHED count=(\d+)/g),
  );
  const connectionFailures = lastIntegerMatch(clientLog, /CONNECT_FAILED failures=(\d+)/g);
  const warmup = lastMatch(clientLog, /CHECKSUM_WARMUP_COMPLETE clients=(\d+) unique_checksums=(\d+) elapsed=([^\s]+)/g);
  const barrier = lastMatch(clientLog, /TRANSFER_BARRIER clients=(\d+) bytes_per_client=(\d+) total_bytes=(\d+) timeout=([^\s]+) at=([^\s]+)/g);
  const progress = lastMatch(clientLog, /TRANSFER_PROGRESS clients=(\d+) successes=(\d+) failures=(\d+) bytes=(\d+) expected_bytes=(\d+) progress_pct=([\d.]+) mib_per_second=([\d.]+) elapsed=([^\s]+) at=([^\s]+)/g);
  const summary = lastMatch(clientLog, /TRANSFER_SUMMARY clients=(\d+) successes=(\d+) failures=(\d+) bytes=(\d+) expected_bytes=(\d+) elapsed=([^\s]+) mib_per_second=([\d.]+) at=([^\s]+)/g);
  const timeout = lastMatch(clientLog, /TRANSFER_TIMEOUT clients=(\d+) successes=(\d+) failures=(\d+) bytes=(\d+) expected_bytes=(\d+) err="[^"]*" at=([^\s]+)/g);
  const transferFailures = [...clientLog.matchAll(/TRANSFER_FAILED client=\d+ target=[0-9a-f]+ variant=\S+ bytes=\d+ failures=(\d+)/g)]
    .reduce((maximum, match) => Math.max(maximum, integer(match[1], 0)), 0);
  const targets = [...clientLog.matchAll(/TARGET_DISTRIBUTION target=([0-9a-f]{16}) clients=(\d+)/g)]
    .map((match) => ({ target: match[1], clients: capacityNonNegativeInteger(match[2]) }));
  const transfer = summary
    ? capacityTransfer(summary, true)
    : progress
      ? capacityTransfer(progress, false)
      : timeout
        ? {
          clients: capacityNonNegativeInteger(timeout[1]),
          successes: capacityNonNegativeInteger(timeout[2]),
          failures: Math.max(capacityNonNegativeInteger(timeout[3]), transferFailures),
          bytes: capacityNonNegativeInteger(timeout[4]),
          expectedBytes: capacityNonNegativeInteger(timeout[5]),
          progressPct: capacityProgress(timeout[4], timeout[5]),
          mibPerSecond: 0,
          elapsed: "",
          observedAt: publicTimestamp(timeout[6]),
        }
        : {
          clients: capacityNonNegativeInteger(barrier?.[1]),
          successes: 0,
          failures: transferFailures,
          bytes: 0,
          expectedBytes: capacityNonNegativeInteger(barrier?.[3]),
          progressPct: 0,
          mibPerSecond: 0,
          elapsed: "",
          observedAt: publicTimestamp(barrier?.[5]),
        };
  const inferredPlanClients = plan
    ? capacityNonNegativeInteger(plan[1])
    : capacityNonNegativeInteger(barrier?.[1]);
  const inferredTransferMiB = plan
    ? capacityNonNegativeInteger(plan[2])
    : barrier
      ? Math.floor(capacityNonNegativeInteger(barrier[2]) / (1024 * 1024))
      : 0;
  const completed = Boolean(summary)
    && transfer.clients > 0
    && transfer.successes === transfer.clients
    && transfer.failures === 0
    && transfer.bytes === transfer.expectedBytes;
  const phase = completed
    ? "COMPLETED"
    : timeout
      ? "TIMEOUT"
      : clientRC !== null && !clientRunning
        ? "FAILED"
        : barrier
          ? "TRANSFERRING"
          : warmup
            ? "READY"
            : "CONNECTING";
  return {
    available: true,
    phase,
    healthy: completed || (clientRunning && transfer.failures === 0 && connectionFailures === 0),
    startedAt: startTime,
    endedAt: endTime,
    clientRunning,
    clientRC,
    plannedClients: inferredPlanClients,
    transferMiB: inferredTransferMiB,
    connected,
    connectionFailures,
    checksumWarmup: {
      clients: capacityNonNegativeInteger(warmup?.[1]),
      uniqueChecksums: capacityNonNegativeInteger(warmup?.[2]),
      elapsed: publicShortText(warmup?.[3]),
    },
    targets,
    transfer,
    resources: capacityResources(resourceRows),
  };
}

function emptyCapacityTest() {
  return {
    available: false,
    phase: "NOT_STARTED",
    healthy: false,
    startedAt: "",
    endedAt: "",
    clientRunning: false,
    clientRC: null,
    plannedClients: 0,
    transferMiB: 0,
    connected: 0,
    connectionFailures: 0,
    checksumWarmup: { clients: 0, uniqueChecksums: 0, elapsed: "" },
    targets: [],
    transfer: {
      clients: 0,
      successes: 0,
      failures: 0,
      bytes: 0,
      expectedBytes: 0,
      progressPct: 0,
      mibPerSecond: 0,
      elapsed: "",
      observedAt: "",
    },
    resources: {
      samples: 0,
      latestAt: "",
      client: {},
      natServers: [],
      relay: {},
      network: {},
      peaks: {},
      trends: {},
    },
  };
}

function capacityTransfer(match, complete) {
  const clients = capacityNonNegativeInteger(match[1]);
  const successes = capacityNonNegativeInteger(match[2]);
  const failures = capacityNonNegativeInteger(match[3]);
  const bytes = capacityNonNegativeInteger(match[4]);
  const expectedBytes = capacityNonNegativeInteger(match[5]);
  return {
    clients,
    successes,
    failures,
    bytes,
    expectedBytes,
    progressPct: complete ? capacityProgress(bytes, expectedBytes) : Math.max(0, number(match[6], 0)),
    mibPerSecond: Math.max(0, number(match[complete ? 7 : 7], 0)),
    elapsed: publicShortText(match[complete ? 6 : 8]),
    observedAt: publicTimestamp(match[complete ? 8 : 9]),
  };
}

function capacityProgress(bytes, expectedBytes) {
  const expected = number(expectedBytes, 0);
  return expected > 0 ? round(number(bytes, 0) * 100 / expected, 3) : 0;
}

function capacityResources(rows) {
  if (rows.length === 0) {
    return {
      samples: 0,
      latestAt: "",
      client: {},
      natServers: [],
      relay: {},
      network: {},
      peaks: {},
      trends: {},
    };
  }
  const latest = rows.at(-1);
  const previous = rows.length > 1 ? rows.at(-2) : latest;
  const seconds = Math.max(1, number(latest.epoch, 0) - number(previous.epoch, 0));
  const cpuPercent = (key) => Math.max(0, (number(latest[key], 0) - number(previous[key], 0)) / seconds);
  const rateMiB = (key) => Math.max(0, (number(latest[key], 0) - number(previous[key], 0)) / seconds / 1024 / 1024);
  const process = (prefix) => ({
    cpuPct: round(cpuPercent(`${prefix}_cpu_ticks`), 2),
    rssMiB: round(number(latest[`${prefix}_rss_kib`], 0) / 1024, 2),
    threads: capacityNonNegativeInteger(latest[`${prefix}_threads`]),
    fds: capacityNonNegativeInteger(latest[`${prefix}_fds`]),
    readMiBps: round(rateMiB(`${prefix}_read_bytes`), 3),
    writeMiBps: round(rateMiB(`${prefix}_write_bytes`), 3),
  });
  const natServers = [1, 2, 3].map((numberValue) => ({
    service: `natserver${numberValue}`,
    ...process(`nat${numberValue}`),
    httpCPUPercent: round(cpuPercent(`http${numberValue}_cpu_ticks`), 2),
    httpRSSMiB: round(number(latest[`http${numberValue}_rss_kib`], 0) / 1024, 2),
    activeSessions: capacityNonNegativeInteger(latest[`nat${numberValue}_active_sessions`]),
  }));
  const maximum = (key) => rows.reduce((value, row) => Math.max(value, number(row[key], 0)), 0);
  return {
    samples: rows.length,
    latestAt: publicTimestamp(latest.iso),
    client: process("client"),
    natServers,
    relay: {
      ...process("relay"),
      tcpEstablished: capacityNonNegativeInteger(latest.relay_tcp_established),
      restarts: capacityNonNegativeInteger(latest.relay_restarts),
      load1: Math.max(0, number(latest.relay_load1, 0)),
    },
    network: {
      localRxMiBps: round(rateMiB("local_net_rx_bytes"), 3),
      localTxMiBps: round(rateMiB("local_net_tx_bytes"), 3),
      relayRxMiBps: round(rateMiB("relay_net_rx_bytes"), 3),
      relayTxMiBps: round(rateMiB("relay_net_tx_bytes"), 3),
    },
    peaks: {
      clientRSSMiB: round(maximum("client_rss_kib") / 1024, 2),
      natRSSMiB: [1, 2, 3].map((numberValue) => round(maximum(`nat${numberValue}_rss_kib`) / 1024, 2)),
      relayRSSMiB: round(maximum("relay_rss_kib") / 1024, 2),
      relayFDs: capacityNonNegativeInteger(maximum("relay_fds")),
      relayTCPEstablished: capacityNonNegativeInteger(maximum("relay_tcp_established")),
    },
    trends: {
      tenMinutes: capacityResourceTrend(rows, 10 * 60),
      thirtyMinutes: capacityResourceTrend(rows, 30 * 60),
    },
  };
}

function capacityResourceTrend(rows, requestedSeconds) {
  const latest = rows.at(-1);
  const latestEpoch = number(latest?.epoch, 0);
  const targetEpoch = latestEpoch - requestedSeconds;
  let baseline = rows[0];
  for (const row of rows) {
    if (Math.abs(number(row.epoch, 0) - targetEpoch)
      < Math.abs(number(baseline.epoch, 0) - targetEpoch)) {
      baseline = row;
    }
  }
  const windowSeconds = Math.max(0, latestEpoch - number(baseline?.epoch, latestEpoch));
  const rssDeltaMiB = (key) => round(
    (number(latest?.[key], 0) - number(baseline?.[key], 0)) / 1024,
    2,
  );
  const metricDelta = (key) => integer(latest?.[key], 0) - integer(baseline?.[key], 0);
  const natRSSDeltaMiB = [1, 2, 3].map((numberValue) => rssDeltaMiB(`nat${numberValue}_rss_kib`));
  const httpRSSDeltaMiB = [1, 2, 3].map((numberValue) => rssDeltaMiB(`http${numberValue}_rss_kib`));
  const localRSSDeltaMiB = round(
    rssDeltaMiB("client_rss_kib")
      + natRSSDeltaMiB.reduce((total, value) => total + value, 0)
      + httpRSSDeltaMiB.reduce((total, value) => total + value, 0),
    2,
  );
  const localFDDelta = metricDelta("client_fds")
    + [1, 2, 3].reduce((total, numberValue) => total + metricDelta(`nat${numberValue}_fds`), 0);
  return {
    windowSeconds,
    clientRSSDeltaMiB: rssDeltaMiB("client_rss_kib"),
    natRSSDeltaMiB,
    httpRSSDeltaMiB,
    relayRSSDeltaMiB: rssDeltaMiB("relay_rss_kib"),
    localRSSDeltaMiB,
    localRSSMiBPerMinute: windowSeconds > 0
      ? round(localRSSDeltaMiB * 60 / windowSeconds, 3)
      : 0,
    clientFDDelta: metricDelta("client_fds"),
    natFDDelta: [1, 2, 3].map((numberValue) => metricDelta(`nat${numberValue}_fds`)),
    relayFDDelta: metricDelta("relay_fds"),
    localFDDelta,
  };
}

function lastMatch(value, pattern) {
  let result = null;
  for (const match of value.matchAll(pattern)) result = match;
  return result;
}

function lastIntegerMatch(value, pattern) {
  const match = lastMatch(value, pattern);
  return capacityNonNegativeInteger(match?.[1]);
}

function capacityNonNegativeInteger(value) {
  return publicNonNegativeInteger(integer(value, 0));
}

function publicShortText(value) {
  const text = String(value ?? "");
  return /^[A-Za-z0-9.+:%-]{0,32}$/.test(text) ? text : "";
}

async function processExists(pid) {
  try {
    await fs.stat(`/proc/${pid}`);
    return true;
  } catch {
    return false;
  }
}

async function readServiceSessions(privateRoot, identities) {
  const clientByPrefix = new Map();
  const serverRelayByService = new Map();
  for (const identity of identities) {
    const client = knownService(identity.service, "natclient");
    const server = knownService(identity.service, "natserver");
    const relay = knownService(identity.ingress_relay, "relay");
    const nodeID = String(identity.node_id ?? "").toLowerCase();
    if (client && relay && /^[0-9a-f]{64}$/.test(nodeID)) {
      clientByPrefix.set(nodeID.slice(0, 16), { service: client, relay });
    }
    if (server && relay) serverRelayByService.set(server, relay);
  }
  const listeners = (await Promise.all(transferServers.map(async (service) => {
    const raw = await readJson(path.join(privateRoot, service, "service-listener.json"));
    if (!raw || raw.schemaVersion !== 1) return null;
    const reportedService = knownService(raw.service, "natserver");
    if (reportedService !== service) return null;
    const relay = knownService(normalizeRelayReference(raw.relayAddress), "relay")
      || serverRelayByService.get(service) || "";
	const carriers = Array.isArray(raw.carriers) ? raw.carriers.slice(0, 3).map((carrier) => {
	  const normalizedCarrierRelay = normalizeRelayReference(carrier?.relayAddress);
	  const carrierRelay = knownService(normalizedCarrierRelay, "relay")
	    || (normalizedCarrierRelay === normalizeRelayReference(raw.relayAddress) ? relay : "");
	  return carrierRelay ? {
	    relay: carrierRelay,
	    connected: carrier?.connected === true,
	    carrierGeneration: publicNonNegativeInteger(carrier?.carrierGeneration),
	    activeSessions: publicNonNegativeInteger(carrier?.activeSessions),
	    dataQueueDepth: publicNonNegativeInteger(carrier?.dataQueueDepth),
	    dataQueueCapacity: publicNonNegativeInteger(carrier?.dataQueueCapacity),
	    controlQueueDepth: publicNonNegativeInteger(carrier?.controlQueueDepth),
	    controlQueueCapacity: publicNonNegativeInteger(carrier?.controlQueueCapacity),
	  } : null;
	}).filter(Boolean) : [];
	if (carriers.length === 0 && relay) {
	  carriers.push({
	    relay,
	    connected: raw.carrierConnected === true,
	    carrierGeneration: publicNonNegativeInteger(raw.carrierGeneration),
	    activeSessions: publicNonNegativeInteger(raw.activeSessions),
	    dataQueueDepth: 0,
	    dataQueueCapacity: 0,
	    controlQueueDepth: 0,
	    controlQueueCapacity: 0,
	  });
	}
    const observedAt = publicTimestamp(raw.observedAt);
    const sessions = Array.isArray(raw.sessions) ? raw.sessions.slice(0, 64).map((session) => {
      const connectionID = /^[0-9a-f]{8}$/i.test(String(session?.connectionId ?? ""))
        ? String(session.connectionId).toLowerCase()
        : "";
      const peerPrefix = /^[0-9a-f]{16}$/i.test(String(session?.peerId ?? ""))
        ? String(session.peerId).toLowerCase()
        : "";
      const client = clientByPrefix.get(peerPrefix);
	  const sessionRelay = knownService(normalizeRelayReference(session?.relayAddress), "relay") || relay;
      return connectionID && client
		? { connectionID, client: client.service, clientRelay: client.relay, relay: sessionRelay }
        : null;
    }).filter(Boolean) : [];
    return {
      service,
      relay,
	  carriers,
	  muxDataQueueDepth: carriers.reduce((sum, carrier) => sum + carrier.dataQueueDepth, 0),
	  muxDataQueueCapacity: carriers.reduce((sum, carrier) => sum + carrier.dataQueueCapacity, 0),
	  muxControlQueueDepth: carriers.reduce((sum, carrier) => sum + carrier.controlQueueDepth, 0),
	  muxControlQueueCapacity: carriers.reduce((sum, carrier) => sum + carrier.controlQueueCapacity, 0),
      observedAt,
      fresh: observedAt !== "" && Date.now() - Date.parse(observedAt) <= 5000,
      carrierConnected: raw.carrierConnected === true,
      carrierGeneration: publicNonNegativeInteger(raw.carrierGeneration),
      activeSessions: publicNonNegativeInteger(raw.activeSessions),
      maxSessions: publicNonNegativeInteger(raw.maxSessions),
      acceptQueueDepth: publicNonNegativeInteger(raw.acceptQueueDepth),
      acceptQueue: publicNonNegativeInteger(raw.acceptQueue),
      acceptedTotal: publicNonNegativeInteger(raw.acceptedTotal),
      rejectedTotal: publicNonNegativeInteger(raw.rejectedTotal),
      sessions,
    };
  }))).filter(Boolean);
  const sessions = listeners.flatMap((listener) => listener.sessions.map((session) => ({
    ...session,
    server: listener.service,
	relay: session.relay || listener.relay,
	serverRelay: session.relay || listener.relay,
  })));
  return {
    available: listeners.length > 0,
    observedAt: listeners.map((listener) => listener.observedAt).filter(Boolean).sort().at(-1) ?? "",
    listeners,
    sessions,
    summary: {
      listeners: listeners.length,
      freshListeners: listeners.filter((listener) => listener.fresh).length,
	  connectedCarriers: listeners.reduce((sum, listener) => sum
	    + listener.carriers.filter((carrier) => carrier.connected).length, 0),
      activeSessions: listeners.reduce((sum, listener) => sum + listener.activeSessions, 0),
      maxSessions: listeners.reduce((sum, listener) => sum + listener.maxSessions, 0),
      acceptedTotal: listeners.reduce((sum, listener) => sum + listener.acceptedTotal, 0),
      rejectedTotal: listeners.reduce((sum, listener) => sum + listener.rejectedTotal, 0),
    },
  };
}

async function readWorkerStatus(file) {
  const text = await readText(file);
  const schedulerRow = text.split(/\r?\n/).map((line) => line.split("\t"))
    .find(([worker]) => worker === "batch-scheduler");
  if (schedulerRow) {
    const [, pidText, starttime] = schedulerRow;
    const alive = /^[1-9][0-9]*$/.test(pidText ?? "") && /^[1-9][0-9]*$/.test(starttime ?? "")
      && await processIdentityAlive(integer(pidText, 0), starttime);
    return {
      mode: "batch-scheduler",
      expected: 1,
      running: alive ? 1 : 0,
      healthy: alive,
      clients: [{ client: "batch-scheduler", alive }],
    };
  }
  const legacyClients = text.split(/\r?\n/).some((line) => line.startsWith(`${maliciousNatClient}\t`))
    ? transferClients
    : numbered("natclient", natClientCount);
  const aliveByClient = new Map(legacyClients.map((client) => [client, false]));
  await Promise.all(text.split(/\r?\n/).map(async (line) => {
    const [client, pidText, starttime] = line.split("\t");
    if (!aliveByClient.has(client) || !/^[1-9][0-9]*$/.test(pidText ?? "")
      || !/^[1-9][0-9]*$/.test(starttime ?? "")) return;
    if (await processIdentityAlive(integer(pidText, 0), starttime)) aliveByClient.set(client, true);
  }));
  const clients = legacyClients.map((client) => ({ client, alive: aliveByClient.get(client) === true }));
  return {
    expected: legacyClients.length,
    running: clients.filter((worker) => worker.alive).length,
    healthy: clients.every((worker) => worker.alive),
    clients,
  };
}

async function readRandomBatches(file) {
  const rows = await readTsv(file, 200);
  const byID = new Map();
  for (const row of rows) {
    const batchID = /^batch-[0-9]+-[0-9]+$/.test(String(row?.batch_id ?? ""))
      ? String(row.batch_id) : "";
    const selectedServer = validService(row?.selected_server, "natserver")
      ? String(row.selected_server) : "";
    const serverMalicious = selectedServer === maliciousRandomNatServer;
    const selectedClients = String(row?.selected_clients ?? "").split(",")
      .filter((client, index, clients) => transferClients.includes(client) && clients.indexOf(client) === index);
    const requestedClients = integer(row?.requested_clients, 0);
    const mode = row?.mode === "single" || row?.mode === "multi" ? row.mode : "";
    const status = ["RUNNING", "PASS", "FAIL"].includes(row?.status) ? row.status : "";
    const validCount = mode === "single" ? requestedClients === 1 : mode === "multi"
      && requestedClients >= 2 && requestedClients <= 4;
    if (!batchID || !selectedServer || !mode || !status || !validCount
      || selectedClients.length !== requestedClients
      || row?.server_pool_includes_malicious !== "true"
      || row?.client_pool_includes_malicious !== "true"
      || (row?.server_malicious === "true") !== serverMalicious) continue;
    const maliciousSelected = selectedClients.includes(maliciousNatClient);
    if ((row?.malicious_client_selected === "true") !== maliciousSelected) continue;
    const targets = String(row?.target_pairs ?? "").split(",").map((pair) => {
      const [client, server, extra] = pair.split("→");
      return extra === undefined && transferClients.includes(client) && validService(server, "natserver")
        ? { client, server } : null;
    }).filter(Boolean);
    if (targets.length !== requestedClients
      || targets.some((target, index) => target.client !== selectedClients[index]
        || target.server !== selectedServer)) continue;
    byID.set(batchID, {
      timestamp: publicTimestamp(row.timestamp),
      batchID,
      selectedServer,
      serverMalicious,
      mode,
      requestedClients,
      selectedClients,
      serverPoolIncludesMalicious: true,
      clientPoolIncludesMalicious: true,
      maliciousSelected,
      status,
      targets,
      succeeded: Math.max(0, integer(row.succeeded, 0)),
      failed: Math.max(0, integer(row.failed, 0)),
    });
  }
  const batches = [...byID.values()];
  const recent = batches.sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp)).slice(0, 20);
  return {
    available: rows.length > 0,
    policy: { multiClientProbabilityPct: 60, multiClientMin: 2, multiClientMax: 4 },
    summary: {
      totalBatches: byID.size,
      multiClientBatches: batches.filter((batch) => batch.mode === "multi").length,
      singleClientBatches: batches.filter((batch) => batch.mode === "single").length,
      maliciousSelectedBatches: batches.filter((batch) => batch.maliciousSelected).length,
      maliciousServerBatches: batches.filter((batch) => batch.serverMalicious).length,
      activeBatches: batches.filter((batch) => batch.status === "RUNNING").length,
      failedBatches: batches.filter((batch) => batch.status === "FAIL").length,
    },
    recent,
  };
}

async function processIdentityAlive(pid, expectedStarttime) {
  if (!Number.isSafeInteger(pid) || pid <= 0 || !/^[1-9][0-9]*$/.test(String(expectedStarttime ?? ""))) {
    return false;
  }
  try {
    const stat = await fs.readFile(`/proc/${pid}/stat`, "utf8");
    const closingParenthesis = stat.lastIndexOf(")");
    if (closingParenthesis < 0) return false;
    const fields = stat.slice(closingParenthesis + 1).trim().split(/\s+/);
    return fields[0] !== "Z" && fields[19] === String(expectedStarttime);
  } catch {
    return false;
  }
}

async function inspectProjectContainers() {
  if (!composeProject) return [];
  try {
    const { stdout: idsOutput } = await execFileAsync(
      "docker",
      ["ps", "-aq", "--filter", `label=com.docker.compose.project=${composeProject}`],
      { timeout: 5000, maxBuffer: 1024 * 1024 },
    );
    const ids = idsOutput.trim().split(/\s+/).filter(Boolean);
    if (ids.length === 0) return [];
    const { stdout } = await execFileAsync("docker", ["inspect", ...ids], {
      timeout: 8000,
      maxBuffer: 8 * 1024 * 1024,
    });
    return JSON.parse(stdout).map((container) => {
      const state = container.State ?? {};
      const service = container.Config?.Labels?.["com.docker.compose.service"] ?? container.Name?.replace(/^\//, "") ?? "unknown";
      return {
        service,
        role: roleOf(service),
        id: String(container.Id ?? "").slice(0, 12),
        name: String(container.Name ?? "").replace(/^\//, ""),
        image: container.Config?.Image ?? "",
        state: state.Status ?? "unknown",
        running: Boolean(state.Running),
        health: state.Health?.Status ?? (state.Running ? "running" : state.Status ?? "unknown"),
        restartCount: integer(container.RestartCount, 0),
        startedAt: state.StartedAt ?? "",
        finishedAt: state.FinishedAt ?? "",
        pid: integer(state.Pid, 0),
        networkAddresses: Object.fromEntries(Object.entries(container.NetworkSettings?.Networks ?? {}).map(([network, settings]) => [
          network,
          String(settings?.IPAddress ?? ""),
        ])),
      };
    }).sort((left, right) => left.service.localeCompare(right.service, "en", { numeric: true }));
  } catch (error) {
    return [{
      service: "docker-inspection",
      role: "diagnostic",
      id: "",
      name: "Docker inspection failed",
      image: "",
      state: "error",
      running: false,
      health: String(error?.message ?? error),
      restartCount: 0,
      startedAt: "",
      finishedAt: "",
      pid: 0,
    }];
  }
}

async function inspectNatFirewalls(services, containerMap) {
  const uniqueServices = [...new Set(services)].filter((service) => {
    const role = roleOf(service);
    return role === "natserver" || role === "natclient";
  });
  const cacheKey = uniqueServices.map((service) => `${service}:${containerMap.get(service)?.id ?? "missing"}`).join("|");
  if (cacheKey === firewallCache.key && Date.now() - firewallCache.cachedAt < 5000) {
    return firewallCache.value;
  }
  const snapshots = await Promise.all(uniqueServices.map(async (service) => {
    const container = containerMap.get(service);
    if (!container?.running || !container.pid) {
      return [service, { available: false, rules: [], error: "container_not_running" }];
    }
    try {
      const { stdout } = await execFileAsync(
        "nsenter",
        ["--target", String(container.pid), "--net", "--", "iptables", "-S", "OUTPUT"],
        { timeout: 4000, maxBuffer: 512 * 1024 },
      );
      return [service, { available: true, rules: parseFirewallRules(stdout), error: "" }];
    } catch (error) {
      return [service, {
        available: false,
        rules: [],
        error: String(error?.message ?? error),
      }];
    }
  }));
  const value = new Map(snapshots);
  firewallCache = { key: cacheKey, cachedAt: Date.now(), value };
  return value;
}

function parseFirewallRules(output) {
  const rules = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line.startsWith("-A OUTPUT ")) continue;
    const protocol = optionValue(line, "-p").toLowerCase() || "all";
    const destination = normalizeCIDR(optionValue(line, "-d") || "0.0.0.0/0");
    const destinationPort = integer(optionValue(line, "--dport"), 0);
    const action = optionValue(line, "-j")?.toUpperCase() ?? "";
    if (!action) continue;
    rules.push({ protocol, destination, destinationPort, action });
  }
  return rules;
}

async function buildTopology({ compose, metadata, workload, nodes, firewalls, mixedPath, nodeProfiles }) {
  const serviceSpecs = compose?.services && typeof compose.services === "object" ? compose.services : {};
  const networkSpecs = compose?.networks && typeof compose.networks === "object" ? compose.networks : {};
  const nodeMap = new Map(nodes.map((node) => [node.service, node]));
  const serviceNames = [...new Set([...Object.keys(serviceSpecs), ...nodes.map((node) => node.service)])]
    .filter((service) => roleOf(service) !== "diagnostic")
    .sort(serviceSort);
  const memberships = new Map(serviceNames.map((service) => [service, serviceNetworks(serviceSpecs[service])]));
  const relays = serviceNames.filter((service) => roleOf(service) === "relay");
  const nats = serviceNames.filter((service) => ["natserver", "natclient"].includes(roleOf(service)));
  const activeServices = new Set([workload.server, workload.client].filter(Boolean));
  const addressMap = new Map();
  for (const node of nodes) {
    for (const address of Object.values(node.networkAddresses ?? {})) {
      if (address) addressMap.set(address, node.service);
    }
  }

  const topologyNodes = serviceNames.map((service) => {
    const runtime = nodeMap.get(service) ?? missingContainer(service);
    const profile = nodeProfiles.get(service) ?? buildNodeProfile(service, "default");
    return {
      id: service,
      service,
      role: roleOf(service),
      running: runtime.running,
      health: publicRuntimeStatus(runtime.health),
      networks: memberships.get(service) ?? [],
      active: activeServices.has(service),
      ...profile,
    };
  });

  const topologyNetworks = Object.entries(networkSpecs)
    .filter(([id]) => expectedNetworkSet.has(id))
    .map(([id, specification]) => ({
      id,
      internal: Boolean(specification?.internal),
      members: serviceNames.filter((service) => memberships.get(service)?.includes(id)),
    })).sort((left, right) => left.id.localeCompare(right.id, "en", { numeric: true }));

  const reachabilityMatrix = [];
  for (const nat of nats) {
    for (const relay of relays) {
      reachabilityMatrix.push(reachabilityCell({
        nat,
        relay,
        memberships,
        nodeMap,
        firewalls,
      }));
    }
  }
  const reachabilityByNat = Object.fromEntries(nats.map((nat) => [
    nat,
    Object.fromEntries(reachabilityMatrix.filter((cell) => cell.nat === nat).map((cell) => [cell.relay, cell.state])),
  ]));

  const relayControlLinks = relays.map((relay) => {
    const target = commandOption(serviceSpecs[relay]?.command, "-index");
    if (!target) return null;
    const upstream = knownServiceReference(normalizeRelayReference(target), ["index", "relay"]);
    if (!upstream) return null;
    const sharedNetworks = intersection(memberships.get(relay), memberships.get(upstream));
    const runtimeReady = Boolean(nodeMap.get(relay)?.running && nodeMap.get(upstream)?.running);
    return {
      id: `control:${relay}:${upstream}`,
      source: relay,
      target: upstream,
      kind: "relay-control",
      directional: true,
      sharedNetworks,
      state: sharedNetworks.length > 0 && runtimeReady ? "dual" : "blocked",
      stateLabel: sharedNetworks.length > 0 && runtimeReady ? "KCP+TCP" : "blocked",
    };
  }).filter(Boolean);

  const caLinkServices = new Set(serviceNames.filter((service) => {
    if (service === "ca") return false;
    const caURL = commandOption(serviceSpecs[service]?.command, "-ca");
    return normalizeRelayReference(caURL) === "ca";
  }));
  for (const service of activeServices) caLinkServices.add(service);
  const caLinks = [...caLinkServices].map((service) => ({
    id: `admission:${service}:ca`,
    source: service,
    target: "ca",
    kind: "ca-admission",
    directional: true,
    state: nodeMap.get(service)?.running && nodeMap.get("ca")?.running ? "up" : "down",
    stateLabel: nodeMap.get(service)?.running && nodeMap.get("ca")?.running ? "HTTP/TCP" : "blocked",
    protocol: "HTTP/TCP",
  }));

  const natRelayLinks = reachabilityMatrix.filter((cell) => cell.state !== "none").map((cell) => ({
    id: `access:${cell.nat}:${cell.relay}`,
    source: cell.nat,
    target: cell.relay,
    kind: "nat-relay",
    directional: false,
    sharedNetworks: cell.sharedNetworks,
    state: cell.state,
    stateLabel: cell.stateLabel,
    tcp: cell.tcp,
    udp: cell.udp,
    reason: cell.reason,
    evidence: cell.evidence,
  }));

  const [serverLog, clientLog] = await Promise.all([
    readTail(path.join(runDir, "runtime", "stability", `${workload.server ?? ""}.log`), 256 * 1024),
    readTail(path.join(runDir, "runtime", "stability", `${workload.client ?? ""}.log`), 256 * 1024),
  ]);
  const clientRelay = detectActiveRelay({
    service: workload.client,
    log: clientLog,
    addressMap,
    metadata,
    workload,
    reachabilityMatrix,
  });
  const serverRelay = detectActiveRelay({
    service: workload.server,
    log: serverLog,
    addressMap,
    metadata,
    workload,
    reachabilityMatrix,
  });
  const activePath = buildActivePath({
    workload,
    clientRelay,
    serverRelay,
    relayControlLinks,
    reachabilityMatrix,
    nodeMap,
  });
  const activePairs = new Set(activePath.links.map((link) => pairKey(link.source, link.target)));
  const mixedLinks = buildMixedPathLinks(mixedPath, nodeMap);
  const links = [...caLinks, ...relayControlLinks, ...natRelayLinks, ...mixedLinks].map((link) => ({
    ...link,
    active: activePairs.has(pairKey(link.source, link.target)),
  }));

  return {
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    basis: "Compose 网络关系 + 当前业务 NAT 的 iptables 规则（推导，非逐链路主动探测）",
    scenario: publicScenario(metadata.scenario),
    nodes: topologyNodes,
    networks: topologyNetworks,
    links,
    relayControlLinks,
    reachability: {
      relays,
      nats,
      matrix: reachabilityMatrix,
      byNat: reachabilityByNat,
    },
    activePath,
    mixedPath: mixedPath.path,
    diagnostics: {
      composeLoaded: Object.keys(serviceSpecs).length > 0,
      firewallInspection: Object.fromEntries([...firewalls].map(([service, snapshot]) => [service, {
        available: snapshot.available,
        ruleCount: snapshot.rules.length,
      }])),
    },
  };
}

function buildMixedPathLinks(mixedPath, nodeMap) {
  if (!mixedPath?.available || !Array.isArray(mixedPath.path?.nodes)) return [];
  const nodes = mixedPath.path.nodes.filter((node) => mixedPathNodes.has(node));
  const probePassed = mixedPath.probe?.status === "PASS" && mixedPath.probe?.sha256Verified === true;
  const state = probePassed ? "attack-contained" : "attack-violation";
  const links = [];
  for (let index = 1; index < nodes.length; index += 1) {
    const normalRelay = [nodes[index - 1], nodes[index]].find((node) => /^relay0[3-7]$/.test(node));
    const normalPartition = publicMixedPartitionForRelay(normalRelay);
    links.push({
      id: `mixed:${nodes[index - 1]}:${nodes[index]}`,
      source: nodes[index - 1],
      target: nodes[index],
      kind: "mixed-attack",
      directional: true,
      state,
      stateLabel: probePassed ? "real P2P payload verified" : "real P2P payload unavailable",
      protocol: "real_p2p_tunnel_http_payload",
      reason: mixedPath.lastTrigger?.scenario ?? "mixed_path_baseline",
      sharedNetworks: normalPartition ? [normalPartition] : [],
      evidence: "live_process_attachment_and_sha256_payload_probe",
      active: probePassed,
    });
  }
  const normalRelayPeer = mixedPath.attachments?.maliciousRelay?.currentRelay;
  if (mixedPath.attachments?.maliciousRelay?.running && normalRelayPeer) {
    const normalRelayRunning = nodeMap.get(normalRelayPeer)?.running !== false;
    links.push({
      id: `mixed:${normalRelayPeer}:malicious-relay`,
      source: normalRelayPeer,
      target: "malicious-relay",
      kind: "mixed-relay-control",
      directional: true,
      state: normalRelayRunning ? "dual" : "blocked",
      stateLabel: normalRelayRunning ? "control-hello verified" : "normal relay unavailable",
      protocol: "P2P relay control",
      reason: "normal_relay_registered_to_malicious_relay",
      sharedNetworks: [publicMixedPartitionForRelay(normalRelayPeer)].filter(Boolean),
      evidence: "live_control_hello",
    });
  }
  return links;
}

function reachabilityCell({ nat, relay, memberships, nodeMap, firewalls }) {
  const sharedNetworks = intersection(memberships.get(nat), memberships.get(relay));
  if (sharedNetworks.length === 0) {
    return {
      nat,
      relay,
      state: "none",
      stateLabel: "no direct network",
      tcp: false,
      udp: false,
      sharedNetworks,
      blockedRuleCount: 0,
      reason: "no_shared_network",
      evidence: "compose_network",
    };
  }

  const natRuntime = nodeMap.get(nat);
  const relayRuntime = nodeMap.get(relay);
  if (!natRuntime?.running || !relayRuntime?.running) {
    return {
      nat,
      relay,
      state: "blocked",
      stateLabel: "blocked",
      tcp: false,
      udp: false,
      sharedNetworks,
      blockedRuleCount: 0,
      reason: !natRuntime?.running ? "nat_not_running" : "relay_not_running",
      evidence: "container_runtime",
    };
  }

  const relayAddresses = Object.values(relayRuntime.networkAddresses ?? {}).filter(Boolean);
  const firewall = firewalls.get(nat);
  if (firewall && !firewall.available) {
    return {
      nat,
      relay,
      state: "unknown",
      stateLabel: "unknown",
      tcp: null,
      udp: null,
      sharedNetworks,
      blockedRuleCount: 0,
      reason: "firewall_inspection_unavailable",
      evidence: "runtime_firewall",
    };
  }
  const tcpResult = protocolReachability(firewall, "tcp", relayAddresses);
  const udpResult = protocolReachability(firewall, "udp", relayAddresses);
  const state = protocolState(tcpResult.allowed, udpResult.allowed);
  return {
    nat,
    relay,
    state,
    stateLabel: protocolStateLabel(state),
    tcp: tcpResult.allowed,
    udp: udpResult.allowed,
    sharedNetworks,
    blockedRuleCount: tcpResult.blockedByRules.length + udpResult.blockedByRules.length,
    reason: state === "blocked" ? "firewall" : "shared_network",
    evidence: firewall ? "runtime_firewall" : "compose_network",
  };
}

function protocolReachability(firewall, protocol, relayAddresses) {
  if (!firewall?.available) return { allowed: true, blockedByRules: [] };
  for (const rule of firewall.rules) {
    if (rule.protocol !== "all" && rule.protocol !== protocol) continue;
    if (rule.destinationPort !== 0 && rule.destinationPort !== 9000) continue;
    if (!destinationMatches(rule.destination, relayAddresses)) continue;
    if (rule.action === "ACCEPT") return { allowed: true, blockedByRules: [] };
    if (rule.action === "DROP" || rule.action === "REJECT") {
      return { allowed: false, blockedByRules: [rule] };
    }
  }
  return { allowed: true, blockedByRules: [] };
}

function destinationMatches(destination, addresses) {
  if (!destination || destination === "0.0.0.0" || destination === "::") return true;
  return addresses.includes(destination);
}

function protocolState(tcp, udp) {
  if (tcp && udp) return "dual";
  if (tcp) return "tcp-only";
  if (udp) return "kcp-only";
  return "blocked";
}

function protocolStateLabel(state) {
  if (state === "dual") return "KCP+TCP";
  if (state === "tcp-only") return "TCP-only";
  if (state === "kcp-only") return "KCP-only";
  if (state === "none") return "no direct network";
  if (state === "unknown") return "unknown";
  return "blocked";
}

function detectActiveRelay({ service, log, addressMap, metadata, reachabilityMatrix }) {
  if (!service) return "";
  let detected = "";
  for (const line of log.split(/\r?\n/)) {
    const match = line.match(/(?:使用指定 relay|注册到 relay):\s*([^\s,;]+)/i);
    if (!match) continue;
    const host = normalizeRelayReference(match[1]);
    const resolved = roleOf(host) === "relay" ? host : addressMap.get(host);
    if (resolved && roleOf(resolved) === "relay") detected = resolved;
  }
  if (detected) return detected;

  const scenarioFallbacks = {
    "1": { natclient02: "relay01", natserver04: "relay03" },
    "2": { natclient04: "relay02", natserver02: "relay02" },
    "3": { natclient05: "relay01", natserver03: "relay03" },
  };
  const fallback = scenarioFallbacks[String(metadata.scenario ?? "")]?.[service];
  if (fallback) return fallback;

  return reachabilityMatrix.find((cell) => cell.nat === service && ["dual", "tcp-only", "kcp-only"].includes(cell.state))?.relay ?? "";
}

function buildActivePath({ workload, clientRelay, serverRelay, relayControlLinks, reachabilityMatrix, nodeMap }) {
  const client = workload.client ?? "";
  const server = workload.server ?? "";
  if (!client || !server) {
    return {
      state: "pending",
      transport: "unknown",
      client,
      server,
      clientRelay,
      serverRelay,
      nodes: [],
      links: [],
      label: "",
    };
  }
  if (!clientRelay || !serverRelay) {
    return {
      state: "unknown",
      transport: "unknown",
      client,
      server,
      clientRelay,
      serverRelay,
      nodes: [client, server],
      links: [],
      label: "entry Relay unresolved",
    };
  }

  const relayRoute = shortestRelayRoute(clientRelay, serverRelay, relayControlLinks);
  const routeResolved = clientRelay === serverRelay || relayRoute.at(-1) === serverRelay;
  const relayHops = routeResolved ? relayRoute : [...new Set([clientRelay, serverRelay])];
  const pathNodes = [client, ...relayHops, server].filter((service, index, values) => index === 0 || service !== values[index - 1]);
  const links = [];
  for (let index = 0; index < pathNodes.length - 1; index += 1) {
    const source = pathNodes[index];
    const target = pathNodes[index + 1];
    const sourceRole = roleOf(source);
    const targetRole = roleOf(target);
    const nat = sourceRole.startsWith("nat") ? source : targetRole.startsWith("nat") ? target : "";
    const relay = sourceRole === "relay" ? source : targetRole === "relay" ? target : "";
    const access = nat && relay
      ? reachabilityMatrix.find((cell) => cell.nat === nat && cell.relay === relay)
      : null;
    const control = sourceRole === "relay" && targetRole === "relay"
      ? relayControlLinks.find((link) => pairKey(link.source, link.target) === pairKey(source, target))
      : null;
    links.push({
      source,
      target,
      kind: access ? "nat-relay" : "relay-control",
      state: access?.state ?? control?.state ?? "blocked",
    });
  }

  const endpointCells = [
    reachabilityMatrix.find((cell) => cell.nat === client && cell.relay === clientRelay),
    reachabilityMatrix.find((cell) => cell.nat === server && cell.relay === serverRelay),
  ].filter(Boolean);
  const transport = endpointCells.some((cell) => cell.state === "blocked" || cell.state === "none")
    ? "unavailable"
    : endpointCells.some((cell) => cell.state === "unknown")
      ? "unknown"
      : endpointCells.some((cell) => cell.state === "tcp-only")
        ? "tcp"
        : endpointCells.some((cell) => cell.state === "kcp-only")
          ? "kcp"
          : "kcp+tcp";
  const allRunning = pathNodes.every((service) => nodeMap.get(service)?.running);
  const allLinksReachable = links.every((link) => ["dual", "tcp-only", "kcp-only", "up"].includes(link.state));
  return {
    state: routeResolved && allRunning && allLinksReachable ? "active" : "blocked",
    transport,
    client,
    server,
    clientRelay,
    serverRelay,
    nodes: pathNodes,
    links,
    label: clientRelay === serverRelay
      ? `单 Relay：${clientRelay}`
      : routeResolved
        ? `跨 Relay：${clientRelay} → ${serverRelay}`
        : `Relay 路由不可达：${clientRelay} → ${serverRelay}`,
  };
}

function shortestRelayRoute(start, target, relayControlLinks) {
  if (!start || !target) return [];
  if (start === target) return [start];
  const directLink = relayControlLinks.find((link) => (
    roleOf(link.source) === "relay"
      && roleOf(link.target) === "relay"
      && pairKey(link.source, link.target) === pairKey(start, target)
  ));
  return directLink ? [start, target] : [];
}

function commandOption(command, option) {
  if (!Array.isArray(command)) return "";
  const index = command.indexOf(option);
  return index >= 0 ? String(command[index + 1] ?? "") : "";
}

function serviceNetworks(service) {
  const networks = service?.networks;
  const values = Array.isArray(networks)
    ? networks
    : networks && typeof networks === "object"
      ? Object.keys(networks)
      : [];
  return values.filter((network) => expectedNetworkSet.has(network));
}

function intersection(left = [], right = []) {
  const rightSet = new Set(right);
  return left.filter((value) => rightSet.has(value));
}

function normalizeRelayReference(value) {
  let reference = String(value ?? "").trim().replace(/[),;]+$/, "");
  if (!reference) return "";
  if (reference.includes("://")) {
    try {
      return new URL(reference).hostname;
    } catch {
      return "";
    }
  }
  if (reference.startsWith("[")) return reference.slice(1, reference.indexOf("]"));
  return reference.replace(/:\d+$/, "");
}

function normalizeCIDR(value) {
  const text = String(value ?? "");
  if (text === "0.0.0.0/0") return "0.0.0.0";
  if (text === "::/0") return "::";
  return text.replace(/\/32$/, "").replace(/\/128$/, "");
}

function optionValue(line, option) {
  const escaped = option.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return line.match(new RegExp(`(?:^|\\s)${escaped}\\s+(?:"([^"]*)"|'([^']*)'|(\\S+))`))?.slice(1).find((value) => value !== undefined) ?? "";
}

function pairKey(left, right) {
  return [left, right].sort().join("|");
}

function serviceSort(left, right) {
  const roleOrder = { ca: 0, index: 1, relay: 2, natserver: 3, natclient: 4, diagnostic: 5 };
  return (roleOrder[roleOf(left)] ?? 9) - (roleOrder[roleOf(right)] ?? 9)
    || left.localeCompare(right, "en", { numeric: true });
}

async function probeCA() {
  const started = process.hrtime.bigint();
  return new Promise((resolve) => {
    const request = http.get({ hostname: "127.0.0.1", port: caPort, path: "/pubkey", timeout: 1800 }, (response) => {
      let bytes = 0;
      response.on("data", (chunk) => { bytes += chunk.length; });
      response.on("end", () => resolve({
        reachable: response.statusCode === 200,
        statusCode: response.statusCode ?? 0,
        latencyMs: elapsedMs(started),
        responseBytes: bytes,
      }));
    });
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", (error) => resolve({
      reachable: false,
      statusCode: 0,
      latencyMs: elapsedMs(started),
      error: "probe_failed",
    }));
  });
}

async function readReconnectGate(finalSnapshotFile, capacityPointerFile = "") {
  if (reconnectGateURL !== "") {
    const liveMetrics = await requestReconnectGateMetrics();
    if (liveMetrics) {
      return publicReconnectGate(liveMetrics, true);
    }
  }
  const finalMetrics = await readJson(finalSnapshotFile);
  if (validReconnectGateMetrics(finalMetrics)) {
    return publicReconnectGate(finalMetrics, false);
  }
  const capacityRunDirectory = String(await readText(capacityPointerFile)).trim();
  if (path.isAbsolute(capacityRunDirectory)) {
    const capacityFinalMetrics = await readJson(
      path.join(capacityRunDirectory, "reconnect-gate-final.json"),
    );
    if (validReconnectGateMetrics(capacityFinalMetrics)) {
      return publicReconnectGate(capacityFinalMetrics, false);
    }
  }
  return emptyReconnectGate(reconnectGateURL !== "");
}

async function requestReconnectGateMetrics() {
  let endpoint;
  try {
    endpoint = new URL(reconnectGateURL);
    if (endpoint.protocol !== "http:" || endpoint.username !== "" || endpoint.password !== "") {
      return null;
    }
    endpoint.pathname = `${endpoint.pathname.replace(/\/+$/, "")}/metrics`;
    endpoint.search = "";
    endpoint.hash = "";
  } catch {
    return null;
  }
  return new Promise((resolve) => {
    const request = http.get(endpoint, {
      timeout: 1500,
      headers: reconnectGateToken === ""
        ? { Connection: "close" }
        : { Authorization: `Bearer ${reconnectGateToken}`, Connection: "close" },
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 256 * 1024) {
          request.destroy(new Error("response_too_large"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (response.statusCode !== 200) {
          resolve(null);
          return;
        }
        try {
          const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          resolve(validReconnectGateMetrics(value) ? value : null);
        } catch {
          resolve(null);
        }
      });
    });
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", () => resolve(null));
  });
}

function validReconnectGateMetrics(value) {
  return value?.status === "ok"
    && Number.isSafeInteger(value.safeRate) && value.safeRate > 0 && value.safeRate <= 1000
    && Number.isSafeInteger(value.windowSeconds) && value.windowSeconds > 0 && value.windowSeconds <= 60
    && Array.isArray(value.scopes) && value.scopes.length <= 1024;
}

function publicReconnectGate(value, live) {
  const transports = new Map();
  let granted = 0;
  let denied = 0;
  let queued = 0;
  let windowRequests = 0;
  let scheduledPerSecondPeak = 0;
  let pressure = 0;
  for (const source of value.scopes) {
    const scope = String(source?.scope ?? "");
    const separator = scope.lastIndexOf("|");
    const candidate = separator >= 0 ? scope.slice(separator + 1) : "";
    const transport = ["tcp", "kcp", "carrier"].includes(candidate) ? candidate : "unknown";
    const metrics = transports.get(transport) ?? {
      transport,
      granted: 0,
      denied: 0,
      queued: 0,
      windowRequests: 0,
    };
    const scopeGranted = reconnectGateMetric(source?.granted);
    const scopeDenied = reconnectGateMetric(source?.denied);
    const scopeQueued = reconnectGateMetric(source?.futureSlots);
    const scopeWindowRequests = reconnectGateMetric(source?.windowRequests);
    metrics.granted = safeMetricSum(metrics.granted, scopeGranted);
    metrics.denied = safeMetricSum(metrics.denied, scopeDenied);
    metrics.queued = safeMetricSum(metrics.queued, scopeQueued);
    metrics.windowRequests = safeMetricSum(metrics.windowRequests, scopeWindowRequests);
    transports.set(transport, metrics);
    granted = safeMetricSum(granted, scopeGranted);
    denied = safeMetricSum(denied, scopeDenied);
    queued = safeMetricSum(queued, scopeQueued);
    windowRequests = safeMetricSum(windowRequests, scopeWindowRequests);
    scheduledPerSecondPeak = Math.max(
      scheduledPerSecondPeak,
      reconnectGateMetric(source?.scheduledPerSecondPeak),
    );
    pressure = Math.max(pressure, reconnectGatePressure(source?.pressure));
  }
  return {
    available: true,
    live,
    healthy: live,
    status: live ? "RUNNING" : "STOPPED",
    startedAt: publicTimestamp(value.startedAt),
    observedAt: publicTimestamp(value.observedAt),
    safeRate: value.safeRate,
    windowSeconds: value.windowSeconds,
    scopeCount: value.scopes.length,
    granted,
    denied,
    queued,
    windowRequests,
    scheduledPerSecondPeak,
    pressurePct: round(pressure * 100, 2),
    transports: [...transports.values()].sort((left, right) => left.transport.localeCompare(right.transport)),
  };
}

function emptyReconnectGate(configured) {
  return {
    available: false,
    live: false,
    healthy: false,
    status: configured ? "UNAVAILABLE" : "NOT_CONFIGURED",
    startedAt: "",
    observedAt: "",
    safeRate: 0,
    windowSeconds: 0,
    scopeCount: 0,
    granted: 0,
    denied: 0,
    queued: 0,
    windowRequests: 0,
    scheduledPerSecondPeak: 0,
    pressurePct: 0,
    transports: [],
  };
}

function reconnectGateMetric(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function reconnectGatePressure(value) {
  return Number.isFinite(value) && value >= 0 && value <= 1 ? value : 0;
}

function safeMetricSum(left, right) {
  return Math.min(Number.MAX_SAFE_INTEGER, left + right);
}

async function readEnv(file) {
  const text = await readText(file);
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const index = line.indexOf("=");
    if (index <= 0) continue;
    values[line.slice(0, index)] = line.slice(index + 1);
  }
  return values;
}

async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return {};
  }
}

async function readClientTransfers(file) {
  let stat;
  try {
    stat = await fs.stat(file);
  } catch {
    transferLogCache = emptyTransferLogCache(file);
    failureEvidenceCache = new Map();
    return transferLogSnapshot(transferLogCache);
  }

  const identity = `${stat.dev}:${stat.ino}`;
  if (transferLogCache.file !== file
    || transferLogCache.identity !== identity
    || stat.size < transferLogCache.size) {
    transferLogCache = emptyTransferLogCache(file, identity);
    failureEvidenceCache = new Map();
  }
  transferLogCache.available = true;
  transferLogCache.updatedAt = stat.mtime.toISOString();

  if (stat.size > transferLogCache.size) {
    const start = transferLogCache.size;
    const length = stat.size - start;
    const buffer = Buffer.alloc(length);
    const handle = await fs.open(file, "r");
    let bytesRead = 0;
    try {
      while (bytesRead < length) {
        const result = await handle.read(buffer, bytesRead, length - bytesRead, start + bytesRead);
        if (result.bytesRead === 0) break;
        bytesRead += result.bytesRead;
      }
    } finally {
      await handle.close();
    }
    await consumeTransferLog(transferLogCache, buffer.subarray(0, bytesRead).toString("utf8"));
    transferLogCache.size += bytesRead;
  }

  return transferLogSnapshot(transferLogCache);
}

function emptyTransferLogCache(file, identity = "") {
  return {
    file,
    identity,
    size: 0,
    available: false,
    updatedAt: "",
    header: null,
    remainder: "",
    summary: emptyTransferStats(),
    failures: [],
    failureStats: emptyFailureStats(),
    ingressStats: new Map(),
    seenTransfers: new Set(),
    clients: new Map(transferClients.map((client) => [client, {
      summary: emptyTransferStats(),
      recent: [],
    }])),
    servers: new Map(transferServers.map((server) => [server, {
      summary: emptyTransferStats(),
      recent: [],
      clients: new Set(),
    }])),
  };
}

async function consumeTransferLog(cache, appendedText) {
  const lines = `${cache.remainder}${appendedText}`.split(/\n/);
  cache.remainder = lines.pop() ?? "";
  for (let line of lines) {
    line = line.replace(/\r$/, "");
    if (!line) continue;
    if (!cache.header) {
      cache.header = line.replace(/^\uFEFF/, "").split("\t");
      continue;
    }
    const values = line.split("\t");
    const parsed = Object.fromEntries(cache.header.map((name, index) => [name, values[index] ?? ""]));
    if (parsed.timestamp === "timestamp" && parsed.client === "client") continue;
    const clientState = cache.clients.get(parsed.client);
    if (!clientState) continue;
    const transfer = Object.fromEntries(transferColumns.map((name) => [name, parsed[name] ?? ""]));
    const transferKey = transfer.transfer_id || [
      transfer.timestamp,
      transfer.client,
      transfer.server,
      transfer.requested_mib,
      transfer.rc,
      transfer.bytes,
    ].join("\u0000");
    if (cache.seenTransfers.has(transferKey)) continue;
    cache.seenTransfers.add(transferKey);
    clientState.recent.unshift(transfer);
    if (clientState.recent.length > 10) clientState.recent.length = 10;
    updateTransferStats(clientState.summary, transfer);
    const serverState = cache.servers.get(transfer.server);
    if (serverState) {
      serverState.recent.unshift(transfer);
      if (serverState.recent.length > 10) serverState.recent.length = 10;
      serverState.clients.add(parsed.client);
      updateTransferStats(serverState.summary, transfer);
    }
    updateTransferStats(cache.summary, transfer);
    updateIngressStats(cache.ingressStats, transfer);
    if (!transferSucceeded(transfer)) await recordFailure(cache, transfer);
  }
}

function emptyFailureStats() {
  return {
    total: 0,
    clients: new Set(),
    servers: new Set(),
    ingressCounts: new Map(),
    pathCounts: new Map(),
    causeCounts: new Map(),
    handshakeByClient: new Map(),
    dataStalls: [],
  };
}

async function recordFailure(cache, transfer) {
  const metrics = transferFailureMetrics(transfer);
  const classification = await inspectFailureEvidence(transfer, metrics);
  const stats = cache.failureStats;
  const client = publicService(transfer.client, "natclient");
  const ingressRelay = publicService(transfer.ingress_relay, "relay");
  const serverName = publicService(transfer.server, "natserver");
  stats.total += 1;
  if (client !== "unknown") stats.clients.add(client);
  if (serverName !== "unknown") stats.servers.add(serverName);
  stats.ingressCounts.set(ingressRelay, (stats.ingressCounts.get(ingressRelay) ?? 0) + 1);
  const pathKey = JSON.stringify([ingressRelay, serverName]);
  stats.pathCounts.set(pathKey, (stats.pathCounts.get(pathKey) ?? 0) + 1);
  stats.causeCounts.set(classification.cause, (stats.causeCounts.get(classification.cause) ?? 0) + 1);
  if (classification.flags.handshake && client !== "unknown") {
    stats.handshakeByClient.set(client, (stats.handshakeByClient.get(client) ?? 0) + 1);
  }
  if (classification.flags.dataStall) {
    stats.dataStalls.push({
      timestampEpoch: Date.parse(publicTimestamp(transfer.timestamp)) || 0,
      client,
      ingressRelay,
      server: serverName,
    });
    if (stats.dataStalls.length > failureRetentionLimit) stats.dataStalls.shift();
  }
  cache.failures.push(transfer);
  if (cache.failures.length > failureRetentionLimit) cache.failures.shift();
}

function updateIngressStats(stats, transfer) {
  const relay = validService(transfer.ingress_relay, "relay") ? transfer.ingress_relay : "unknown";
  const current = stats.get(relay) ?? { total: 0, succeeded: 0, failed: 0 };
  const succeeded = transferSucceeded(transfer);
  current.total += 1;
  current.succeeded += succeeded ? 1 : 0;
  current.failed += succeeded ? 0 : 1;
  stats.set(relay, current);
}

function emptyTransferStats() {
  return {
    totalTransfers: 0,
    succeeded: 0,
    failed: 0,
    sha256Correct: 0,
    sha256Incorrect: 0,
    totalBytes: 0,
    totalRequestedMiB: 0,
    totalSeconds: 0,
    throughputSum: 0,
    throughputSamples: 0,
    latestTimestamp: "",
  };
}

function updateTransferStats(stats, transfer) {
  const bytes = Math.max(0, number(transfer.bytes, 0));
  const seconds = Math.max(0, number(transfer.seconds, 0));
  const requestedMiB = Math.max(0, number(transfer.requested_mib, 0));
  const recordedThroughput = number(transfer.mib_per_second, Number.NaN);
  const throughput = Number.isFinite(recordedThroughput)
    ? Math.max(0, recordedThroughput)
    : seconds > 0
      ? bytes / 1048576 / seconds
      : Number.NaN;
  const sha256State = transferSha256State(transfer.sha256_ok);
  const succeeded = transferSucceeded(transfer);

  stats.totalTransfers += 1;
  stats.succeeded += succeeded ? 1 : 0;
  stats.failed += succeeded ? 0 : 1;
  stats.sha256Correct += sha256State === true ? 1 : 0;
  stats.sha256Incorrect += sha256State === false ? 1 : 0;
  stats.totalBytes += bytes;
  stats.totalRequestedMiB += requestedMiB;
  stats.totalSeconds += seconds;
  if (Number.isFinite(throughput)) {
    stats.throughputSum += throughput;
    stats.throughputSamples += 1;
  }
  if (transfer.timestamp) stats.latestTimestamp = transfer.timestamp;
}

function transferSucceeded(transfer) {
  return String(transfer.rc) === "0" && transferSha256State(transfer.sha256_ok) === true;
}

function transferSha256State(value) {
  const state = String(value ?? "").trim().toLowerCase();
  if (["1", "yes", "true", "ok", "pass", "passed", "correct"].includes(state)) return true;
  if (["0", "no", "false", "fail", "failed", "incorrect", "mismatch"].includes(state)) return false;
  return null;
}

function publicTransferStats(stats) {
  return {
    totalTransfers: stats.totalTransfers,
    succeeded: stats.succeeded,
    failed: stats.failed,
    sha256Correct: stats.sha256Correct,
    sha256Incorrect: stats.sha256Incorrect,
    totalBytes: stats.totalBytes,
    totalMiB: stats.totalBytes / 1048576,
    totalRequestedMiB: stats.totalRequestedMiB,
    totalSeconds: stats.totalSeconds,
    averageMiBPerSecond: stats.throughputSamples > 0 ? stats.throughputSum / stats.throughputSamples : 0,
    latestTimestamp: publicTimestamp(stats.latestTimestamp),
  };
}

function transferLogSnapshot(cache) {
  const byClient = Object.fromEntries(transferClients.map((client) => {
    const state = cache.clients.get(client);
    return [client, {
      summary: publicTransferStats(state.summary),
      recent: state.recent.map(publicRecentTransfer),
    }];
  }));
  const summary = publicTransferStats(cache.summary);
  summary.clientCount = transferClients.length;
  summary.activeClients = transferClients.filter((client) => cache.clients.get(client).summary.totalTransfers > 0).length;
  const byServer = Object.fromEntries(transferServers.map((server) => {
    const state = cache.servers.get(server);
    const recent = state.recent.map(publicRecentTransfer);
    return [server, {
      server,
      summary: publicTransferStats(state.summary),
      distinctClients: state.clients.size,
      recentClients: [...state.clients].filter((client) => validService(client, "natclient")).sort(serviceSort),
      lastTransferAt: publicTimestamp(state.summary.latestTimestamp),
      lastClient: recent[0]?.client ?? "",
      lastIngressRelay: recent[0]?.ingress_relay ?? "",
      recent,
    }];
  }));
  return {
    source: "transfer_records",
    available: cache.available,
    updatedAt: publicTimestamp(cache.updatedAt),
    summary,
    byClient,
    byServer,
  };
}

function buildNodeProfiles(serverRows, clientRows, planRows) {
  const families = new Map(expectedServices.map((service) => [service, "default"]));
  for (const row of planRows) {
    const family = publicIPFamily(row?.family);
    if (family === "default") continue;
    for (const [field, role] of [["relay", "relay"], ["natserver", "natserver"], ["natclient", "natclient"]]) {
      const service = knownService(row?.[field], role);
      if (service) families.set(service, family);
    }
  }
  for (const [rows, role, field] of [[serverRows, "natserver", "server"], [clientRows, "natclient", "client"]]) {
    for (const row of rows) {
      const service = knownService(row?.[field], role);
      if (service) families.set(service, publicIPFamily(row?.ip_family));
    }
  }
  return new Map([...families].map(([service, family]) => [service, buildNodeProfile(service, family)]));
}

function buildNodeProfile(service, family) {
  const role = roleOf(service);
  const ipFamily = publicIPFamily(family);
  const ipType = {
    default: "IPv4（默认网络）",
    ipv4: "IPv4",
    ipv6: "IPv6",
    dual: "IPv4 + IPv6 双栈",
  }[ipFamily];
  const transportStack = role === "ca" || role === "index"
    ? "HTTP/TCP"
    : role === "diagnostic"
      ? "诊断网络"
      : "KCP/UDP + TCP 故障切换";
  return {
    ipFamily,
    ipType,
    transportStack,
    networkStack: `${ipType} · ${transportStack}`,
  };
}

function publicIPFamily(value) {
  const family = String(value ?? "");
  return ["ipv4", "ipv6", "dual"].includes(family) ? family : "default";
}

function enrichClientTransfers(snapshot, profiles) {
  const enrichTransfer = (transfer) => {
    const clientProfile = profiles.get(transfer.client) ?? buildNodeProfile(transfer.client, "default");
    const serverProfile = profiles.get(transfer.server) ?? buildNodeProfile(transfer.server, "default");
    return {
      ...transfer,
      clientIPType: clientProfile.ipType,
      serverIPType: serverProfile.ipType,
      transportStack: clientProfile.transportStack,
      networkStack: clientProfile.ipType === serverProfile.ipType
        ? clientProfile.networkStack
        : `${clientProfile.ipType} → ${serverProfile.ipType} · ${clientProfile.transportStack}`,
    };
  };
  const byClient = Object.fromEntries(transferClients.map((client) => {
    const state = snapshot.byClient?.[client] ?? { summary: publicTransferStats(emptyTransferStats()), recent: [] };
    const profile = profiles.get(client) ?? buildNodeProfile(client, "default");
    return [client, { ...state, ...profile, recent: state.recent.map(enrichTransfer) }];
  }));
  const byServer = Object.fromEntries(transferServers.map((server) => {
    const state = snapshot.byServer?.[server] ?? {};
    const profile = profiles.get(server) ?? buildNodeProfile(server, "default");
    return [server, { ...state, server, ...profile, recent: (state.recent ?? []).map(enrichTransfer) }];
  }));
  return { ...snapshot, byClient, byServer };
}

function publicRecentTransfer(transfer) {
  const sha256State = transferSha256State(transfer.sha256_ok);
  return {
    timestamp: publicTimestamp(transfer.timestamp),
    client: publicService(transfer.client, "natclient"),
    ingress_relay: publicService(transfer.ingress_relay, "relay"),
    server: publicService(transfer.server, "natserver"),
    requested_mib: Math.max(0, number(transfer.requested_mib, 0)),
    rc: integer(transfer.rc, -1),
    bytes: Math.max(0, integer(transfer.bytes, 0)),
    seconds: Math.max(0, number(transfer.seconds, 0)),
    mib_per_second: Math.max(0, number(transfer.mib_per_second, 0)),
    sha256_ok: sha256State === true ? "yes" : sha256State === false ? "no" : "unknown",
  };
}

function publicProbe(probe) {
  if (!probe) return null;
  const rawLabel = String(probe.label ?? "");
  const label = rawLabel === "profile3_kcp_to_tcp_inflight"
    ? rawLabel
    : rawLabel.startsWith("profile3-tcp-cold-")
      ? "profile-validation"
      : /^\d{16,}-natclient\d{2}$/.test(rawLabel)
        ? "random-transfer"
        : "probe";
  const sha256State = transferSha256State(probe.sha256_ok);
  return {
    timestamp: publicTimestamp(probe.timestamp),
    label,
    requested_mib: Math.max(0, number(probe.requested_mib, 0)),
    rc: String(integer(probe.rc, -1)),
    bytes: Math.max(0, integer(probe.bytes, 0)),
    seconds: Math.max(0, number(probe.seconds, 0)),
    mib_per_second: Math.max(0, number(probe.mib_per_second, 0)),
    sha256_ok: sha256State === true ? "yes" : sha256State === false ? "no" : "unknown",
    client: publicService(probe.client, "natclient"),
  };
}

async function readFailureWatcher(file) {
  const value = await readJson(file);
  if (value.schemaVersion !== 1) {
    return {
      schemaVersion: 1,
      available: false,
      status: "NOT_STARTED",
      healthy: false,
      startedAt: "",
      monitoringSince: "",
      heartbeatAt: "",
      lastScanAt: "",
      source: { name: "transfer_records", available: false, lagBytes: 0 },
      baseline: { transferRecords: 0, failureRecords: 0 },
      observed: { transferRecords: 0, failureRecords: 0, newFailureRecords: 0 },
      alerts: { limit: 0, total: 0, retained: 0, lastAlertAt: "", recent: [] },
      lastError: null,
    };
  }

  const heartbeatAt = publicTimestamp(value.heartbeatAt);
  const heartbeatEpoch = Date.parse(heartbeatAt);
  const status = ["STARTING", "RUNNING", "WAITING_FOR_SOURCE", "DEGRADED", "STOPPED", "FAILED"]
    .includes(value.status) ? value.status : "UNKNOWN";
  const now = Date.now();
  const heartbeatFresh = Number.isFinite(heartbeatEpoch)
    && heartbeatEpoch <= now + 5000
    && now - heartbeatEpoch <= 15000;
  const recent = Array.isArray(value.alerts?.recent)
    ? value.alerts.recent.map(publicWatcherAlert).filter(Boolean).slice(0, 100)
    : [];
  const sourceSize = Math.max(0, integer(value.source?.sizeBytes, 0));
  const sourceOffset = Math.max(0, integer(value.source?.offsetBytes, 0));
  const sourceAvailable = Boolean(value.source?.available);
  const sourceCursorValid = sourceOffset <= sourceSize;
  const sourceLagBytes = Math.max(0, sourceSize - sourceOffset);
  const lastErrorCode = publicEnum(value.lastError?.code, failureWatcherErrorCodes, "watcher_error");

  return {
    schemaVersion: 1,
    available: true,
    status,
    healthy: status === "RUNNING" && heartbeatFresh && sourceAvailable
      && sourceCursorValid && sourceLagBytes === 0,
    startedAt: publicTimestamp(value.startedAt),
    monitoringSince: publicTimestamp(value.monitoringSince),
    heartbeatAt,
    lastScanAt: publicTimestamp(value.lastScanAt),
    source: {
      name: "transfer_records",
      available: sourceAvailable,
      lagBytes: sourceLagBytes,
    },
    baseline: {
      transferRecords: Math.max(0, integer(value.baseline?.transferRecords, 0)),
      failureRecords: Math.max(0, integer(value.baseline?.failureRecords, 0)),
    },
    observed: {
      transferRecords: Math.max(0, integer(value.observed?.transferRecords, 0)),
      failureRecords: Math.max(0, integer(value.observed?.failureRecords, 0)),
      newFailureRecords: Math.max(0, integer(value.observed?.newFailureRecords, 0)),
    },
    alerts: {
      limit: Math.max(0, integer(value.alerts?.limit, 0)),
      total: Math.max(0, integer(value.alerts?.total, 0)),
      retained: recent.length,
      lastAlertAt: publicTimestamp(value.alerts?.lastAlertAt),
      recent,
    },
    lastError: lastErrorCode
      ? { at: publicTimestamp(value.lastError?.at), code: lastErrorCode }
      : null,
  };
}

async function readBillingAdversary(file) {
  const scenarios = [
    ["relay_usage_inflation", "relay"],
    ["relay_request_replay", "relay"],
    ["relay_fee_override", "relay"],
    ["relay_window_overrun", "relay"],
    ["nat_stale_watermark", "natserver"],
    ["nat_same_sequence_fork", "natserver"],
    ["nat_signature_refusal", "natserver"],
    ["relay_voucher_tamper", "relay"],
    ["index_disconnect_backlog_recovery", "network"],
  ];
  const value = await readJson(file);
  if (value.schemaVersion !== 1) return emptyBillingAdversary(scenarios);

  const allowedStatuses = new Set(["STARTING", "RUNNING", "FAILED", "DEGRADED", "STOPPED"]);
  const allowedVerdicts = new Set(["CONTAINED", "VIOLATION", "HARNESS_ERROR"]);
  const status = allowedStatuses.has(value.status) ? value.status : "UNKNOWN";
  const heartbeatAt = publicTimestamp(value.heartbeatAt);
  const heartbeatEpoch = Date.parse(heartbeatAt);
  const now = Date.now();
  const heartbeatFresh = Number.isFinite(heartbeatEpoch)
    && heartbeatEpoch <= now + 5000
    && now - heartbeatEpoch <= 20000;
  const coverage = scenarios.map(([scenario, actor]) => {
    const source = value.coverage?.[scenario] ?? {};
    return {
      scenario,
      actor,
      executed: Math.max(0, integer(source.executed, 0)),
      contained: Math.max(0, integer(source.contained, 0)),
      violations: Math.max(0, integer(source.violations, 0)),
    };
  });
  const actorNames = ["natserver", "relay", "network"];
  const actors = Object.fromEntries(actorNames.map((actor) => {
    const actorCoverage = coverage.filter((item) => item.actor === actor);
    return [actor, {
      executed: actorCoverage.reduce((sum, item) => sum + item.executed, 0),
      contained: actorCoverage.reduce((sum, item) => sum + item.contained, 0),
      violations: actorCoverage.reduce((sum, item) => sum + item.violations, 0),
    }];
  }));
  const executedChecks = coverage.reduce((sum, item) => sum + item.executed, 0);
  const containedChecks = coverage.reduce((sum, item) => sum + item.contained, 0);
  const failedChecks = coverage.reduce((sum, item) => sum + item.violations, 0);
  const coveredScenarios = coverage.filter((item) => item.executed > 0).length;
  const componentProbe = publicBillingComponentProbe(value.componentProbe, scenarios.length);
  const componentProbeHealthy = componentProbe.status === "RUNNING"
    && componentProbe.failed === 0
    && componentProbe.required === scenarios.length
    && componentProbe.covered === componentProbe.required;
  const containerProbe = publicBillingContainerProbe(value.containerProbe);
  const containerProbeHealthy = containerProbe.status === "DISABLED" || (
    containerProbe.status === "RUNNING"
    && containerProbe.failed === 0
    && containerProbe.covered === containerProbe.required
  );
  const recent = Array.isArray(value.recent)
    ? value.recent.map((event) => publicAdversaryEvent(event, scenarios, allowedVerdicts)).filter(Boolean).slice(0, 24)
    : [];
  const lastErrorCode = publicEnum(value.lastError?.code, billingAdversaryErrorCodes, "billing_adversary_error");

  return {
    schemaVersion: 1,
    available: true,
    status,
    healthy: status === "RUNNING" && heartbeatFresh && failedChecks === 0
      && coveredScenarios === scenarios.length && componentProbeHealthy && containerProbeHealthy,
    mode: value.mode === "active_local_api" ? value.mode : "isolated_probe",
    heartbeatAt,
    summary: {
      executedChecks,
      preventedChecks: containedChecks,
      missedChecks: failedChecks,
      preventionRatePct: executedChecks > 0 ? round(containedChecks / executedChecks * 100, 2) : 0,
      stateChanges: Math.max(0, integer(value.summary?.stateChanges, 0)),
      coveredScenarios,
      requiredScenarioCount: scenarios.length,
    },
    actors,
    coverage,
    componentProbe,
    containerProbe,
    recent,
    lastError: lastErrorCode
      ? { at: publicTimestamp(value.lastError?.at), code: lastErrorCode }
      : null,
  };
}

async function readMixedAdversaryPath(file) {
  const value = await readJson(file);
  if (!value || value.schemaVersion !== 1 || !mixedPathStatuses.has(value.status)) return emptyMixedAdversaryPath();
  const heartbeatAt = publicTimestamp(value.heartbeatAt);
  const heartbeatEpoch = Date.parse(heartbeatAt);
  const heartbeatFresh = Number.isFinite(heartbeatEpoch)
    && heartbeatEpoch <= Date.now() + 5000
    && Date.now() - heartbeatEpoch <= 20000;
  const attachmentDefinitions = [
    ["maliciousNatserver", "malicious-natserver", "malicious-natserver"],
    ["normalProbe", "mixed-path-probe", "natclient"],
    ["maliciousRelay", "malicious-relay", "malicious-relay"],
  ];
  const attachments = Object.fromEntries(attachmentDefinitions.map(([key, node, role]) => {
    const source = value.attachments?.[key] ?? {};
    return [key, {
      node,
      role,
      currentRelay: publicMixedPathNode(source.currentRelay),
      previousRelay: publicMixedPathNode(source.previousRelay),
      attachmentType: publicEnum(source.attachmentType, mixedPathAttachmentTypes, ""),
      normalPartition: publicEnum(source.normalPartition, mixedPathPartitions, ""),
      basis: publicEnum(source.basis, mixedPathAttachmentBases, ""),
      peerDirection: source.peerDirection === "normal_relay_to_malicious_relay"
        ? source.peerDirection
        : "",
      generation: Math.max(0, integer(source.generation, 0)),
      running: source.running === true,
      switchedAt: publicTimestamp(source.switchedAt),
      lastScenario: publicEnum(source.lastScenario, maliciousScenarioNames, ""),
    }];
  }));
  const pathNodes = Array.isArray(value.path?.nodes)
    ? value.path.nodes.map(publicMixedPathNode).filter(Boolean).slice(0, 8)
    : [];
  const pathState = new Set(["starting", "active", "migrating", "blocked"]).has(value.path?.state)
    ? value.path.state
    : "blocked";
  const probeStatus = new Set(["PENDING", "PASS", "FAIL"]).has(value.probe?.status) ? value.probe.status : "FAIL";
  const migrations = Array.isArray(value.migrations)
    ? value.migrations.map(publicMixedMigration).filter(Boolean).slice(0, 20)
    : [];
  const networkCoverage = publicMixedNetworkCoverage(value.networkCoverage);
  const networkSummary = {
    executed: networkCoverage.reduce((sum, item) => sum + item.executed, 0),
    contained: networkCoverage.reduce((sum, item) => sum + item.contained, 0),
    violations: networkCoverage.reduce((sum, item) => sum + item.violations, 0),
    covered: networkCoverage.filter((item) => item.executed > 0 && item.violations === 0).length,
    required: maliciousScenarioActors.size,
  };
  const lastTrigger = publicMixedTrigger(value.lastTrigger);
  const normalRelays = [...new Set([
    ...pathNodes.filter((node) => /^relay0[3-7]$/.test(node)),
    attachments.maliciousNatserver.currentRelay,
    attachments.maliciousRelay.currentRelay,
  ].filter((relay) => publicMixedPartitionForRelay(relay)))];
  const normalPartitions = [...new Set(normalRelays.map(publicMixedPartitionForRelay).filter(Boolean))];
  const pathContainsMaliciousNode = pathNodes.includes("malicious-natserver") || pathNodes.includes("malicious-relay");
  const pathContainsNormalPartition = normalPartitions.length > 0;
  const attachmentEvidenceValid = mixedAttachmentEvidenceValid(attachments);
  const requiredAttachmentsRunning = attachments.maliciousNatserver.running
    && attachments.normalProbe.running
    && attachments.maliciousRelay.running;
  const attachmentLifecycleReady = value.status === "MIGRATING" || requiredAttachmentsRunning;
  const containmentStatus = new Set(["PENDING", "VERIFIED", "FAILED"]).has(value.containment?.status)
    ? value.containment.status
    : "PENDING";
  return {
    schemaVersion: 1,
    available: true,
    status: value.status,
    healthy: ["RUNNING", "MIGRATING"].includes(value.status) && heartbeatFresh
      && probeStatus === "PASS" && integer(value.probe?.consecutiveFailures, 0) === 0
      && attachmentLifecycleReady && attachmentEvidenceValid
      && pathContainsNormalPartition && pathContainsMaliciousNode,
    heartbeatAt,
    generation: Math.max(0, integer(value.generation, 0)),
    observedTriggers: Math.max(0, integer(value.observedTriggers, 0)),
    normalPartitions: {
      control_partition_a: ["relay03", "relay04", "relay05"],
      control_partition_b: ["relay06", "relay07"],
    },
    attachments,
    path: {
      state: pathState,
      nodes: pathNodes,
      transport: value.path?.transport === "real_p2p_tunnel_http_payload" ? value.path.transport : "unknown",
      basis: value.path?.basis === "live_process_attachment_and_sha256_payload_probe" ? value.path.basis : "unknown",
      kind: value.path?.kind === "normal_partition_mixed_adversary" ? value.path.kind : "unknown",
      normalRelays,
      normalPartitions,
      containsNormalPartition: pathContainsNormalPartition,
      containsMaliciousNode: pathContainsMaliciousNode,
    },
    probe: {
      status: probeStatus,
      observedAt: publicTimestamp(value.probe?.observedAt),
      successes: Math.max(0, integer(value.probe?.successes, 0)),
      failures: Math.max(0, integer(value.probe?.failures, 0)),
      consecutiveFailures: Math.max(0, integer(value.probe?.consecutiveFailures, 0)),
      bytes: Math.max(0, integer(value.probe?.bytes, 0)),
      sha256Verified: value.probe?.sha256Verified === true,
      errorCode: publicMixedError(value.probe?.errorCode),
    },
    lastTrigger,
    migrations,
    networkCoverage,
    networkSummary,
    containment: {
      status: containmentStatus,
      verifiedMigrations: Math.max(0, integer(value.containment?.verifiedMigrations, 0)),
      lastScenario: publicEnum(value.containment?.lastScenario, maliciousScenarioNames, ""),
      lastActor: value.containment?.lastActor === "natserver" || value.containment?.lastActor === "relay"
        ? value.containment.lastActor
        : "",
      lastAction: publicMixedContainmentAction(value.containment?.lastAction),
      verifiedAt: publicTimestamp(value.containment?.verifiedAt),
    },
    diagnostics: {
      heartbeatFresh,
      requiredAttachmentsRunning,
      attachmentLifecycleReady,
      attachmentEvidenceValid,
      pathContainsNormalPartition,
      pathContainsMaliciousNode,
    },
  };
}

function publicMixedMigration(value) {
  const trigger = publicMixedTrigger(value?.trigger);
  const endpoint = value?.endpoint === "malicious-natserver" || value?.endpoint === "malicious-relay"
    || value?.endpoint === "mixed-path-probe"
    ? value.endpoint
    : "";
  const previousRelay = publicMixedPathNode(value?.previousRelay);
  const currentRelay = publicMixedPathNode(value?.currentRelay);
  if (!trigger || !endpoint || !previousRelay || !currentRelay) return null;
  return {
    generation: Math.max(0, integer(value.generation, 0)),
    trigger,
    endpoint,
    previousRelay,
    currentRelay,
    normalPartition: publicMixedPartitionForRelay(currentRelay),
    failureInjected: value.failureInjected === true,
    isolationVerified: value.isolationVerified === true,
    triggerContained: value.triggerContained === true && trigger.contained === true,
    containmentVerified: value.containmentVerified === true,
    probePassed: value.probePassed === true,
    postContainmentPath: Array.isArray(value.postContainmentPath)
      ? value.postContainmentPath.map(publicMixedPathNode).filter(Boolean).slice(0, 8)
      : [],
    switchedAt: publicTimestamp(value.switchedAt),
  };
}

function mixedAttachmentEvidenceValid(attachments) {
  const maliciousNatserver = attachments.maliciousNatserver;
  const maliciousRelay = attachments.maliciousRelay;
  const normalProbe = attachments.normalProbe;
  const natserverValid = publicMixedPartitionForRelay(maliciousNatserver.currentRelay) === maliciousNatserver.normalPartition
    && maliciousNatserver.attachmentType === "registered_to_normal_relay"
    && maliciousNatserver.basis === "live_relay_registration";
  const relayValid = publicMixedPartitionForRelay(maliciousRelay.currentRelay) === maliciousRelay.normalPartition
    && maliciousRelay.attachmentType === "control_peer_with_normal_relay"
    && maliciousRelay.basis === "live_control_hello"
    && maliciousRelay.peerDirection === "normal_relay_to_malicious_relay";
  const probePartition = publicMixedPartitionForRelay(normalProbe.currentRelay);
  const probeValid = normalProbe.currentRelay === "malicious-relay"
    ? normalProbe.attachmentType === "connected_to_malicious_relay"
      && normalProbe.normalPartition === ""
      && normalProbe.basis === "live_tunnel_registration"
    : Boolean(probePartition)
      && normalProbe.normalPartition === probePartition
      && normalProbe.attachmentType === "connected_to_normal_relay"
      && normalProbe.basis === "live_tunnel_registration";
  return natserverValid && relayValid && probeValid;
}

function publicMixedPartitionForRelay(relay) {
  if (["relay03", "relay04", "relay05"].includes(relay)) return "control_partition_a";
  if (["relay06", "relay07"].includes(relay)) return "control_partition_b";
  return "";
}

function publicMixedContainmentAction(value) {
  const actions = new Set([
    "isolate_malicious_natserver_and_migrate_to_random_normal_relay",
    "isolate_malicious_relay_and_migrate_to_random_normal_relay",
  ]);
  return actions.has(value) ? value : "";
}

function publicMixedTrigger(value) {
  const actor = value?.actor === "natserver" || value?.actor === "relay" ? value.actor : "";
  const scenario = publicEnum(value?.scenario, maliciousScenarioNames, "");
  if (!actor || !scenario || maliciousScenarioActors.get(scenario) !== actor
    || !Number.isSafeInteger(value?.sequence) || value.sequence < 1) return null;
  return {
    actor,
    scenario,
    sequence: value.sequence,
    observedAt: publicTimestamp(value.observedAt),
    contained: value.contained === true,
    defense: publicBillingContainerProbeCode(value.defense),
    requestCount: Math.max(0, integer(value.requestCount, 0)),
    httpStatuses: Array.isArray(value.httpStatuses)
      ? value.httpStatuses.map((status) => integer(status, 0)).filter((status) => status >= 100 && status <= 599).slice(0, 8)
      : [],
  };
}

function publicMixedNetworkCoverage(value) {
  const sourceByScenario = new Map();
  if (Array.isArray(value)) {
    for (const item of value) {
      const expectedActor = maliciousScenarioActors.get(item?.scenario);
      if (!expectedActor || item.actor !== expectedActor) continue;
      const counters = [item.executed, item.contained, item.violations];
      if (counters.some((counter) => !Number.isSafeInteger(counter) || counter < 0)
        || item.executed !== item.contained + item.violations) continue;
      sourceByScenario.set(item.scenario, item);
    }
  }
  return [...maliciousScenarioActors].map(([scenario, actor]) => {
    const source = sourceByScenario.get(scenario);
    return {
      scenario,
      actor,
      executed: source?.executed ?? 0,
      contained: source?.contained ?? 0,
      violations: source?.violations ?? 0,
    };
  });
}

function publicMixedPathNode(value) {
  const node = String(value ?? "");
  return mixedPathNodes.has(node) ? node : "";
}

function publicMixedError(value) {
  const code = String(value ?? "");
  return /^mixed_path_[a-z0-9_]{1,52}$/.test(code) ? code : code ? "mixed_path_probe_failed" : "";
}

function emptyMixedAdversaryPath() {
  return {
    schemaVersion: 1,
    available: false,
    status: "NOT_STARTED",
    healthy: false,
    heartbeatAt: "",
    generation: 0,
    observedTriggers: 0,
    normalPartitions: {
      control_partition_a: ["relay03", "relay04", "relay05"],
      control_partition_b: ["relay06", "relay07"],
    },
    attachments: {
      maliciousNatserver: { node: "malicious-natserver", role: "malicious-natserver", currentRelay: "", previousRelay: "", attachmentType: "", normalPartition: "", basis: "", peerDirection: "", generation: 0, running: false, switchedAt: "", lastScenario: "" },
      normalProbe: { node: "mixed-path-probe", role: "natclient", currentRelay: "", previousRelay: "", attachmentType: "", normalPartition: "", basis: "", peerDirection: "", generation: 0, running: false, switchedAt: "", lastScenario: "" },
      maliciousRelay: { node: "malicious-relay", role: "malicious-relay", currentRelay: "", previousRelay: "", attachmentType: "", normalPartition: "", basis: "", peerDirection: "", generation: 0, running: false, switchedAt: "", lastScenario: "" },
    },
    path: { state: "starting", nodes: [], transport: "unknown", basis: "unknown", kind: "unknown", normalRelays: [], normalPartitions: [], containsNormalPartition: false, containsMaliciousNode: false },
    probe: { status: "PENDING", observedAt: "", successes: 0, failures: 0, consecutiveFailures: 0, bytes: 0, sha256Verified: false, errorCode: "" },
    lastTrigger: null,
    migrations: [],
    networkCoverage: [...maliciousScenarioActors].map(([scenario, actor]) => ({ scenario, actor, executed: 0, contained: 0, violations: 0 })),
    networkSummary: { executed: 0, contained: 0, violations: 0, covered: 0, required: maliciousScenarioActors.size },
    containment: { status: "PENDING", verifiedMigrations: 0, lastScenario: "", lastActor: "", lastAction: "", verifiedAt: "" },
    diagnostics: { heartbeatFresh: false, requiredAttachmentsRunning: false, attachmentLifecycleReady: false, attachmentEvidenceValid: false, pathContainsNormalPartition: false, pathContainsMaliciousNode: false },
  };
}

function publicBillingContainerProbe(value) {
  const expected = [
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
  const failed = () => emptyBillingContainerProbe(expected, "FAILED", 1);
  if (!value || typeof value !== "object" || Array.isArray(value) || value.schemaVersion !== 1) return failed();
  const allowedStatuses = new Set(["DISABLED", "STARTING", "RUNNING", "FAILED", "STOPPED"]);
  if (!allowedStatuses.has(value.status)) return failed();
  const counters = [value.executed, value.failed, value.covered, value.required];
  if (counters.some((count) => !Number.isSafeInteger(count) || count < 0)
    || value.required !== expected.length || value.covered > value.required) return failed();
  if (value.status === "DISABLED") {
    if (value.executed !== 0 || value.failed !== 0 || value.covered !== 0) return failed();
    return emptyBillingContainerProbe(expected, "DISABLED", 0);
  }
  if (!Array.isArray(value.coverage) || value.coverage.length !== expected.length) return failed();
  const sourceByScenario = new Map();
  for (const source of value.coverage) {
    if (!source || typeof source !== "object" || sourceByScenario.has(source.scenario)) return failed();
    sourceByScenario.set(source.scenario, source);
  }
  const coverage = [];
  for (const [scenario, actor] of expected) {
    const source = sourceByScenario.get(scenario);
    const itemCounters = [source?.executed, source?.contained, source?.violations];
    if (!source || source.actor !== actor
      || itemCounters.some((count) => !Number.isSafeInteger(count) || count < 0)
      || source.contained + source.violations !== source.executed) return failed();
    coverage.push({
      scenario,
      actor,
      executed: source.executed,
      contained: source.contained,
      violations: source.violations,
    });
  }
  const executed = coverage.reduce((sum, item) => sum + item.executed, 0);
  const violations = coverage.reduce((sum, item) => sum + item.violations, 0);
  const covered = coverage.filter((item) => item.executed > 0).length;
  const errorCode = publicBillingContainerProbeCode(value.errorCode);
  const infrastructureFailure = errorCode.startsWith("container_probe_");
  if (value.executed !== executed || value.covered !== covered
    || value.failed > violations + 2
    || (value.failed !== violations && !(infrastructureFailure && value.failed >= 1))
    || (value.status === "RUNNING" && (value.failed !== 0 || covered !== expected.length || errorCode !== ""))
    || (value.status === "FAILED" && value.failed === 0)) return failed();
  const actorStatuses = value.actors && typeof value.actors === "object" && !Array.isArray(value.actors)
    ? value.actors
    : {};
  const actors = {};
  for (const actor of ["natserver", "relay"]) {
    const actorCoverage = coverage.filter((item) => item.actor === actor);
    const actorSource = actorStatuses[actor];
    const required = actorCoverage.length;
    const actorExecuted = actorCoverage.reduce((sum, item) => sum + item.executed, 0);
    const actorFailed = actorCoverage.reduce((sum, item) => sum + item.violations, 0);
    const actorCovered = actorCoverage.filter((item) => item.executed > 0).length;
    if (!actorSource || !allowedStatuses.has(actorSource.status)
      || actorSource.required !== required || actorSource.executed !== actorExecuted
      || actorSource.covered !== actorCovered || !Number.isSafeInteger(actorSource.failed)
      || actorSource.failed < actorFailed || actorSource.failed > actorFailed + 1) return failed();
    actors[actor] = {
      status: actorSource.status,
      executed: actorExecuted,
      failed: actorSource.failed,
      covered: actorCovered,
      required,
    };
  }
  if (value.status === "RUNNING" && Object.values(actors).some((actor) => actor.status !== "RUNNING")) return failed();
  const recent = Array.isArray(value.recent)
    ? value.recent.map((event) => publicBillingContainerEvent(event, expected)).filter(Boolean).slice(0, 16)
    : [];
  return {
    schemaVersion: 1,
    status: value.status,
    executed,
    failed: value.failed,
    covered,
    required: expected.length,
    actors,
    coverage,
    recent,
    scope: "isolated_container_http_ca_fixture",
    transport: ["container_http_peer", "container_http_ca"],
    limitations: ["does_not_instantiate_full_p2p_payload_socket"],
    errorCode,
  };
}

function emptyBillingContainerProbe(expected, status, failed) {
  const coverage = expected.map(([scenario, actor]) => ({ scenario, actor, executed: 0, contained: 0, violations: 0 }));
  return {
    schemaVersion: 1,
    status,
    executed: 0,
    failed,
    covered: 0,
    required: expected.length,
    actors: {
      natserver: { status, executed: 0, failed, covered: 0, required: expected.filter(([, actor]) => actor === "natserver").length },
      relay: { status, executed: 0, failed, covered: 0, required: expected.filter(([, actor]) => actor === "relay").length },
    },
    coverage,
    recent: [],
    scope: "isolated_container_http_ca_fixture",
    transport: ["container_http_peer", "container_http_ca"],
    limitations: ["does_not_instantiate_full_p2p_payload_socket"],
    errorCode: failed > 0 ? "container_probe_snapshot_invalid" : "",
  };
}

function publicBillingContainerEvent(value, expected) {
  const actor = new Map(expected).get(value?.scenario);
  const observedAt = publicTimestamp(value?.observedAt);
  if (!actor || value.actor !== actor || !observedAt
    || !Number.isSafeInteger(value.sequence) || value.sequence < 1) return null;
  const allowedPaths = new Set([
    "container_peer_protocol",
    "malicious-relay->malicious-natserver",
    "malicious-relay->malicious-natserver->ca",
    "malicious-natserver->malicious-relay",
    "malicious-natserver->malicious-relay->ca",
    "malicious-natserver->malicious-relay->malicious-natserver",
  ]);
  return {
    sequence: value.sequence,
    observedAt,
    scenario: value.scenario,
    actor,
    passed: value.passed === true,
    verdict: value.passed === true ? "CONTAINED" : "VIOLATION",
    failureCode: publicBillingContainerProbeCode(value.failureCode),
    defense: publicBillingContainerProbeCode(value.defense),
    requestCount: Math.max(0, integer(value.requestCount, 0)),
    httpStatuses: Array.isArray(value.httpStatuses)
      ? value.httpStatuses.map((status) => integer(status, 0)).filter((status) => status >= 100 && status <= 599).slice(0, 8)
      : [],
    balanceDelta: Number.isSafeInteger(value.balanceDelta) ? value.balanceDelta : 0,
    stateChanged: value.stateChanged === true,
    path: allowedPaths.has(value.path) ? value.path : "container_peer_protocol",
  };
}

function publicBillingContainerProbeCode(value) {
  const code = String(value ?? "");
  return billingContainerProbeCodes.has(code) ? code : code ? "container_probe_failed" : "";
}

function publicBillingComponentProbe(value, expectedScenarios) {
  const failed = {
    schemaVersion: 1,
    status: "FAILED",
    executed: 0,
    failed: 1,
    required: expectedScenarios,
    covered: 0,
  };
  if (!value || typeof value !== "object" || Array.isArray(value)) return failed;
  const allowedStatuses = new Set(["STARTING", "RUNNING", "FAILED", "DEGRADED", "STOPPED"]);
  const counters = [value.executed, value.failed, value.required, value.covered];
  if (value.schemaVersion !== 1 || !allowedStatuses.has(value.status)
    || counters.some((count) => !Number.isSafeInteger(count) || count < 0)
    || value.required !== expectedScenarios || value.failed > value.executed
    || value.covered > value.required || value.covered > value.executed
    || (value.status === "STARTING" && (value.executed !== 0 || value.failed !== 0 || value.covered !== 0))
    || (["RUNNING", "DEGRADED", "STOPPED"].includes(value.status) && value.failed !== 0)
    || (value.status === "FAILED" && value.failed === 0)) {
    return failed;
  }
  return {
    schemaVersion: 1,
    status: value.status,
    executed: value.executed,
    failed: value.failed,
    required: value.required,
    covered: value.covered,
  };
}

async function readBillingProductionGate(file) {
  const value = await readJson(file);
  const source = value && typeof value === "object" && !Array.isArray(value) && value.schemaVersion === 2
    ? value
    : {};
  const allowedStatuses = new Set(["STARTING", "PASSED", "FAILED"]);
  const status = allowedStatuses.has(source.status) ? source.status : "UNKNOWN";
  return {
    schemaVersion: 2,
    status,
    detail: publicBillingProductionGateDetail(status, source.detail),
    queueDepthBefore: publicNonNegativeInteger(source.queueDepthBefore),
    queueDepthAfterRestart: publicNonNegativeInteger(source.queueDepthAfterRestart),
    queueDepthAfterRecovery: publicNonNegativeInteger(source.queueDepthAfterRecovery),
    transferBytes: publicNonNegativeInteger(source.transferBytes),
    observedBillableBytes: publicNonNegativeInteger(source.observedBillableBytes),
    authorizedBillableBytes: publicNonNegativeInteger(source.authorizedBillableBytes),
    payerDebit: publicNonNegativeInteger(source.payerDebit),
    unsettledTailBytes: publicNonNegativeInteger(source.unsettledTailBytes),
    relayCredit: publicNonNegativeInteger(source.relayCredit),
    caCredit: publicNonNegativeInteger(source.caCredit),
    amountVerified: source.amountVerified === true,
    splitVerified: source.splitVerified === true,
    observedAt: publicTimestamp(source.observedAt),
  };
}

function publicBillingProductionGateDetail(status, value) {
  if (status === "STARTING") return "initializing";
  if (status === "PASSED") return "verified";
  if (status !== "FAILED") return "";
  return billingProductionGateFailureDetails.has(value) ? value : "billing_production_gate_failed";
}

function publicNonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function emptyBillingAdversary(scenarios) {
  return {
    schemaVersion: 1,
    available: false,
    status: "NOT_STARTED",
    healthy: false,
    mode: "isolated_probe",
    heartbeatAt: "",
    summary: {
      executedChecks: 0,
      preventedChecks: 0,
      missedChecks: 0,
      preventionRatePct: 0,
      stateChanges: 0,
      coveredScenarios: 0,
      requiredScenarioCount: scenarios.length,
    },
    actors: {
      natserver: { executed: 0, contained: 0, violations: 0 },
      relay: { executed: 0, contained: 0, violations: 0 },
      network: { executed: 0, contained: 0, violations: 0 },
    },
    coverage: scenarios.map(([scenario, actor]) => ({ scenario, actor, executed: 0, contained: 0, violations: 0 })),
    componentProbe: {
      schemaVersion: 1,
      status: "NOT_STARTED",
      executed: 0,
      failed: 0,
      required: scenarios.length,
      covered: 0,
    },
    containerProbe: emptyBillingContainerProbe([
      ["nat_stale_watermark", "natserver"],
      ["nat_same_sequence_fork", "natserver"],
      ["nat_signature_refusal", "natserver"],
      ["nat_identity_forgery", "natserver"],
      ["relay_usage_inflation", "relay"],
      ["relay_request_replay", "relay"],
      ["relay_fee_override", "relay"],
      ["relay_window_overrun", "relay"],
      ["relay_voucher_tamper", "relay"],
    ], "NOT_STARTED", 0),
    recent: [],
    lastError: null,
  };
}

function publicAdversaryEvent(value, scenarios, allowedVerdicts) {
  if (!value || typeof value !== "object") return null;
  const actorByScenario = new Map(scenarios);
  const actor = actorByScenario.get(value.scenario);
  if (!actor) return null;
  const verdict = allowedVerdicts.has(value.verdict) ? value.verdict : "HARNESS_ERROR";
  const failureCode = publicEnum(value.failureCode, billingAdversaryEventCodes, "adversary_event_failed");
  const defense = publicEnum(value.defense, billingAdversaryEventCodes, "defense_applied");
  return {
    sequence: Math.max(0, integer(value.sequence, 0)),
    observedAt: publicTimestamp(value.observedAt),
    scenario: value.scenario,
    actor,
    actorInstance: actor === "relay"
      ? "simulated-malicious-relay"
      : actor === "natserver"
        ? "simulated-malicious-natserver"
        : "simulated-index-link",
    passed: value.passed === true,
    verdict,
    failureCode,
    defense,
    requestCount: Math.max(0, integer(value.requestCount, 0)),
    httpStatuses: Array.isArray(value.httpStatuses)
      ? value.httpStatuses.map((status) => integer(status, 0)).filter((status) => status >= 0 && status <= 599).slice(0, 10)
      : [],
    balanceDelta: integer(value.balanceDelta, 0),
    stateChanged: value.stateChanged === true,
    depth: publicEnum(value.depth, billingAdversaryDepths, "isolated_probe"),
  };
}

function publicWatcherAlert(value) {
  if (!value || typeof value !== "object") return null;
  const categoryMessages = {
    handshake_first_frame_contamination: "隧道建立前出现握手首帧公钥解析异常",
    data_path_stall: "业务传输收到部分数据后停滞至超时",
    client_tunnel_not_ready: "客户端隧道未在就绪窗口完成建立",
    server_registration_failed: "服务端身份或 Relay 注册检查失败",
    client_entry_relay_unresolved: "客户端入口 Relay 未能识别",
    transfer_failed: "传输失败，等待进一步诊断",
  };
  const allowedStages = new Set(["tunnel_setup", "data_transfer", "registration", "ingress_detection", "unknown"]);
  const allowedSignals = new Set([
    "public_key_parser_rejected_N",
    "kcp_reconnect_timeout",
    "resume_leg_slot_occupied",
    "curl_900s_timeout",
  ]);
  const category = Object.hasOwn(categoryMessages, value.category) ? value.category : "transfer_failed";
  const client = publicService(value.client, "natclient");
  const ingressRelay = publicService(value.ingressRelay, "relay");
  const server = publicService(value.server, "natserver");
  const serverRelay = publicService(value.serverRelay, "relay");
  const progressPct = Math.min(100, Math.max(0, number(value.progressPct, 0)));
  return {
    sequence: Math.max(0, integer(value.sequence, 0)),
    observedAt: publicTimestamp(value.observedAt),
    timestamp: publicTimestamp(value.timestamp),
    severity: value.severity === "critical" ? "critical" : "warning",
    category,
    stage: allowedStages.has(value.stage) ? value.stage : "unknown",
    message: categoryMessages[category],
    client,
    ingressRelay,
    server,
    serverRelay,
    route: [client, ingressRelay, serverRelay, server],
    rc: integer(value.rc, -1),
    requestedMiB: round(Math.max(0, number(value.requestedMiB, 0)), 3),
    bytes: Math.max(0, integer(value.bytes, 0)),
    seconds: round(Math.max(0, number(value.seconds, 0)), 3),
    progressPct: round(progressPct, 2),
    signals: Array.isArray(value.signals)
      ? value.signals.filter((signal) => allowedSignals.has(signal))
      : [],
  };
}

function publicEnum(value, allowed, fallback = "") {
  const label = String(value ?? "");
  if (!label) return "";
  return allowed.has(label) ? label : fallback;
}

function transferFailureMetrics(transfer) {
  const requestedMiB = Math.max(0, number(transfer.requested_mib, 0));
  const bytes = Math.max(0, integer(transfer.bytes, 0));
  const seconds = Math.max(0, number(transfer.seconds, 0));
  const expectedBytes = requestedMiB * 1048576;
  const progressPct = expectedBytes > 0
    ? round(Math.min(100, bytes / expectedBytes * 100), 2)
    : 0;
  return { requestedMiB, bytes, seconds, expectedBytes, progressPct };
}

async function buildFailureAnalysis({ failures, failureStats, ingressStats, available, updatedAt, serverPool, compose }) {
  const serverRelays = new Map();
  for (const row of serverPool) {
    if (!validService(row.server, "natserver") || !validService(row.ingress_relay, "relay")) continue;
    serverRelays.set(row.server, row.ingress_relay);
  }
  const relayPartitions = composeRelayPartitions(compose);
  const analyzed = await Promise.all(failures.map(async (transfer) => {
    const client = publicService(transfer.client, "natclient");
    const ingressRelay = publicService(transfer.ingress_relay, "relay");
    const targetServer = publicService(transfer.server, "natserver");
    const serverRelay = publicService(serverRelays.get(targetServer), "relay");
    const partition = relayPartitionLabel(relayPartitions.get(serverRelay));
    const ingressPartition = relayPartitionLabel(relayPartitions.get(ingressRelay));
    const metrics = transferFailureMetrics(transfer);
    const classification = await inspectFailureEvidence(transfer, metrics);
    const publicFailure = {
      timestamp: publicTimestamp(transfer.timestamp),
      client,
      ingressRelay,
      server: targetServer,
      serverRelay,
      partition,
      route: [
        {
          id: client,
          label: client,
          role: "natclient",
          network: sharedServiceNetwork(compose, client, ingressRelay),
        },
        {
          id: ingressRelay,
          label: ingressRelay,
          role: "relay",
          bridge: ingressPartition === "bridge",
          partition: ingressPartition,
          network: sharedServiceNetwork(compose, ingressRelay, serverRelay),
        },
        {
          id: serverRelay,
          label: serverRelay,
          role: "relay",
          partition,
          network: sharedServiceNetwork(compose, serverRelay, targetServer),
        },
        {
          id: targetServer,
          label: targetServer,
          role: "natserver",
        },
      ],
      rc: integer(transfer.rc, -1),
      requestedMiB: metrics.requestedMiB,
      bytes: metrics.bytes,
      seconds: round(metrics.seconds, 3),
      progressPct: metrics.progressPct,
      cause: classification.cause,
      diagnosis: classification.diagnosis,
      evidence: classification.evidence,
    };
    return {
      publicFailure,
      timestampEpoch: Date.parse(publicFailure.timestamp) || 0,
    };
  }));
  analyzed.sort((left, right) => right.timestampEpoch - left.timestampEpoch);

  const affectedClients = sortedServices(failureStats.clients);
  const affectedServers = sortedServices(failureStats.servers);
  const ingressCounts = failureStats.ingressCounts;
  const partitionCounts = { A: 0, B: 0, bridge: 0, unknown: 0 };
  let crossRelay = 0;
  for (const [pathKey, count] of failureStats.pathCounts) {
    const [ingressRelay, targetServer] = JSON.parse(pathKey);
    const serverRelay = publicService(serverRelays.get(targetServer), "relay");
    const partition = relayPartitionLabel(relayPartitions.get(serverRelay));
    const partitionKey = ["A", "B", "bridge"].includes(partition) ? partition : "unknown";
    partitionCounts[partitionKey] += count;
    if (ingressRelay !== "unknown" && serverRelay !== "unknown" && ingressRelay !== serverRelay) {
      crossRelay += count;
    }
  }
  const causeCounts = Object.fromEntries([...failureStats.causeCounts]
    .sort(([left], [right]) => left.localeCompare(right, "en")));
  const commonIngress = [...ingressCounts.entries()]
    .filter(([relay]) => relay !== "unknown")
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0], "en", { numeric: true }))[0];
  const commonIngressRuntime = commonIngress ? ingressStats.get(commonIngress[0]) : null;
  const commonIngressRelay = commonIngress && commonIngress[1] >= 2
    ? {
        relay: commonIngress[0],
        failures: commonIngress[1],
        sharePct: round(commonIngress[1] / Math.max(1, failureStats.total) * 100, 1),
        successfulTransfers: commonIngressRuntime?.succeeded ?? 0,
      }
    : null;
  const summary = {
    totalFailures: failureStats.total,
    affectedClients,
    affectedServers,
    crossRelay,
    commonIngressRelay,
    partitionCounts,
    causeCounts,
  };
  const historicalStalls = failureStats.dataStalls.map((item) => ({
    ...item,
    serverRelay: publicService(serverRelays.get(item.server), "relay"),
  }));

  return {
    schemaVersion: 1,
    available,
    updatedAt,
    generatedAt: new Date().toISOString(),
    metadata: {
      source: "redacted_local_evidence",
      totalFailureRecords: failureStats.total,
      retainedFailureRecords: analyzed.length,
      retentionLimit: failureRetentionLimit,
    },
    summary,
    patterns: detectFailurePatterns(summary, failureStats.handshakeByClient, historicalStalls),
    failures: analyzed.map((item) => item.publicFailure),
  };
}

async function inspectFailureEvidence(transfer, metrics) {
  const transferId = safeFileComponent(transfer.transfer_id);
  const cacheKey = transferId || [
    transfer.timestamp,
    transfer.client,
    transfer.server,
    transfer.rc,
    transfer.bytes,
  ].join("\u0000");
  if (failureEvidenceCache.has(cacheKey)) return failureEvidenceCache.get(cacheKey);

  let clientLog = "";
  let serverLog = "";
  let errorLog = "";
  if (transferId) {
    const client = safeFileComponent(transfer.client);
    [clientLog, serverLog, errorLog] = await Promise.all([
      readTail(path.join(runDir, "transfer-logs", `${transferId}-client.log`), 256 * 1024),
      readTail(path.join(runDir, "transfer-logs", `${transferId}-server.log`), 256 * 1024),
      client
        ? readTail(path.join(runDir, "transfer-errors", `${client}-${transferId}.log`), 64 * 1024)
        : "",
    ]);
  }
  const classification = classifyFailure({ transfer, metrics, clientLog, serverLog, errorLog });
  failureEvidenceCache.set(cacheKey, classification);
  if (failureEvidenceCache.size > failureRetentionLimit) {
    failureEvidenceCache.delete(failureEvidenceCache.keys().next().value);
  }
  return classification;
}

function classifyFailure({ transfer, metrics, clientLog, serverLog, errorLog }) {
  const rc = integer(transfer.rc, -1);
  const hasHandshakeContamination = /invalid byte:?\s*U\+004E\s*['"]N['"]/i.test(serverLog);
  const hasKcpReconnectTimeout = /KCP[^\n]*(?:context deadline exceeded|重连拨号失败)/i.test(clientLog);
  const hasResumeSlotConflict = /resume leg slot occupied|resume[^\n]*slot[^\n]*occupied/i.test(`${clientLog}\n${serverLog}`);
  const hasCurl900Timeout = /curl:\s*\(28\)[^\n]*(?:900000|900001)\s+milliseconds/i.test(errorLog);
  const partial = metrics.bytes > 0 && metrics.expectedBytes > metrics.bytes;
  const reachedTransferTimeout = metrics.seconds >= 899 && partial;

  if (hasHandshakeContamination) {
    return {
      cause: "handshake_first_frame_contamination",
      diagnosis: "代码级门控回归已确认：Relay 在同步转发客户端公钥前提前启动 frame pump 并返回 ACK，随后到达的 Noise hello 越过公钥；服务端因此在十六进制公钥位置读到首字符 N。",
      evidence: [
        "server snapshot: peer public-key parser rejected U+004E ('N')",
        `client tunnel readiness failed (rc=${rc})`,
        "root-cause regression: ACK/frame pump preceded the forwarded public key",
      ],
      flags: { handshake: true, dataStall: false },
    };
  }

  if (reachedTransferTimeout && (hasCurl900Timeout || metrics.seconds >= 900)) {
    const evidence = [
      "curl reached the 900-second limit with a partial payload",
      `received ${metrics.bytes} of ${metrics.expectedBytes} bytes (${metrics.progressPct}%)`,
    ];
    if (hasKcpReconnectTimeout) evidence.push("client snapshot contains KCP reconnect timeouts");
    if (hasResumeSlotConflict) evidence.push("endpoint snapshot contains a Resume leg slot conflict");
    return {
      cause: "data_path_stall",
      diagnosis: "Relay 日志时序与回归已确认：KCP accept 循环曾串行等待半开连接首帧，形成最长 60 秒的队头阻塞；初始 KCP 未建立后仍保留的重连拨号又持续产生 Resume leg，放大积压并使已建立的数据路径停滞至 900 秒超时。",
      evidence,
      flags: { handshake: false, dataStall: true },
    };
  }

  const fallbacks = {
    2: {
      cause: "client_tunnel_not_ready",
      diagnosis: "客户端隧道未在就绪窗口内完成建立，传输流程未进入数据请求阶段。",
      evidence: ["harness readiness fallback rc=2", `received ${metrics.bytes} bytes`],
    },
    3: {
      cause: "server_registration_failed",
      diagnosis: "服务端重启后的身份或 Relay 注册检查未通过，传输流程未启动客户端数据请求。",
      evidence: ["harness registration fallback rc=3", `received ${metrics.bytes} bytes`],
    },
    4: {
      cause: "client_entry_relay_unresolved",
      diagnosis: "客户端看似就绪，但未能在观察窗口内解析出实际入口 Relay，因此传输被中止。",
      evidence: ["harness ingress detection fallback rc=4", `received ${metrics.bytes} bytes`],
    },
  };
  if (fallbacks[rc]) {
    return {
      ...fallbacks[rc],
      flags: { handshake: false, dataStall: false },
    };
  }

  if (rc === 0 && transferSha256State(transfer.sha256_ok) === false) {
    return {
      cause: "integrity_mismatch",
      diagnosis: "传输命令已返回成功，但接收大小或 SHA-256 校验未通过。",
      evidence: [`received ${metrics.bytes} of ${metrics.expectedBytes} bytes`, "sha256_ok=no"],
      flags: { handshake: false, dataStall: false },
    };
  }

  return {
    cause: partial ? "partial_transfer_failure" : "transfer_failed",
    diagnosis: partial
      ? "传输收到部分数据后失败，现有脱敏证据不足以进一步归因。"
      : "传输流程失败，现有脱敏证据不足以进一步归因。",
    evidence: [`process rc=${rc}`, `received ${metrics.bytes} bytes`, `elapsed ${round(metrics.seconds, 3)} seconds`],
    flags: { handshake: false, dataStall: false },
  };
}

function detectFailurePatterns(summary, handshakeByClient, dataStalls) {
  const patterns = [];
  const commonIngress = summary.commonIngressRelay;
  if (commonIngress) {
    const successContext = commonIngress.successfulTransfers > 0
      ? `；该入口同时承载 ${commonIngress.successfulTransfers} 条成功传输`
      : "";
    patterns.push({
      type: "common_ingress_relay",
      severity: "observe",
      title: `失败共同经过 ${commonIngress.relay}`,
      description: `${commonIngress.failures} 条失败共享同一实际入口 Relay${successContext}。这是共同路径和候选故障域，不是单因果结论。`,
      count: commonIngress.failures,
      services: [commonIngress.relay],
    });
  }

  if (summary.partitionCounts.A > 0 && summary.partitionCounts.B > 0) {
    patterns.push({
      type: "cross_partition_distribution",
      severity: "observe",
      title: "失败横跨 A/B 服务端分区",
      description: `分区 A 有 ${summary.partitionCounts.A} 条，分区 B 有 ${summary.partitionCounts.B} 条，故障并非只集中在单一服务端分区。`,
      count: summary.partitionCounts.A + summary.partitionCounts.B,
      services: [],
    });
  }

  for (const [client, failureCount] of handshakeByClient) {
    if (client === "unknown" || failureCount < 2) continue;
    patterns.push({
      type: "client_handshake_cluster",
      severity: "warning",
      title: `${client} 出现握手首帧异常聚集`,
      description: `${failureCount} 条失败命中相同的公钥解析特征；门控回归已复现 Relay 提前 ACK/启动 frame pump，使 Noise hello 越过公钥首帧。`,
      count: failureCount,
      services: [client],
    });
  }

  const stallCluster = closestFailureCluster(
    dataStalls.filter((failure) => failure.timestampEpoch > 0),
    120,
  );
  if (stallCluster.length >= 2) {
    const epochs = stallCluster.map((item) => item.timestampEpoch);
    const spanSeconds = Math.round((Math.max(...epochs) - Math.min(...epochs)) / 1000);
    patterns.push({
      type: "simultaneous_data_stalls",
      severity: "warning",
      title: "多条数据路径近同时停滞",
      description: `${stallCluster.length} 条部分传输在 ${spanSeconds} 秒窗口内进入同一停滞时段；Relay 日志已确认 KCP accept 的串行首帧等待造成队头阻塞，并被无效 KCP Resume 重连放大。`,
      count: stallCluster.length,
      services: sortedServices(new Set(stallCluster.flatMap((item) => [item.client, item.server, item.ingressRelay, item.serverRelay]).filter((service) => service !== "unknown"))),
      windowSeconds: spanSeconds,
    });
  }
  return patterns;
}

function closestFailureCluster(failures, windowSeconds) {
  const sorted = [...failures].sort((left, right) => left.timestampEpoch - right.timestampEpoch);
  let best = [];
  let left = 0;
  for (let right = 0; right < sorted.length; right += 1) {
    while (sorted[right].timestampEpoch - sorted[left].timestampEpoch > windowSeconds * 1000) left += 1;
    const candidate = sorted.slice(left, right + 1);
    if (candidate.length > best.length) best = candidate;
  }
  return best;
}

function composeRelayPartitions(compose) {
  const partitions = new Map();
  for (const [service, specification] of Object.entries(compose?.services ?? {})) {
    if (!validService(service, "relay")) continue;
    const networks = serviceNetworks(specification);
    const values = [];
    if (networks.includes("control_partition_a")) values.push("A");
    if (networks.includes("control_partition_b")) values.push("B");
    partitions.set(service, values);
  }
  return partitions;
}

function sharedServiceNetwork(compose, left, right) {
  const services = compose?.services ?? {};
  return intersection(serviceNetworks(services[left]), serviceNetworks(services[right]))
    .sort((first, second) => first.localeCompare(second, "en", { numeric: true }))[0] ?? "";
}

function relayPartitionLabel(partitions = []) {
  if (partitions.length === 1) return partitions[0];
  if (partitions.includes("A") && partitions.includes("B")) return "bridge";
  return "unknown";
}

function sortedServices(services) {
  return [...services].sort(serviceSort);
}

function validService(value, role) {
  const service = String(value ?? "");
  return expectedServiceSet.has(service) && roleOf(service) === role;
}

function publicService(value, role) {
  return validService(value, role) ? String(value) : "unknown";
}

function knownService(value, role) {
  return validService(value, role) ? String(value) : "";
}

function knownServiceReference(value, roles) {
  const service = String(value ?? "");
  return expectedServiceSet.has(service) && roles.includes(roleOf(service)) ? service : "";
}

function publicMetadata(value) {
  const result = {};
  const scenario = publicScenario(value.scenario);
  if (scenario) {
    result.scenario = scenario;
    result.scenario_name = {
      1: "partition_bridge",
      2: "nat_path_failover",
      3: "kcp_tcp_fallback",
    }[scenario];
  }
  const numericKeys = [
    "duration_seconds",
    "cpu_limit_pct",
    "memory_limit_pct",
    "disk_limit_pct",
    "sample_seconds",
    "probe_seconds",
    "max_inflight",
    "workload_limit_mibps",
    "per_transfer_limit_mibps",
  ];
  for (const key of numericKeys) {
    if (!Object.hasOwn(value, key)) continue;
    const parsed = number(value[key], Number.NaN);
    if (Number.isFinite(parsed) && parsed >= 0) result[key] = String(parsed);
  }
  if (["enforce", "report", "off"].includes(value.billing_adversary_mode)) {
    result.billing_adversary_mode = value.billing_adversary_mode;
  }
  if (["off", "random"].includes(value.ip_family_coverage)) {
    result.ip_family_coverage = value.ip_family_coverage;
  }
  return result;
}

function publicIPFamilyCoverage(planRows, evidenceRows) {
  const families = ["ipv4", "ipv6", "dual"];
  const assignments = new Map();
  for (const row of planRows) {
    const family = String(row?.family ?? "");
    const relay = String(row?.relay ?? "");
    const natserver = String(row?.natserver ?? "");
    const natclient = String(row?.natclient ?? "");
    if (!families.includes(family) || assignments.has(family)
      || !/^relay0[3-7]$/.test(relay) || !/^natserver(?:0[1-9]|1[0-3])$/.test(natserver)
      || !/^natclient0[1-6]$/.test(natclient)) continue;
    assignments.set(family, { family, relay, natserver, natclient });
  }
  const evidence = new Map();
  for (const row of evidenceRows) {
    const family = String(row?.family ?? "");
    const assignment = assignments.get(family);
    if (!assignment || String(row?.relay ?? "") !== assignment.relay
      || String(row?.natserver ?? "") !== assignment.natserver
      || String(row?.natclient ?? "") !== assignment.natclient) continue;
    const state = ["address_check", "client_socket", "server_socket", "sha256", "status"]
      .every((key) => row?.[key] === "pass") ? "PASS" : "FAIL";
    evidence.set(family, {
      family,
      timestamp: publicTimestamp(row?.timestamp),
      addressCheck: row?.address_check === "pass",
      clientSocket: row?.client_socket === "pass",
      serverSocket: row?.server_socket === "pass",
      sha256: row?.sha256 === "pass",
      state,
    });
  }
  const plan = families.map((family) => assignments.get(family)).filter(Boolean);
  const results = plan.map((assignment) => ({
    ...assignment,
    ...(evidence.get(assignment.family) ?? {
      timestamp: "",
      addressCheck: false,
      clientSocket: false,
      serverSocket: false,
      sha256: false,
      state: "PENDING",
    }),
  }));
  return {
    enabled: plan.length === families.length,
    required: families.length,
    passed: results.filter((item) => item.state === "PASS").length,
    healthy: results.length === families.length && results.every((item) => item.state === "PASS"),
    results,
  };
}

function publicRunStatus(value) {
  return {
    outcome: publicEnum(value.outcome, publicRunOutcomes),
    detail: publicEnum(value.detail, publicRunDetails, "status_detail_redacted"),
  };
}

function publicRuntimeNode(value, profile = buildNodeProfile(String(value.service ?? ""), "default")) {
  const service = String(value.service ?? "");
  const role = roleOf(service);
  return {
    service: role === "diagnostic" ? "diagnostic" : service,
    role,
    state: publicRuntimeStatus(value.state),
    running: value.running === true,
    health: publicRuntimeStatus(value.health),
    restartCount: Math.max(0, integer(value.restartCount, 0)),
    ...profile,
  };
}

function finalMaliciousRuntimeMap(rows) {
  const expected = new Set(maliciousNodeCatalog.map(({ service }) => service));
  const runtimes = new Map();
  for (const row of rows) {
    const service = String(row?.service ?? "");
    if (!expected.has(service) || runtimes.has(service)) continue;
    runtimes.set(service, {
      service,
      running: row.status === "running",
      health: publicRuntimeStatus(row.health),
      restartCount: Math.max(0, integer(row.restart_count, 0)),
    });
  }
  return runtimes;
}

function publicMaliciousNodes(containerMap, containerProbe) {
  const actors = containerProbe?.actors && typeof containerProbe.actors === "object"
    ? containerProbe.actors
    : {};
  const recent = Array.isArray(containerProbe?.recent) ? containerProbe.recent : [];
  return maliciousNodeCatalog.map(({ service, actor }) => {
    const runtime = containerMap.get(service) ?? missingContainer(service);
    const probe = actors[actor] ?? {};
    return {
      service,
      actor,
      ...buildNodeProfile(service, "default"),
      running: runtime.running === true,
      health: publicRuntimeStatus(runtime.health),
      restartCount: Math.max(0, integer(runtime.restartCount, 0)),
      probe: {
        status: ["DISABLED", "STARTING", "RUNNING", "FAILED", "STOPPED", "NOT_STARTED"].includes(probe.status)
          ? probe.status
          : "UNKNOWN",
        executed: Math.max(0, integer(probe.executed, 0)),
        failed: Math.max(0, integer(probe.failed, 0)),
        covered: Math.max(0, integer(probe.covered, 0)),
        required: Math.max(0, integer(probe.required, 0)),
      },
      latestActivity: publicMaliciousNodeActivity(latestActorActivity(recent, actor)),
    };
  });
}

function publicRuntimeStatus(value) {
  const status = String(value ?? "");
  return publicRuntimeStatuses.has(status) ? status : "unknown";
}

function latestActorActivity(events, actor) {
  return events.filter((event) => event?.actor === actor).sort((left, right) => (
    Date.parse(right.observedAt) - Date.parse(left.observedAt)
      || integer(right.sequence, 0) - integer(left.sequence, 0)
  ))[0];
}

function publicMaliciousNodeActivity(value) {
  if (!value) return null;
  return {
    observedAt: publicTimestamp(value.observedAt),
    scenario: publicEnum(value.scenario, maliciousScenarioNames, "unknown"),
    passed: value.passed === true,
    verdict: value.passed === true ? "CONTAINED" : "VIOLATION",
    defense: publicBillingContainerProbeCode(value.defense),
    failureCode: publicBillingContainerProbeCode(value.failureCode),
  };
}

function publicPhase(value) {
  const phase = String(value ?? "").trim();
  const allowed = new Set([
    "LAUNCHING",
    "BUILDING",
    "STARTING_CLUSTER",
    "CONFIGURING_PROFILE",
    "VERIFYING_BILLING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "RESOURCE_LIMIT",
    "STOPPED",
  ]);
  return allowed.has(phase) ? phase : "UNKNOWN";
}

function publicScenario(value) {
  const scenario = String(value ?? "");
  return ["1", "2", "3"].includes(scenario) ? scenario : "";
}

function publicResourceGuard(value) {
  const status = String(value ?? "").trim().split(/\s+/, 1)[0];
  return ["RUNNING", "TERMINATED", "COMPLETED", "STOPPED_BY_SIGNAL", "RUNNER_EXITED"].includes(status)
    ? status
    : "UNKNOWN";
}

function publicResourceSample(value) {
  if (!value || typeof value !== "object") return null;
  const sample = {
    timestamp: publicTimestamp(value.timestamp),
    epoch: Math.max(0, integer(value.epoch, 0)),
    containers: Math.max(0, integer(value.containers, 0)),
    state: publicEnum(value.state, resourceSampleStates, "UNKNOWN") || "UNKNOWN",
  };
  for (const key of [
    "project_cpu_raw_pct",
    "project_cpu_host_pct",
    "host_cpu_pct",
    "project_memory_host_pct",
    "host_memory_pct",
    "docker_disk_pct",
    "artifact_disk_pct",
    "guard_disk_pct",
  ]) {
    sample[key] = Math.max(0, number(value[key], 0));
  }
  return sample;
}

function safeFileComponent(value) {
  const component = String(value ?? "");
  return /^[A-Za-z0-9._-]+$/.test(component) ? component : "";
}

function publicTimestamp(value) {
  const timestamp = String(value ?? "");
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/.test(timestamp)
    ? timestamp
    : "";
}

function round(value, digits) {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

async function readTsv(file, limit, maxBytes = 256 * 1024) {
  const text = await readTail(file, maxBytes);
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return [];
  const header = lines[0].split("\t");
  return lines.slice(Math.max(1, lines.length - limit)).map((line) => {
    const values = line.split("\t");
    return Object.fromEntries(header.map((name, index) => [name, values[index] ?? ""]));
  });
}

async function readTail(file, maxBytes) {
  try {
    const handle = await fs.open(file, "r");
    try {
      const stat = await handle.stat();
      const start = Math.max(0, stat.size - maxBytes);
      const buffer = Buffer.alloc(stat.size - start);
      await handle.read(buffer, 0, buffer.length, start);
      let text = buffer.toString("utf8");
      if (start > 0) {
        const newline = text.indexOf("\n");
        text = newline >= 0 ? text.slice(newline + 1) : "";
        const header = await readHeader(file);
        text = `${header}\n${text}`;
      }
      return text;
    } finally {
      await handle.close();
    }
  } catch {
    return "";
  }
}

async function readHeader(file) {
  try {
    const handle = await fs.open(file, "r");
    try {
      const buffer = Buffer.alloc(4096);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      return buffer.subarray(0, bytesRead).toString("utf8").split(/\r?\n/, 1)[0];
    } finally {
      await handle.close();
    }
  } catch {
    return "";
  }
}

async function readText(file) {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return "";
  }
}

function missingContainer(service) {
  return {
    service,
    role: roleOf(service),
    id: "",
    name: service,
    image: "",
    state: "missing",
    running: false,
    health: "missing",
    restartCount: 0,
    startedAt: "",
    finishedAt: "",
    pid: 0,
    networkAddresses: {},
  };
}

function roleOf(service) {
  if (service === maliciousNatClient) return "natclient";
  if (service === maliciousRandomNatServer) return "natserver";
  if (service === "malicious-natserver" || service === "malicious-relay") return service;
  if (service === "mixed-path-probe") return "natclient";
  if (!expectedServiceSet.has(service)) return "diagnostic";
  if (service === "ca" || service === "index") return service;
  if (service.startsWith("relay")) return "relay";
  if (service.startsWith("natserver")) return "natserver";
  if (service.startsWith("natclient")) return "natclient";
  return "diagnostic";
}

function isHealthy(node) {
  return node.running && (node.health === "healthy" || node.health === "running");
}

function numbered(prefix, count) {
  return Array.from({ length: count }, (_, index) => `${prefix}${String(index + 1).padStart(2, "0")}`);
}

function elapsedMs(started) {
  return Number(process.hrtime.bigint() - started) / 1e6;
}

function integer(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function number(value, fallback) {
  const parsed = Number.parseFloat(String(value ?? ""));
  return Number.isFinite(parsed) ? parsed : fallback;
}

function json(response, statusCode, value, headers = {}) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  response.end(body);
}
