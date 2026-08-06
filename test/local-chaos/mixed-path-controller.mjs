import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const normalRelays = Object.freeze(Array.from({ length: 5 }, (_, index) => `relay${String(index + 3).padStart(2, "0")}`));
const normalRelayPartitions = Object.freeze({
  relay03: "control_partition_a",
  relay04: "control_partition_a",
  relay05: "control_partition_a",
  relay06: "control_partition_b",
  relay07: "control_partition_b",
});
const scenariosByActor = Object.freeze({
  natserver: Object.freeze(["nat_stale_watermark", "nat_same_sequence_fork", "nat_signature_refusal", "nat_identity_forgery"]),
  relay: Object.freeze(["relay_usage_inflation", "relay_request_replay", "relay_fee_override", "relay_window_overrun", "relay_voucher_tamper"]),
});
const allowedDefenses = new Set([
  "nat_meter_rejected_usage_inflation",
  "nat_rejected_policy_override",
  "nat_rejected_one_mib_window_overrun",
  "ca_idempotent_replay",
  "ca_rejected_tampered_double_signature",
  "relay_rejected_stale_nat_watermark",
  "relay_rejected_same_sequence_fork",
  "relay_never_submitted_unsigned_bill",
  "relay_rejected_forged_nat_identity",
  "relay_rejected_invalid_nat_candidate",
]);
const terminalPhases = new Set(["COMPLETED", "FAILED", "RESOURCE_LIMIT", "STOPPED"]);
const relayControlStartTimeoutMs = 90_000;

export function selectRandomNormalRelay(currentRelay, excludedRelays = [], randomInteger = crypto.randomInt) {
  const excluded = new Set([currentRelay, ...excludedRelays]);
  const candidates = normalRelays.filter((relay) => !excluded.has(relay));
  return candidates[randomInteger(candidates.length)];
}

export function generateEphemeralServerIdentity() {
  const keyPair = crypto.createECDH("prime256v1");
  keyPair.generateKeys();
  const privateKey = keyPair.getPrivateKey("hex").padStart(64, "0");
  const publicKey = keyPair.getPublicKey("hex", "uncompressed");
  const nodeID = crypto.createHash("sha256").update(publicKey).digest("hex");
  return { privateKey, publicKey, nodeID };
}

export function buildSignedNodeAuthorization(identity, bundle, timestamp = Math.floor(Date.now() / 1000)) {
  if (!identity || !/^[0-9a-f]{64}$/.test(String(identity.privateKey ?? ""))
    || !/^04[0-9a-f]{128}$/.test(String(identity.publicKey ?? ""))
    || !/^[0-9a-f]{64}$/.test(String(identity.nodeID ?? ""))
    || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
    throw codedError("mixed_path_identity_invalid");
  }
  const identityPrivateKey = privateKeyFromScalar(Buffer.from(identity.privateKey, "hex"));
  const derivedPublicKey = publicKeyHex(identityPrivateKey);
  const derivedNodeID = crypto.createHash("sha256").update(derivedPublicKey).digest("hex");
  if (derivedPublicKey !== identity.publicKey || derivedNodeID !== identity.nodeID) {
    throw codedError("mixed_path_identity_key_binding_invalid");
  }
  const billingPrivateKey = validateBillingBundle(bundle);
  const request = {
    subject_pubkey: identity.publicKey,
    role: "server",
    billing_key_id: bundle.key_id,
    timestamp,
    nonce: crypto.randomBytes(24).toString("base64url"),
    ttl_seconds: 86400,
    node_signature: "",
    billing_signature: "",
  };
  const canonical = nodeAuthorizationCanonical(request);
  request.node_signature = signCanonical(canonical, identityPrivateKey);
  request.billing_signature = signCanonical(canonical, billingPrivateKey);
  return request;
}

export function mixedPathNodes(clientRelay, serverRelay) {
  const controlPath = clientRelay === "malicious-relay"
    ? [clientRelay, serverRelay]
    : clientRelay === serverRelay
      ? [clientRelay]
      : [clientRelay, "relay01", serverRelay];
  return ["mixed-path-probe", ...controlPath, "malicious-natserver"]
    .filter((node, index, nodes) => node && (index === 0 || node !== nodes[index - 1]));
}

export function normalPartitionForRelay(relay) {
  return normalRelayPartitions[relay] ?? "";
}

export function publicTrigger(actor, event) {
  const scenarios = new Set(scenariosByActor[actor] ?? []);
  if (!event || !Number.isSafeInteger(event.sequence) || event.sequence < 1 || !scenarios.has(event.scenario)) return null;
  const defense = allowedDefenses.has(event.defense) ? event.defense : "";
  const requestCount = Number.isSafeInteger(event.requestCount) && event.requestCount >= 0 ? event.requestCount : 0;
  const httpStatuses = Array.isArray(event.httpStatuses)
    ? event.httpStatuses.filter((status) => Number.isSafeInteger(status) && status >= 100 && status <= 599).slice(0, 8)
    : [];
  return {
    actor,
    scenario: event.scenario,
    sequence: event.sequence,
    observedAt: validTimestamp(event.observedAt),
    contained: event.passed === true,
    defense,
    requestCount,
    httpStatuses,
  };
}

export function pendingTriggers(events, lastSequences) {
  const triggers = [];
  for (const actor of ["natserver", "relay"]) {
    const lastSequence = Number.isSafeInteger(lastSequences?.[actor]) ? lastSequences[actor] : 0;
    const actorTriggers = (Array.isArray(events?.[actor]) ? events[actor] : [])
      .map((event) => publicTrigger(actor, event))
      .filter((trigger) => trigger && trigger.sequence > lastSequence)
      .sort((left, right) => left.sequence - right.sequence);
    triggers.push(...actorTriggers);
  }
  return triggers.sort((left, right) => (
    Date.parse(left.observedAt || "") - Date.parse(right.observedAt || "")
      || left.sequence - right.sequence
      || left.actor.localeCompare(right.actor)
  ));
}

export function createSerialHeartbeatPublisher(state, publishSnapshot, intervalMs = 2000) {
  let tail = Promise.resolve();
  const publish = () => {
    state.heartbeatAt = new Date().toISOString();
    const snapshot = JSON.parse(JSON.stringify(state));
    const current = tail.then(() => publishSnapshot(snapshot));
    tail = current.catch(() => {});
    return current;
  };
  const timer = setInterval(() => {
    void publish().catch(() => {});
  }, intervalMs);
  timer.unref?.();
  return {
    publish,
    async stop() {
      clearInterval(timer);
      await tail;
    },
  };
}

export function recordControllerFailure(state, error) {
  state.status = "FAILED";
  state.errorCode = safeCode(error?.code || "mixed_path_controller_failed");
  return state;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await run().catch(failAndExit);

async function run() {
  process.umask(0o077);
  const config = configuration();
  const state = initialState();
  let stopping = false;
  let wakeDelay;
  config.shouldStop = () => stopping;
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(signal, () => {
      stopping = true;
      wakeDelay?.();
    });
  }

  const publisher = createSerialHeartbeatPublisher(state, (snapshot) => Promise.all([
    writeJSONAtomic(path.join(config.runDir, "mixed-adversary-path.json"), snapshot),
    writeStatusAtomic(path.join(config.runDir, "mixed-adversary-path.status"), snapshot),
  ]));
  const publish = publisher.publish;

  try {
    await publish();
    await waitForProvisionedIdentity(config, "malicious-natserver", "server");
    await waitForProvisionedIdentity(config, "malicious-relay", "relay");
    await startMaliciousRelay(config);
    state.attachments.maliciousRelay.running = true;
    let maliciousNodeID = await startMaliciousServer(
      config,
      state.attachments.maliciousNatserver.currentRelay,
    );
    state.attachments.maliciousNatserver.identityGeneration = 1;
    state.attachments.maliciousNatserver.running = true;
    await startNormalProbe(config, maliciousNodeID, state.attachments.normalProbe.currentRelay);
    state.attachments.normalProbe.running = true;
    await probeMixedPath(config, state);
    if (state.probe.status !== "PASS") throw codedError("mixed_path_initial_probe_failed");
    state.initialPathVerified = true;
    state.status = "RUNNING";
    state.path.state = "active";
    state.path.nodes = mixedPathNodes(
      state.attachments.normalProbe.currentRelay,
      state.attachments.maliciousNatserver.currentRelay,
    );
    refreshPathEvidence(state);
    await publish();
    process.stdout.write("BNFS mixed adversary P2P path running\n");

    const lastSequences = { natserver: 0, relay: 0 };
    let nextProbeAt = 0;
    while (!stopping) {
      if (config.watchPid > 0 && !processAlive(config.watchPid)) break;
      if (terminalPhases.has((await readText(path.join(config.runDir, "phase"))).trim())) break;
      if (await fileExists(path.join(config.runDir, "mixed-adversary-path.drain"))) {
        if (!state.drainComplete) {
          state.drainComplete = true;
          state.drainCompletedAt = new Date().toISOString();
          await publish();
        }
        await interruptibleDelay(config, 250);
        continue;
      }
      const events = await actorEvents(config);
      for (const trigger of pendingTriggers(events, lastSequences)) {
        if (trigger.sequence !== lastSequences[trigger.actor] + 1) throw codedError("mixed_path_event_gap");
        state.observedTriggers += 1;
        state.lastTrigger = trigger;
        maliciousNodeID = await migrateForTrigger(
          config,
          state,
          maliciousNodeID,
          trigger,
          publish,
        );
        lastSequences[trigger.actor] = trigger.sequence;
      }
      const now = Date.now();
      if (now >= nextProbeAt) {
        await probeMixedPath(config, state);
        nextProbeAt = now + config.probeIntervalMs;
        if (state.probe.consecutiveFailures >= 3) throw codedError("mixed_path_probe_failed");
      }
      await publish();
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 1000);
        wakeDelay = () => {
          clearTimeout(timer);
          resolve();
        };
      });
      wakeDelay = null;
    }
  } catch (error) {
    if (!stopping) {
      recordControllerFailure(state, error);
      try {
        await publish();
        error.evidencePublished = true;
      } catch {}
      await publisher.stop();
      throw error;
    }
  }

  await publisher.stop();
  state.status = "STOPPED";
  state.stopReason = stopping ? "signal_requested" : "runner_or_phase_ended";
  await publish();
}

async function migrateForTrigger(config, state, targetNodeID, trigger, publish) {
  if (trigger.contained !== true) throw codedError("mixed_path_trigger_not_contained");
  state.status = "MIGRATING";
  state.path.state = "migrating";
  await publish();
  const migration = {
    generation: state.generation + 1,
    trigger,
    endpoint: trigger.actor === "natserver" ? "malicious-natserver" : "malicious-relay",
    previousRelay: "",
    currentRelay: "",
    normalPartition: "",
    failureInjected: false,
    isolationVerified: false,
    triggerContained: true,
    containmentVerified: false,
    probePassed: false,
    identityRotated: false,
    identityGeneration: state.attachments.maliciousNatserver.identityGeneration,
    postContainmentPath: [],
    switchedAt: new Date().toISOString(),
  };
  let restartNormalProbe = false;
  let activeTargetNodeID = targetNodeID;

  if (trigger.actor === "natserver") {
    const attachment = state.attachments.maliciousNatserver;
    const probeAttachment = state.attachments.normalProbe;
    migration.previousRelay = attachment.currentRelay;
    migration.currentRelay = selectRandomNormalRelay(attachment.currentRelay);
    migration.isolationVerified = await stopProcess(config, "malicious-natserver", "tunserver");
    if (!migration.isolationVerified) throw codedError("mixed_path_endpoint_isolation_failed");
    migration.failureInjected = true;
    attachment.running = false;
    await stopProcess(config, "mixed-path-probe", "tunclient");
    probeAttachment.running = false;
    restartNormalProbe = true;
    attachment.previousRelay = attachment.currentRelay;
    attachment.currentRelay = migration.currentRelay;
    attachment.normalPartition = normalPartitionForRelay(migration.currentRelay);
    attachment.generation += 1;
    attachment.lastScenario = trigger.scenario;
    attachment.switchedAt = migration.switchedAt;
    probeAttachment.previousRelay = probeAttachment.currentRelay;
    probeAttachment.currentRelay = migration.currentRelay;
    probeAttachment.attachmentType = "connected_to_normal_relay";
    probeAttachment.normalPartition = normalPartitionForRelay(migration.currentRelay);
    probeAttachment.basis = "live_tunnel_registration";
    probeAttachment.generation += 1;
    probeAttachment.lastScenario = trigger.scenario;
    probeAttachment.switchedAt = migration.switchedAt;
    activeTargetNodeID = await startMaliciousServer(config, attachment.currentRelay);
    attachment.identityGeneration += 1;
    migration.identityRotated = activeTargetNodeID !== targetNodeID;
    migration.identityGeneration = attachment.identityGeneration;
    attachment.running = true;
  } else {
    const attachment = state.attachments.maliciousRelay;
    const probeAttachment = state.attachments.normalProbe;
    migration.previousRelay = attachment.currentRelay;
    migration.currentRelay = selectRandomNormalRelay(attachment.currentRelay);
    migration.isolationVerified = await stopProcess(config, "malicious-relay", "nodeserver");
    if (!migration.isolationVerified) throw codedError("mixed_path_endpoint_isolation_failed");
    migration.failureInjected = true;
    attachment.running = false;
    attachment.previousRelay = attachment.currentRelay;
    attachment.currentRelay = migration.currentRelay;
    attachment.normalPartition = normalPartitionForRelay(migration.currentRelay);
    attachment.generation += 1;
    attachment.lastScenario = trigger.scenario;
    attachment.switchedAt = migration.switchedAt;
    await startMaliciousRelay(config, attachment.currentRelay);
    attachment.running = true;
    if (probeAttachment.currentRelay === "malicious-relay") {
      await stopProcess(config, "mixed-path-probe", "tunclient");
      probeAttachment.running = false;
      restartNormalProbe = true;
      probeAttachment.previousRelay = probeAttachment.currentRelay;
      probeAttachment.currentRelay = state.attachments.maliciousNatserver.currentRelay;
      probeAttachment.attachmentType = "connected_to_normal_relay";
      probeAttachment.normalPartition = normalPartitionForRelay(probeAttachment.currentRelay);
      probeAttachment.generation += 1;
      probeAttachment.lastScenario = trigger.scenario;
      probeAttachment.switchedAt = migration.switchedAt;
    }
  }

  if (restartNormalProbe) {
    await stopProcess(config, "mixed-path-probe", "tunclient");
    state.attachments.normalProbe.running = false;
    await startNormalProbe(config, activeTargetNodeID, state.attachments.normalProbe.currentRelay);
    state.attachments.normalProbe.running = true;
  }
  await probeMixedPath(config, state);
  migration.probePassed = state.probe.status === "PASS";
  migration.normalPartition = normalPartitionForRelay(migration.currentRelay);
  state.generation = migration.generation;
  state.path.nodes = mixedPathNodes(
    state.attachments.normalProbe.currentRelay,
    state.attachments.maliciousNatserver.currentRelay,
  );
  refreshPathEvidence(state);
  migration.postContainmentPath = [...state.path.nodes];
  migration.containmentVerified = migration.triggerContained
    && migration.isolationVerified
    && migration.probePassed
    && Boolean(migration.normalPartition)
    && state.path.containsNormalPartition === true
    && state.path.containsMaliciousNode === true;
  state.migrations.unshift(migration);
  state.migrations = state.migrations.slice(0, 20);
  recordNetworkContainment(state, migration);
  state.containment.status = migration.containmentVerified ? "VERIFIED" : "FAILED";
  if (migration.containmentVerified) state.containment.verifiedMigrations += 1;
  state.containment.lastScenario = trigger.scenario;
  state.containment.lastActor = trigger.actor;
  state.containment.lastAction = trigger.actor === "natserver"
    ? "isolate_malicious_natserver_and_migrate_to_random_normal_relay"
    : "isolate_malicious_relay_and_migrate_to_random_normal_relay";
  state.containment.verifiedAt = migration.containmentVerified ? new Date().toISOString() : "";
  state.path.state = migration.probePassed ? "active" : "blocked";
  state.status = migration.probePassed ? "RUNNING" : "DEGRADED";
  await publish();
  if (!migration.containmentVerified) throw codedError("mixed_path_containment_unverified");
  return activeTargetNodeID;
}

async function startMaliciousRelay(config, recoveryPeer = "") {
  if (recoveryPeer) assertNormalRelay(recoveryPeer);
  await stopProcess(config, "malicious-relay", "nodeserver");
  await fs.rm(path.join(config.privateRoot, "malicious-relay", "mixed-nodeserver.log"), { force: true });
  await compose(config, ["exec", "-T", "-d", "malicious-relay", "sh", "-lc", [
    "exec env BNFS_CA_CERT_FILE=/state/certificate.json",
    "/opt/bnfs/nodeserver -mode relay -listen :9300 -public malicious-relay:9300",
    recoveryPeer ? `-peer ${recoveryPeer}:9000` : "",
    "-key /state/identity.key -billing-queue /state/mixed-wait-submit.queue",
    "-ca http://ca:9100 -admission enforce > /state/mixed-nodeserver.log 2>&1",
  ].join(" ")]);
  await waitForFilePattern(
    path.join(config.privateRoot, "malicious-relay", "mixed-nodeserver.log"),
    /relay 已就绪/,
    45_000,
    config,
    "mixed_path_relay_ready_timeout",
  );
  await waitForFilePattern(
    path.join(config.privateRoot, "malicious-relay", "mixed-nodeserver.log"),
    /准入校验通过 control-hello [0-9a-f]{16}: subject=[0-9a-f]{16} role=relay/,
    relayControlStartTimeoutMs,
    config,
    "mixed_path_relay_control_timeout",
  );
}

async function startMaliciousServer(config, relay) {
  assertNormalRelay(relay);
  await stopProcess(config, "malicious-natserver", "tunserver");
  await stopProcess(config, "malicious-natserver", "httpfileserver");
  const targetNodeID = await provisionMixedServerIdentity(config);
  await fs.rm(path.join(config.privateRoot, "malicious-natserver", "mixed-billing-meter.json"), { force: true });
  const logPath = path.join(config.privateRoot, "malicious-natserver", "mixed-tunserver.log");
  await fs.rm(logPath, { force: true });
  await compose(config, ["exec", "-T", "-d", "malicious-natserver", "sh", "-lc",
    "exec /opt/bnfs/httpfileserver -port 8080 -size 1 -max-size 4 > /state/mixed-http.log 2>&1"]);
  await waitForHTTP(config, "malicious-natserver", "http://127.0.0.1:8080/checksum?size_mb=1", 20_000);
  await compose(config, ["exec", "-T", "-d", "malicious-natserver", "sh", "-lc", [
    "exec env BNFS_RELAY_INCLUDE_INDEX=0 BNFS_CA_CERT_FILE=/state/mixed-network-certificate.json",
    "/opt/bnfs/tunserver -index index:9000 -relay", `${relay}:9000`,
    "-target 127.0.0.1:8080 -key /state/mixed-network-identity.key",
    "-billing-private-snapshot /state/mixed-billing-meter.json -ca http://ca:9100",
    "> /state/mixed-tunserver.log 2>&1",
  ].join(" ")]);
  await waitForFilePattern(
    logPath,
    /服务端已就绪/,
    45_000,
    config,
    "mixed_path_natserver_ready_timeout",
  );
  await waitForHostedNode(config, relay, targetNodeID, 45_000);
  return targetNodeID;
}

async function provisionMixedServerIdentity(config) {
  const identity = generateEphemeralServerIdentity();
  const stateDirectory = path.join(config.privateRoot, "malicious-natserver");
  const bundle = await readPrivateJSON(path.join(stateDirectory, "billing-key.json"));
  const authorization = buildSignedNodeAuthorization(identity, bundle);
  const expectedAuthorizationID = nodeAuthorizationID(identity.nodeID, bundle.key_id);
  const response = await fetch(new URL("/v1/node/authorize", config.caBaseURL), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authorization),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw codedError("mixed_path_identity_authorization_rejected");
  const body = await response.json();
  const certificate = body?.signed_cert;
  if (body?.node_id !== identity.nodeID || body?.authorization_id !== expectedAuthorizationID
    || !validBillingCertificate(certificate, identity, bundle, expectedAuthorizationID)) {
    throw codedError("mixed_path_identity_certificate_invalid");
  }
  await Promise.all([
    writeTextAtomic(path.join(stateDirectory, "mixed-network-identity.key"), `${identity.privateKey}\n`),
    writeJSONAtomic(path.join(stateDirectory, "mixed-network-certificate.json"), certificate),
  ]);
  await ensureCredit(config, identity.nodeID, expectedAuthorizationID);
  return identity.nodeID;
}

async function startNormalProbe(config, targetNodeID, relay) {
  if (!/^[0-9a-f]{64}$/.test(targetNodeID)) throw codedError("mixed_path_target_invalid");
  if (relay !== "malicious-relay") assertNormalRelay(relay);
  await stopProcess(config, "mixed-path-probe", "tunclient");
  const logPath = path.join(config.privateRoot, "mixed-path-probe", "mixed-tunclient.log");
  await fs.rm(logPath, { force: true });
  const relayAddress = relay === "malicious-relay" ? "malicious-relay:9300" : `${relay}:9000`;
  await compose(config, ["exec", "-T", "-d", "mixed-path-probe", "sh", "-lc", [
    "exec env BNFS_RELAY_INCLUDE_INDEX=0",
    "/opt/bnfs/tunclient -index index:9000 -target", targetNodeID,
    "-relay", relayAddress, "-listen 127.0.0.1:18080",
    "-key /artifacts/.private/identity.key -ca http://ca:9100",
    "> /artifacts/.private/mixed-tunclient.log 2>&1",
  ].join(" ")]);
  const probeNodeID = await waitForNodeID(logPath, 20_000, config);
  const probeBundle = await readPrivateJSON(path.join(config.privateRoot, "mixed-path-probe", "billing-key.json"));
  validateBillingBundle(probeBundle);
  await ensureCredit(config, probeNodeID, nodeAuthorizationID(probeNodeID, probeBundle.key_id));
  await waitForFilePattern(
    logPath,
    /已建立隧道连接/,
    60_000,
    config,
    "mixed_path_probe_connect_timeout",
  );
  await waitForFilePattern(
    logPath,
    /本地监听:/,
    10_000,
    config,
    "mixed_path_probe_listen_timeout",
  );
}

async function probeMixedPath(config, state) {
  const observedAt = new Date().toISOString();
  try {
    const expected = (await compose(config, ["exec", "-T", "malicious-natserver", "curl", "-fsS", "--max-time", "10",
      "http://127.0.0.1:8080/checksum?size_mb=1"])).stdout.trim();
    if (!/^[0-9a-f]{64}$/.test(expected)) throw codedError("mixed_path_expected_hash_invalid");
    const result = (await compose(config, ["exec", "-T", "mixed-path-probe", "sh", "-lc",
      "file=/tmp/mixed-path-probe.bin; rm -f \"$file\"; curl -fsS --max-time 60 -o \"$file\" 'http://127.0.0.1:18080/file?size_mb=1'; bytes=$(stat -c %s \"$file\"); digest=$(sha256sum \"$file\" | awk '{print $1}'); rm -f \"$file\"; printf '%s\\t%s\\n' \"$bytes\" \"$digest\""])).stdout.trim();
    const [bytes, digest] = result.split("\t");
    if (bytes !== "1048576" || digest !== expected) throw codedError("mixed_path_payload_mismatch");
    state.probe.status = "PASS";
    state.probe.successes += 1;
    state.probe.consecutiveFailures = 0;
    state.probe.bytes = 1048576;
    state.probe.sha256Verified = true;
  } catch (error) {
    state.probe.status = "FAIL";
    state.probe.failures += 1;
    state.probe.consecutiveFailures += 1;
    state.probe.bytes = 0;
    state.probe.sha256Verified = false;
    state.probe.errorCode = safeCode(error?.code || "mixed_path_probe_failed");
  }
  state.probe.observedAt = observedAt;
  if (state.probe.status === "PASS") state.probe.errorCode = "";
}

async function actorEvents(config) {
  const [natserver, relay] = await Promise.all([
    readJSON(path.join(config.privateRoot, "malicious-natserver", "status.json")),
    readJSON(path.join(config.privateRoot, "malicious-relay", "status.json")),
  ]);
  return {
    natserver: Array.isArray(natserver?.recent) ? natserver.recent : [],
    relay: Array.isArray(relay?.recent) ? relay.recent : [],
  };
}

async function waitForProvisionedIdentity(config, service, role) {
  const deadline = Date.now() + 60_000;
  const stateDirectory = path.join(config.privateRoot, service);
  while (Date.now() < deadline) {
    throwIfStopping(config);
    const [enrollment, certificate] = await Promise.all([
      readJSON(path.join(stateDirectory, "enrollment.json")),
      readJSON(path.join(stateDirectory, "certificate.json")),
    ]);
    if (enrollment?.role === role && /^[0-9a-f]{64}$/.test(String(enrollment.nodeID ?? ""))
      && certificate?.cert?.subject_node_id === enrollment.nodeID && certificate?.cert?.role === role) {
      return enrollment.nodeID;
    }
    await delay(250);
  }
  throw codedError("mixed_path_identity_unavailable");
}

async function ensureCredit(config, nodeID, authorizationID) {
  if (!/^[0-9a-f]{64}$/.test(nodeID) || !/^[0-9a-f]{64}$/.test(authorizationID)) {
    throw codedError("mixed_path_balance_identity_invalid");
  }
  const desiredBalance = 64 * 1024 * 1024 * 1024;
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    throwIfStopping(config);
    const target = new URL("/balance", config.caBaseURL);
    target.searchParams.set("node", nodeID);
    target.searchParams.set("authorization_id", authorizationID);
    const response = await fetch(target, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
    if (response.ok) {
      const body = await response.json();
      if (!Number.isSafeInteger(body.balance) || body.balance < 0) {
        throw codedError("mixed_path_balance_invalid");
      }
      if (body.balance < desiredBalance) throw codedError("mixed_path_authorized_balance_insufficient");
      return;
    }
    if (![401, 404].includes(response.status)) throw codedError("mixed_path_balance_unavailable");
    await delay(250);
  }
  throw codedError("mixed_path_authorized_balance_unavailable");
}

async function stopProcess(config, service, processName) {
  if (!/^[a-z0-9-]+$/.test(service) || !/^[a-z0-9-]+$/.test(processName)) throw codedError("mixed_path_process_invalid");
  try {
    await compose(config, ["exec", "-T", service, "sh", "-lc",
      `pkill -TERM -x '${processName}' >/dev/null 2>&1 || true; attempt=0; while pgrep -x '${processName}' >/dev/null 2>&1 && [ \"$attempt\" -lt 30 ]; do sleep 0.1; attempt=$((attempt + 1)); done; pkill -KILL -x '${processName}' >/dev/null 2>&1 || true; ! pgrep -x '${processName}' >/dev/null 2>&1`]);
    return true;
  } catch {
    return false;
  }
}

async function waitForHTTP(config, service, url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    throwIfStopping(config);
    try {
      await compose(config, ["exec", "-T", service, "curl", "-fsS", "--max-time", "2", url]);
      return;
    } catch {
      await delay(250);
    }
  }
  throw codedError("mixed_path_http_start_timeout");
}

export async function waitForFilePattern(
  filename,
  pattern,
  timeoutMs,
  config,
  timeoutCode = "mixed_path_process_start_timeout",
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    throwIfStopping(config);
    const value = await readText(filename);
    if (pattern.test(value)) return value;
    await delay(250);
  }
  throw codedError(timeoutCode);
}

async function waitForHostedNode(config, relay, nodeID, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  const pattern = new RegExp(`(?:新建 StreamGroup|注册代次切换并清理旧 StreamGroup): nodeId=${nodeID.slice(0, 16)}`);
  while (Date.now() < deadline) {
    throwIfStopping(config);
    try {
      const output = (await compose(config, ["logs", "--no-color", "--tail", "300", relay])).stdout;
      if (pattern.test(output)) return;
    } catch {}
    await delay(250);
  }
  throw codedError("mixed_path_natserver_registration_timeout");
}

async function waitForNodeID(filename, timeoutMs, config) {
  const contents = await waitForFilePattern(
    filename,
    /本节点 ID:\s*[0-9a-f]{64}/,
    timeoutMs,
    config,
    "mixed_path_probe_identity_timeout",
  );
  const match = contents.match(/本节点 ID:\s*([0-9a-f]{64})/);
  if (!match) throw codedError("mixed_path_probe_identity_invalid");
  return match[1];
}

function throwIfStopping(config) {
  if (config?.shouldStop?.()) throw codedError("mixed_path_stop_requested");
}

async function compose(config, args) {
  return execFileAsync("docker", ["compose", "--project-name", config.project, "--file", config.composeFile, ...args], {
    timeout: 90_000,
    maxBuffer: 8 * 1024 * 1024,
  });
}

function configuration() {
  const runDir = path.resolve(process.env.RUN_DIR ?? "");
  const privateRoot = path.resolve(process.env.PRIVATE_RUNTIME_DIR ?? "");
  const composeFile = path.resolve(process.env.COMPOSE_FILE ?? "");
  const project = process.env.COMPOSE_PROJECT ?? "";
  const caBaseURL = new URL(process.env.CA_BASE_URL ?? "http://127.0.0.1:19100");
  const watchPid = boundedInteger(process.env.WATCH_PID, 0, 0, Number.MAX_SAFE_INTEGER);
  const probeIntervalMs = boundedInteger(process.env.PROBE_INTERVAL_MS, 15_000, 1000, 300_000);
  if (!process.env.RUN_DIR || runDir === path.parse(runDir).root
    || !process.env.PRIVATE_RUNTIME_DIR || privateRoot === path.parse(privateRoot).root
    || !process.env.COMPOSE_FILE || composeFile === path.parse(composeFile).root
    || !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(project)
    || caBaseURL.protocol !== "http:" || !isLoopback(caBaseURL.hostname)) {
    throw codedError("mixed_path_configuration_invalid");
  }
  return {
    runDir,
    privateRoot,
    composeFile,
    project,
    caBaseURL,
    watchPid,
    probeIntervalMs,
  };
}

function initialState() {
  return {
    schemaVersion: 1,
    status: "STARTING",
    heartbeatAt: new Date().toISOString(),
    stopReason: "",
    errorCode: "",
    initialPathVerified: false,
    generation: 0,
    observedTriggers: 0,
    drainComplete: false,
    drainCompletedAt: "",
    normalPartitions: {
      control_partition_a: ["relay03", "relay04", "relay05"],
      control_partition_b: ["relay06", "relay07"],
    },
    attachments: {
      maliciousNatserver: {
        node: "malicious-natserver",
        role: "malicious-natserver",
        currentRelay: "relay03",
        previousRelay: "",
        attachmentType: "registered_to_normal_relay",
        normalPartition: "control_partition_a",
        basis: "live_relay_registration",
        generation: 0,
        identityGeneration: 0,
        running: false,
        switchedAt: "",
        lastScenario: "",
      },
      normalProbe: {
        node: "mixed-path-probe",
        role: "natclient",
        currentRelay: "malicious-relay",
        previousRelay: "",
        attachmentType: "connected_to_malicious_relay",
        normalPartition: "",
        basis: "live_tunnel_registration",
        generation: 0,
        running: false,
        switchedAt: "",
        lastScenario: "",
      },
      maliciousRelay: {
        node: "malicious-relay",
        role: "malicious-relay",
        currentRelay: "relay03",
        previousRelay: "",
        attachmentType: "control_peer_with_normal_relay",
        normalPartition: "control_partition_a",
        basis: "live_control_hello",
        peerDirection: "normal_relay_to_malicious_relay",
        generation: 0,
        running: false,
        switchedAt: "",
        lastScenario: "",
      },
    },
    path: {
      state: "starting",
      nodes: ["mixed-path-probe", "malicious-relay", "relay03", "malicious-natserver"],
      transport: "real_p2p_tunnel_http_payload",
      basis: "live_process_attachment_and_sha256_payload_probe",
      kind: "normal_partition_mixed_adversary",
      normalRelays: ["relay03"],
      normalPartitions: ["control_partition_a"],
      containsNormalPartition: true,
      containsMaliciousNode: true,
    },
    probe: {
      status: "PENDING",
      observedAt: "",
      successes: 0,
      failures: 0,
      consecutiveFailures: 0,
      bytes: 0,
      sha256Verified: false,
      errorCode: "",
    },
    lastTrigger: null,
    migrations: [],
    networkCoverage: Object.entries(scenariosByActor).flatMap(([actor, scenarios]) => (
      scenarios.map((scenario) => ({ scenario, actor, executed: 0, contained: 0, violations: 0 }))
    )),
    containment: {
      status: "PENDING",
      verifiedMigrations: 0,
      lastScenario: "",
      lastActor: "",
      lastAction: "",
      verifiedAt: "",
    },
  };
}

function recordNetworkContainment(state, migration) {
  const entry = state.networkCoverage.find((item) => item.scenario === migration.trigger.scenario
    && item.actor === migration.trigger.actor);
  if (!entry) throw codedError("mixed_path_scenario_invalid");
  entry.executed += 1;
  if (migration.containmentVerified) entry.contained += 1;
  else entry.violations += 1;
}

function refreshPathEvidence(state) {
  const normalPathRelays = state.path.nodes.filter((node) => normalRelays.includes(node));
  const attachmentRelays = [
    state.attachments.maliciousNatserver.currentRelay,
    state.attachments.maliciousRelay.currentRelay,
  ].filter((relay) => normalRelays.includes(relay));
  state.path.normalRelays = [...new Set([...normalPathRelays, ...attachmentRelays])];
  state.path.normalPartitions = [...new Set(state.path.normalRelays.map(normalPartitionForRelay).filter(Boolean))];
  state.path.containsNormalPartition = state.path.normalPartitions.length > 0;
  state.path.containsMaliciousNode = state.path.nodes.some((node) => node === "malicious-natserver" || node === "malicious-relay");
}

async function writeJSONAtomic(filename, value) {
  const temporary = `${filename}.tmp-${process.pid}`;
  await fs.writeFile(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await fs.rename(temporary, filename);
}

async function fileExists(filename) {
  try {
    await fs.access(filename);
    return true;
  } catch {
    return false;
  }
}

async function interruptibleDelay(config, milliseconds) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    throwIfStopping(config);
    await delay(Math.min(100, deadline - Date.now()));
  }
}

async function writeTextAtomic(filename, value) {
  const temporary = `${filename}.tmp-${process.pid}`;
  await fs.writeFile(temporary, value, { mode: 0o600 });
  await fs.rename(temporary, filename);
}

async function writeStatusAtomic(filename, state) {
  const heartbeatEpoch = Math.floor(Date.parse(state.heartbeatAt) / 1000);
  const maliciousNatserverRelay = state.attachments?.maliciousNatserver?.currentRelay ?? "";
  const maliciousRelayPeer = state.attachments?.maliciousRelay?.currentRelay ?? "";
  const attachmentsVerified = Boolean(normalPartitionForRelay(maliciousNatserverRelay))
    && Boolean(normalPartitionForRelay(maliciousRelayPeer))
    && state.attachments?.maliciousNatserver?.running === true
    && state.attachments?.maliciousRelay?.running === true;
  const latestTwoMigrationsVerified = state.migrations.length >= 2
    && state.migrations.slice(0, 2).every((migration) => migration.triggerContained === true
      && migration.isolationVerified === true
      && migration.probePassed === true
      && migration.containmentVerified === true
      && Boolean(normalPartitionForRelay(migration.currentRelay)));
  const networkEventCount = state.networkCoverage.reduce((sum, item) => sum + item.executed, 0);
  const networkViolationCount = state.networkCoverage.reduce((sum, item) => sum + item.violations, 0);
  const networkScenarioCoverage = state.networkCoverage.filter((item) => item.executed > 0
    && item.contained === item.executed && item.violations === 0).length;
  const requiredNetworkScenarios = Object.values(scenariosByActor).reduce((sum, scenarios) => sum + scenarios.length, 0);
  const contents = [
    "schema_version=1",
    `status=${state.status}`,
    `error_code=${safeCode(state.errorCode)}`,
    `heartbeat_epoch=${heartbeatEpoch}`,
    `initial_path_verified=${state.initialPathVerified ? 1 : 0}`,
    `generation=${state.generation}`,
    `observed_triggers=${state.observedTriggers}`,
    `drain_complete=${state.drainComplete ? 1 : 0}`,
    `probe_status=${state.probe.status}`,
    `probe_failures=${state.probe.failures}`,
    `probe_consecutive_failures=${state.probe.consecutiveFailures}`,
    `migration_count=${state.migrations.length}`,
    `verified_migration_count=${state.containment.verifiedMigrations}`,
    `latest_two_migrations_verified=${latestTwoMigrationsVerified ? 1 : 0}`,
    `network_event_count=${networkEventCount}`,
    `network_violation_count=${networkViolationCount}`,
    `network_scenario_coverage=${networkScenarioCoverage}`,
    `required_network_scenarios=${requiredNetworkScenarios}`,
    `malicious_natserver_relay=${maliciousNatserverRelay}`,
    `malicious_natserver_partition=${normalPartitionForRelay(maliciousNatserverRelay)}`,
    `malicious_relay_peer=${maliciousRelayPeer}`,
    `malicious_relay_partition=${normalPartitionForRelay(maliciousRelayPeer)}`,
    `normal_partition_attachment_verified=${attachmentsVerified ? 1 : 0}`,
    `path_contains_normal_partition=${state.path?.containsNormalPartition === true ? 1 : 0}`,
    `path_contains_malicious_node=${state.path?.containsMaliciousNode === true ? 1 : 0}`,
    "",
  ].join("\n");
  const temporary = `${filename}.tmp-${process.pid}`;
  await fs.writeFile(temporary, contents, { mode: 0o600 });
  await fs.rename(temporary, filename);
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

async function readPrivateJSON(filename) {
  const handle = await fs.open(filename, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size <= 0 || stat.size > 65536) {
      throw codedError("mixed_path_private_json_invalid");
    }
    return JSON.parse(await handle.readFile("utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) throw codedError("mixed_path_private_json_invalid");
    throw error;
  } finally {
    await handle.close();
  }
}

function validateBillingBundle(bundle) {
  if (!bundle || bundle.version !== 1 || bundle.algorithm !== "ECDSA_P256_SHA256"
    || bundle.registration_status !== "active" || !/^[0-9a-f]{64}$/.test(String(bundle.key_id ?? ""))
    || !/^04[0-9a-f]{128}$/.test(String(bundle.public_key_hex ?? ""))
    || !bundle.private_key_jwk?.d) {
    throw codedError("mixed_path_billing_bundle_invalid");
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey({ key: bundle.private_key_jwk, format: "jwk" });
  } catch {
    throw codedError("mixed_path_billing_private_key_invalid");
  }
  const publicKey = publicKeyHex(privateKey);
  const keyID = crypto.createHash("sha256").update(Buffer.from(publicKey, "hex")).digest("hex");
  if (publicKey !== bundle.public_key_hex || keyID !== bundle.key_id) {
    throw codedError("mixed_path_billing_key_binding_invalid");
  }
  return privateKey;
}

function privateKeyFromScalar(privateScalar) {
  const keyPair = crypto.createECDH("prime256v1");
  try {
    keyPair.setPrivateKey(privateScalar);
  } catch {
    throw codedError("mixed_path_identity_private_key_invalid");
  }
  const publicKey = keyPair.getPublicKey(undefined, "uncompressed");
  return crypto.createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: publicKey.subarray(1, 33).toString("base64url"),
      y: publicKey.subarray(33, 65).toString("base64url"),
      d: privateScalar.toString("base64url"),
    },
    format: "jwk",
  });
}

function publicKeyHex(privateKey) {
  const publicJWK = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  return Buffer.concat([
    Buffer.from([4]),
    Buffer.from(publicJWK.x, "base64url"),
    Buffer.from(publicJWK.y, "base64url"),
  ]).toString("hex");
}

function nodeAuthorizationCanonical(request) {
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

function signCanonical(canonical, privateKey) {
  return crypto.sign("sha256", Buffer.from(canonical), {
    key: privateKey,
    dsaEncoding: "der",
  }).toString("base64url");
}

function nodeAuthorizationID(nodeID, billingKeyID) {
  return crypto.createHash("sha256")
    .update(`CA-NODE-AUTHORIZATION-ID-V1\0${nodeID}\0${billingKeyID}`)
    .digest("hex");
}

function validBillingCertificate(certificate, identity, bundle, expectedAuthorizationID) {
  return certificate && typeof certificate === "object"
    && certificate.cert?.subject_node_id === identity.nodeID
    && certificate.cert?.subject_pubkey === identity.publicKey
    && certificate.cert?.role === "server"
    && certificate.cert?.billing_key_id === bundle.key_id
    && certificate.cert?.billing_public_key === bundle.public_key_hex
    && certificate.cert?.authorization_id === expectedAuthorizationID
    && Number.isSafeInteger(certificate.cert?.not_before)
    && Number.isSafeInteger(certificate.cert?.not_after)
    && certificate.cert.not_after > certificate.cert.not_before
    && typeof certificate.sig === "string"
    && /^[0-9a-f]{16,256}$/.test(certificate.sig);
}

async function readText(filename) {
  try {
    return await fs.readFile(filename, "utf8");
  } catch {
    return "";
  }
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function validTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : "";
}

function assertNormalRelay(relay) {
  if (!normalRelays.includes(relay)) throw codedError("mixed_path_relay_invalid");
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

function isLoopback(hostname) {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost" || normalized === "::1" || normalized.startsWith("127.");
}

function safeCode(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 64);
}

function codedError(code) {
  return Object.assign(new Error(code), { code });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function failAndExit(error) {
  const runDir = path.resolve(process.env.RUN_DIR ?? ".");
  const failure = {
    schemaVersion: 1,
    status: "FAILED",
    heartbeatAt: new Date().toISOString(),
    errorCode: safeCode(error?.code || "mixed_path_controller_failed"),
  };
  if (runDir !== path.parse(runDir).root && error?.evidencePublished !== true) {
    await writeJSONAtomic(path.join(runDir, "mixed-adversary-path.json"), failure).catch(() => {});
    await fs.writeFile(path.join(runDir, "mixed-adversary-path.status"), [
      "schema_version=1",
      "status=FAILED",
      `heartbeat_epoch=${Math.floor(Date.now() / 1000)}`,
      "probe_status=FAIL",
      "probe_failures=1",
      "probe_consecutive_failures=1",
      "migration_count=0",
      "verified_migration_count=0",
      "latest_two_migrations_verified=0",
      "malicious_natserver_relay=",
      "malicious_natserver_partition=",
      "malicious_relay_peer=",
      "malicious_relay_partition=",
      "normal_partition_attachment_verified=0",
      "path_contains_normal_partition=0",
      "path_contains_malicious_node=0",
      "",
    ].join("\n"), { mode: 0o600 }).catch(() => {});
  }
  process.stderr.write(`mixed adversary path failed: ${failure.errorCode}\n`);
  process.exitCode = 1;
}
