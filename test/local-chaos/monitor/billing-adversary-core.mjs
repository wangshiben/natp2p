import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";

import { openDurableWaitSubmit } from "./billing-adversary-outbox.mjs";

const mebibyte = 1 << 20;
const fixtureCreditBytes = 16 * 1024 * mebibyte;
const authorizedThroughBytes = 0x7fffffffffffffffn;
const p256Order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const p256HalfOrder = p256Order >> 1n;
const voucherBodyDomain = Buffer.from("BNFS/USAGE-VOUCHER-BODY/V1");
const mutualVoucherDomain = Buffer.from("BNFS/MUTUAL-VOUCHER/V1");
const mutualWireDomain = Buffer.from("BNFS/MUTUAL-VOUCHER-WIRE/V1");
const payerSignatureDomain = Buffer.from("BNFS/NAT-VOUCHER/V1");
const relaySignatureDomain = Buffer.from("BNFS/RELAY-VOUCHER/V1");
const zeroIdentifier = Buffer.alloc(32);
const policyDigest = currentPolicyDigest();
const fixturePromises = new WeakMap();

export const attackScenarios = Object.freeze([
  "relay_usage_inflation",
  "relay_request_replay",
  "relay_fee_override",
  "relay_window_overrun",
  "nat_stale_watermark",
  "nat_same_sequence_fork",
  "nat_signature_refusal",
  "relay_voucher_tamper",
  "index_disconnect_backlog_recovery",
]);

const scenarioActors = Object.freeze({
  relay_usage_inflation: "relay",
  relay_request_replay: "relay",
  relay_fee_override: "relay",
  relay_window_overrun: "relay",
  nat_stale_watermark: "natserver",
  nat_same_sequence_fork: "natserver",
  nat_signature_refusal: "natserver",
  relay_voucher_tamper: "relay",
  index_disconnect_backlog_recovery: "network",
});

const actorInstances = Object.freeze({
  relay: "simulated-malicious-relay",
  natserver: "simulated-malicious-natserver",
  network: "simulated-index-link",
});

export function createAPIClient(baseURL, timeoutMs = 3000, credentials = {}) {
  const base = new URL(baseURL);
  if (!isLoopbackHost(base.hostname)) {
    throw new Error("billing adversary target must be loopback");
  }
  if (!/^https?:$/.test(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new Error("billing adversary target must be an HTTP loopback URL without credentials or query data");
  }
  const authorization = normalizeCredentials(credentials);
  return {
    get: (pathname) => requestJSON(base, "GET", pathname, null, timeoutMs, ""),
    post: (pathname, body) => requestJSON(
      base,
      "POST",
      pathname,
      body,
      timeoutMs,
      authorizationFor(authorization, pathname, body),
    ),
  };
}

export async function runAttackCycle(client, cycleNonce, context = {}) {
  const events = [];
  for (let index = 0; index < attackScenarios.length; index += 1) {
    events.push(await runAttackScenario(client, attackScenarios[index], `${cycleNonce}-${index + 1}`, context));
  }
  return events;
}

export async function runAttackScenario(client, scenario, nonce, context = {}) {
  if (!attackScenarios.includes(scenario)) {
    throw new Error("unknown billing adversary scenario");
  }
  const startedAt = new Date().toISOString();
  let componentProbeCovered = false;
  let componentProbePassed = false;
  try {
    const componentResult = await runComponentProbe(context, scenario, nonce);
    componentProbeCovered = true;
    componentProbePassed = componentResult.status === "PASS";
    const fixture = await fixtureFor(client);
    let result;
    switch (scenario) {
      case "relay_usage_inflation":
        result = await relayUsageInflation(client, fixture, nonce);
        break;
      case "relay_request_replay":
        result = await relayRequestReplay(client, fixture, nonce);
        break;
      case "relay_fee_override":
        result = await relayFeeOverride(client, fixture, nonce);
        break;
      case "relay_window_overrun":
        result = await relayWindowOverrun(client, fixture, nonce);
        break;
      case "nat_stale_watermark":
        result = await natStaleWatermark(client, fixture, nonce);
        break;
      case "nat_same_sequence_fork":
        result = await natSameSequenceFork(client, fixture, nonce);
        break;
      case "nat_signature_refusal":
        result = await natSignatureRefusal(client, fixture, nonce);
        break;
      case "relay_voucher_tamper":
        result = await relayVoucherTamper(client, fixture, nonce);
        break;
      case "index_disconnect_backlog_recovery":
        result = await backlogRecovery(client, fixture, nonce, context);
        break;
    }
    if (!componentProbePassed) {
      result = {
        ...result,
        passed: false,
        verdict: "VIOLATION",
        failureCode: `component_probe_${safeCode(componentResult.failureCode || "failed")}`,
        defense: "",
        depth: "production_go_component_probe",
      };
    }
    return publicEvent({
      scenario,
      startedAt,
      ...result,
      componentProbeCovered,
      componentProbePassed,
    });
  } catch (error) {
    return publicEvent({
      scenario,
      startedAt,
      passed: false,
      verdict: "HARNESS_ERROR",
      failureCode: safeCode(error?.code || "attack_probe_error"),
      defense: "",
      requestCount: 0,
      statuses: [],
      balanceDelta: 0,
      stateChanged: false,
      depth: String(error?.code ?? "").startsWith("component_probe_")
        ? "production_go_component_probe"
        : "voucher_api",
      componentProbeCovered,
      componentProbePassed,
    });
  }
}

async function runComponentProbe(context, scenario, nonce) {
  if (!context?.componentProbe || typeof context.componentProbe.run !== "function") {
    throw codedError("component_probe_missing");
  }
  const result = await context.componentProbe.run(scenario, nonce);
  if (!result || result.scenario !== scenario || !["PASS", "FAIL"].includes(result.status)
    || typeof result.failureCode !== "string") {
    throw codedError("component_probe_output_invalid");
  }
  return result;
}

async function fixtureFor(client) {
  let fixturePromise = fixturePromises.get(client);
  if (!fixturePromise) {
    fixturePromise = initializeFixture(client);
    fixturePromises.set(client, fixturePromise);
  }
  return fixturePromise;
}

async function initializeFixture(client) {
  const payer = createIdentity();
  const relay = createIdentity();
  const payerIssue = await client.post("/issue", {
    subject_pubkey: payer.publicHex,
    role: "server",
    ttl_seconds: 86400,
  });
  const relayIssue = await client.post("/issue", {
    subject_pubkey: relay.publicHex,
    role: "relay",
    ttl_seconds: 86400,
  });
  if (payerIssue.status !== 200 || !validCertificate(payerIssue.body?.signed_cert, payer, "server")
    || relayIssue.status !== 200 || !validCertificate(relayIssue.body?.signed_cert, relay, "relay")) {
    throw codedError("fixture_identity_issue_failed");
  }
  const credit = await client.post("/credit", { node_id: payer.nodeIDHex, add_bytes: fixtureCreditBytes });
  if (credit.status !== 200 || !Number.isSafeInteger(Number(credit.body?.balance))) {
    throw codedError("fixture_credit_failed");
  }
  return {
    payer: { ...payer, certificate: payerIssue.body.signed_cert },
    relay: { ...relay, certificate: relayIssue.body.signed_cert },
  };
}

async function relayUsageInflation(client, fixture, nonce) {
  const honestBody = voucherBody(fixture, nonce, { cumulative: 512 * 1024 });
  const honestVoucher = signVoucher(fixture, honestBody);
  const inflatedBody = cloneBody(honestBody, {
    cumulative: honestBody.cumulative + 64 * 1024,
    lastRecordID: identifier(`${nonce}:inflated-record`),
    recordSetDigest: identifier(`${nonce}:inflated-root`),
  });
  const maliciousVoucher = signVoucher(fixture, inflatedBody, {
    payerSignature: honestVoucher.payerSignature,
  });
  return rejectedMutation(client, fixture, maliciousVoucher, "usage_inflation_rejected");
}

async function relayRequestReplay(client, fixture, nonce) {
  const voucher = signVoucher(fixture, voucherBody(fixture, nonce, { cumulative: mebibyte }));
  const before = await balances(client, fixture);
  const first = await submitVoucher(client, fixture, voucher);
  const afterFirst = await balances(client, fixture);
  if (!before.available || !afterFirst.available) {
    return failedVerdict("balance_probe_unavailable", [first], 0, false, "voucher_api_replay");
  }
  if (first.status !== 200 || Number(first.body?.delta) !== mebibyte) {
    return failedVerdict("valid_voucher_rejected", [first], balanceDifference(before, afterFirst).net, false, "voucher_api_replay");
  }

  const replay = await submitVoucher(client, fixture, voucher);
  const afterReplay = await balances(client, fixture);
  if (!afterReplay.available) {
    return failedVerdict("balance_probe_unavailable", [first, replay], 0, false, "voucher_api_replay");
  }
  const unauthorized = balanceDifference(afterFirst, afterReplay);
  if (replay.status !== 200 || Number(replay.body?.delta) !== 0 || replay.body?.replayed !== true) {
    return failedVerdict("voucher_replay_not_idempotent", [first, replay], unauthorized.net, unauthorized.changed, "voucher_api_replay");
  }
  if (unauthorized.changed) {
    return failedVerdict("replay_changed_balance", [first, replay], unauthorized.net, true, "voucher_api_replay");
  }
  return containedVerdict("idempotent_replay", [first, replay], "voucher_api_replay");
}

async function relayFeeOverride(client, fixture, nonce) {
  const honestBody = voucherBody(fixture, nonce, { cumulative: 512 * 1024 });
  const honestVoucher = signVoucher(fixture, honestBody);
  const alteredPolicy = Buffer.from(policyDigest);
  alteredPolicy[0] ^= 1;
  const overriddenBody = cloneBody(honestBody, { policyDigest: alteredPolicy });
  const maliciousVoucher = signVoucher(fixture, overriddenBody, {
    payerSignature: honestVoucher.payerSignature,
  });
  const before = await balances(client, fixture);
  const settle = await client.post("/settle", {
    node_id: fixture.payer.nodeIDHex,
    relay_node_id: fixture.relay.nodeIDHex,
    used_delta: mebibyte,
  });
  const reserve = await client.post("/reserve", {
    conn_id: `synthetic-${safeCode(nonce)}`,
    client_node_id: fixture.payer.nodeIDHex,
    server_node_id: fixture.payer.nodeIDHex,
    relay_node_id: fixture.relay.nodeIDHex,
    client_fee: mebibyte,
    server_fee: mebibyte,
  });
  const voucherResponse = await submitVoucher(client, fixture, maliciousVoucher);
  const after = await balances(client, fixture);
  const responses = [settle, reserve, voucherResponse];
  if (!before.available || !after.available) {
    return failedVerdict("balance_probe_unavailable", responses, 0, false, "fee_and_legacy_api_rejection");
  }
  const difference = balanceDifference(before, after);
  if (difference.changed) {
    return failedVerdict("unauthorized_balance_change", responses, difference.net, true, "fee_and_legacy_api_rejection");
  }
  if (settle.status !== 410 || reserve.status !== 410) {
    return failedVerdict("legacy_billing_endpoint_not_retired", responses, 0, false, "fee_and_legacy_api_rejection");
  }
  if (voucherResponse.status >= 200 && voucherResponse.status < 300) {
    return failedVerdict("malicious_voucher_accepted", responses, difference.net, difference.changed, "fee_and_legacy_api_rejection");
  }
  if (!explicitProtocolRejection(voucherResponse)) {
    return failedVerdict("voucher_api_unavailable", responses, difference.net, difference.changed, "fee_and_legacy_api_rejection");
  }
  return containedVerdict("fixed_policy_and_legacy_endpoints_rejected", responses, "fee_and_legacy_api_rejection");
}

async function relayWindowOverrun(client, fixture, nonce) {
  const overrun = signVoucher(fixture, voucherBody(fixture, nonce, {
    cumulative: mebibyte + 1,
  }));
  return rejectedMutation(client, fixture, overrun, "one_mib_window_enforced");
}

async function natStaleWatermark(client, fixture, nonce) {
  const first = signVoucher(fixture, voucherBody(fixture, nonce, { cumulative: 768 * 1024 }));
  const firstResponse = await submitVoucher(client, fixture, first);
  if (firstResponse.status !== 200 || Number(firstResponse.body?.delta) !== 768 * 1024) {
    return failedVerdict("valid_voucher_rejected", [firstResponse], 0, false, "voucher_chain_validation");
  }
  const staleBody = voucherBody(fixture, nonce, {
    sequence: 2,
    previousID: first.id,
    cumulative: 768 * 1024,
  });
  const stale = signVoucher(fixture, staleBody);
  return rejectedMutation(client, fixture, stale, "stale_watermark_rejected", [firstResponse], "voucher_chain_validation");
}

async function natSameSequenceFork(client, fixture, nonce) {
  const accepted = signVoucher(fixture, voucherBody(fixture, nonce, { cumulative: 512 * 1024 }));
  const acceptedResponse = await submitVoucher(client, fixture, accepted);
  if (acceptedResponse.status !== 200 || Number(acceptedResponse.body?.delta) !== 512 * 1024) {
    return failedVerdict("valid_voucher_rejected", [acceptedResponse], 0, false, "voucher_fork_freeze");
  }
  const fork = signVoucher(fixture, voucherBody(fixture, nonce, {
    cumulative: 640 * 1024,
    recordLabel: "fork",
  }));
  const before = await balances(client, fixture);
  const response = await submitVoucher(client, fixture, fork);
  const after = await balances(client, fixture);
  if (!before.available || !after.available) {
    return failedVerdict("balance_probe_unavailable", [acceptedResponse, response], 0, false, "voucher_fork_freeze");
  }
  const difference = balanceDifference(before, after);
  if (response.status !== 409 || response.body?.frozen !== true) {
    return failedVerdict("same_sequence_fork_not_frozen", [acceptedResponse, response], difference.net, difference.changed, "voucher_fork_freeze");
  }
  if (difference.changed) {
    return failedVerdict("fork_changed_balance", [acceptedResponse, response], difference.net, true, "voucher_fork_freeze");
  }
  return containedVerdict("channel_frozen_on_fork", [acceptedResponse, response], "voucher_fork_freeze");
}

async function natSignatureRefusal(client, fixture, nonce) {
  const body = voucherBody(fixture, nonce, { cumulative: 512 * 1024 });
  const relaySignature = signBody(body, fixture.relay.privateKey, relaySignatureDomain);
  const voucher = assembleVoucher(body, relaySignature, relaySignature);
  return rejectedMutation(client, fixture, voucher, "payer_signature_required");
}

async function relayVoucherTamper(client, fixture, nonce) {
  const honestBody = voucherBody(fixture, nonce, { cumulative: 512 * 1024 });
  const honestVoucher = signVoucher(fixture, honestBody);
  const tamperedBody = cloneBody(honestBody, {
    lastRecordID: identifier(`${nonce}:tampered-record`),
    recordSetDigest: identifier(`${nonce}:tampered-root`),
  });
  const maliciousVoucher = signVoucher(fixture, tamperedBody, {
    payerSignature: honestVoucher.payerSignature,
  });
  return rejectedMutation(client, fixture, maliciousVoucher, "signed_record_root_protected");
}

async function backlogRecovery(client, fixture, nonce, context) {
  if (typeof context.waitSubmitPath !== "string" || context.waitSubmitPath.length === 0) {
    throw codedError("waitsubmit_path_missing");
  }
  let queue = await openDurableWaitSubmit(context.waitSubmitPath);
  while (queue.depth > 0) {
    const pending = queue.peek();
    const response = await submitRequest(client, pending.request);
    if (response.status !== 200) throw codedError("waitsubmit_previous_recovery_failed");
    await queue.removeHead(pending.order);
  }
  const vouchers = [];
  let previousID = zeroIdentifier;
  for (let sequence = 1; sequence <= 3; sequence += 1) {
    const voucher = signVoucher(fixture, voucherBody(fixture, nonce, {
      sequence,
      previousID,
      cumulative: sequence * mebibyte,
    }));
    vouchers.push(voucher);
    previousID = voucher.id;
  }

  const disconnectedClient = createAPIClient("http://127.0.0.1:1", 250);
  const disconnected = [];
  const queuedRequests = vouchers.map((voucher) => voucherRequest(fixture, voucher));
  for (const request of queuedRequests) {
    const response = await submitRequest(disconnectedClient, request);
    disconnected.push(response);
    if (response.status !== 0) {
      return failedVerdict("disconnect_fixture_not_isolated", disconnected, 0, false, "waitsubmit_fifo_recovery");
    }
    await queue.enqueue(request);
  }
  if (!disconnected.every((response) => response.status === 0)) {
    return failedVerdict("disconnect_fixture_not_isolated", disconnected, 0, false, "waitsubmit_fifo_recovery");
  }

  const revisionAfterEnqueue = queue.revision;
  queue = await openDurableWaitSubmit(context.waitSubmitPath);
  const restored = queue.snapshot();
  if (restored.entries.length !== queuedRequests.length
    || restored.entries.some((entry, index) => entry.request.canonical_voucher !== queuedRequests[index].canonical_voucher)) {
    return failedVerdict("waitsubmit_restart_restore_failed", disconnected, 0, false, "waitsubmit_fifo_recovery");
  }

  const before = await balances(client, fixture);
  const recovered = [];
  while (queue.depth > 0) {
    const pending = queue.peek();
    const response = await submitRequest(client, pending.request);
    recovered.push(response);
    if (response.status !== 200) break;
    await queue.removeHead(pending.order);
  }
  const afterRecovery = await balances(client, fixture);
  if (!before.available || !afterRecovery.available) {
    return failedVerdict("balance_probe_unavailable", [...disconnected, ...recovered], 0, false, "waitsubmit_fifo_recovery");
  }
  const recoveredDifference = balanceDifference(before, afterRecovery);
  if (!recovered.every((response) => response.status === 200 && Number(response.body?.delta) === mebibyte)) {
    return failedVerdict("waitsubmit_fifo_recovery_failed", [...disconnected, ...recovered], recoveredDifference.net, false, "waitsubmit_fifo_recovery");
  }
  const expectedGross = queuedRequests.length * mebibyte;
  const expectedRelayCredit = policyRelayTotal(expectedGross);
  if (recoveredDifference.payer !== -expectedGross || recoveredDifference.relay !== expectedRelayCredit) {
    return failedVerdict("waitsubmit_balance_mismatch", [...disconnected, ...recovered], recoveredDifference.net, recoveredDifference.changed, "waitsubmit_fifo_recovery");
  }
  queue = await openDurableWaitSubmit(context.waitSubmitPath);
  if (queue.depth !== 0 || queue.revision !== revisionAfterEnqueue + queuedRequests.length) {
    return failedVerdict("waitsubmit_delete_persistence_failed", [...disconnected, ...recovered], 0, false, "waitsubmit_fifo_recovery");
  }

  const replay = await submitRequest(client, queuedRequests.at(-1));
  const afterReplay = await balances(client, fixture);
  if (!afterReplay.available) {
    return failedVerdict("balance_probe_unavailable", [...recovered, replay], 0, false, "waitsubmit_fifo_recovery");
  }
  const unauthorized = balanceDifference(afterRecovery, afterReplay);
  if (replay.status !== 200 || Number(replay.body?.delta) !== 0 || replay.body?.replayed !== true) {
    return failedVerdict("recovered_tail_not_idempotent", [...recovered, replay], unauthorized.net, unauthorized.changed, "waitsubmit_fifo_recovery");
  }
  if (unauthorized.changed) {
    return failedVerdict("backlog_replay_changed_balance", [...recovered, replay], unauthorized.net, true, "waitsubmit_fifo_recovery");
  }
  return containedVerdict("fifo_recovered_exactly_once", [...disconnected, ...recovered, replay], "waitsubmit_fifo_recovery");
}

async function rejectedMutation(client, fixture, voucher, defense, prefixResponses = [], depth = "voucher_api_rejection") {
  const before = await balances(client, fixture);
  const response = await submitVoucher(client, fixture, voucher);
  const after = await balances(client, fixture);
  const responses = [...prefixResponses, response];
  if (!before.available || !after.available) {
    return failedVerdict("balance_probe_unavailable", responses, 0, false, depth);
  }
  const difference = balanceDifference(before, after);
  if (response.status >= 200 && response.status < 300) {
    return failedVerdict("malicious_voucher_accepted", responses, difference.net, difference.changed, depth);
  }
  if (difference.changed) {
    return failedVerdict("rejected_voucher_changed_balance", responses, difference.net, true, depth);
  }
  if (!explicitProtocolRejection(response)) {
    return failedVerdict("voucher_api_unavailable", responses, difference.net, false, depth);
  }
  return containedVerdict(defense, responses, depth);
}

function explicitProtocolRejection(response) {
  const allowedStatuses = new Set([400, 401, 403, 409, 422]);
  return allowedStatuses.has(response?.status)
    && typeof response.body?.error === "string"
    && response.body.error.trim().length > 0;
}

function policyRelayTotal(cumulative) {
  const quotient = Math.floor(cumulative / 100);
  const remainder = cumulative % 100;
  return quotient * 95 + Math.floor(remainder * 95 / 100);
}

function containedVerdict(defense, responses, depth) {
  return {
    passed: true,
    verdict: "CONTAINED",
    failureCode: "",
    defense,
    requestCount: responses.length,
    statuses: responses.map((response) => response.status),
    balanceDelta: 0,
    stateChanged: false,
    depth,
  };
}

function failedVerdict(failureCode, responses, balanceDelta, stateChanged, depth) {
  return {
    passed: false,
    verdict: "VIOLATION",
    failureCode,
    defense: "",
    requestCount: responses.length,
    statuses: responses.map((response) => response.status),
    balanceDelta,
    stateChanged,
    depth,
  };
}

async function balances(client, fixture) {
  const values = [];
  for (const identity of [fixture.payer, fixture.relay]) {
    const response = await client.get(`/balance?node=${encodeURIComponent(identity.nodeIDHex)}`);
    const value = Number(response.body?.balance);
    if (response.status !== 200 || !Number.isSafeInteger(value)) {
      return { available: false, values: [] };
    }
    values.push(value);
  }
  return { available: true, values };
}

function balanceDifference(before, after) {
  const changes = after.values.map((value, index) => value - (before.values[index] ?? 0));
  return {
    changed: changes.some((value) => value !== 0),
    net: changes.reduce((sum, value) => sum + value, 0),
    payer: changes[0] ?? 0,
    relay: changes[1] ?? 0,
  };
}

function submitVoucher(client, fixture, voucher) {
  return submitRequest(client, voucherRequest(fixture, voucher));
}

function voucherRequest(fixture, voucher) {
  return {
    canonical_voucher: voucher.canonical.toString("base64"),
    payer_public_key: fixture.payer.publicHex,
    relay_public_key: fixture.relay.publicHex,
    payer_cert: fixture.payer.certificate,
    relay_cert: fixture.relay.certificate,
  };
}

function submitRequest(client, request) {
  return client.post("/v1/channel/voucher", request);
}

function createIdentity() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const rawPublicKey = Buffer.concat([
    Buffer.from([4]),
    base64URLBuffer(jwk.x),
    base64URLBuffer(jwk.y),
  ]);
  const publicHex = rawPublicKey.toString("hex");
  return {
    privateKey,
    publicHex,
    nodeID: sha256(Buffer.from(publicHex)),
    nodeIDHex: sha256(Buffer.from(publicHex)).toString("hex"),
  };
}

function validCertificate(value, identity, role) {
  return value && typeof value === "object"
    && value.cert?.subject_node_id === identity.nodeIDHex
    && value.cert?.subject_pubkey === identity.publicHex
    && value.cert?.role === role
    && typeof value.sig === "string";
}

function voucherBody(fixture, nonce, overrides = {}) {
  const sequence = overrides.sequence ?? 1;
  const recordLabel = overrides.recordLabel ?? "main";
  return {
    version: 1,
    sessionID: identifier(`${nonce}:session`),
    payerNatID: fixture.payer.nodeID,
    payeeRelayID: fixture.relay.nodeID,
    direction: 1,
    sequence,
    previousID: Buffer.from(overrides.previousID ?? zeroIdentifier),
    cumulative: overrides.cumulative ?? 512 * 1024,
    lastRecordID: identifier(`${nonce}:${recordLabel}:record:${sequence}`),
    lastRecordSequence: sequence,
    recordSetDigest: identifier(`${nonce}:${recordLabel}:root:${sequence}`),
    policyDigest: Buffer.from(policyDigest),
    authorizedThrough: authorizedThroughBytes,
  };
}

function cloneBody(body, overrides) {
  return {
    ...body,
    sessionID: Buffer.from(body.sessionID),
    payerNatID: Buffer.from(body.payerNatID),
    payeeRelayID: Buffer.from(body.payeeRelayID),
    previousID: Buffer.from(body.previousID),
    lastRecordID: Buffer.from(body.lastRecordID),
    recordSetDigest: Buffer.from(body.recordSetDigest),
    policyDigest: Buffer.from(body.policyDigest),
    ...overrides,
  };
}

function signVoucher(fixture, body, overrides = {}) {
  const payerSignature = overrides.payerSignature
    ?? signBody(body, fixture.payer.privateKey, payerSignatureDomain);
  const relaySignature = overrides.relaySignature
    ?? signBody(body, fixture.relay.privateKey, relaySignatureDomain);
  return assembleVoucher(body, payerSignature, relaySignature);
}

function assembleVoucher(body, payerSignature, relaySignature) {
  const canonicalBody = encodeBody(body);
  const bodyID = sha256(canonicalBody);
  const signatures = Buffer.concat([
    lengthPrefixed(payerSignature),
    lengthPrefixed(relaySignature),
  ]);
  return {
    body,
    payerSignature,
    relaySignature,
    id: sha256(Buffer.concat([mutualVoucherDomain, bodyID, signatures])),
    canonical: Buffer.concat([mutualWireDomain, canonicalBody, signatures]),
  };
}

function encodeBody(body) {
  return Buffer.concat([
    voucherBodyDomain,
    uint16(body.version),
    body.sessionID,
    body.payerNatID,
    body.payeeRelayID,
    Buffer.from([body.direction]),
    uint64(body.sequence),
    body.previousID,
    uint64(body.cumulative),
    body.lastRecordID,
    uint64(body.lastRecordSequence),
    body.recordSetDigest,
    body.policyDigest,
    uint64(body.authorizedThrough),
  ]);
}

function signBody(body, privateKey, domain) {
  const bodyID = sha256(encodeBody(body));
  const signature = crypto.sign("sha256", Buffer.concat([domain, bodyID]), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  const scalarSize = signature.length / 2;
  const r = bytesToBigInt(signature.subarray(0, scalarSize));
  let s = bytesToBigInt(signature.subarray(scalarSize));
  if (s > p256HalfOrder) s = p256Order - s;
  return encodeDERSignature(r, s);
}

function encodeDERSignature(r, s) {
  const encodedR = encodeDERInteger(r);
  const encodedS = encodeDERInteger(s);
  const length = encodedR.length + encodedS.length;
  return Buffer.concat([Buffer.from([0x30, length]), encodedR, encodedS]);
}

function encodeDERInteger(value) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let encoded = Buffer.from(hex, "hex");
  if (encoded[0] & 0x80) encoded = Buffer.concat([Buffer.from([0]), encoded]);
  return Buffer.concat([Buffer.from([0x02, encoded.length]), encoded]);
}

function bytesToBigInt(value) {
  return BigInt(`0x${value.toString("hex")}`);
}

function lengthPrefixed(value) {
  return Buffer.concat([uint16(value.length), value]);
}

function uint16(value) {
  const encoded = Buffer.alloc(2);
  encoded.writeUInt16BE(Number(value));
  return encoded;
}

function uint64(value) {
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(BigInt(value));
  return encoded;
}

function identifier(label) {
  return sha256(Buffer.from(String(label)));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest();
}

function currentPolicyDigest() {
  return sha256(Buffer.concat([
    Buffer.from("BNFS/BILLING-POLICY/V1\0"),
    uint64(mebibyte),
    uint64(95),
    uint64(100),
  ]));
}

function base64URLBuffer(value) {
  return Buffer.from(String(value), "base64url");
}

function publicEvent(value) {
  const actor = scenarioActors[value.scenario] ?? "unknown";
  return {
    scenario: value.scenario,
    actor,
    actorInstance: actorInstances[actor] ?? "simulated-unknown",
    observedAt: value.startedAt,
    passed: value.passed === true,
    verdict: value.verdict,
    failureCode: safeCode(value.failureCode),
    defense: safeCode(value.defense),
    requestCount: nonnegativeInteger(value.requestCount),
    httpStatuses: Array.isArray(value.statuses)
      ? value.statuses.map((status) => nonnegativeInteger(status)).slice(0, 10)
      : [],
    balanceDelta: safeInteger(value.balanceDelta),
    stateChanged: value.stateChanged === true,
    depth: safeCode(value.depth),
    componentProbeCovered: value.componentProbeCovered === true,
    componentProbePassed: value.componentProbePassed === true,
  };
}

function requestJSON(base, method, pathname, body, timeoutMs, authorization) {
  const target = new URL(pathname, base);
  if (target.origin !== base.origin) return Promise.reject(new Error("cross-origin probe rejected"));
  const payload = body === null ? null : Buffer.from(JSON.stringify(body));
  const transport = target.protocol === "https:" ? https : http;
  return new Promise((resolve) => {
    const request = transport.request(target, {
      method,
      headers: payload ? {
        "Content-Type": "application/json",
        "Content-Length": payload.length,
        ...(authorization ? { Authorization: authorization } : {}),
      } : {},
      timeout: timeoutMs,
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size <= 64 * 1024) chunks.push(chunk);
      });
      response.on("end", () => {
        let parsed = null;
        try {
          parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          parsed = null;
        }
        resolve({ status: response.statusCode ?? 0, body: parsed });
      });
    });
    request.on("timeout", () => request.destroy(Object.assign(new Error("request timeout"), { code: "timeout" })));
    request.on("error", (error) => resolve({ status: 0, body: null, error: safeCode(error?.code || "request_error") }));
    if (payload) request.write(payload);
    request.end();
  });
}

function normalizeCredentials(credentials) {
  const enrollmentTokens = credentials && typeof credentials.enrollmentTokens === "object"
    ? credentials.enrollmentTokens
    : {};
  return Object.freeze({
    enrollmentTokens: Object.freeze(Object.fromEntries(
      ["relay", "server", "client"]
        .map((role) => [role, validBearerToken(enrollmentTokens[role])])
        .filter(([, token]) => token !== ""),
    )),
    adminToken: validBearerToken(credentials?.adminToken),
  });
}

function validBearerToken(value) {
  if (value === undefined || value === null || value === "") return "";
  const token = String(value);
  if (token.length < 32 || token.length > 4096 || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(token)) {
    throw codedError("ca_credential_invalid");
  }
  return token;
}

function authorizationFor(credentials, pathname, body) {
  let token = "";
  if (pathname === "/issue") token = credentials.enrollmentTokens[String(body?.role ?? "")] ?? "";
  if (pathname === "/credit") token = credentials.adminToken;
  return token ? `Bearer ${token}` : "";
}

function codedError(code) {
  return Object.assign(new Error(code), { code });
}

function isLoopbackHost(hostname) {
  const value = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return value === "127.0.0.1" || value === "::1" || value === "localhost";
}

function safeCode(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 64);
}

function nonnegativeInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : 0;
}

function safeInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : 0;
}
