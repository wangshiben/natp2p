import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

process.umask(0o077);

const privateRoot = path.resolve(process.env.PRIVATE_RUNTIME_DIR ?? "");
const caBaseURL = new URL(process.env.CA_BASE_URL ?? "http://127.0.0.1:19100");
const serverTokenFile = path.resolve(process.env.CA_SERVER_ENROLLMENT_TOKEN_FILE ?? "");
const relayTokenFile = path.resolve(process.env.CA_RELAY_ENROLLMENT_TOKEN_FILE ?? "");
const adminTokenFile = path.resolve(process.env.CA_ADMIN_TOKEN_FILE ?? "");
const timeoutMs = boundedInteger(process.env.PROVISION_TIMEOUT_MS, 30000, 1000, 120000);
const creditBytes = boundedInteger(process.env.ADVERSARY_CREDIT_BYTES, 64 * 1024 * 1024 * 1024, 16 * 1024 * 1024, Number.MAX_SAFE_INTEGER);

try {
  validateConfiguration();
  const tokens = {
    server: await readToken(serverTokenFile),
    relay: await readToken(relayTokenFile),
    admin: await readToken(adminTokenFile),
  };
  const actors = [
    { service: "malicious-natserver", role: "server", token: tokens.server, credit: true },
    { service: "malicious-relay", role: "relay", token: tokens.relay, credit: false },
  ];
  for (const actor of actors) {
    await provisionActor(actor);
  }
  process.stdout.write("container adversary identities provisioned\n");
} catch (error) {
  process.stderr.write(`container adversary provisioning failed: ${safeCode(error?.code || "provision_failed")}\n`);
  process.exitCode = 1;
}

function validateConfiguration() {
  if (!process.env.PRIVATE_RUNTIME_DIR || privateRoot === path.parse(privateRoot).root) {
    throw codedError("private_runtime_invalid");
  }
  if (caBaseURL.protocol !== "http:" || !isLoopback(caBaseURL.hostname)
    || caBaseURL.username || caBaseURL.password || caBaseURL.search || caBaseURL.hash) {
    throw codedError("ca_url_invalid");
  }
  for (const [value, code] of [
    [process.env.CA_SERVER_ENROLLMENT_TOKEN_FILE, "server_token_file_missing"],
    [process.env.CA_RELAY_ENROLLMENT_TOKEN_FILE, "relay_token_file_missing"],
    [process.env.CA_ADMIN_TOKEN_FILE, "admin_token_file_missing"],
  ]) {
    if (!value) throw codedError(code);
  }
}

async function provisionActor(actor) {
  const stateDir = path.join(privateRoot, actor.service);
  const enrollmentPath = path.join(stateDir, "enrollment.json");
  const enrollment = await waitForEnrollment(enrollmentPath, actor.role);
  const issue = await requestJSON("POST", "/issue", {
    subject_pubkey: enrollment.publicKey,
    role: actor.role,
    ttl_seconds: 86400,
  }, actor.token);
  if (issue.status !== 200 || !validCertificate(issue.body?.signed_cert, enrollment, actor.role)) {
    throw codedError(`${actor.service}_issue_rejected`);
  }
  await writeJSONAtomic(path.join(stateDir, "certificate.json"), issue.body.signed_cert);
  if (actor.credit) await ensureCredit(enrollment.nodeID);
}

async function ensureCredit(nodeID) {
  const current = await requestJSON("GET", `/balance?node=${encodeURIComponent(nodeID)}`, null, "");
  const balance = Number(current.body?.balance);
  if (current.status !== 200 || !Number.isSafeInteger(balance) || balance < 0) {
    throw codedError("adversary_balance_invalid");
  }
  if (balance >= creditBytes) return;
  const credit = await requestJSON("POST", "/credit", {
    node_id: nodeID,
    add_bytes: creditBytes - balance,
  }, await readToken(adminTokenFile));
  if (credit.status !== 200 || Number(credit.body?.balance) !== creditBytes) {
    throw codedError("adversary_credit_rejected");
  }
}

async function waitForEnrollment(filename, role) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await readJSON(filename);
    if (validEnrollment(value, role)) return value;
    await delay(100);
  }
  throw codedError(`${role}_enrollment_timeout`);
}

function validEnrollment(value, role) {
  if (!value || value.schemaVersion !== 1 || value.role !== role
    || !/^04[0-9a-f]{128}$/.test(String(value.publicKey ?? ""))
    || !/^[0-9a-f]{64}$/.test(String(value.nodeID ?? ""))) return false;
  const derived = crypto.createHash("sha256").update(value.publicKey).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(derived, "hex"), Buffer.from(value.nodeID, "hex"));
}

function validCertificate(value, enrollment, role) {
  return value && typeof value === "object"
    && value.cert?.subject_node_id === enrollment.nodeID
    && value.cert?.subject_pubkey === enrollment.publicKey
    && value.cert?.role === role
    && Number.isSafeInteger(value.cert?.not_before)
    && Number.isSafeInteger(value.cert?.not_after)
    && value.cert.not_after > value.cert.not_before
    && typeof value.sig === "string"
    && /^[0-9a-f]{16,256}$/.test(value.sig);
}

async function requestJSON(method, pathname, body, token) {
  const target = new URL(pathname, caBaseURL);
  const headers = { Accept: "application/json" };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(target, {
      method,
      headers,
      body: body === null ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await response.text();
    let decoded = {};
    try {
      decoded = text ? JSON.parse(text) : {};
    } catch {
      throw codedError("ca_response_invalid");
    }
    return { status: response.status, body: decoded };
  } catch (error) {
    if (error?.code) throw error;
    throw codedError("ca_request_failed");
  } finally {
    clearTimeout(timer);
  }
}

async function readToken(filename) {
  let encoded;
  try {
    encoded = await fs.readFile(filename, "utf8");
  } catch {
    throw codedError("credential_unavailable");
  }
  if (encoded.length > 4096) throw codedError("credential_invalid");
  const token = encoded.trim();
  if (token.length < 32 || !/^[A-Za-z0-9\-._~+/]+={0,2}$/.test(token)) {
    throw codedError("credential_invalid");
  }
  return token;
}

async function readJSON(filename) {
  try {
    const encoded = await fs.readFile(filename, "utf8");
    if (encoded.length > 65536) return {};
    return JSON.parse(encoded);
  } catch {
    return {};
  }
}

async function writeJSONAtomic(filename, value) {
  const temporary = `${filename}.tmp-${process.pid}`;
  await fs.writeFile(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  const handle = await fs.open(temporary, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, filename);
  const directory = await fs.open(path.dirname(filename), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

function isLoopback(hostname) {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost" || normalized === "::1" || normalized.startsWith("127.");
}

function codedError(code) {
  return Object.assign(new Error(code), { code });
}

function safeCode(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 64);
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
