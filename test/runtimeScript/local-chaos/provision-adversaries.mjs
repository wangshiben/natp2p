import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

process.umask(0o077);

const privateRoot = path.resolve(process.env.PRIVATE_RUNTIME_DIR ?? "");
const caBaseURL = new URL(process.env.CA_BASE_URL ?? "http://127.0.0.1:19100");
const timeoutMs = boundedInteger(process.env.PROVISION_TIMEOUT_MS, 30000, 1000, 120000);

try {
  validateConfiguration();
  for (const actor of [
    { service: "malicious-natserver", role: "server" },
    { service: "malicious-relay", role: "relay" },
  ]) {
    await provisionActor(actor);
  }
  process.stdout.write("container adversary billing identities provisioned\n");
} catch (error) {
  process.stderr.write(`container adversary provisioning failed: ${safeCode(error?.code || "provision_failed")}\n`);
  process.exitCode = 1;
}

function validateConfiguration() {
  if (!process.env.PRIVATE_RUNTIME_DIR || privateRoot === path.parse(privateRoot).root) {
    throw codedError("private_runtime_invalid");
  }
  if (caBaseURL.protocol !== "http:" || !isLoopback(caBaseURL.hostname)
    || caBaseURL.username || caBaseURL.password || caBaseURL.search || caBaseURL.hash
    || !["", "/"].includes(caBaseURL.pathname)) {
    throw codedError("ca_url_invalid");
  }
}

async function provisionActor(actor) {
  const stateDir = path.join(privateRoot, actor.service);
  const enrollment = await waitForEnrollment(path.join(stateDir, "enrollment.json"), actor.role);
  const bundle = await readPrivateJSON(path.join(stateDir, "billing-key.json"));
  const billingPrivateKey = validateBillingBundle(bundle);
  const authorization = signedAuthorization(enrollment, bundle.key_id, billingPrivateKey);
  const issued = await requestJSON("POST", "/v1/node/authorize", authorization);
  if (issued.status !== 200
    || !validCertificate(issued.body?.signed_cert, enrollment, actor.role, bundle)
    || issued.body?.node_id !== enrollment.nodeID
    || issued.body?.authorization_id !== authorizationID(enrollment.nodeID, bundle.key_id)) {
    throw codedError(`${actor.service}_authorization_rejected`);
  }
  await writeJSONAtomic(path.join(stateDir, "certificate.json"), issued.body.signed_cert);
}

function signedAuthorization(enrollment, billingKeyID, billingPrivateKey) {
  const request = {
    subject_pubkey: enrollment.publicKey,
    role: enrollment.role,
    billing_key_id: billingKeyID,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: crypto.randomBytes(24).toString("base64url"),
    ttl_seconds: 86400,
    node_signature: "",
    billing_signature: "",
  };
  const canonical = authorizationCanonical(request);
  request.node_signature = signCanonical(canonical, enrollment.privateKey);
  request.billing_signature = signCanonical(canonical, billingPrivateKey);
  return request;
}

function authorizationCanonical(request) {
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

function authorizationID(nodeID, billingKeyID) {
  return crypto.createHash("sha256")
    .update(`CA-NODE-AUTHORIZATION-ID-V1\0${nodeID}\0${billingKeyID}`)
    .digest("hex");
}

async function waitForEnrollment(filename, role) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await readEnrollment(filename);
    if (value && value.role === role) return value;
    await delay(100);
  }
  throw codedError(`${role}_enrollment_timeout`);
}

async function readEnrollment(filename) {
  try {
    const encoded = await fs.readFile(filename, "utf8");
    if (encoded.length > 65536) return null;
    const value = JSON.parse(encoded);
    if (!validEnrollment(value)) return null;
    const privateKeyPath = path.join(path.dirname(filename), "identity.key");
    const privateScalar = await fs.readFile(privateKeyPath);
    if (privateScalar.length !== 32) throw codedError("identity_private_key_invalid");
    const privateKey = privateKeyFromScalar(privateScalar);
    if (publicKeyHex(privateKey) !== value.publicKey) throw codedError("identity_key_binding_invalid");
    return { ...value, privateKey };
  } catch (error) {
    if (error?.code && error.code !== "ENOENT") throw error;
    return null;
  }
}

function validEnrollment(value) {
  if (!value || value.schemaVersion !== 1 || !["server", "relay"].includes(value.role)
    || !/^04[0-9a-f]{128}$/.test(String(value.publicKey ?? ""))
    || !/^[0-9a-f]{64}$/.test(String(value.nodeID ?? ""))) return false;
  const derived = crypto.createHash("sha256").update(value.publicKey).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(derived, "hex"), Buffer.from(value.nodeID, "hex"));
}

function validateBillingBundle(bundle) {
  if (!bundle || bundle.version !== 1 || bundle.algorithm !== "ECDSA_P256_SHA256"
    || bundle.registration_status !== "active" || !/^[0-9a-f]{64}$/.test(String(bundle.key_id ?? ""))
    || !/^04[0-9a-f]{128}$/.test(String(bundle.public_key_hex ?? ""))
    || !bundle.private_key_jwk?.d) throw codedError("billing_bundle_invalid");
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey({ key: bundle.private_key_jwk, format: "jwk" });
  } catch {
    throw codedError("billing_private_key_invalid");
  }
  const publicHex = publicKeyHex(privateKey);
  const keyID = crypto.createHash("sha256").update(Buffer.from(publicHex, "hex")).digest("hex");
  if (publicHex !== bundle.public_key_hex || keyID !== bundle.key_id) {
    throw codedError("billing_key_binding_invalid");
  }
  return privateKey;
}

function privateKeyFromScalar(privateScalar) {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(privateScalar);
  const publicKey = ecdh.getPublicKey(undefined, "uncompressed");
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: publicKey.subarray(1, 33).toString("base64url"),
    y: publicKey.subarray(33, 65).toString("base64url"),
    d: privateScalar.toString("base64url"),
  };
  return crypto.createPrivateKey({ key: jwk, format: "jwk" });
}

function publicKeyHex(privateKey) {
  const jwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  return Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("hex");
}

function validCertificate(value, enrollment, role, bundle) {
  return value && typeof value === "object"
    && value.cert?.subject_node_id === enrollment.nodeID
    && value.cert?.subject_pubkey === enrollment.publicKey
    && value.cert?.role === role
    && value.cert?.billing_key_id === bundle.key_id
    && value.cert?.billing_public_key === bundle.public_key_hex
    && value.cert?.authorization_id === authorizationID(enrollment.nodeID, bundle.key_id)
    && Number.isSafeInteger(value.cert?.not_before)
    && Number.isSafeInteger(value.cert?.not_after)
    && value.cert.not_after > value.cert.not_before
    && typeof value.sig === "string"
    && /^[0-9a-f]{16,256}$/.test(value.sig);
}

async function requestJSON(method, pathname, body) {
  const target = new URL(pathname, caBaseURL);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(target, {
      method,
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await response.text();
    if (text.length > 65536) throw codedError("ca_response_too_large");
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

async function readPrivateJSON(filename) {
  const handle = await fs.open(filename, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size <= 0 || stat.size > 65536) {
      throw codedError("private_json_invalid");
    }
    return JSON.parse(await handle.readFile("utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) throw codedError("private_json_invalid");
    throw error;
  } finally {
    await handle.close();
  }
}

async function writeJSONAtomic(filename, value) {
  const temporary = `${filename}.tmp-${process.pid}`;
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`);
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
  if (value === undefined || value === "") return fallback;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw codedError("integer_configuration_invalid");
  }
  return number;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
