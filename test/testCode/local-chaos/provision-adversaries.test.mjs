import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const provisioner = fileURLToPath(new URL("../../runtimeScript/local-chaos/provision-adversaries.mjs", import.meta.url));

test("host provisioner double-signs billing-bound adversary certificates without management credentials", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-provision-adversaries-test-"));
  const privateRoot = path.join(root, "private");
  const actors = new Map();
  const requests = [];
  for (const [service, role] of [["malicious-natserver", "server"], ["malicious-relay", "relay"]]) {
    const actor = await createActor(privateRoot, service, role);
    actors.set(actor.nodeID, actor);
  }
  const server = http.createServer(async (request, response) => {
    const target = new URL(request.url ?? "/", `http://${request.headers.host}`);
    const body = request.method === "POST" ? await readJSON(request) : {};
    requests.push({
      path: target.pathname,
      authorization: request.headers.authorization ?? "",
      cookie: request.headers.cookie ?? "",
      body,
    });
    if (target.pathname !== "/v1/node/authorize") {
      return json(response, 404, { error: "not_found" });
    }
    const nodeID = crypto.createHash("sha256").update(String(body.subject_pubkey ?? "")).digest("hex");
    const actor = actors.get(nodeID);
    if (!actor || body.role !== actor.role || body.billing_key_id !== actor.billingKeyID) {
      return json(response, 401, { error: "binding_invalid" });
    }
    const canonical = authorizationCanonical(body);
    const nodeValid = verifyCanonical(canonical, actor.identityPublicKey, body.node_signature);
    const billingValid = verifyCanonical(canonical, actor.billingPublicKey, body.billing_signature);
    if (!nodeValid || !billingValid) return json(response, 401, { error: "signature_invalid" });
    const id = authorizationID(actor.nodeID, actor.billingKeyID);
    return json(response, 200, {
      authorization_id: id,
      node_id: actor.nodeID,
      signed_cert: {
        cert: {
          subject_node_id: actor.nodeID,
          subject_pubkey: actor.identityPublicHex,
          role: actor.role,
          not_before: 1,
          not_after: 4102444800,
          nonce: "fixture",
          issuer: "fixture",
          authorization_id: id,
          billing_key_id: actor.billingKeyID,
          billing_public_key: actor.billingPublicHex,
        },
        sig: "ab".repeat(40),
      },
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    const result = await execFileAsync(process.execPath, [provisioner], {
      env: {
        ...process.env,
        PRIVATE_RUNTIME_DIR: privateRoot,
        CA_BASE_URL: `http://127.0.0.1:${address.port}`,
      },
    });
    assert.match(result.stdout, /billing identities provisioned/);
    for (const actor of actors.values()) {
      assert.equal(result.stdout.includes(actor.identityPrivateHex), false);
      assert.equal(result.stderr.includes(actor.identityPrivateHex), false);
      assert.equal(result.stdout.includes(actor.billingPrivateJWK.d), false);
      assert.equal(result.stderr.includes(actor.billingPrivateJWK.d), false);
      const cert = JSON.parse(await fs.readFile(
        path.join(privateRoot, actor.service, "certificate.json"), "utf8",
      ));
      assert.equal(cert.cert.subject_node_id, actor.nodeID);
      assert.equal(cert.cert.billing_key_id, actor.billingKeyID);
      assert.equal(cert.cert.billing_public_key, actor.billingPublicHex);
      assert.equal(cert.cert.authorization_id, authorizationID(actor.nodeID, actor.billingKeyID));
    }
    assert.equal(requests.length, 2);
    assert.ok(requests.every(request => request.path === "/v1/node/authorize"));
    assert.ok(requests.every(request => request.authorization === "" && request.cookie === ""));
    assert.ok(requests.every(request => request.body.node_signature && request.body.billing_signature));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
});

async function createActor(privateRoot, service, role) {
  const directory = path.join(privateRoot, service);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const identity = crypto.createECDH("prime256v1");
  identity.generateKeys();
  const identityPrivate = identity.getPrivateKey();
  const identityPublic = identity.getPublicKey(undefined, "uncompressed");
  const identityPublicHex = identityPublic.toString("hex");
  const nodeID = crypto.createHash("sha256").update(identityPublicHex).digest("hex");
  const identityPrivateKey = privateKeyFromScalar(identityPrivate);

  const billing = crypto.createECDH("prime256v1");
  billing.generateKeys();
  const billingPrivate = billing.getPrivateKey();
  const billingPrivateKey = privateKeyFromScalar(billingPrivate);
  const billingPrivateJWK = billingPrivateKey.export({ format: "jwk" });
  const billingPublicHex = billing.getPublicKey(undefined, "uncompressed").toString("hex");
  const billingKeyID = crypto.createHash("sha256")
    .update(Buffer.from(billingPublicHex, "hex"))
    .digest("hex");

  await fs.writeFile(path.join(directory, "identity.key"), identityPrivate, { mode: 0o600 });
  await fs.writeFile(path.join(directory, "enrollment.json"), `${JSON.stringify({
    schemaVersion: 1,
    role,
    publicKey: identityPublicHex,
    nodeID,
  })}\n`, { mode: 0o600 });
  await fs.writeFile(path.join(directory, "billing-key.json"), `${JSON.stringify({
    version: 1,
    key_id: billingKeyID,
    label: `test-${service}`,
    algorithm: "ECDSA_P256_SHA256",
    private_key_jwk: billingPrivateJWK,
    public_key_hex: billingPublicHex,
    registration_status: "active",
  })}\n`, { mode: 0o600 });
  return {
    service,
    role,
    nodeID,
    identityPrivateHex: identityPrivate.toString("hex"),
    identityPublicHex,
    identityPublicKey: crypto.createPublicKey(identityPrivateKey),
    billingKeyID,
    billingPrivateJWK,
    billingPublicHex,
    billingPublicKey: crypto.createPublicKey(billingPrivateKey),
  };
}

function privateKeyFromScalar(privateScalar) {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(privateScalar);
  const publicKey = ecdh.getPublicKey(undefined, "uncompressed");
  return crypto.createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: publicKey.subarray(1, 33).toString("base64url"),
      y: publicKey.subarray(33).toString("base64url"),
      d: privateScalar.toString("base64url"),
    },
    format: "jwk",
  });
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

function verifyCanonical(canonical, publicKey, signature) {
  try {
    return crypto.verify("sha256", Buffer.from(canonical), publicKey, Buffer.from(signature, "base64url"));
  } catch {
    return false;
  }
}

function authorizationID(nodeID, billingKeyID) {
  return crypto.createHash("sha256")
    .update(`CA-NODE-AUTHORIZATION-ID-V1\0${nodeID}\0${billingKeyID}`)
    .digest("hex");
}

async function readJSON(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function json(response, status, value) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(`${JSON.stringify(value)}\n`);
}
