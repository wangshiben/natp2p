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
const provisioner = fileURLToPath(new URL("./provision-adversaries.mjs", import.meta.url));

test("host provisioner supplies role certificates and credit without exposing credentials", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-provision-adversaries-test-"));
  const privateRoot = path.join(root, "private");
  const credentials = path.join(root, "credentials");
  const tokens = {
    server: "s".repeat(48),
    relay: "r".repeat(48),
    admin: "a".repeat(48),
  };
  const requests = [];
  const balances = new Map();
  const server = http.createServer(async (request, response) => {
    const target = new URL(request.url ?? "/", `http://${request.headers.host}`);
    const body = request.method === "POST" ? await readJSON(request) : {};
    requests.push({ path: target.pathname, authorization: request.headers.authorization ?? "", role: body.role ?? "" });
    if (target.pathname === "/issue") {
      const expected = body.role === "server" ? tokens.server : tokens.relay;
      if (request.headers.authorization !== `Bearer ${expected}`) return json(response, 401, { error: "unauthorized" });
      const nodeID = crypto.createHash("sha256").update(body.subject_pubkey).digest("hex");
      return json(response, 200, {
        signed_cert: {
          cert: {
            subject_node_id: nodeID,
            subject_pubkey: body.subject_pubkey,
            role: body.role,
            not_before: 1,
            not_after: 4102444800,
            nonce: "fixture",
            issuer: "fixture",
          },
          sig: "ab".repeat(40),
        },
      });
    }
    if (target.pathname === "/balance") {
      return json(response, 200, { balance: balances.get(target.searchParams.get("node")) ?? 0 });
    }
    if (target.pathname === "/credit") {
      if (request.headers.authorization !== `Bearer ${tokens.admin}`) return json(response, 401, { error: "unauthorized" });
      const balance = (balances.get(body.node_id) ?? 0) + Number(body.add_bytes);
      balances.set(body.node_id, balance);
      return json(response, 200, { balance });
    }
    return json(response, 404, { error: "not_found" });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    await fs.mkdir(credentials, { recursive: true });
    for (const [role, token] of Object.entries(tokens)) {
      await fs.writeFile(path.join(credentials, `${role}.token`), `${token}\n`, { mode: 0o600 });
    }
    for (const [service, role] of [["malicious-natserver", "server"], ["malicious-relay", "relay"]]) {
      const directory = path.join(privateRoot, service);
      await fs.mkdir(directory, { recursive: true });
      const coordinate = role === "server" ? "11" : "22";
      const publicKey = `04${coordinate.repeat(64)}`;
      const nodeID = crypto.createHash("sha256").update(publicKey).digest("hex");
      await fs.writeFile(path.join(directory, "enrollment.json"), `${JSON.stringify({
        schemaVersion: 1,
        role,
        publicKey,
        nodeID,
      })}\n`);
    }
    const address = server.address();
    const result = await execFileAsync(process.execPath, [provisioner], {
      env: {
        ...process.env,
        PRIVATE_RUNTIME_DIR: privateRoot,
        CA_BASE_URL: `http://127.0.0.1:${address.port}`,
        CA_SERVER_ENROLLMENT_TOKEN_FILE: path.join(credentials, "server.token"),
        CA_RELAY_ENROLLMENT_TOKEN_FILE: path.join(credentials, "relay.token"),
        CA_ADMIN_TOKEN_FILE: path.join(credentials, "admin.token"),
      },
    });
    assert.match(result.stdout, /identities provisioned/);
    for (const token of Object.values(tokens)) {
      assert.equal(result.stdout.includes(token), false);
      assert.equal(result.stderr.includes(token), false);
    }
    for (const service of ["malicious-natserver", "malicious-relay"]) {
      const cert = JSON.parse(await fs.readFile(path.join(privateRoot, service, "certificate.json"), "utf8"));
      assert.match(cert.cert.subject_node_id, /^[0-9a-f]{64}$/);
    }
    assert.deepEqual(requests.filter((request) => request.path === "/issue").map((request) => request.authorization).sort(), [
      `Bearer ${tokens.relay}`,
      `Bearer ${tokens.server}`,
    ].sort());
    assert.equal(requests.find((request) => request.path === "/credit")?.authorization, `Bearer ${tokens.admin}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
});

async function readJSON(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function json(response, status, value) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(`${JSON.stringify(value)}\n`);
}
