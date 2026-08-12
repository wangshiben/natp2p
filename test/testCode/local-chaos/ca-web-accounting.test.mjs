import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const inspector = fileURLToPath(new URL("../../runtimeScript/local-chaos/ca-web-accounting.mjs", import.meta.url));

test("CA Web accounting inspector summarizes one payer and relay", async (context) => {
  const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "ca-web-accounting-"));
  context.after(() => fs.rm(temporaryDirectory, { recursive: true, force: true }));
  const token = `caadm_${"a".repeat(64)}`;
  const tokenFile = path.join(temporaryDirectory, "admin.token");
  await fs.writeFile(tokenFile, `${token}\n`, { mode: 0o600 });
  await fs.writeFile(path.join(temporaryDirectory, "billing-key-bootstrap.json"), `${JSON.stringify({
    version: 1,
    users: [{
      user_id: "usr_mock_developer",
      services: ["relay04", "natserver06"],
    }],
  })}\n`, { mode: 0o600 });
  const relayID = "b".repeat(64);
  const payerID = "c".repeat(64);
  const responses = new Map([
    ["/api/v1/overview", { ca: { ca_revenue_bytes: 75, transaction: 19 } }],
    ["/api/v1/nodes", { items: [{ id: relayID, role: "relay", relay_income_bytes: 1425 }] }],
    ["/api/v1/channels?limit=500", { items: [
      { payer_node_id: payerID, relay_node_id: relayID, gross_total_bytes: 1000, relay_total_bytes: 950, ca_total_bytes: 50 },
      { payer_node_id: payerID, relay_node_id: relayID, gross_total_bytes: 500, relay_total_bytes: 475, ca_total_bytes: 25 },
      { payer_node_id: "d".repeat(64), relay_node_id: relayID, gross_total_bytes: 10, relay_total_bytes: 9, ca_total_bytes: 1 },
    ] }],
    ["/api/v1/admin/users", { items: [{
      id: "usr_mock_developer", balance_bytes: 998575, consumed_bytes: 1500, earned_bytes: 1425,
    }] }],
  ]);
  const server = http.createServer(async (request, response) => {
    assert.equal(request.headers.authorization, undefined);
    if (request.url === "/api/v1/auth/admin-login") {
      assert.equal(request.method, "POST");
      let encoded = "";
      for await (const chunk of request) encoded += chunk;
      assert.deepEqual(JSON.parse(encoded), { token });
      response.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "quickSession=test-admin-session; Path=/; HttpOnly; SameSite=Strict",
      });
      response.end('{"authenticated":true,"role":"admin"}');
      return;
    }
    assert.equal(request.headers.cookie, "quickSession=test-admin-session");
    const body = responses.get(request.url);
    response.writeHead(body ? 200 : 404, { "Content-Type": "application/json" });
    response.end(JSON.stringify(body ?? {}));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  const { stdout } = await execFileAsync(
    process.execPath,
    [inspector, relayID, payerID, "relay04", "natserver06"],
    {
    env: {
      ...process.env,
      CA_BASE_URL: `http://127.0.0.1:${address.port}`,
      CA_ADMIN_TOKEN_FILE: tokenFile,
    },
    },
  );
  assert.equal(stdout, "75\t1425\t19\t2\t1500\t1425\t75\t1500\t998575\t998575\ttrue\n");
});
