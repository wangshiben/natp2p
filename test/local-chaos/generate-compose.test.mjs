import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const generator = fileURLToPath(new URL("./generate-compose.mjs", import.meta.url));

test("every Compose service overlays an isolated private artifact directory", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-isolation-runtime-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));
  const privateRoot = path.join(runtimeDir, ".private");
  const { stdout } = await execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_ENABLE_CA: "1",
      BNFS_CHAOS_CA_HOST_PORT: "19100",
    },
    maxBuffer: 1024 * 1024,
  });
  const compose = JSON.parse(stdout);
  const serviceNames = [
    "ca",
    "index",
    ...numbered("relay", 7),
    ...numbered("natserver", 13),
    ...numbered("natclient", 6),
  ];

  assert.deepEqual(Object.keys(compose.services).sort(), [...serviceNames].sort());
  const privateSources = new Set();
  for (const serviceName of serviceNames) {
    const volumes = compose.services[serviceName].volumes;
    assert.deepEqual(volumes, [
      `${runtimeDir}:/artifacts`,
      `${path.join(privateRoot, serviceName)}:/artifacts/.private`,
    ]);
    privateSources.add(path.join(privateRoot, serviceName));
  }
  assert.equal(privateSources.size, serviceNames.length);

  assert.deepEqual(sensitivePaths(compose.services.ca.command), [
    "/artifacts/.private/ca-key.pem",
    "/artifacts/.private/ledger.json",
  ]);
  for (const serviceName of ["index", ...numbered("relay", 7)]) {
    assert.deepEqual(sensitivePaths(compose.services[serviceName].command), [
      "/artifacts/.private/identity.key",
      "/artifacts/.private/wait-submit.queue",
    ]);
  }

  const tokenFiles = {
    relay: path.join(privateRoot, "ca", "enroll-relay.token"),
    server: path.join(privateRoot, "ca", "enroll-server.token"),
    client: path.join(privateRoot, "ca", "enroll-client.token"),
    admin: path.join(privateRoot, "ca", "admin.token"),
  };
  const tokens = Object.fromEntries(await Promise.all(Object.entries(tokenFiles).map(async ([role, filename]) => {
    const stat = await fs.stat(filename);
    assert.equal(stat.mode & 0o777, 0o600);
    const token = (await fs.readFile(filename, "utf8")).trim();
    assert.match(token, /^[A-Za-z0-9._~+/-]{32,}={0,2}$/);
    return [role, token];
  })));
  assert.equal(new Set(Object.values(tokens)).size, 4);

  for (const serviceName of ["index", ...numbered("relay", 7)]) {
    await assertEnrollmentCredential(compose, privateRoot, serviceName, tokens.relay);
  }
  for (const serviceName of numbered("natserver", 13)) {
    await assertEnrollmentCredential(compose, privateRoot, serviceName, tokens.server);
  }
  for (const serviceName of numbered("natclient", 6)) {
    await assertEnrollmentCredential(compose, privateRoot, serviceName, tokens.client);
  }
  assert.equal(Object.hasOwn(compose.services.ca, "environment"), false);
  assert.deepEqual(compose.services.ca.command.slice(-8), [
    "-relay-enrollment-token-file", "/artifacts/.private/enroll-relay.token",
    "-server-enrollment-token-file", "/artifacts/.private/enroll-server.token",
    "-client-enrollment-token-file", "/artifacts/.private/enroll-client.token",
    "-admin-token-file", "/artifacts/.private/admin.token",
  ]);

  const serialized = JSON.stringify(compose);
  for (const token of Object.values(tokens)) assert.equal(serialized.includes(token), false);
  for (const legacyPath of [
    "/artifacts/identities/",
    "/artifacts/billing/",
    "/artifacts/ca_key.pem",
    "/artifacts/ca_ledger.json",
  ]) {
    assert.equal(serialized.includes(legacyPath), false, `legacy shared secret path remains: ${legacyPath}`);
  }
});

test("malicious Compose actors receive neither management credentials nor shared artifacts", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-adversary-runtime-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));
  const { stdout } = await execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_ENABLE_CA: "1",
      BNFS_CHAOS_ENABLE_ADVERSARIES: "1",
    },
    maxBuffer: 1024 * 1024,
  });
  const compose = JSON.parse(stdout);
  for (const serviceName of ["malicious-natserver", "malicious-relay"]) {
    const service = compose.services[serviceName];
    assert.deepEqual(service.volumes, [`${path.join(runtimeDir, ".private", serviceName)}:/state`]);
    assert.equal(Object.hasOwn(service, "environment"), false);
    assert.equal(JSON.stringify(service).includes("token"), false);
    assert.equal(JSON.stringify(service).includes("/artifacts"), false);
    assert.equal((await fs.stat(path.join(runtimeDir, ".private", serviceName))).mode & 0o777, 0o700);
  }

  assert.deepEqual(compose.services["malicious-natserver"].networks, [
    "adversary_billing",
    ...numbered("access_r", 7),
  ]);
  assert.deepEqual(compose.services["malicious-relay"].networks, [
    "adversary_billing",
    "adversary_mixed_access",
    "control_partition_a",
    "control_partition_b",
  ]);
  for (const relay of numbered("relay", 7)) {
    const command = compose.services[relay].command;
    const peerIndex = command.indexOf("-peer");
    if (relay === "relay03") {
      assert.equal(command[peerIndex + 1], "malicious-relay:9300");
    } else {
      assert.equal(peerIndex, -1);
    }
  }
  const probe = compose.services["mixed-path-probe"];
  assert.deepEqual(probe.networks, ["adversary_mixed_access", ...numbered("access_r", 7)]);
  assert.deepEqual(probe.environment, [
    "BNFS_CA_ISSUE_TOKEN_FILE=/artifacts/.private/ca-issue.token",
  ]);
  assert.deepEqual(probe.volumes, [
    `${runtimeDir}:/artifacts`,
    `${path.join(runtimeDir, ".private", "mixed-path-probe")}:/artifacts/.private`,
  ]);
  assert.equal((await fs.stat(path.join(runtimeDir, ".private", "mixed-path-probe"))).mode & 0o777, 0o700);
  const probeToken = (await fs.readFile(
    path.join(runtimeDir, ".private", "mixed-path-probe", "ca-issue.token"),
    "utf8",
  )).trim();
  const clientToken = (await fs.readFile(
    path.join(runtimeDir, ".private", "ca", "enroll-client.token"),
    "utf8",
  )).trim();
  assert.equal(probeToken, clientToken);
  assert.equal(JSON.stringify(compose.services["malicious-natserver"]).includes("ca-issue.token"), false);
  assert.equal(JSON.stringify(compose.services["malicious-relay"]).includes("ca-issue.token"), false);
});

function numbered(prefix, count) {
  return Array.from({ length: count }, (_, index) => `${prefix}${String(index + 1).padStart(2, "0")}`);
}

function sensitivePaths(command) {
  const options = ["-key", "-ledger", "-billing-queue"];
  return options.flatMap((option) => {
    const index = command.indexOf(option);
    return index >= 0 ? [command[index + 1]] : [];
  });
}

async function assertEnrollmentCredential(compose, privateRoot, serviceName, expectedToken) {
  assert.deepEqual(compose.services[serviceName].environment, [
    "BNFS_CA_ISSUE_TOKEN_FILE=/artifacts/.private/ca-issue.token",
  ]);
  const filename = path.join(privateRoot, serviceName, "ca-issue.token");
  const stat = await fs.stat(filename);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal((await fs.readFile(filename, "utf8")).trim(), expectedToken);
}
