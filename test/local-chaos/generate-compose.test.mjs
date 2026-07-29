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
    "malicious-random-natserver",
    "malicious-natclient",
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
  await assertEnrollmentCredential(compose, privateRoot, "malicious-random-natserver", tokens.server);
  for (const serviceName of numbered("natclient", 6)) {
    await assertEnrollmentCredential(compose, privateRoot, serviceName, tokens.client);
  }
  await assertEnrollmentCredential(compose, privateRoot, "malicious-natclient", tokens.client);
  assert.deepEqual(compose.services["malicious-natclient"].networks, ["access_r01"]);
  assert.equal(compose.services["malicious-natclient"].labels["bnfs.test.actor"], "malicious-natclient");
  assert.deepEqual(compose.services["malicious-random-natserver"].networks, ["access_r03"]);
  assert.equal(compose.services["malicious-random-natserver"].labels["bnfs.test.actor"],
    "malicious-random-natserver");
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
    assert.equal(commandOption(service.command, "-interval"), "60s");
  }
  assert.equal(commandOption(compose.services["malicious-natserver"].command, "-attack-offset"), "0s");
  assert.equal(commandOption(compose.services["malicious-relay"].command, "-attack-offset"), "30s");

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

test("IP-family plan assigns isolated IPv4, IPv6 and dual-stack paths", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-ip-family-runtime-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));
  const planFile = path.join(runtimeDir, "ip-family-plan.tsv");
  await fs.writeFile(planFile, [
    "family\trelay\tnatserver\tnatclient",
    "ipv4\trelay03\tnatserver01\tnatclient01",
    "ipv6\trelay04\tnatserver02\tnatclient02",
    "dual\trelay05\tnatserver03\tnatclient03",
    "",
  ].join("\n"), { mode: 0o600 });
  const { stdout } = await execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_ENABLE_CA: "1",
      BNFS_CHAOS_IP_FAMILY_PLAN_FILE: planFile,
    },
    maxBuffer: 1024 * 1024,
  });
  const compose = JSON.parse(stdout);

  assert.deepEqual(compose.networks.ip_family_ipv4.ipam.config, [{ subnet: "10.253.41.0/24" }]);
  assert.equal(compose.networks.ip_family_ipv4.enable_ipv6, false);
  assert.deepEqual(compose.networks.ip_family_ipv6.ipam.config, [{ subnet: "fd92:7b5e:4c31:42::/64" }]);
  assert.equal(compose.networks.ip_family_ipv6.enable_ipv6, true);
  assert.deepEqual(compose.networks.ip_family_dual.ipam.config, [
    { subnet: "10.253.43.0/24" },
    { subnet: "fd92:7b5e:4c31:43::/64" },
  ]);

  assert.deepEqual(compose.services.relay03.networks.ip_family_ipv4, { ipv4_address: "10.253.41.250" });
  assert.deepEqual(compose.services.relay04.networks.ip_family_ipv6, { ipv6_address: "fd92:7b5e:4c31:42::250" });
  assert.deepEqual(compose.services.relay05.networks.ip_family_dual, {
    ipv4_address: "10.253.43.250",
    ipv6_address: "fd92:7b5e:4c31:43::250",
  });
  assert.ok(compose.services.natserver01.networks.ip_family_ipv4);
  assert.ok(compose.services.natserver02.networks.ip_family_ipv6);
  assert.ok(compose.services.natclient03.networks.ip_family_dual);
  assert.deepEqual(compose.services.ca.networks.ip_family_ipv4, { ipv4_address: "10.253.41.251" });
  assert.deepEqual(compose.services.ca.networks.ip_family_ipv6, { ipv6_address: "fd92:7b5e:4c31:42::251" });
  assert.deepEqual(compose.services.ca.networks.ip_family_dual, {
    ipv4_address: "10.253.43.251",
    ipv6_address: "fd92:7b5e:4c31:43::251",
  });
  assert.equal(commandOption(compose.services.relay03.command, "-ca"), "http://10.253.41.251:9100");
  assert.equal(commandOption(compose.services.relay04.command, "-ca"), "http://[fd92:7b5e:4c31:42::251]:9100");
  assert.equal(commandOption(compose.services.relay05.command, "-ca"), "http://10.253.43.251:9100");
});

test("access networks can move away from a stale Docker address pool", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-access-network-runtime-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));
  const { stdout } = await execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET: "212",
    },
    maxBuffer: 1024 * 1024,
  });
  const compose = JSON.parse(stdout);

  for (let relay = 1; relay <= 7; relay += 1) {
    assert.deepEqual(compose.networks[`access_r${String(relay).padStart(2, "0")}`].ipam.config, [
      { subnet: `10.212.${relay}.0/24` },
    ]);
  }
});

test("access network override rejects overlapping reserved topology ranges", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-access-network-invalid-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));

  await assert.rejects(execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET: "200",
    },
    maxBuffer: 1024 * 1024,
  }), /isolated RFC1918/);
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

function commandOption(command, option) {
  const index = command.indexOf(option);
  return index < 0 ? "" : command[index + 1];
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
