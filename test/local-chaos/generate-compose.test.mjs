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
  const fixedAdminToken = `caadm_${"a".repeat(64)}`;
  const fixedAdminTokenFile = path.join(runtimeDir, "fixed-admin.token");
  await fs.writeFile(fixedAdminTokenFile, `${fixedAdminToken}\n`, { mode: 0o600 });
  const { stdout } = await execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_ENABLE_CA: "1",
      BNFS_CHAOS_CA_HOST_PORT: "19100",
      BNFS_CHAOS_CA_CLIENT_ROLE_SERVICES: "natserver01,natserver04,natserver06",
      BNFS_CHAOS_CA_ADMIN_TOKEN_FILE: fixedAdminTokenFile,
    },
    maxBuffer: 1024 * 1024,
  });
  const compose = JSON.parse(stdout);
  const serviceNames = [
    "ca-postgres",
    "ca",
    "ca-web",
    "index",
    ...numbered("relay", 7),
    ...numbered("natserver", 13),
    ...numbered("natclient", 6),
    "malicious-random-natserver",
    "malicious-natclient",
  ];

  assert.deepEqual(Object.keys(compose.services).sort(), [...serviceNames].sort());
  const commonArtifactServices = [
    "index",
    ...numbered("relay", 7),
    ...numbered("natserver", 13),
    ...numbered("natclient", 6),
    "malicious-random-natserver",
    "malicious-natclient",
  ];
  const privateSources = new Set();
  for (const serviceName of commonArtifactServices) {
    const volumes = compose.services[serviceName].volumes;
    assert.deepEqual(volumes, [
      `${runtimeDir}:/artifacts`,
      `${path.join(privateRoot, serviceName)}:/artifacts/.private`,
    ]);
    privateSources.add(path.join(privateRoot, serviceName));
  }
  assert.equal(privateSources.size, commonArtifactServices.length);

  assert.deepEqual(compose.services.ca.volumes, [`${path.join(privateRoot, "ca")}:/data`]);
  assert.deepEqual(compose.services["ca-postgres"].volumes, [
    `${path.join(privateRoot, "ca-postgres", "data")}:/var/lib/postgresql/data`,
  ]);
  assert.deepEqual(compose.services["ca-web"].volumes, [
    `${path.join(privateRoot, "ca-web", "tls")}:/etc/nginx/tls`,
  ]);
  assert.equal(compose.services.ca.image, "bnfs-ca-web-backend:latest");
  assert.equal(compose.services["ca-web"].image, "bnfs-ca-web-frontend:latest");
  assert.deepEqual(compose.services["ca-web"].ports, ["8088:8088"]);
  assert.equal(compose.services["ca-web"].environment.BACKEND_URL, "http://ca:9100");
  assert.deepEqual(compose.services["ca-postgres"].networks, ["ca_database"]);
  assert.ok(compose.services.ca.networks.includes("ca_database"));

  assert.deepEqual(sensitivePaths(compose.services.ca.command), []);
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
  assert.equal(tokens.admin, fixedAdminToken);
  assert.equal(new Set(Object.values(tokens)).size, 4);

  const billingServices = commonArtifactServices;
  const manifestFile = path.join(privateRoot, "ca", "billing-key-bootstrap.json");
  const manifestStat = await fs.stat(manifestFile);
  assert.equal(manifestStat.mode & 0o777, 0o600);
  const manifest = JSON.parse(await fs.readFile(manifestFile, "utf8"));
  assert.equal(manifest.version, 1);
  assert.deepEqual(manifest.users.map(user => user.username).sort(), ["demo_user", "developer", "observer"]);
  assert.equal(new Set(manifest.users.map(user => user.key_id)).size, 3);
  assert.equal(manifest.users.flatMap(user => user.services).length, billingServices.length);
  assert.deepEqual(manifest.users.flatMap(user => user.services).sort(), [...billingServices].sort());
  assert.equal(JSON.stringify(manifest).includes("private_key"), false);
  assert.equal(JSON.stringify(manifest).includes('"d"'), false);
  for (const user of manifest.users) {
    assert.match(user.key_id, /^[0-9a-f]{64}$/);
    assert.match(user.public_key_hex, /^04[0-9a-f]{128}$/);
    assert.ok(user.services.length > 1, `${user.username} must share one key across multiple nodes`);
    for (const serviceName of user.services) {
      await assertBillingCredential(compose, privateRoot, serviceName, user);
    }
  }
  assert.deepEqual(compose.services["malicious-natclient"].networks, ["access_r01"]);
  assert.equal(compose.services["malicious-natclient"].labels["bnfs.test.actor"], "malicious-natclient");
  assert.deepEqual(compose.services["malicious-random-natserver"].networks, ["access_r03"]);
  assert.equal(compose.services["malicious-random-natserver"].labels["bnfs.test.actor"],
    "malicious-random-natserver");
  assert.equal(compose.services.ca.environment.CA_DATABASE_DRIVER, "postgres");
  assert.deepEqual(compose.services.ca.command.slice(-8), [
    "--relay-enrollment-token-file", "/data/enroll-relay.token",
    "--server-enrollment-token-file", "/data/enroll-server.token",
    "--client-enrollment-token-file", "/data/enroll-client.token",
    "--admin-token-file", "/data/admin.token",
  ]);

  const serialized = JSON.stringify(compose);
  for (const token of Object.values(tokens)) assert.equal(serialized.includes(token), false);
  for (const user of manifest.users) {
    assert.equal(serialized.includes(user.public_key_hex), false);
    assert.equal(serialized.includes(user.key_id), false);
  }
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
    assert.deepEqual(service.environment, [
      ...frameworkLogEnvironment("/state/logs"),
      "BNFS_BILLING_KEY_FILE=/state/billing-key.json",
    ]);
    assert.equal(JSON.stringify(service).includes("token"), false);
    assert.equal(JSON.stringify(service).includes("/artifacts"), false);
    assert.equal((await fs.stat(path.join(runtimeDir, ".private", serviceName))).mode & 0o777, 0o700);
    const bundleFile = path.join(runtimeDir, ".private", serviceName, "billing-key.json");
    assert.equal((await fs.stat(bundleFile)).mode & 0o777, 0o600);
    const bundle = JSON.parse(await fs.readFile(bundleFile, "utf8"));
    assert.match(bundle.key_id, /^[0-9a-f]{64}$/);
    assert.ok(bundle.private_key_jwk?.d);
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
    ...frameworkLogEnvironment("/artifacts/.private/logs"),
    "BNFS_BILLING_KEY_FILE=/artifacts/.private/billing-key.json",
  ]);
  assert.deepEqual(probe.volumes, [
    `${runtimeDir}:/artifacts`,
    `${path.join(runtimeDir, ".private", "mixed-path-probe")}:/artifacts/.private`,
  ]);
  assert.equal((await fs.stat(path.join(runtimeDir, ".private", "mixed-path-probe"))).mode & 0o777, 0o700);
  const probeBundle = JSON.parse(await fs.readFile(
    path.join(runtimeDir, ".private", "mixed-path-probe", "billing-key.json"), "utf8",
  ));
  assert.match(probeBundle.key_id, /^[0-9a-f]{64}$/);
  assert.ok(probeBundle.private_key_jwk?.d);
  assert.equal(JSON.stringify(compose.services["malicious-natserver"]).includes("ca-issue.token"), false);
  assert.equal(JSON.stringify(compose.services["malicious-relay"]).includes("ca-issue.token"), false);
});

test("reconnect gate credentials are injected only into NAT test containers", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-reconnect-gate-runtime-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));
  const token = "a".repeat(64);
  const gateURL = "http://host.docker.internal:18912";
  const { stdout } = await execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_ENABLE_CA: "1",
      BNFS_CHAOS_RECONNECT_GATE_URL: gateURL,
      BNFS_CHAOS_RECONNECT_GATE_TOKEN: token,
    },
    maxBuffer: 1024 * 1024,
  });
  const compose = JSON.parse(stdout);
  const natServices = [
    ...numbered("natserver", 13),
    ...numbered("natclient", 6),
    "malicious-random-natserver",
    "malicious-natclient",
  ];
  for (const serviceName of natServices) {
    assert.equal(compose.services[serviceName].environment.includes(
      `BNFS_RECONNECT_GATE_URL=${gateURL}`,
    ), true);
    assert.equal(compose.services[serviceName].environment.includes(
      `BNFS_RECONNECT_GATE_TOKEN=${token}`,
    ), true);
    assert.deepEqual(compose.services[serviceName].extra_hosts, [
      "host.docker.internal:host-gateway",
    ]);
  }
  for (const serviceName of ["ca-postgres", "ca", "ca-web", "index", ...numbered("relay", 7)]) {
    assert.equal(JSON.stringify(compose.services[serviceName]).includes("RECONNECT_GATE"), false);
    assert.equal(JSON.stringify(compose.services[serviceName]).includes(token), false);
  }
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

test("control networks can move away from a running topology", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-control-network-runtime-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));
  const { stdout } = await execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET: "213",
      BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET: "214",
    },
    maxBuffer: 1024 * 1024,
  });
  const compose = JSON.parse(stdout);

  assert.deepEqual(compose.networks.control_index.ipam.config, [{ subnet: "10.213.0.0/24" }]);
  assert.deepEqual(compose.networks.control_partition_a.ipam.config, [{ subnet: "10.213.1.0/24" }]);
  assert.deepEqual(compose.networks.control_partition_b.ipam.config, [{ subnet: "10.213.2.0/24" }]);
  assert.deepEqual(compose.networks.access_r01.ipam.config, [{ subnet: "10.214.1.0/24" }]);
});

test("control network override rejects the access address pool", async (context) => {
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-compose-control-network-invalid-"));
  context.after(() => fs.rm(runtimeDir, { recursive: true, force: true }));

  await assert.rejects(execFileAsync(process.execPath, [generator, runtimeDir], {
    env: {
      ...process.env,
      BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET: "212",
      BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET: "212",
    },
    maxBuffer: 1024 * 1024,
  }), /must not overlap/);
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

async function assertBillingCredential(compose, privateRoot, serviceName, expectedUser) {
  assert.deepEqual(compose.services[serviceName].environment, [
    ...frameworkLogEnvironment("/artifacts/.private/logs"),
    "BNFS_BILLING_KEY_FILE=/artifacts/.private/billing-key.json",
  ]);
  const filename = path.join(privateRoot, serviceName, "billing-key.json");
  const stat = await fs.stat(filename);
  assert.equal(stat.mode & 0o777, 0o600);
  const bundle = JSON.parse(await fs.readFile(filename, "utf8"));
  assert.equal(bundle.key_id, expectedUser.key_id);
  assert.equal(bundle.public_key_hex, expectedUser.public_key_hex);
  assert.equal(bundle.registration_status, "pending");
  assert.ok(bundle.private_key_jwk?.d);
  const privateKeyFilename = path.join(privateRoot, serviceName, "billing-private.key");
  const privateKeyStat = await fs.stat(privateKeyFilename);
  assert.equal(privateKeyStat.mode & 0o777, 0o600);
  assert.equal(
    (await fs.readFile(privateKeyFilename, "utf8")).trim(),
    Buffer.from(bundle.private_key_jwk.d, "base64url").toString("hex"),
  );
}

function frameworkLogEnvironment(directory) {
  return [
    `BNFS_LOG_DIRECTORY=${directory}`,
    "BNFS_LOG_LEVEL=info",
    "BNFS_LOG_MAX_SIZE_MIB=64",
    "BNFS_LOG_ROTATE_INTERVAL=24h",
    "BNFS_LOG_RETENTION=720h",
    "BNFS_LOG_CONSOLE=true",
    "BNFS_LOG_ERROR_STACK=true",
  ];
}
