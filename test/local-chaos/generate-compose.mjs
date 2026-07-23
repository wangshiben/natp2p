import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const runtimeDir = path.resolve(process.argv[2] ?? "test/local-chaos/.runtime");
const privateRuntimeDir = path.join(runtimeDir, ".private");
const image = process.env.BNFS_CHAOS_IMAGE ?? "bnfs-local-chaos:latest";
const enableCA = process.env.BNFS_CHAOS_ENABLE_CA === "1";
const enableAdversaries = enableCA && process.env.BNFS_CHAOS_ENABLE_ADVERSARIES === "1";
const caHostPort = process.env.BNFS_CHAOS_CA_HOST_PORT ?? "19100";
const adversarySeed = process.env.BNFS_CHAOS_ADVERSARY_SEED ?? "bnfs-container-adversary-v1";
const relayCount = 7;
const natServerCount = 13;
const natClientCount = 6;
const caCredentials = enableCA ? provisionCACredentials() : null;

const networks = {
  control_index: network("10.200.0.0/24"),
  control_partition_a: network("10.200.1.0/24"),
  control_partition_b: network("10.200.2.0/24"),
};
for (let relay = 1; relay <= relayCount; relay += 1) {
  networks[relayNetwork(relay)] = network(`10.201.${relay}.0/24`);
}
if (enableCA) {
  // Docker intentionally blocks published ports for containers attached only
  // to `internal` networks. This CA-only bridge keeps the Web/API reachable
  // on the explicitly loopback-bound host port without changing NAT/Relay
  // partition reachability.
  networks.ca_host = { driver: "bridge" };
}
if (enableAdversaries) {
  networks.adversary_billing = network("10.202.0.0/24");
  networks.adversary_mixed_access = network("10.203.0.0/24");
}

const admissionArgs = enableCA
  ? ["-ca", "http://ca:9100", "-admission", "enforce"]
  : ["-admission", "off"];

const services = {};
if (enableCA) {
  services.ca = caService("ca");
}
if (enableAdversaries) {
  services["malicious-natserver"] = adversaryService(
    "malicious-natserver",
    "natserver",
    "http://malicious-relay:9200",
    ["adversary_billing", ...numberedRelayNetworks()],
  );
  services["malicious-relay"] = adversaryService(
    "malicious-relay",
    "relay",
    "http://malicious-natserver:9200",
    ["adversary_billing", "adversary_mixed_access", "control_partition_a", "control_partition_b"],
  );
  services["mixed-path-probe"] = idleNatService(
    "mixed-path-probe",
    ["adversary_mixed_access", ...numberedRelayNetworks()],
  );
}
services.index = nodeService(
  "index",
  [
    "/opt/bnfs/nodeserver", "-mode", "index", "-listen", ":9000", "-public", "index:9000",
    "-key", "/artifacts/.private/identity.key",
    "-billing-queue", "/artifacts/.private/wait-submit.queue",
    ...admissionArgs,
  ],
  ["control_index"],
);

for (let relay = 1; relay <= relayCount; relay += 1) {
  const name = relayName(relay);
  const upstream = relay <= 2 ? "index:9000" : "relay01:9000";
  const attachedNetworks = relay === 1
    ? ["control_index", "control_partition_a", "control_partition_b", relayNetwork(relay)]
    : relay === 2
      ? ["control_index", "control_partition_a", relayNetwork(relay)]
      : relay <= 5
        ? ["control_partition_a", relayNetwork(relay)]
        : ["control_partition_b", relayNetwork(relay)];
  const adversaryPeer = enableAdversaries && relay === 3
    ? ["-peer", "malicious-relay:9300"]
    : [];
  services[name] = nodeService(
    name,
    [
      "/opt/bnfs/nodeserver", "-mode", "relay", "-listen", ":9000",
      "-public", `${name}:9000`, "-index", upstream,
      ...adversaryPeer,
      "-key", "/artifacts/.private/identity.key",
      "-billing-queue", "/artifacts/.private/wait-submit.queue",
      ...admissionArgs,
    ],
    attachedNetworks,
  );
}

const serverNetworks = new Map([
  [1, [relayNetwork(3)]],
  [2, ["control_index"]],
  [3, [relayNetwork(3)]],
  [4, [relayNetwork(3)]],
  [5, [relayNetwork(3)]],
  [6, [relayNetwork(4)]],
]);
const clientNetworks = new Map([
  [4, ["control_index"]],
]);

for (let server = 1; server <= natServerCount; server += 1) {
  const attachedNetworks = serverNetworks.get(server) ?? [relayNetwork(((server - 1) % (relayCount - 2)) + 3)];
  const name = nodeName("natserver", server);
  services[name] = idleNatService(name, attachedNetworks);
}
for (let client = 1; client <= natClientCount; client += 1) {
  const attachedNetworks = clientNetworks.get(client) ?? [relayNetwork(1)];
  const name = nodeName("natclient", client);
  services[name] = idleNatService(name, attachedNetworks);
}

const compose = {
  name: "bnfs-local-chaos",
  services,
  networks,
};

process.stdout.write(`${JSON.stringify(compose, null, 2)}\n`);

function network(subnet) {
  return {
    driver: "bridge",
    internal: true,
    ipam: { config: [{ subnet }] },
  };
}

function commonService(name) {
  const servicePrivateDirectory = preparePrivateDirectory(name);
  return {
    image,
    init: true,
    stop_grace_period: "3s",
    volumes: [
      `${runtimeDir}:/artifacts`,
      `${servicePrivateDirectory}:/artifacts/.private`,
    ],
    logging: { driver: "local", options: { "max-size": "20m", "max-file": "2" } },
  };
}

function caService(name) {
  return {
    ...commonService(name),
    command: [
      "/opt/bnfs/caserver", "-listen", ":9100",
      "-key", "/artifacts/.private/ca-key.pem",
      "-ledger", "/artifacts/.private/ledger.json",
      "-issuer", "bnfs-local-chaos",
      "-relay-enrollment-token-file", "/artifacts/.private/enroll-relay.token",
      "-server-enrollment-token-file", "/artifacts/.private/enroll-server.token",
      "-client-enrollment-token-file", "/artifacts/.private/enroll-client.token",
      "-admin-token-file", "/artifacts/.private/admin.token",
    ],
    networks: Object.keys(networks),
    ports: [`127.0.0.1:${caHostPort}:9100`],
    healthcheck: {
      test: ["CMD-SHELL", "bash -c 'exec 3<>/dev/tcp/127.0.0.1/9100'"],
      interval: "2s",
      timeout: "1s",
      retries: 20,
      start_period: "2s",
    },
  };
}

function nodeService(name, command, attachedNetworks) {
  const service = {
    ...commonService(name),
    command,
    networks: attachedNetworks,
    healthcheck: {
      test: ["CMD-SHELL", "kill -0 1"],
      interval: "2s",
      timeout: "1s",
      retries: 20,
      start_period: "2s",
    },
  };
  if (enableCA && caCredentials) {
    service.depends_on = { ca: { condition: "service_healthy" } };
    service.environment = ["BNFS_CA_ISSUE_TOKEN_FILE=/artifacts/.private/ca-issue.token"];
  }
  return service;
}

function idleNatService(name, attachedNetworks) {
  const service = {
    ...commonService(name),
    command: ["sleep", "infinity"],
    cap_add: ["NET_ADMIN"],
    networks: attachedNetworks,
  };
  if (enableCA && caCredentials) {
    service.environment = ["BNFS_CA_ISSUE_TOKEN_FILE=/artifacts/.private/ca-issue.token"];
  }
  return service;
}

function adversaryService(name, role, peerURL, attachedNetworks) {
  const servicePrivateDirectory = preparePrivateDirectory(name);
  return {
    image,
    init: true,
    read_only: true,
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    stop_grace_period: "3s",
    command: [
      "/opt/bnfs/billing-adversary-node",
      "-role", role,
      "-listen", ":9200",
      "-ca", "http://ca:9100",
      "-peer", peerURL,
      "-state-dir", "/state",
      "-seed", adversarySeed,
    ],
    volumes: [`${servicePrivateDirectory}:/state`],
    tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=16m"],
    networks: attachedNetworks,
    depends_on: { ca: { condition: "service_healthy" } },
    labels: {
      "bnfs.test.actor": role === "relay" ? "malicious-relay" : "malicious-natserver",
      "bnfs.test.scope": "billing-fixture-and-real-mixed-p2p",
      "bnfs.test.transport": "container-peer-http-ca-http-and-p2p",
    },
    healthcheck: {
      test: ["CMD-SHELL", "kill -0 1"],
      interval: "2s",
      timeout: "1s",
      retries: 20,
      start_period: "2s",
    },
    logging: { driver: "local", options: { "max-size": "10m", "max-file": "2" } },
  };
}

function relayName(index) {
  return nodeName("relay", index);
}

function relayNetwork(index) {
  return `access_r${String(index).padStart(2, "0")}`;
}

function nodeName(prefix, index) {
  return `${prefix}${String(index).padStart(2, "0")}`;
}

function provisionCACredentials() {
  const caDirectory = path.join(privateRuntimeDir, "ca");
  const values = {
    relay: readOrCreateCredential(path.join(caDirectory, "enroll-relay.token")),
    server: readOrCreateCredential(path.join(caDirectory, "enroll-server.token")),
    client: readOrCreateCredential(path.join(caDirectory, "enroll-client.token")),
    admin: readOrCreateCredential(path.join(caDirectory, "admin.token")),
  };
  if (new Set(Object.values(values)).size !== Object.keys(values).length) {
    throw new Error("CA credentials must be distinct");
  }
  for (const service of ["index", ...numberedNames("relay", relayCount)]) {
    installCredential(path.join(privateRuntimeDir, service, "ca-issue.token"), values.relay);
  }
  for (const service of numberedNames("natserver", natServerCount)) {
    installCredential(path.join(privateRuntimeDir, service, "ca-issue.token"), values.server);
  }
  for (const service of numberedNames("natclient", natClientCount)) {
    installCredential(path.join(privateRuntimeDir, service, "ca-issue.token"), values.client);
  }
  if (enableAdversaries) {
    installCredential(path.join(privateRuntimeDir, "mixed-path-probe", "ca-issue.token"), values.client);
  }
  return Object.freeze(values);
}

function readOrCreateCredential(filename) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(filename), 0o700);
  const generated = crypto.randomBytes(32).toString("base64url");
  try {
    const descriptor = fs.openSync(
      filename,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      fs.writeFileSync(descriptor, `${generated}\n`);
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
  const token = readCredential(filename);
  fs.chmodSync(filename, 0o600);
  return token;
}

function installCredential(filename, token) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(filename), 0o700);
  try {
    const descriptor = fs.openSync(
      filename,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      fs.writeFileSync(descriptor, `${token}\n`);
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
  const installed = readCredential(filename);
  if (installed.length !== token.length
    || !crypto.timingSafeEqual(Buffer.from(installed), Buffer.from(token))) {
    throw new Error(`credential mismatch for ${path.basename(path.dirname(filename))}`);
  }
  fs.chmodSync(filename, 0o600);
}

function readCredential(filename) {
  const file = fs.lstatSync(filename);
  if (!file.isFile() || file.isSymbolicLink() || file.size > 4096) {
    throw new Error(`invalid credential file for ${path.basename(path.dirname(filename))}`);
  }
  const token = fs.readFileSync(filename, "utf8").trim();
  if (token.length < 32 || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(token)) {
    throw new Error(`invalid credential for ${path.basename(path.dirname(filename))}`);
  }
  return token;
}

function numberedNames(prefix, count) {
  return Array.from({ length: count }, (_, index) => nodeName(prefix, index + 1));
}

function numberedRelayNetworks() {
  return Array.from({ length: relayCount }, (_, index) => relayNetwork(index + 1));
}

function preparePrivateDirectory(name) {
  const directory = path.join(privateRuntimeDir, name);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  return directory;
}
