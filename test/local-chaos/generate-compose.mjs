import path from "node:path";
import process from "node:process";

const runtimeDir = path.resolve(process.argv[2] ?? "test/local-chaos/.runtime");
const image = process.env.BNFS_CHAOS_IMAGE ?? "bnfs-local-chaos:latest";
const enableCA = process.env.BNFS_CHAOS_ENABLE_CA === "1";
const caHostPort = process.env.BNFS_CHAOS_CA_HOST_PORT ?? "19100";
const relayCount = 7;
const natServerCount = 13;
const natClientCount = 6;

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

const admissionArgs = enableCA
  ? ["-ca", "http://ca:9100", "-admission", "enforce"]
  : ["-admission", "off"];

const services = {};
if (enableCA) {
  services.ca = caService();
}
services.index = nodeService(
  ["/opt/bnfs/nodeserver", "-mode", "index", "-listen", ":9000", "-public", "index:9000", ...admissionArgs],
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
  services[name] = nodeService(
    [
      "/opt/bnfs/nodeserver", "-mode", "relay", "-listen", ":9000",
      "-public", `${name}:9000`, "-index", upstream, ...admissionArgs,
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
  services[nodeName("natserver", server)] = idleNatService(attachedNetworks);
}
for (let client = 1; client <= natClientCount; client += 1) {
  const attachedNetworks = clientNetworks.get(client) ?? [relayNetwork(1)];
  services[nodeName("natclient", client)] = idleNatService(attachedNetworks);
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

function commonService() {
  return {
    image,
    init: true,
    stop_grace_period: "3s",
    volumes: [`${runtimeDir}:/artifacts`],
    logging: { driver: "local", options: { "max-size": "20m", "max-file": "2" } },
  };
}

function caService() {
  return {
    ...commonService(),
    command: [
      "/opt/bnfs/caserver", "-listen", ":9100",
      "-key", "/artifacts/ca_key.pem",
      "-ledger", "/artifacts/ca_ledger.json",
      "-issuer", "bnfs-local-chaos",
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

function nodeService(command, attachedNetworks) {
  const service = {
    ...commonService(),
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
  if (enableCA) {
    service.depends_on = { ca: { condition: "service_healthy" } };
  }
  return service;
}

function idleNatService(attachedNetworks) {
  return {
    ...commonService(),
    command: ["sleep", "infinity"],
    cap_add: ["NET_ADMIN"],
    networks: attachedNetworks,
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
