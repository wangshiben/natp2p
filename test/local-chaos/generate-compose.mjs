import path from "node:path";
import process from "node:process";

const runtimeDir = path.resolve(process.argv[2] ?? "test/local-chaos/.runtime");
const image = process.env.BNFS_CHAOS_IMAGE ?? "bnfs-local-chaos:latest";

const networks = {
  control_index: network("10.200.0.0/24"),
  control_partition: network("10.200.1.0/24"),
};
for (let relay = 1; relay <= 9; relay += 1) {
  networks[relayNetwork(relay)] = network(`10.201.${relay}.0/24`);
}

const services = {
  index: nodeService(
    ["/opt/bnfs/nodeserver", "-mode", "index", "-listen", ":9000", "-public", "index:9000", "-admission", "off"],
    ["control_index"],
  ),
};

for (let relay = 1; relay <= 9; relay += 1) {
  const name = relayName(relay);
  const upstream = relay <= 2 ? "index:9000" : "relay01:9000";
  const attachedNetworks = relay === 1
    ? ["control_index", "control_partition", relayNetwork(relay)]
    : relay === 2
      ? ["control_index", relayNetwork(relay)]
      : ["control_partition", relayNetwork(relay)];
  services[name] = nodeService(
    [
      "/opt/bnfs/nodeserver", "-mode", "relay", "-listen", ":9000",
      "-public", `${name}:9000`, "-index", upstream, "-admission", "off",
    ],
    attachedNetworks,
  );
}

const serverNetworks = new Map([
  [1, [relayNetwork(3)]],
  [2, ["control_index"]],
  [3, [relayNetwork(2)]],
  [4, [relayNetwork(3)]],
  [5, [relayNetwork(3)]],
]);
const clientNetworks = new Map([
  [1, [relayNetwork(3)]],
  [2, [relayNetwork(1)]],
  [3, [relayNetwork(4)]],
  [4, ["control_index"]],
  [5, [relayNetwork(2)]],
]);

for (let server = 1; server <= 17; server += 1) {
  const attachedNetworks = serverNetworks.get(server) ?? [relayNetwork(((server - 1) % 9) + 1)];
  services[nodeName("natserver", server)] = idleNatService(attachedNetworks);
}
for (let client = 1; client <= 10; client += 1) {
  const attachedNetworks = clientNetworks.get(client) ?? [relayNetwork(((client + 3) % 9) + 1)];
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

function nodeService(command, attachedNetworks) {
  return {
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
