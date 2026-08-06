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
const caWebHostPort = process.env.BNFS_CHAOS_CA_WEB_HOST_PORT ?? "8088";
const caBackendImage = process.env.BNFS_CHAOS_CA_BACKEND_IMAGE ?? "bnfs-ca-web-backend:latest";
const caFrontendImage = process.env.BNFS_CHAOS_CA_FRONTEND_IMAGE ?? "bnfs-ca-web-frontend:latest";
const caTLSHosts = process.env.BNFS_CHAOS_CA_TLS_HOSTS ?? "localhost,127.0.0.1,::1,192.168.1.12";
const caAdminTokenFile = process.env.BNFS_CHAOS_CA_ADMIN_TOKEN_FILE ?? "";
const caBackendUser = typeof process.getuid === "function" && typeof process.getgid === "function"
  ? `${process.getuid()}:${process.getgid()}`
  : "65532:65532";
const adversarySeed = process.env.BNFS_CHAOS_ADVERSARY_SEED ?? "bnfs-container-adversary-v1";
const ipFamilyPlanFile = process.env.BNFS_CHAOS_IP_FAMILY_PLAN_FILE ?? "";
const reconnectGateURL = process.env.BNFS_CHAOS_RECONNECT_GATE_URL ?? "";
const reconnectGateToken = process.env.BNFS_CHAOS_RECONNECT_GATE_TOKEN ?? "";
const caClientRoleServices = parseCAClientRoleServices(
  process.env.BNFS_CHAOS_CA_CLIENT_ROLE_SERVICES ?? "",
);
const accessNetworkSecondOctet = parseAccessNetworkSecondOctet(
  process.env.BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET ?? "211",
);
const controlNetworkSecondOctet = parseControlNetworkSecondOctet(
  process.env.BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET ?? "200",
  accessNetworkSecondOctet,
);
const relayCount = 7;
const natServerCount = 13;
const natClientCount = 6;
const caCredentials = enableCA ? provisionCACredentials() : null;
const billingBundles = enableCA ? provisionBillingKeys() : new Map();
const ipFamilyPlan = readIPFamilyPlan(ipFamilyPlanFile);
validateReconnectGateConfiguration();
const ipFamilySpecs = Object.freeze({
  ipv4: Object.freeze({
    network: "ip_family_ipv4",
    ipv4Subnet: "10.253.41.0/24",
    relayIPv4: "10.253.41.250",
    caIPv4: "10.253.41.251",
  }),
  ipv6: Object.freeze({
    network: "ip_family_ipv6",
    ipv6Subnet: "fd92:7b5e:4c31:42::/64",
    relayIPv6: "fd92:7b5e:4c31:42::250",
    caIPv6: "fd92:7b5e:4c31:42::251",
  }),
  dual: Object.freeze({
    network: "ip_family_dual",
    ipv4Subnet: "10.253.43.0/24",
    ipv6Subnet: "fd92:7b5e:4c31:43::/64",
    relayIPv4: "10.253.43.250",
    relayIPv6: "fd92:7b5e:4c31:43::250",
    caIPv4: "10.253.43.251",
    caIPv6: "fd92:7b5e:4c31:43::251",
  }),
});

const networks = {
  control_index: network(`10.${controlNetworkSecondOctet}.0.0/24`),
  control_partition_a: network(`10.${controlNetworkSecondOctet}.1.0/24`),
  control_partition_b: network(`10.${controlNetworkSecondOctet}.2.0/24`),
};
for (let relay = 1; relay <= relayCount; relay += 1) {
  networks[relayNetwork(relay)] = network(`10.${accessNetworkSecondOctet}.${relay}.0/24`);
}
for (const assignment of ipFamilyPlan) {
  const spec = ipFamilySpecs[assignment.family];
  networks[spec.network] = ipFamilyNetwork(spec);
}
if (enableCA) {
  // Docker intentionally blocks published ports for containers attached only
  // to `internal` networks. This CA-only bridge keeps the Web/API reachable
  // on the explicitly loopback-bound host port without changing NAT/Relay
  // partition reachability.
  networks.ca_host = { driver: "bridge" };
  networks.ca_database = network(`10.${controlNetworkSecondOctet}.3.0/24`);
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
  services["ca-postgres"] = caPostgresService();
  services.ca = caService("ca");
  services["ca-web"] = caWebService();
  services["malicious-random-natserver"] = {
    ...idleNatService("malicious-random-natserver", [relayNetwork(3)]),
    labels: {
      "bnfs.test.actor": "malicious-random-natserver",
      "bnfs.test.scope": "random-workload-real-p2p",
      "bnfs.test.transport": "p2p-server-batch-target",
    },
  };
  services["malicious-natclient"] = {
    ...idleNatService("malicious-natclient", [relayNetwork(1)]),
    labels: {
      "bnfs.test.actor": "malicious-natclient",
      "bnfs.test.scope": "random-workload-real-p2p",
      "bnfs.test.transport": "p2p-client-batch-member",
    },
  };
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
      ...admissionArgsForService(name),
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

function parseAccessNetworkSecondOctet(value) {
  if (!/^(?:1[6-9]|[2-9][0-9]|1[0-9]{2}|20[14-9]|21[0-9]|22[0-3])$/.test(value)) {
    throw new Error("BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET must select an isolated RFC1918 /16");
  }
  return Number.parseInt(value, 10);
}

function parseControlNetworkSecondOctet(value, accessSecondOctet) {
  if (!/^(?:200|1[6-9]|[2-9][0-9]|1[0-9]{2}|20[14-9]|21[0-9]|22[0-3])$/.test(value)) {
    throw new Error("BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET must select an isolated RFC1918 /16");
  }
  const parsed = Number.parseInt(value, 10);
  if (parsed === accessSecondOctet) {
    throw new Error("control and access network address pools must not overlap");
  }
  return parsed;
}

function ipFamilyNetwork(spec) {
  const config = [];
  if (spec.ipv4Subnet) config.push({ subnet: spec.ipv4Subnet });
  if (spec.ipv6Subnet) config.push({ subnet: spec.ipv6Subnet });
  return {
    driver: "bridge",
    internal: true,
    enable_ipv6: Boolean(spec.ipv6Subnet),
    ipam: { config },
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
  const servicePrivateDirectory = preparePrivateDirectory(name);
  return {
    image: caBackendImage,
    user: caBackendUser,
    init: true,
    stop_grace_period: "15s",
    command: [
      "--listen", "0.0.0.0:9100",
      "--data", "/data",
      "--issuer", "bnfs-local-chaos",
      "--database-connections", "32",
      "--database-idle-connections", "4",
      "--relay-enrollment-token-file", "/data/enroll-relay.token",
      "--server-enrollment-token-file", "/data/enroll-server.token",
      "--client-enrollment-token-file", "/data/enroll-client.token",
      "--admin-token-file", "/data/admin.token",
    ],
    environment: {
      CA_DATABASE_DRIVER: "postgres",
      CA_DATABASE_URL: "postgres://ca_web:bnfs_soak_local_password@ca-postgres:5432/ca_web?sslmode=disable",
      CA_ENABLE_MOCK_USERS: "true",
      CA_LOG_DIRECTORY: "/data/logs",
      CA_LOG_LEVEL: "info",
      CA_LOG_MAX_SIZE_MIB: "32",
      CA_LOG_ROTATE_INTERVAL: "24h",
      CA_LOG_RETENTION: "720h",
      CA_LOG_CONSOLE: "true",
      CA_LOG_REDACT_ERRORS: "false",
    },
    volumes: [`${servicePrivateDirectory}:/data`],
    networks: caNetworkAttachments(),
    ports: [`127.0.0.1:${caHostPort}:9100`],
    depends_on: { "ca-postgres": { condition: "service_healthy" } },
    healthcheck: {
      test: ["CMD", "/ca-web", "--healthcheck", "http://127.0.0.1:9100/readyz"],
      interval: "2s",
      timeout: "3s",
      retries: 30,
      start_period: "5s",
    },
    read_only: true,
    tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=16m"],
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    logging: { driver: "local", options: { "max-size": "20m", "max-file": "2" } },
  };
}

function caPostgresService() {
  const servicePrivateDirectory = preparePrivateDirectory("ca-postgres");
  const dataDirectory = path.join(servicePrivateDirectory, "data");
  fs.mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
  return {
    image: "postgres:17-alpine",
    restart: "unless-stopped",
    stop_grace_period: "15s",
    environment: {
      POSTGRES_DB: "ca_web",
      POSTGRES_USER: "ca_web",
      POSTGRES_PASSWORD: "bnfs_soak_local_password",
    },
    volumes: [`${dataDirectory}:/var/lib/postgresql/data`],
    networks: ["ca_database"],
    healthcheck: {
      test: ["CMD-SHELL", "pg_isready -U ca_web -d ca_web"],
      interval: "2s",
      timeout: "3s",
      retries: 30,
      start_period: "5s",
    },
    security_opt: ["no-new-privileges:true"],
    logging: { driver: "local", options: { "max-size": "20m", "max-file": "2" } },
  };
}

function caWebService() {
  const servicePrivateDirectory = preparePrivateDirectory("ca-web");
  const tlsDirectory = path.join(servicePrivateDirectory, "tls");
  fs.mkdirSync(tlsDirectory, { recursive: true, mode: 0o700 });
  return {
    image: caFrontendImage,
    restart: "unless-stopped",
    environment: {
      BACKEND_URL: "http://ca:9100",
      TLS_HOSTS: caTLSHosts,
    },
    ports: [`${caWebHostPort}:8088`],
    volumes: [`${tlsDirectory}:/etc/nginx/tls`],
    networks: ["ca_host"],
    depends_on: { ca: { condition: "service_healthy" } },
    healthcheck: {
      test: ["CMD", "curl", "-kfsS", "https://127.0.0.1:8088/"],
      interval: "5s",
      timeout: "3s",
      retries: 12,
      start_period: "5s",
    },
    read_only: true,
    tmpfs: [
      "/var/cache/nginx:rw,nosuid,nodev,size=32m,mode=0755",
      "/var/run:rw,nosuid,nodev,size=4m,mode=0755",
      "/etc/nginx/conf.d:rw,nosuid,nodev,size=1m,mode=0755",
      "/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777",
    ],
    security_opt: ["no-new-privileges:true"],
    logging: { driver: "local", options: { "max-size": "20m", "max-file": "2" } },
  };
}

function nodeService(name, command, attachedNetworks) {
  const service = {
    ...commonService(name),
    command,
    networks: attachedNetworks,
    environment: frameworkLogEnvironment("/artifacts/.private/logs"),
    healthcheck: {
      test: ["CMD-SHELL", "kill -0 1"],
      interval: "2s",
      timeout: "1s",
      retries: 20,
      start_period: "2s",
    },
  };
  if (enableCA && caCredentials && billingBundles.has(name)) {
    service.depends_on = { ca: { condition: "service_healthy" } };
    service.environment.push("BNFS_BILLING_KEY_FILE=/artifacts/.private/billing-key.json");
  }
  return attachIPFamilyNetwork(service, name);
}

function idleNatService(name, attachedNetworks) {
  const service = {
    ...commonService(name),
    command: ["sleep", "infinity"],
    cap_add: ["NET_ADMIN"],
    networks: attachedNetworks,
    environment: frameworkLogEnvironment("/artifacts/.private/logs"),
  };
  if (enableCA && caCredentials && billingBundles.has(name)) {
    service.environment.push("BNFS_BILLING_KEY_FILE=/artifacts/.private/billing-key.json");
  }
  if (reconnectGateURL !== "") {
    service.environment ??= [];
    service.environment.push(
      `BNFS_RECONNECT_GATE_URL=${reconnectGateURL}`,
      `BNFS_RECONNECT_GATE_TOKEN=${reconnectGateToken}`,
    );
    service.extra_hosts = ["host.docker.internal:host-gateway"];
  }
  return attachIPFamilyNetwork(service, name);
}

function validateReconnectGateConfiguration() {
  if (reconnectGateURL === "" && reconnectGateToken === "") return;
  if (!/^http:\/\/host\.docker\.internal:[1-9][0-9]{0,4}$/.test(reconnectGateURL)) {
    throw new Error("invalid reconnect gate URL");
  }
  const port = Number.parseInt(reconnectGateURL.slice(reconnectGateURL.lastIndexOf(":") + 1), 10);
  if (port > 65535 || !/^[a-f0-9]{64}$/.test(reconnectGateToken)) {
    throw new Error("invalid reconnect gate credentials");
  }
}

function adversaryService(name, role, peerURL, attachedNetworks) {
  const servicePrivateDirectory = preparePrivateDirectory(name);
  const service = {
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
      "-interval", "60s",
      "-attack-offset", role === "relay" ? "30s" : "0s",
    ],
    volumes: [`${servicePrivateDirectory}:/state`],
    environment: frameworkLogEnvironment("/state/logs"),
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
  if (billingBundles.has(name)) {
    service.environment.push("BNFS_BILLING_KEY_FILE=/state/billing-key.json");
  }
  return service;
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
  const adminTokenPath = path.join(caDirectory, "admin.token");
  const adminToken = caAdminTokenFile === ""
    ? readOrCreateCredential(adminTokenPath)
    : readExternalCredential(caAdminTokenFile);
  if (caAdminTokenFile !== "") installCredential(adminTokenPath, adminToken);
  const values = {
    relay: readOrCreateCredential(path.join(caDirectory, "enroll-relay.token")),
    server: readOrCreateCredential(path.join(caDirectory, "enroll-server.token")),
    client: readOrCreateCredential(path.join(caDirectory, "enroll-client.token")),
    admin: adminToken,
  };
  if (new Set(Object.values(values)).size !== Object.keys(values).length) {
    throw new Error("CA credentials must be distinct");
  }
  return Object.freeze(values);
}

function provisionBillingKeys() {
  const groups = new Map([
    ["demo_user", []],
    ["developer", []],
    ["observer", []],
  ]);
  const services = ["index", ...numberedNames("relay", relayCount),
    ...numberedNames("natserver", natServerCount), ...numberedNames("natclient", natClientCount),
    "malicious-random-natserver", "malicious-natclient"];
  if (enableAdversaries) services.push("malicious-natserver", "malicious-relay", "mixed-path-probe");
  const users = [...groups.keys()];
  services.forEach((service, index) => groups.get(users[index % users.length]).push(service));

  const bundles = new Map();
  const manifest = { version: 1, users: [] };
  for (const [username, assignedServices] of groups) {
    const primary = assignedServices[0];
    const filename = path.join(privateRuntimeDir, primary, "billing-key.json");
    const bundle = readOrCreateBillingBundle(filename, username);
    for (const service of assignedServices) {
      const target = path.join(privateRuntimeDir, service, "billing-key.json");
      installBillingBundle(target, bundle);
      installBillingPrivateKey(path.join(privateRuntimeDir, service, "billing-private.key"), bundle);
      bundles.set(service, Object.freeze({ ...bundle, username }));
    }
    manifest.users.push({
      username,
      user_id: `usr_mock_${username === "demo_user" ? "demo" : username}`,
      key_id: bundle.key_id,
      public_key_hex: bundle.public_key_hex,
      label: bundle.label,
      services: assignedServices,
    });
  }
  const manifestPath = path.join(privateRuntimeDir, "ca", "billing-key-bootstrap.json");
  writeSecureJSON(manifestPath, manifest);
  return bundles;
}

function readOrCreateBillingBundle(filename, username) {
  const existing = readOptionalJSON(filename);
  if (existing !== null) {
    validateBillingBundle(existing, username);
    return existing;
  }
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateJWK = pair.privateKey.export({ format: "jwk" });
  const x = Buffer.from(privateJWK.x, "base64url");
  const y = Buffer.from(privateJWK.y, "base64url");
  const publicKeyHex = Buffer.concat([Buffer.from([4]), x, y]).toString("hex");
  const keyID = crypto.createHash("sha256").update(Buffer.concat([Buffer.from([4]), x, y])).digest("hex");
  const bundle = {
    version: 1,
    key_id: keyID,
    label: `local-chaos-${username}`,
    algorithm: "ECDSA_P256_SHA256",
    private_key_jwk: privateJWK,
    public_key_hex: publicKeyHex,
    charge_endpoint: "/api/v1/billing/charge",
    node_authorization_endpoint: "/v1/node/authorize",
    framework_environment: "BNFS_BILLING_KEY_FILE",
    canonical_format: "CA-BILLING-V1\\n{key_id}\\n{amount_bytes}\\n{unix_timestamp}\\n{nonce}\\n{reference}",
    registration_status: "pending",
    generated_at: new Date().toISOString(),
  };
  writeSecureJSON(filename, bundle);
  return bundle;
}

function validateBillingBundle(bundle, username) {
  if (!bundle || bundle.version !== 1 || bundle.algorithm !== "ECDSA_P256_SHA256"
    || bundle.label !== `local-chaos-${username}` || bundle.registration_status === "unconfirmed"
    || typeof bundle.key_id !== "string" || !/^[0-9a-f]{64}$/.test(bundle.key_id)
    || typeof bundle.public_key_hex !== "string" || !/^04[0-9a-f]{128}$/.test(bundle.public_key_hex)
    || !bundle.private_key_jwk?.d) {
    throw new Error(`invalid billing key bundle for ${username}`);
  }
  const privateKey = crypto.createPrivateKey({ key: bundle.private_key_jwk, format: "jwk" });
  const publicJWK = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  const publicKeyHex = Buffer.concat([
    Buffer.from([4]), Buffer.from(publicJWK.x, "base64url"), Buffer.from(publicJWK.y, "base64url"),
  ]).toString("hex");
  const keyID = crypto.createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex");
  if (publicKeyHex !== bundle.public_key_hex || keyID !== bundle.key_id) {
    throw new Error(`billing key bundle does not match its fingerprint for ${username}`);
  }
}

function installBillingBundle(filename, bundle) {
  const existing = readOptionalJSON(filename);
  if (existing !== null) {
    validateBillingBundle(existing, bundle.label.replace(/^local-chaos-/, ""));
    if (existing.key_id !== bundle.key_id || existing.public_key_hex !== bundle.public_key_hex) {
      throw new Error(`billing key mismatch for ${path.dirname(filename)}`);
    }
  }
  writeSecureJSON(filename, bundle);
}

function installBillingPrivateKey(filename, bundle) {
  const privateScalar = Buffer.from(bundle.private_key_jwk.d, "base64url");
  if (privateScalar.length !== 32) {
    throw new Error(`invalid billing private key for ${path.basename(path.dirname(filename))}`);
  }
  writeSecureFile(filename, `${privateScalar.toString("hex")}\n`);
}

function readOptionalJSON(filename) {
  try {
    const file = fs.lstatSync(filename);
    if (!file.isFile() || file.isSymbolicLink() || file.size > 65536 || (file.mode & 0o077) !== 0) {
      throw new Error(`invalid private JSON file ${filename}`);
    }
    return JSON.parse(fs.readFileSync(filename, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function writeSecureJSON(filename, value) {
  writeSecureFile(filename, `${JSON.stringify(value, null, 2)}\n`);
}

function writeSecureFile(filename, value) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(filename), 0o700);
  const temporary = `${filename}.tmp-${process.pid}`;
  const descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(descriptor, value);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, filename);
  fs.chmodSync(filename, 0o600);
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

function readExternalCredential(filename) {
  if (!path.isAbsolute(filename)) throw new Error("CA admin token file must be absolute");
  const file = fs.lstatSync(filename);
  if ((file.mode & 0o077) !== 0) throw new Error("CA admin token file permissions must be 0600");
  return readCredential(filename);
}

function numberedNames(prefix, count) {
  return Array.from({ length: count }, (_, index) => nodeName(prefix, index + 1));
}

function parseCAClientRoleServices(value) {
  if (value === "") return Object.freeze([]);
  const services = value.split(",");
  if (services.some((service) => !/^natserver(?:0[1-9]|1[0-3])$/.test(service))
    || new Set(services).size !== services.length) {
    throw new Error("BNFS_CHAOS_CA_CLIENT_ROLE_SERVICES must contain distinct natserver service names");
  }
  return Object.freeze(services);
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

function readIPFamilyPlan(filename) {
  if (!filename) return Object.freeze([]);
  const file = fs.lstatSync(filename);
  if (!file.isFile() || file.isSymbolicLink() || file.size > 4096) {
    throw new Error("invalid IP family plan file");
  }
  const lines = fs.readFileSync(filename, "utf8").trim().split(/\r?\n/).filter(Boolean);
  if (lines[0] !== "family\trelay\tnatserver\tnatclient" || lines.length !== 4) {
    throw new Error("invalid IP family plan schema");
  }
  const assignments = lines.slice(1).map((line) => {
    const [family, relay, natserver, natclient, extra] = line.split("\t");
    if (extra !== undefined || !["ipv4", "ipv6", "dual"].includes(family)
      || !/^relay0[3-7]$/.test(relay ?? "")
      || !/^natserver(?:0[1-9]|1[0-3])$/.test(natserver ?? "")
      || !/^natclient0[1-6]$/.test(natclient ?? "")) {
      throw new Error("invalid IP family plan entry");
    }
    return Object.freeze({ family, relay, natserver, natclient });
  });
  if (new Set(assignments.map((assignment) => assignment.family)).size !== 3
    || new Set(assignments.map((assignment) => assignment.relay)).size !== 3
    || new Set(assignments.map((assignment) => assignment.natserver)).size !== 3
    || new Set(assignments.map((assignment) => assignment.natclient)).size !== 3) {
    throw new Error("IP family plan must use distinct IPv4, IPv6 and dual-stack nodes");
  }
  return Object.freeze(assignments);
}

function assignmentForService(name) {
  return ipFamilyPlan.find((assignment) => (
    assignment.relay === name || assignment.natserver === name || assignment.natclient === name
  ));
}

function attachIPFamilyNetwork(service, name) {
  const assignment = assignmentForService(name);
  if (!assignment) return service;
  const spec = ipFamilySpecs[assignment.family];
  const attachments = Array.isArray(service.networks)
    ? Object.fromEntries(service.networks.map((networkName) => [networkName, {}]))
    : { ...service.networks };
  const attachment = {};
  if (name === assignment.relay) {
    if (spec.relayIPv4) attachment.ipv4_address = spec.relayIPv4;
    if (spec.relayIPv6) attachment.ipv6_address = spec.relayIPv6;
  }
  attachments[spec.network] = attachment;
  service.networks = attachments;
  return service;
}

function admissionArgsForService(name) {
  if (!enableCA) return ["-admission", "off"];
  const assignment = assignmentForService(name);
  if (!assignment || name !== assignment.relay) return admissionArgs;
  const spec = ipFamilySpecs[assignment.family];
  const caAddress = assignment.family === "ipv4" || assignment.family === "dual"
    ? spec.caIPv4
    : spec.caIPv6;
  const host = caAddress.includes(":") ? `[${caAddress}]` : caAddress;
  return ["-ca", `http://${host}:9100`, "-admission", "enforce"];
}

function caNetworkAttachments() {
  if (ipFamilyPlan.length === 0) return Object.keys(networks);
  const attachments = Object.fromEntries(Object.keys(networks).map((networkName) => [networkName, {}]));
  for (const assignment of ipFamilyPlan) {
    const spec = ipFamilySpecs[assignment.family];
    const attachment = {};
    if (spec.caIPv4) attachment.ipv4_address = spec.caIPv4;
    if (spec.caIPv6) attachment.ipv6_address = spec.caIPv6;
    attachments[spec.network] = attachment;
  }
  return attachments;
}
