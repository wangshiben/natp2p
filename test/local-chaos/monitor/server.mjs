import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import process from "node:process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const host = process.env.HOST ?? "127.0.0.1";
const port = integer(process.env.PORT, 8911);
const runDir = path.resolve(process.env.RUN_DIR ?? ".");
const composeProject = process.env.COMPOSE_PROJECT ?? "";
const composeFile = path.resolve(process.env.COMPOSE_FILE ?? path.join(runDir, "runtime", "compose.json"));
const caPort = integer(process.env.CA_PORT, 19100);
const htmlPath = new URL("./index.html", import.meta.url);
const relayCount = 7;
const natServerCount = 13;
const natClientCount = 6;
const transferClients = numbered("natclient", natClientCount);
const failureRetentionLimit = 50;
const transferColumns = [
  "timestamp",
  "transfer_id",
  "client",
  "ingress_relay",
  "server",
  "requested_mib",
  "rc",
  "bytes",
  "seconds",
  "mib_per_second",
  "sha256_ok",
];
const expectedServices = [
  "ca",
  "index",
  ...numbered("relay", relayCount),
  ...numbered("natserver", natServerCount),
  ...numbered("natclient", natClientCount),
];

let cachedStatus = null;
let cachedAt = 0;
let refreshPromise = null;
let firewallCache = { key: "", cachedAt: 0, value: new Map() };
let failureEvidenceCache = new Map();
let transferLogCache = emptyTransferLogCache("");

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    if (request.method !== "GET") {
      return json(response, 405, { error: "method_not_allowed" });
    }
    if (url.pathname === "/healthz") {
      return json(response, 200, {
        ok: true,
        timestamp: new Date().toISOString(),
        runDir,
        composeProject,
      });
    }
    if (url.pathname === "/api/status") {
      const status = await statusSnapshot();
      return json(response, 200, status, { "Cache-Control": "no-store" });
    }
    if (url.pathname === "/" || url.pathname === "/index.html") {
      const body = await fs.readFile(htmlPath);
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": body.length,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
      });
      return response.end(body);
    }
    return json(response, 404, { error: "not_found" });
  } catch (error) {
    return json(response, 500, { error: "dashboard_error", detail: String(error?.message ?? error) });
  }
});

server.listen(port, host, () => {
  process.stdout.write(`BNFS stability dashboard listening on http://${host}:${port}/\n`);
});

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}

async function statusSnapshot() {
  const now = Date.now();
  if (cachedStatus && now - cachedAt < 1800) return cachedStatus;
  if (refreshPromise) return refreshPromise;
  refreshPromise = buildStatus()
    .then((value) => {
      cachedStatus = value;
      cachedAt = Date.now();
      return value;
    })
    .finally(() => {
      refreshPromise = null;
    });
  return refreshPromise;
}

async function buildStatus() {
  const [metadata, status, phase, guardStatus, resources, probes, largeProbes, clientTransfers, workers, workload, compose, containers, ca, serverPool, failureWatcher] = await Promise.all([
    readEnv(path.join(runDir, "metadata.env")),
    readEnv(path.join(runDir, "status.env")),
    readText(path.join(runDir, "phase")),
    readText(path.join(runDir, "resource-guard.status")),
    readTsv(path.join(runDir, "resources.tsv"), 240),
    readTsv(path.join(runDir, "probes.tsv"), 30),
    readTsv(path.join(runDir, "large-probes.tsv"), 30),
    readClientTransfers(path.join(runDir, "transfers.tsv")),
    readWorkerStatus(path.join(runDir, "worker-pids.tsv")),
    readEnv(path.join(runDir, "workload.env")),
    readJson(composeFile),
    inspectProjectContainers(),
    probeCA(),
    readTsv(path.join(runDir, "server-pool.tsv"), 100),
    readFailureWatcher(path.join(runDir, "failure-watcher.json")),
  ]);

  const containerMap = new Map(containers.map((item) => [item.service, item]));
  const nodes = expectedServices.map((service) => containerMap.get(service) ?? missingContainer(service));
  for (const item of containers) {
    if (!expectedServices.includes(item.service)) nodes.push(item);
  }

  const nowEpoch = Math.floor(Date.now() / 1000);
  const startedEpoch = integer(metadata.started_epoch, 0);
  const deadlineEpoch = integer(metadata.deadline_epoch, 0);
  const durationSeconds = integer(metadata.duration_seconds, 0);
  const remainingSeconds = deadlineEpoch > 0
    ? Math.max(0, deadlineEpoch - nowEpoch)
    : durationSeconds;
  const core = nodes.filter((item) => item.role === "ca" || item.role === "index" || item.role === "relay");
  const nat = nodes.filter((item) => item.role === "natserver" || item.role === "natclient");
  const activeNatServices = [workload.server, workload.client].filter(Boolean);
  const firewalls = await inspectNatFirewalls(activeNatServices, containerMap);
  const topology = await buildTopology({
    compose,
    metadata,
    workload,
    nodes,
    firewalls,
  });
  const failureAnalysis = await buildFailureAnalysis({
    failures: transferLogCache.failures,
    failureStats: transferLogCache.failureStats,
    ingressStats: transferLogCache.ingressStats,
    available: transferLogCache.available,
    updatedAt: transferLogCache.updatedAt,
    serverPool,
    compose,
  });
  const publicNodes = nodes.map(({ networkAddresses: _networkAddresses, ...node }) => node);

  return {
    generatedAt: new Date().toISOString(),
    phase: phase.trim() || "UNKNOWN",
    metadata,
    status,
    timing: { nowEpoch, startedEpoch, deadlineEpoch, durationSeconds, remainingSeconds },
    thresholds: {
      cpu: number(metadata.cpu_limit_pct, 55),
      memory: number(metadata.memory_limit_pct, 40),
      disk: number(metadata.disk_limit_pct, 40),
    },
    resourceGuard: guardStatus.trim(),
    resources: { latest: resources.at(-1) ?? null, history: resources },
    probes: {
      latest: publicProbe(probes.at(-1)),
      history: probes.map(publicProbe),
    },
    largeProbes: {
      latest: publicProbe(largeProbes.at(-1)),
      history: largeProbes.map(publicProbe),
    },
    clientTransfers,
    workers,
    failureAnalysis,
    failureWatcher,
    ca,
    summary: {
      coreExpected: core.length,
      coreHealthy: core.filter(isHealthy).length,
      natExpected: nat.length,
      natRunning: nat.filter((item) => item.running).length,
      totalExpected: expectedServices.length,
      totalRunning: nodes.filter((item) => item.running).length,
      totalRestarts: nodes.reduce((sum, item) => sum + (item.restartCount ?? 0), 0),
    },
    nodes: publicNodes,
    topology,
  };
}

async function readWorkerStatus(file) {
  const aliveByClient = new Map(transferClients.map((client) => [client, false]));
  const text = await readText(file);
  await Promise.all(text.split(/\r?\n/).map(async (line) => {
    const [client, pidText, starttime] = line.split("\t");
    if (!aliveByClient.has(client) || !/^[1-9][0-9]*$/.test(pidText ?? "")
      || !/^[1-9][0-9]*$/.test(starttime ?? "")) return;
    if (await processIdentityAlive(integer(pidText, 0), starttime)) aliveByClient.set(client, true);
  }));
  const clients = transferClients.map((client) => ({ client, alive: aliveByClient.get(client) === true }));
  return {
    expected: transferClients.length,
    running: clients.filter((worker) => worker.alive).length,
    healthy: clients.every((worker) => worker.alive),
    clients,
  };
}

async function processIdentityAlive(pid, expectedStarttime) {
  if (!Number.isSafeInteger(pid) || pid <= 0 || !/^[1-9][0-9]*$/.test(String(expectedStarttime ?? ""))) {
    return false;
  }
  try {
    const stat = await fs.readFile(`/proc/${pid}/stat`, "utf8");
    const closingParenthesis = stat.lastIndexOf(")");
    if (closingParenthesis < 0) return false;
    const fields = stat.slice(closingParenthesis + 1).trim().split(/\s+/);
    return fields[0] !== "Z" && fields[19] === String(expectedStarttime);
  } catch {
    return false;
  }
}

async function inspectProjectContainers() {
  if (!composeProject) return [];
  try {
    const { stdout: idsOutput } = await execFileAsync(
      "docker",
      ["ps", "-aq", "--filter", `label=com.docker.compose.project=${composeProject}`],
      { timeout: 5000, maxBuffer: 1024 * 1024 },
    );
    const ids = idsOutput.trim().split(/\s+/).filter(Boolean);
    if (ids.length === 0) return [];
    const { stdout } = await execFileAsync("docker", ["inspect", ...ids], {
      timeout: 8000,
      maxBuffer: 8 * 1024 * 1024,
    });
    return JSON.parse(stdout).map((container) => {
      const state = container.State ?? {};
      const service = container.Config?.Labels?.["com.docker.compose.service"] ?? container.Name?.replace(/^\//, "") ?? "unknown";
      return {
        service,
        role: roleOf(service),
        id: String(container.Id ?? "").slice(0, 12),
        name: String(container.Name ?? "").replace(/^\//, ""),
        image: container.Config?.Image ?? "",
        state: state.Status ?? "unknown",
        running: Boolean(state.Running),
        health: state.Health?.Status ?? (state.Running ? "running" : state.Status ?? "unknown"),
        restartCount: integer(container.RestartCount, 0),
        startedAt: state.StartedAt ?? "",
        finishedAt: state.FinishedAt ?? "",
        pid: integer(state.Pid, 0),
        networkAddresses: Object.fromEntries(Object.entries(container.NetworkSettings?.Networks ?? {}).map(([network, settings]) => [
          network,
          String(settings?.IPAddress ?? ""),
        ])),
      };
    }).sort((left, right) => left.service.localeCompare(right.service, "en", { numeric: true }));
  } catch (error) {
    return [{
      service: "docker-inspection",
      role: "diagnostic",
      id: "",
      name: "Docker inspection failed",
      image: "",
      state: "error",
      running: false,
      health: String(error?.message ?? error),
      restartCount: 0,
      startedAt: "",
      finishedAt: "",
      pid: 0,
    }];
  }
}

async function inspectNatFirewalls(services, containerMap) {
  const uniqueServices = [...new Set(services)].filter((service) => {
    const role = roleOf(service);
    return role === "natserver" || role === "natclient";
  });
  const cacheKey = uniqueServices.map((service) => `${service}:${containerMap.get(service)?.id ?? "missing"}`).join("|");
  if (cacheKey === firewallCache.key && Date.now() - firewallCache.cachedAt < 5000) {
    return firewallCache.value;
  }
  const snapshots = await Promise.all(uniqueServices.map(async (service) => {
    const container = containerMap.get(service);
    if (!container?.running || !container.pid) {
      return [service, { available: false, rules: [], error: "container_not_running" }];
    }
    try {
      const { stdout } = await execFileAsync(
        "nsenter",
        ["--target", String(container.pid), "--net", "--", "iptables", "-S", "OUTPUT"],
        { timeout: 4000, maxBuffer: 512 * 1024 },
      );
      return [service, { available: true, rules: parseFirewallRules(stdout), error: "" }];
    } catch (error) {
      return [service, {
        available: false,
        rules: [],
        error: String(error?.message ?? error),
      }];
    }
  }));
  const value = new Map(snapshots);
  firewallCache = { key: cacheKey, cachedAt: Date.now(), value };
  return value;
}

function parseFirewallRules(output) {
  const rules = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line.startsWith("-A OUTPUT ")) continue;
    const protocol = optionValue(line, "-p").toLowerCase() || "all";
    const destination = normalizeCIDR(optionValue(line, "-d") || "0.0.0.0/0");
    const destinationPort = integer(optionValue(line, "--dport"), 0);
    const action = optionValue(line, "-j")?.toUpperCase() ?? "";
    if (!action) continue;
    rules.push({ protocol, destination, destinationPort, action });
  }
  return rules;
}

async function buildTopology({ compose, metadata, workload, nodes, firewalls }) {
  const serviceSpecs = compose?.services && typeof compose.services === "object" ? compose.services : {};
  const networkSpecs = compose?.networks && typeof compose.networks === "object" ? compose.networks : {};
  const nodeMap = new Map(nodes.map((node) => [node.service, node]));
  const serviceNames = [...new Set([...Object.keys(serviceSpecs), ...nodes.map((node) => node.service)])]
    .filter((service) => roleOf(service) !== "diagnostic")
    .sort(serviceSort);
  const memberships = new Map(serviceNames.map((service) => [service, serviceNetworks(serviceSpecs[service])]));
  const relays = serviceNames.filter((service) => roleOf(service) === "relay");
  const nats = serviceNames.filter((service) => ["natserver", "natclient"].includes(roleOf(service)));
  const activeServices = new Set([workload.server, workload.client].filter(Boolean));
  const addressMap = new Map();
  for (const node of nodes) {
    for (const address of Object.values(node.networkAddresses ?? {})) {
      if (address) addressMap.set(address, node.service);
    }
  }

  const topologyNodes = serviceNames.map((service) => {
    const runtime = nodeMap.get(service) ?? missingContainer(service);
    return {
      id: service,
      service,
      role: roleOf(service),
      running: runtime.running,
      health: runtime.health,
      networks: memberships.get(service) ?? [],
      active: activeServices.has(service),
    };
  });

  const topologyNetworks = Object.entries(networkSpecs).map(([id, specification]) => ({
    id,
    internal: Boolean(specification?.internal),
    members: serviceNames.filter((service) => memberships.get(service)?.includes(id)),
  })).sort((left, right) => left.id.localeCompare(right.id, "en", { numeric: true }));

  const reachabilityMatrix = [];
  for (const nat of nats) {
    for (const relay of relays) {
      reachabilityMatrix.push(reachabilityCell({
        nat,
        relay,
        memberships,
        nodeMap,
        firewalls,
      }));
    }
  }
  const reachabilityByNat = Object.fromEntries(nats.map((nat) => [
    nat,
    Object.fromEntries(reachabilityMatrix.filter((cell) => cell.nat === nat).map((cell) => [cell.relay, cell.state])),
  ]));

  const relayControlLinks = relays.map((relay) => {
    const target = commandOption(serviceSpecs[relay]?.command, "-index");
    if (!target) return null;
    const upstream = normalizeRelayReference(target);
    const sharedNetworks = intersection(memberships.get(relay), memberships.get(upstream));
    const runtimeReady = Boolean(nodeMap.get(relay)?.running && nodeMap.get(upstream)?.running);
    return {
      id: `control:${relay}:${upstream}`,
      source: relay,
      target: upstream,
      kind: "relay-control",
      directional: true,
      sharedNetworks,
      state: sharedNetworks.length > 0 && runtimeReady ? "dual" : "blocked",
      stateLabel: sharedNetworks.length > 0 && runtimeReady ? "KCP+TCP" : "blocked",
    };
  }).filter(Boolean);

  const caLinkServices = new Set(serviceNames.filter((service) => {
    if (service === "ca") return false;
    const caURL = commandOption(serviceSpecs[service]?.command, "-ca");
    return normalizeRelayReference(caURL) === "ca";
  }));
  for (const service of activeServices) caLinkServices.add(service);
  const caLinks = [...caLinkServices].map((service) => ({
    id: `admission:${service}:ca`,
    source: service,
    target: "ca",
    kind: "ca-admission",
    directional: true,
    state: nodeMap.get(service)?.running && nodeMap.get("ca")?.running ? "up" : "down",
    stateLabel: nodeMap.get(service)?.running && nodeMap.get("ca")?.running ? "HTTP/TCP" : "blocked",
    protocol: "HTTP/TCP",
  }));

  const natRelayLinks = reachabilityMatrix.filter((cell) => cell.state !== "none").map((cell) => ({
    id: `access:${cell.nat}:${cell.relay}`,
    source: cell.nat,
    target: cell.relay,
    kind: "nat-relay",
    directional: false,
    sharedNetworks: cell.sharedNetworks,
    state: cell.state,
    stateLabel: cell.stateLabel,
    tcp: cell.tcp,
    udp: cell.udp,
    reason: cell.reason,
    evidence: cell.evidence,
  }));

  const [serverLog, clientLog] = await Promise.all([
    readTail(path.join(runDir, "runtime", "stability", `${workload.server ?? ""}.log`), 256 * 1024),
    readTail(path.join(runDir, "runtime", "stability", `${workload.client ?? ""}.log`), 256 * 1024),
  ]);
  const clientRelay = detectActiveRelay({
    service: workload.client,
    log: clientLog,
    addressMap,
    metadata,
    workload,
    reachabilityMatrix,
  });
  const serverRelay = detectActiveRelay({
    service: workload.server,
    log: serverLog,
    addressMap,
    metadata,
    workload,
    reachabilityMatrix,
  });
  const activePath = buildActivePath({
    workload,
    clientRelay,
    serverRelay,
    relayControlLinks,
    reachabilityMatrix,
    nodeMap,
  });
  const activePairs = new Set(activePath.links.map((link) => pairKey(link.source, link.target)));
  const links = [...caLinks, ...relayControlLinks, ...natRelayLinks].map((link) => ({
    ...link,
    active: activePairs.has(pairKey(link.source, link.target)),
  }));

  return {
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    basis: "Compose 网络关系 + 当前业务 NAT 的 iptables 规则（推导，非逐链路主动探测）",
    scenario: String(metadata.scenario ?? ""),
    nodes: topologyNodes,
    networks: topologyNetworks,
    links,
    relayControlLinks,
    reachability: {
      relays,
      nats,
      matrix: reachabilityMatrix,
      byNat: reachabilityByNat,
    },
    activePath,
    diagnostics: {
      composeLoaded: Object.keys(serviceSpecs).length > 0,
      firewallInspection: Object.fromEntries([...firewalls].map(([service, snapshot]) => [service, {
        available: snapshot.available,
        error: snapshot.error,
        ruleCount: snapshot.rules.length,
      }])),
    },
  };
}

function reachabilityCell({ nat, relay, memberships, nodeMap, firewalls }) {
  const sharedNetworks = intersection(memberships.get(nat), memberships.get(relay));
  if (sharedNetworks.length === 0) {
    return {
      nat,
      relay,
      state: "none",
      stateLabel: "no direct network",
      tcp: false,
      udp: false,
      sharedNetworks,
      blockedByRules: [],
      reason: "no_shared_network",
      evidence: "compose_network",
    };
  }

  const natRuntime = nodeMap.get(nat);
  const relayRuntime = nodeMap.get(relay);
  if (!natRuntime?.running || !relayRuntime?.running) {
    return {
      nat,
      relay,
      state: "blocked",
      stateLabel: "blocked",
      tcp: false,
      udp: false,
      sharedNetworks,
      blockedByRules: [],
      reason: !natRuntime?.running ? "nat_not_running" : "relay_not_running",
      evidence: "container_runtime",
    };
  }

  const relayAddresses = Object.values(relayRuntime.networkAddresses ?? {}).filter(Boolean);
  const firewall = firewalls.get(nat);
  if (firewall && !firewall.available) {
    return {
      nat,
      relay,
      state: "unknown",
      stateLabel: "unknown",
      tcp: null,
      udp: null,
      sharedNetworks,
      blockedByRules: [],
      reason: "firewall_inspection_unavailable",
      evidence: "runtime_firewall",
    };
  }
  const tcpResult = protocolReachability(firewall, "tcp", relayAddresses);
  const udpResult = protocolReachability(firewall, "udp", relayAddresses);
  const state = protocolState(tcpResult.allowed, udpResult.allowed);
  return {
    nat,
    relay,
    state,
    stateLabel: protocolStateLabel(state),
    tcp: tcpResult.allowed,
    udp: udpResult.allowed,
    sharedNetworks,
    blockedByRules: [...tcpResult.blockedByRules, ...udpResult.blockedByRules],
    reason: state === "blocked" ? "firewall" : "shared_network",
    evidence: firewall ? "runtime_firewall" : "compose_network",
  };
}

function protocolReachability(firewall, protocol, relayAddresses) {
  if (!firewall?.available) return { allowed: true, blockedByRules: [] };
  for (const rule of firewall.rules) {
    if (rule.protocol !== "all" && rule.protocol !== protocol) continue;
    if (rule.destinationPort !== 0 && rule.destinationPort !== 9000) continue;
    if (!destinationMatches(rule.destination, relayAddresses)) continue;
    if (rule.action === "ACCEPT") return { allowed: true, blockedByRules: [] };
    if (rule.action === "DROP" || rule.action === "REJECT") {
      return { allowed: false, blockedByRules: [rule] };
    }
  }
  return { allowed: true, blockedByRules: [] };
}

function destinationMatches(destination, addresses) {
  if (!destination || destination === "0.0.0.0" || destination === "::") return true;
  return addresses.includes(destination);
}

function protocolState(tcp, udp) {
  if (tcp && udp) return "dual";
  if (tcp) return "tcp-only";
  if (udp) return "kcp-only";
  return "blocked";
}

function protocolStateLabel(state) {
  if (state === "dual") return "KCP+TCP";
  if (state === "tcp-only") return "TCP-only";
  if (state === "kcp-only") return "KCP-only";
  if (state === "none") return "no direct network";
  if (state === "unknown") return "unknown";
  return "blocked";
}

function detectActiveRelay({ service, log, addressMap, metadata, reachabilityMatrix }) {
  if (!service) return "";
  let detected = "";
  for (const line of log.split(/\r?\n/)) {
    const match = line.match(/(?:使用指定 relay|注册到 relay):\s*([^\s,;]+)/i);
    if (!match) continue;
    const host = normalizeRelayReference(match[1]);
    const resolved = roleOf(host) === "relay" ? host : addressMap.get(host);
    if (resolved && roleOf(resolved) === "relay") detected = resolved;
  }
  if (detected) return detected;

  const scenarioFallbacks = {
    "1": { natclient02: "relay01", natserver04: "relay03" },
    "2": { natclient04: "relay02", natserver02: "relay02" },
    "3": { natclient05: "relay01", natserver03: "relay03" },
  };
  const fallback = scenarioFallbacks[String(metadata.scenario ?? "")]?.[service];
  if (fallback) return fallback;

  return reachabilityMatrix.find((cell) => cell.nat === service && ["dual", "tcp-only", "kcp-only"].includes(cell.state))?.relay ?? "";
}

function buildActivePath({ workload, clientRelay, serverRelay, relayControlLinks, reachabilityMatrix, nodeMap }) {
  const client = workload.client ?? "";
  const server = workload.server ?? "";
  if (!client || !server) {
    return {
      state: "pending",
      transport: "unknown",
      client,
      server,
      clientRelay,
      serverRelay,
      nodes: [],
      links: [],
      label: "",
    };
  }
  if (!clientRelay || !serverRelay) {
    return {
      state: "unknown",
      transport: "unknown",
      client,
      server,
      clientRelay,
      serverRelay,
      nodes: [client, server],
      links: [],
      label: "entry Relay unresolved",
    };
  }

  const relayRoute = shortestRelayRoute(clientRelay, serverRelay, relayControlLinks);
  const routeResolved = clientRelay === serverRelay || relayRoute.at(-1) === serverRelay;
  const relayHops = routeResolved ? relayRoute : [...new Set([clientRelay, serverRelay])];
  const pathNodes = [client, ...relayHops, server].filter((service, index, values) => index === 0 || service !== values[index - 1]);
  const links = [];
  for (let index = 0; index < pathNodes.length - 1; index += 1) {
    const source = pathNodes[index];
    const target = pathNodes[index + 1];
    const sourceRole = roleOf(source);
    const targetRole = roleOf(target);
    const nat = sourceRole.startsWith("nat") ? source : targetRole.startsWith("nat") ? target : "";
    const relay = sourceRole === "relay" ? source : targetRole === "relay" ? target : "";
    const access = nat && relay
      ? reachabilityMatrix.find((cell) => cell.nat === nat && cell.relay === relay)
      : null;
    const control = sourceRole === "relay" && targetRole === "relay"
      ? relayControlLinks.find((link) => pairKey(link.source, link.target) === pairKey(source, target))
      : null;
    links.push({
      source,
      target,
      kind: access ? "nat-relay" : "relay-control",
      state: access?.state ?? control?.state ?? "blocked",
    });
  }

  const endpointCells = [
    reachabilityMatrix.find((cell) => cell.nat === client && cell.relay === clientRelay),
    reachabilityMatrix.find((cell) => cell.nat === server && cell.relay === serverRelay),
  ].filter(Boolean);
  const transport = endpointCells.some((cell) => cell.state === "blocked" || cell.state === "none")
    ? "unavailable"
    : endpointCells.some((cell) => cell.state === "unknown")
      ? "unknown"
      : endpointCells.some((cell) => cell.state === "tcp-only")
        ? "tcp"
        : endpointCells.some((cell) => cell.state === "kcp-only")
          ? "kcp"
          : "kcp+tcp";
  const allRunning = pathNodes.every((service) => nodeMap.get(service)?.running);
  const allLinksReachable = links.every((link) => ["dual", "tcp-only", "kcp-only", "up"].includes(link.state));
  return {
    state: routeResolved && allRunning && allLinksReachable ? "active" : "blocked",
    transport,
    client,
    server,
    clientRelay,
    serverRelay,
    nodes: pathNodes,
    links,
    label: clientRelay === serverRelay
      ? `单 Relay：${clientRelay}`
      : routeResolved
        ? `跨 Relay：${clientRelay} → ${serverRelay}`
        : `Relay 路由不可达：${clientRelay} → ${serverRelay}`,
  };
}

function shortestRelayRoute(start, target, relayControlLinks) {
  if (!start || !target) return [];
  if (start === target) return [start];
  const neighbors = new Map();
  for (const link of relayControlLinks) {
    if (roleOf(link.source) !== "relay" || roleOf(link.target) !== "relay") continue;
    addNeighbor(neighbors, link.source, link.target);
    addNeighbor(neighbors, link.target, link.source);
  }
  const queue = [[start]];
  const visited = new Set([start]);
  while (queue.length > 0) {
    const route = queue.shift();
    const current = route.at(-1);
    for (const next of neighbors.get(current) ?? []) {
      if (visited.has(next)) continue;
      const candidate = [...route, next];
      if (next === target) return candidate;
      visited.add(next);
      queue.push(candidate);
    }
  }
  return [];
}

function addNeighbor(neighbors, source, target) {
  if (!neighbors.has(source)) neighbors.set(source, []);
  neighbors.get(source).push(target);
}

function commandOption(command, option) {
  if (!Array.isArray(command)) return "";
  const index = command.indexOf(option);
  return index >= 0 ? String(command[index + 1] ?? "") : "";
}

function serviceNetworks(service) {
  const networks = service?.networks;
  if (Array.isArray(networks)) return [...networks];
  if (networks && typeof networks === "object") return Object.keys(networks);
  return [];
}

function intersection(left = [], right = []) {
  const rightSet = new Set(right);
  return left.filter((value) => rightSet.has(value));
}

function normalizeRelayReference(value) {
  let reference = String(value ?? "").trim().replace(/[),;]+$/, "");
  if (!reference) return "";
  if (reference.includes("://")) {
    try {
      return new URL(reference).hostname;
    } catch {
      return "";
    }
  }
  if (reference.startsWith("[")) return reference.slice(1, reference.indexOf("]"));
  return reference.replace(/:\d+$/, "");
}

function normalizeCIDR(value) {
  const text = String(value ?? "");
  if (text === "0.0.0.0/0") return "0.0.0.0";
  if (text === "::/0") return "::";
  return text.replace(/\/32$/, "").replace(/\/128$/, "");
}

function optionValue(line, option) {
  const escaped = option.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return line.match(new RegExp(`(?:^|\\s)${escaped}\\s+(?:"([^"]*)"|'([^']*)'|(\\S+))`))?.slice(1).find((value) => value !== undefined) ?? "";
}

function pairKey(left, right) {
  return [left, right].sort().join("|");
}

function serviceSort(left, right) {
  const roleOrder = { ca: 0, index: 1, relay: 2, natserver: 3, natclient: 4, diagnostic: 5 };
  return (roleOrder[roleOf(left)] ?? 9) - (roleOrder[roleOf(right)] ?? 9)
    || left.localeCompare(right, "en", { numeric: true });
}

async function probeCA() {
  const started = process.hrtime.bigint();
  return new Promise((resolve) => {
    const request = http.get({ hostname: "127.0.0.1", port: caPort, path: "/pubkey", timeout: 1800 }, (response) => {
      let bytes = 0;
      response.on("data", (chunk) => { bytes += chunk.length; });
      response.on("end", () => resolve({
        reachable: response.statusCode === 200,
        statusCode: response.statusCode ?? 0,
        latencyMs: elapsedMs(started),
        responseBytes: bytes,
      }));
    });
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", (error) => resolve({
      reachable: false,
      statusCode: 0,
      latencyMs: elapsedMs(started),
      error: String(error.message ?? error),
    }));
  });
}

async function readEnv(file) {
  const text = await readText(file);
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const index = line.indexOf("=");
    if (index <= 0) continue;
    values[line.slice(0, index)] = line.slice(index + 1);
  }
  return values;
}

async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return {};
  }
}

async function readClientTransfers(file) {
  let stat;
  try {
    stat = await fs.stat(file);
  } catch {
    transferLogCache = emptyTransferLogCache(file);
    failureEvidenceCache = new Map();
    return transferLogSnapshot(transferLogCache);
  }

  const identity = `${stat.dev}:${stat.ino}`;
  if (transferLogCache.file !== file
    || transferLogCache.identity !== identity
    || stat.size < transferLogCache.size) {
    transferLogCache = emptyTransferLogCache(file, identity);
    failureEvidenceCache = new Map();
  }
  transferLogCache.available = true;
  transferLogCache.updatedAt = stat.mtime.toISOString();

  if (stat.size > transferLogCache.size) {
    const start = transferLogCache.size;
    const length = stat.size - start;
    const buffer = Buffer.alloc(length);
    const handle = await fs.open(file, "r");
    let bytesRead = 0;
    try {
      while (bytesRead < length) {
        const result = await handle.read(buffer, bytesRead, length - bytesRead, start + bytesRead);
        if (result.bytesRead === 0) break;
        bytesRead += result.bytesRead;
      }
    } finally {
      await handle.close();
    }
    await consumeTransferLog(transferLogCache, buffer.subarray(0, bytesRead).toString("utf8"));
    transferLogCache.size += bytesRead;
  }

  return transferLogSnapshot(transferLogCache);
}

function emptyTransferLogCache(file, identity = "") {
  return {
    file,
    identity,
    size: 0,
    available: false,
    updatedAt: "",
    header: null,
    remainder: "",
    summary: emptyTransferStats(),
    failures: [],
    failureStats: emptyFailureStats(),
    ingressStats: new Map(),
    seenTransfers: new Set(),
    clients: new Map(transferClients.map((client) => [client, {
      summary: emptyTransferStats(),
      recent: [],
    }])),
  };
}

async function consumeTransferLog(cache, appendedText) {
  const lines = `${cache.remainder}${appendedText}`.split(/\n/);
  cache.remainder = lines.pop() ?? "";
  for (let line of lines) {
    line = line.replace(/\r$/, "");
    if (!line) continue;
    if (!cache.header) {
      cache.header = line.replace(/^\uFEFF/, "").split("\t");
      continue;
    }
    const values = line.split("\t");
    const parsed = Object.fromEntries(cache.header.map((name, index) => [name, values[index] ?? ""]));
    if (parsed.timestamp === "timestamp" && parsed.client === "client") continue;
    const clientState = cache.clients.get(parsed.client);
    if (!clientState) continue;
    const transfer = Object.fromEntries(transferColumns.map((name) => [name, parsed[name] ?? ""]));
    const transferKey = transfer.transfer_id || [
      transfer.timestamp,
      transfer.client,
      transfer.server,
      transfer.requested_mib,
      transfer.rc,
      transfer.bytes,
    ].join("\u0000");
    if (cache.seenTransfers.has(transferKey)) continue;
    cache.seenTransfers.add(transferKey);
    clientState.recent.unshift(transfer);
    if (clientState.recent.length > 10) clientState.recent.length = 10;
    updateTransferStats(clientState.summary, transfer);
    updateTransferStats(cache.summary, transfer);
    updateIngressStats(cache.ingressStats, transfer);
    if (!transferSucceeded(transfer)) await recordFailure(cache, transfer);
  }
}

function emptyFailureStats() {
  return {
    total: 0,
    clients: new Set(),
    servers: new Set(),
    ingressCounts: new Map(),
    pathCounts: new Map(),
    causeCounts: new Map(),
    handshakeByClient: new Map(),
    dataStalls: [],
  };
}

async function recordFailure(cache, transfer) {
  const metrics = transferFailureMetrics(transfer);
  const classification = await inspectFailureEvidence(transfer, metrics);
  const stats = cache.failureStats;
  const client = publicService(transfer.client, "natclient");
  const ingressRelay = publicService(transfer.ingress_relay, "relay");
  const serverName = publicService(transfer.server, "natserver");
  stats.total += 1;
  if (client !== "unknown") stats.clients.add(client);
  if (serverName !== "unknown") stats.servers.add(serverName);
  stats.ingressCounts.set(ingressRelay, (stats.ingressCounts.get(ingressRelay) ?? 0) + 1);
  const pathKey = JSON.stringify([ingressRelay, serverName]);
  stats.pathCounts.set(pathKey, (stats.pathCounts.get(pathKey) ?? 0) + 1);
  stats.causeCounts.set(classification.cause, (stats.causeCounts.get(classification.cause) ?? 0) + 1);
  if (classification.flags.handshake && client !== "unknown") {
    stats.handshakeByClient.set(client, (stats.handshakeByClient.get(client) ?? 0) + 1);
  }
  if (classification.flags.dataStall) {
    stats.dataStalls.push({
      timestampEpoch: Date.parse(publicTimestamp(transfer.timestamp)) || 0,
      client,
      ingressRelay,
      server: serverName,
    });
    if (stats.dataStalls.length > failureRetentionLimit) stats.dataStalls.shift();
  }
  cache.failures.push(transfer);
  if (cache.failures.length > failureRetentionLimit) cache.failures.shift();
}

function updateIngressStats(stats, transfer) {
  const relay = validService(transfer.ingress_relay, "relay") ? transfer.ingress_relay : "unknown";
  const current = stats.get(relay) ?? { total: 0, succeeded: 0, failed: 0 };
  const succeeded = transferSucceeded(transfer);
  current.total += 1;
  current.succeeded += succeeded ? 1 : 0;
  current.failed += succeeded ? 0 : 1;
  stats.set(relay, current);
}

function emptyTransferStats() {
  return {
    totalTransfers: 0,
    succeeded: 0,
    failed: 0,
    sha256Correct: 0,
    sha256Incorrect: 0,
    totalBytes: 0,
    totalRequestedMiB: 0,
    totalSeconds: 0,
    throughputSum: 0,
    throughputSamples: 0,
    latestTimestamp: "",
  };
}

function updateTransferStats(stats, transfer) {
  const bytes = Math.max(0, number(transfer.bytes, 0));
  const seconds = Math.max(0, number(transfer.seconds, 0));
  const requestedMiB = Math.max(0, number(transfer.requested_mib, 0));
  const recordedThroughput = number(transfer.mib_per_second, Number.NaN);
  const throughput = Number.isFinite(recordedThroughput)
    ? Math.max(0, recordedThroughput)
    : seconds > 0
      ? bytes / 1048576 / seconds
      : Number.NaN;
  const sha256State = transferSha256State(transfer.sha256_ok);
  const succeeded = transferSucceeded(transfer);

  stats.totalTransfers += 1;
  stats.succeeded += succeeded ? 1 : 0;
  stats.failed += succeeded ? 0 : 1;
  stats.sha256Correct += sha256State === true ? 1 : 0;
  stats.sha256Incorrect += sha256State === false ? 1 : 0;
  stats.totalBytes += bytes;
  stats.totalRequestedMiB += requestedMiB;
  stats.totalSeconds += seconds;
  if (Number.isFinite(throughput)) {
    stats.throughputSum += throughput;
    stats.throughputSamples += 1;
  }
  if (transfer.timestamp) stats.latestTimestamp = transfer.timestamp;
}

function transferSucceeded(transfer) {
  return String(transfer.rc) === "0" && transferSha256State(transfer.sha256_ok) === true;
}

function transferSha256State(value) {
  const state = String(value ?? "").trim().toLowerCase();
  if (["1", "yes", "true", "ok", "pass", "passed", "correct"].includes(state)) return true;
  if (["0", "no", "false", "fail", "failed", "incorrect", "mismatch"].includes(state)) return false;
  return null;
}

function publicTransferStats(stats) {
  return {
    totalTransfers: stats.totalTransfers,
    succeeded: stats.succeeded,
    failed: stats.failed,
    sha256Correct: stats.sha256Correct,
    sha256Incorrect: stats.sha256Incorrect,
    totalBytes: stats.totalBytes,
    totalMiB: stats.totalBytes / 1048576,
    totalRequestedMiB: stats.totalRequestedMiB,
    totalSeconds: stats.totalSeconds,
    averageMiBPerSecond: stats.throughputSamples > 0 ? stats.throughputSum / stats.throughputSamples : 0,
    latestTimestamp: stats.latestTimestamp,
  };
}

function transferLogSnapshot(cache) {
  const byClient = Object.fromEntries(transferClients.map((client) => {
    const state = cache.clients.get(client);
    return [client, {
      summary: publicTransferStats(state.summary),
      recent: state.recent.map(publicRecentTransfer),
    }];
  }));
  const summary = publicTransferStats(cache.summary);
  summary.clientCount = transferClients.length;
  summary.activeClients = transferClients.filter((client) => cache.clients.get(client).summary.totalTransfers > 0).length;
  return {
    source: "transfers.tsv",
    available: cache.available,
    updatedAt: cache.updatedAt,
    summary,
    byClient,
  };
}

function publicRecentTransfer(transfer) {
  const {
    transfer_id: _transferId,
    expected_sha: _expectedSha,
    actual_sha: _actualSha,
    ...publicTransfer
  } = transfer;
  return publicTransfer;
}

function publicProbe(probe) {
  if (!probe) return null;
  const {
    expected_sha: _expectedSha,
    actual_sha: _actualSha,
    ...publicValue
  } = probe;
  if (/^\d{16,}-natclient\d{2}$/.test(String(publicValue.label ?? ""))) {
    publicValue.label = "random-transfer";
  }
  return publicValue;
}

async function readFailureWatcher(file) {
  const value = await readJson(file);
  if (value.schemaVersion !== 1) {
    return {
      schemaVersion: 1,
      available: false,
      status: "NOT_STARTED",
      healthy: false,
      startedAt: "",
      monitoringSince: "",
      heartbeatAt: "",
      lastScanAt: "",
      source: { name: "transfers.tsv", available: false, lagBytes: 0 },
      baseline: { transferRecords: 0, failureRecords: 0 },
      observed: { transferRecords: 0, failureRecords: 0, newFailureRecords: 0 },
      alerts: { limit: 0, total: 0, retained: 0, lastAlertAt: "", recent: [] },
      lastError: null,
    };
  }

  const heartbeatAt = publicTimestamp(value.heartbeatAt);
  const heartbeatEpoch = Date.parse(heartbeatAt);
  const status = ["STARTING", "RUNNING", "WAITING_FOR_SOURCE", "DEGRADED", "STOPPED", "FAILED"]
    .includes(value.status) ? value.status : "UNKNOWN";
  const heartbeatFresh = Number.isFinite(heartbeatEpoch) && Date.now() - heartbeatEpoch <= 15000;
  const recent = Array.isArray(value.alerts?.recent)
    ? value.alerts.recent.map(publicWatcherAlert).filter(Boolean).slice(0, 100)
    : [];
  const sourceSize = Math.max(0, integer(value.source?.sizeBytes, 0));
  const sourceOffset = Math.max(0, integer(value.source?.offsetBytes, 0));
  const sourceAvailable = Boolean(value.source?.available);
  const sourceCursorValid = sourceOffset <= sourceSize;
  const sourceLagBytes = Math.max(0, sourceSize - sourceOffset);
  const lastErrorCode = safeDiagnosticLabel(value.lastError?.code);

  return {
    schemaVersion: 1,
    available: true,
    status,
    healthy: status === "RUNNING" && heartbeatFresh && sourceAvailable
      && sourceCursorValid && sourceLagBytes === 0,
    startedAt: publicTimestamp(value.startedAt),
    monitoringSince: publicTimestamp(value.monitoringSince),
    heartbeatAt,
    lastScanAt: publicTimestamp(value.lastScanAt),
    source: {
      name: "transfers.tsv",
      available: sourceAvailable,
      lagBytes: sourceLagBytes,
    },
    baseline: {
      transferRecords: Math.max(0, integer(value.baseline?.transferRecords, 0)),
      failureRecords: Math.max(0, integer(value.baseline?.failureRecords, 0)),
    },
    observed: {
      transferRecords: Math.max(0, integer(value.observed?.transferRecords, 0)),
      failureRecords: Math.max(0, integer(value.observed?.failureRecords, 0)),
      newFailureRecords: Math.max(0, integer(value.observed?.newFailureRecords, 0)),
    },
    alerts: {
      limit: Math.max(0, integer(value.alerts?.limit, 0)),
      total: Math.max(0, integer(value.alerts?.total, 0)),
      retained: recent.length,
      lastAlertAt: publicTimestamp(value.alerts?.lastAlertAt),
      recent,
    },
    lastError: lastErrorCode
      ? { at: publicTimestamp(value.lastError?.at), code: lastErrorCode }
      : null,
  };
}

function publicWatcherAlert(value) {
  if (!value || typeof value !== "object") return null;
  const categoryMessages = {
    handshake_first_frame_contamination: "隧道建立前出现握手首帧公钥解析异常",
    data_path_stall: "业务传输收到部分数据后停滞至超时",
    client_tunnel_not_ready: "客户端隧道未在就绪窗口完成建立",
    server_registration_failed: "服务端身份或 Relay 注册检查失败",
    client_entry_relay_unresolved: "客户端入口 Relay 未能识别",
    transfer_failed: "传输失败，等待进一步诊断",
  };
  const allowedStages = new Set(["tunnel_setup", "data_transfer", "registration", "ingress_detection", "unknown"]);
  const allowedSignals = new Set([
    "public_key_parser_rejected_N",
    "kcp_reconnect_timeout",
    "resume_leg_slot_occupied",
    "curl_900s_timeout",
  ]);
  const category = Object.hasOwn(categoryMessages, value.category) ? value.category : "transfer_failed";
  const client = publicService(value.client, "natclient");
  const ingressRelay = publicService(value.ingressRelay, "relay");
  const server = publicService(value.server, "natserver");
  const serverRelay = publicService(value.serverRelay, "relay");
  const progressPct = Math.min(100, Math.max(0, number(value.progressPct, 0)));
  return {
    sequence: Math.max(0, integer(value.sequence, 0)),
    observedAt: publicTimestamp(value.observedAt),
    timestamp: publicTimestamp(value.timestamp),
    severity: value.severity === "critical" ? "critical" : "warning",
    category,
    stage: allowedStages.has(value.stage) ? value.stage : "unknown",
    message: categoryMessages[category],
    client,
    ingressRelay,
    server,
    serverRelay,
    route: [client, ingressRelay, serverRelay, server],
    rc: integer(value.rc, -1),
    requestedMiB: round(Math.max(0, number(value.requestedMiB, 0)), 3),
    bytes: Math.max(0, integer(value.bytes, 0)),
    seconds: round(Math.max(0, number(value.seconds, 0)), 3),
    progressPct: round(progressPct, 2),
    signals: Array.isArray(value.signals)
      ? value.signals.filter((signal) => allowedSignals.has(signal))
      : [],
  };
}

function safeDiagnosticLabel(value) {
  const label = String(value ?? "");
  return /^[a-z][a-z0-9_]{0,63}$/.test(label) ? label : "";
}

function transferFailureMetrics(transfer) {
  const requestedMiB = Math.max(0, number(transfer.requested_mib, 0));
  const bytes = Math.max(0, integer(transfer.bytes, 0));
  const seconds = Math.max(0, number(transfer.seconds, 0));
  const expectedBytes = requestedMiB * 1048576;
  const progressPct = expectedBytes > 0
    ? round(Math.min(100, bytes / expectedBytes * 100), 2)
    : 0;
  return { requestedMiB, bytes, seconds, expectedBytes, progressPct };
}

async function buildFailureAnalysis({ failures, failureStats, ingressStats, available, updatedAt, serverPool, compose }) {
  const serverRelays = new Map();
  for (const row of serverPool) {
    if (!validService(row.server, "natserver") || !validService(row.ingress_relay, "relay")) continue;
    serverRelays.set(row.server, row.ingress_relay);
  }
  const relayPartitions = composeRelayPartitions(compose);
  const analyzed = await Promise.all(failures.map(async (transfer) => {
    const client = publicService(transfer.client, "natclient");
    const ingressRelay = publicService(transfer.ingress_relay, "relay");
    const targetServer = publicService(transfer.server, "natserver");
    const serverRelay = publicService(serverRelays.get(targetServer), "relay");
    const partition = relayPartitionLabel(relayPartitions.get(serverRelay));
    const ingressPartition = relayPartitionLabel(relayPartitions.get(ingressRelay));
    const metrics = transferFailureMetrics(transfer);
    const classification = await inspectFailureEvidence(transfer, metrics);
    const publicFailure = {
      timestamp: publicTimestamp(transfer.timestamp),
      client,
      ingressRelay,
      server: targetServer,
      serverRelay,
      partition,
      route: [
        {
          id: client,
          label: client,
          role: "natclient",
          network: sharedServiceNetwork(compose, client, ingressRelay),
        },
        {
          id: ingressRelay,
          label: ingressRelay,
          role: "relay",
          bridge: ingressPartition === "bridge",
          partition: ingressPartition,
          network: sharedServiceNetwork(compose, ingressRelay, serverRelay),
        },
        {
          id: serverRelay,
          label: serverRelay,
          role: "relay",
          partition,
          network: sharedServiceNetwork(compose, serverRelay, targetServer),
        },
        {
          id: targetServer,
          label: targetServer,
          role: "natserver",
        },
      ],
      rc: integer(transfer.rc, -1),
      requestedMiB: metrics.requestedMiB,
      bytes: metrics.bytes,
      seconds: round(metrics.seconds, 3),
      progressPct: metrics.progressPct,
      cause: classification.cause,
      diagnosis: classification.diagnosis,
      evidence: classification.evidence,
    };
    return {
      publicFailure,
      timestampEpoch: Date.parse(publicFailure.timestamp) || 0,
    };
  }));
  analyzed.sort((left, right) => right.timestampEpoch - left.timestampEpoch);

  const affectedClients = sortedServices(failureStats.clients);
  const affectedServers = sortedServices(failureStats.servers);
  const ingressCounts = failureStats.ingressCounts;
  const partitionCounts = { A: 0, B: 0, bridge: 0, unknown: 0 };
  let crossRelay = 0;
  for (const [pathKey, count] of failureStats.pathCounts) {
    const [ingressRelay, targetServer] = JSON.parse(pathKey);
    const serverRelay = publicService(serverRelays.get(targetServer), "relay");
    const partition = relayPartitionLabel(relayPartitions.get(serverRelay));
    const partitionKey = ["A", "B", "bridge"].includes(partition) ? partition : "unknown";
    partitionCounts[partitionKey] += count;
    if (ingressRelay !== "unknown" && serverRelay !== "unknown" && ingressRelay !== serverRelay) {
      crossRelay += count;
    }
  }
  const causeCounts = Object.fromEntries([...failureStats.causeCounts]
    .sort(([left], [right]) => left.localeCompare(right, "en")));
  const commonIngress = [...ingressCounts.entries()]
    .filter(([relay]) => relay !== "unknown")
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0], "en", { numeric: true }))[0];
  const commonIngressRuntime = commonIngress ? ingressStats.get(commonIngress[0]) : null;
  const commonIngressRelay = commonIngress && commonIngress[1] >= 2
    ? {
        relay: commonIngress[0],
        failures: commonIngress[1],
        sharePct: round(commonIngress[1] / Math.max(1, failureStats.total) * 100, 1),
        successfulTransfers: commonIngressRuntime?.succeeded ?? 0,
      }
    : null;
  const summary = {
    totalFailures: failureStats.total,
    affectedClients,
    affectedServers,
    crossRelay,
    commonIngressRelay,
    partitionCounts,
    causeCounts,
  };
  const historicalStalls = failureStats.dataStalls.map((item) => ({
    ...item,
    serverRelay: publicService(serverRelays.get(item.server), "relay"),
  }));

  return {
    schemaVersion: 1,
    available,
    updatedAt,
    generatedAt: new Date().toISOString(),
    metadata: {
      source: "transfers.tsv + server-pool.tsv + transfer-logs/ + transfer-errors/",
      totalFailureRecords: failureStats.total,
      retainedFailureRecords: analyzed.length,
      retentionLimit: failureRetentionLimit,
    },
    summary,
    patterns: detectFailurePatterns(summary, failureStats.handshakeByClient, historicalStalls),
    failures: analyzed.map((item) => item.publicFailure),
  };
}

async function inspectFailureEvidence(transfer, metrics) {
  const transferId = safeFileComponent(transfer.transfer_id);
  const cacheKey = transferId || [
    transfer.timestamp,
    transfer.client,
    transfer.server,
    transfer.rc,
    transfer.bytes,
  ].join("\u0000");
  if (failureEvidenceCache.has(cacheKey)) return failureEvidenceCache.get(cacheKey);

  let clientLog = "";
  let serverLog = "";
  let errorLog = "";
  if (transferId) {
    const client = safeFileComponent(transfer.client);
    [clientLog, serverLog, errorLog] = await Promise.all([
      readTail(path.join(runDir, "transfer-logs", `${transferId}-client.log`), 256 * 1024),
      readTail(path.join(runDir, "transfer-logs", `${transferId}-server.log`), 256 * 1024),
      client
        ? readTail(path.join(runDir, "transfer-errors", `${client}-${transferId}.log`), 64 * 1024)
        : "",
    ]);
  }
  const classification = classifyFailure({ transfer, metrics, clientLog, serverLog, errorLog });
  failureEvidenceCache.set(cacheKey, classification);
  if (failureEvidenceCache.size > failureRetentionLimit) {
    failureEvidenceCache.delete(failureEvidenceCache.keys().next().value);
  }
  return classification;
}

function classifyFailure({ transfer, metrics, clientLog, serverLog, errorLog }) {
  const rc = integer(transfer.rc, -1);
  const hasHandshakeContamination = /invalid byte:?\s*U\+004E\s*['"]N['"]/i.test(serverLog);
  const hasKcpReconnectTimeout = /KCP[^\n]*(?:context deadline exceeded|重连拨号失败)/i.test(clientLog);
  const hasResumeSlotConflict = /resume leg slot occupied|resume[^\n]*slot[^\n]*occupied/i.test(`${clientLog}\n${serverLog}`);
  const hasCurl900Timeout = /curl:\s*\(28\)[^\n]*(?:900000|900001)\s+milliseconds/i.test(errorLog);
  const partial = metrics.bytes > 0 && metrics.expectedBytes > metrics.bytes;
  const reachedTransferTimeout = metrics.seconds >= 899 && partial;

  if (hasHandshakeContamination) {
    return {
      cause: "handshake_first_frame_contamination",
      diagnosis: "代码级门控回归已确认：Relay 在同步转发客户端公钥前提前启动 frame pump 并返回 ACK，随后到达的 Noise hello 越过公钥；服务端因此在十六进制公钥位置读到首字符 N。",
      evidence: [
        "server snapshot: peer public-key parser rejected U+004E ('N')",
        `client tunnel readiness failed (rc=${rc})`,
        "root-cause regression: ACK/frame pump preceded the forwarded public key",
      ],
      flags: { handshake: true, dataStall: false },
    };
  }

  if (reachedTransferTimeout && (hasCurl900Timeout || metrics.seconds >= 900)) {
    const evidence = [
      "curl reached the 900-second limit with a partial payload",
      `received ${metrics.bytes} of ${metrics.expectedBytes} bytes (${metrics.progressPct}%)`,
    ];
    if (hasKcpReconnectTimeout) evidence.push("client snapshot contains KCP reconnect timeouts");
    if (hasResumeSlotConflict) evidence.push("endpoint snapshot contains a Resume leg slot conflict");
    return {
      cause: "data_path_stall",
      diagnosis: "Relay 日志时序与回归已确认：KCP accept 循环曾串行等待半开连接首帧，形成最长 60 秒的队头阻塞；初始 KCP 未建立后仍保留的重连拨号又持续产生 Resume leg，放大积压并使已建立的数据路径停滞至 900 秒超时。",
      evidence,
      flags: { handshake: false, dataStall: true },
    };
  }

  const fallbacks = {
    2: {
      cause: "client_tunnel_not_ready",
      diagnosis: "客户端隧道未在就绪窗口内完成建立，传输流程未进入数据请求阶段。",
      evidence: ["harness readiness fallback rc=2", `received ${metrics.bytes} bytes`],
    },
    3: {
      cause: "server_registration_failed",
      diagnosis: "服务端重启后的身份或 Relay 注册检查未通过，传输流程未启动客户端数据请求。",
      evidence: ["harness registration fallback rc=3", `received ${metrics.bytes} bytes`],
    },
    4: {
      cause: "client_entry_relay_unresolved",
      diagnosis: "客户端看似就绪，但未能在观察窗口内解析出实际入口 Relay，因此传输被中止。",
      evidence: ["harness ingress detection fallback rc=4", `received ${metrics.bytes} bytes`],
    },
  };
  if (fallbacks[rc]) {
    return {
      ...fallbacks[rc],
      flags: { handshake: false, dataStall: false },
    };
  }

  if (rc === 0 && transferSha256State(transfer.sha256_ok) === false) {
    return {
      cause: "integrity_mismatch",
      diagnosis: "传输命令已返回成功，但接收大小或 SHA-256 校验未通过。",
      evidence: [`received ${metrics.bytes} of ${metrics.expectedBytes} bytes`, "sha256_ok=no"],
      flags: { handshake: false, dataStall: false },
    };
  }

  return {
    cause: partial ? "partial_transfer_failure" : "transfer_failed",
    diagnosis: partial
      ? "传输收到部分数据后失败，现有脱敏证据不足以进一步归因。"
      : "传输流程失败，现有脱敏证据不足以进一步归因。",
    evidence: [`process rc=${rc}`, `received ${metrics.bytes} bytes`, `elapsed ${round(metrics.seconds, 3)} seconds`],
    flags: { handshake: false, dataStall: false },
  };
}

function detectFailurePatterns(summary, handshakeByClient, dataStalls) {
  const patterns = [];
  const commonIngress = summary.commonIngressRelay;
  if (commonIngress) {
    const successContext = commonIngress.successfulTransfers > 0
      ? `；该入口同时承载 ${commonIngress.successfulTransfers} 条成功传输`
      : "";
    patterns.push({
      type: "common_ingress_relay",
      severity: "observe",
      title: `失败共同经过 ${commonIngress.relay}`,
      description: `${commonIngress.failures} 条失败共享同一实际入口 Relay${successContext}。这是共同路径和候选故障域，不是单因果结论。`,
      count: commonIngress.failures,
      services: [commonIngress.relay],
    });
  }

  if (summary.partitionCounts.A > 0 && summary.partitionCounts.B > 0) {
    patterns.push({
      type: "cross_partition_distribution",
      severity: "observe",
      title: "失败横跨 A/B 服务端分区",
      description: `分区 A 有 ${summary.partitionCounts.A} 条，分区 B 有 ${summary.partitionCounts.B} 条，故障并非只集中在单一服务端分区。`,
      count: summary.partitionCounts.A + summary.partitionCounts.B,
      services: [],
    });
  }

  for (const [client, failureCount] of handshakeByClient) {
    if (client === "unknown" || failureCount < 2) continue;
    patterns.push({
      type: "client_handshake_cluster",
      severity: "warning",
      title: `${client} 出现握手首帧异常聚集`,
      description: `${failureCount} 条失败命中相同的公钥解析特征；门控回归已复现 Relay 提前 ACK/启动 frame pump，使 Noise hello 越过公钥首帧。`,
      count: failureCount,
      services: [client],
    });
  }

  const stallCluster = closestFailureCluster(
    dataStalls.filter((failure) => failure.timestampEpoch > 0),
    120,
  );
  if (stallCluster.length >= 2) {
    const epochs = stallCluster.map((item) => item.timestampEpoch);
    const spanSeconds = Math.round((Math.max(...epochs) - Math.min(...epochs)) / 1000);
    patterns.push({
      type: "simultaneous_data_stalls",
      severity: "warning",
      title: "多条数据路径近同时停滞",
      description: `${stallCluster.length} 条部分传输在 ${spanSeconds} 秒窗口内进入同一停滞时段；Relay 日志已确认 KCP accept 的串行首帧等待造成队头阻塞，并被无效 KCP Resume 重连放大。`,
      count: stallCluster.length,
      services: sortedServices(new Set(stallCluster.flatMap((item) => [item.client, item.server, item.ingressRelay, item.serverRelay]).filter((service) => service !== "unknown"))),
      windowSeconds: spanSeconds,
    });
  }
  return patterns;
}

function closestFailureCluster(failures, windowSeconds) {
  const sorted = [...failures].sort((left, right) => left.timestampEpoch - right.timestampEpoch);
  let best = [];
  let left = 0;
  for (let right = 0; right < sorted.length; right += 1) {
    while (sorted[right].timestampEpoch - sorted[left].timestampEpoch > windowSeconds * 1000) left += 1;
    const candidate = sorted.slice(left, right + 1);
    if (candidate.length > best.length) best = candidate;
  }
  return best;
}

function composeRelayPartitions(compose) {
  const partitions = new Map();
  for (const [service, specification] of Object.entries(compose?.services ?? {})) {
    if (!validService(service, "relay")) continue;
    const networks = serviceNetworks(specification);
    const values = [];
    if (networks.includes("control_partition_a")) values.push("A");
    if (networks.includes("control_partition_b")) values.push("B");
    partitions.set(service, values);
  }
  return partitions;
}

function sharedServiceNetwork(compose, left, right) {
  const services = compose?.services ?? {};
  return intersection(serviceNetworks(services[left]), serviceNetworks(services[right]))
    .sort((first, second) => first.localeCompare(second, "en", { numeric: true }))[0] ?? "";
}

function relayPartitionLabel(partitions = []) {
  if (partitions.length === 1) return partitions[0];
  if (partitions.includes("A") && partitions.includes("B")) return "bridge";
  return "unknown";
}

function sortedServices(services) {
  return [...services].sort(serviceSort);
}

function validService(value, role) {
  const service = String(value ?? "");
  const patterns = {
    relay: /^relay\d{2}$/,
    natserver: /^natserver\d{2}$/,
    natclient: /^natclient\d{2}$/,
  };
  return Boolean(patterns[role]?.test(service));
}

function publicService(value, role) {
  return validService(value, role) ? String(value) : "unknown";
}

function safeFileComponent(value) {
  const component = String(value ?? "");
  return /^[A-Za-z0-9._-]+$/.test(component) ? component : "";
}

function publicTimestamp(value) {
  const timestamp = String(value ?? "");
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/.test(timestamp)
    ? timestamp
    : "";
}

function round(value, digits) {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

async function readTsv(file, limit) {
  const text = await readTail(file, 256 * 1024);
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return [];
  const header = lines[0].split("\t");
  return lines.slice(Math.max(1, lines.length - limit)).map((line) => {
    const values = line.split("\t");
    return Object.fromEntries(header.map((name, index) => [name, values[index] ?? ""]));
  });
}

async function readTail(file, maxBytes) {
  try {
    const handle = await fs.open(file, "r");
    try {
      const stat = await handle.stat();
      const start = Math.max(0, stat.size - maxBytes);
      const buffer = Buffer.alloc(stat.size - start);
      await handle.read(buffer, 0, buffer.length, start);
      let text = buffer.toString("utf8");
      if (start > 0) {
        const newline = text.indexOf("\n");
        text = newline >= 0 ? text.slice(newline + 1) : "";
        const header = await readHeader(file);
        text = `${header}\n${text}`;
      }
      return text;
    } finally {
      await handle.close();
    }
  } catch {
    return "";
  }
}

async function readHeader(file) {
  try {
    const handle = await fs.open(file, "r");
    try {
      const buffer = Buffer.alloc(4096);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      return buffer.subarray(0, bytesRead).toString("utf8").split(/\r?\n/, 1)[0];
    } finally {
      await handle.close();
    }
  } catch {
    return "";
  }
}

async function readText(file) {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return "";
  }
}

function missingContainer(service) {
  return {
    service,
    role: roleOf(service),
    id: "",
    name: service,
    image: "",
    state: "missing",
    running: false,
    health: "missing",
    restartCount: 0,
    startedAt: "",
    finishedAt: "",
    pid: 0,
    networkAddresses: {},
  };
}

function roleOf(service) {
  if (service === "ca" || service === "index") return service;
  if (service.startsWith("relay")) return "relay";
  if (service.startsWith("natserver")) return "natserver";
  if (service.startsWith("natclient")) return "natclient";
  return "diagnostic";
}

function isHealthy(node) {
  return node.running && (node.health === "healthy" || node.health === "running");
}

function numbered(prefix, count) {
  return Array.from({ length: count }, (_, index) => `${prefix}${String(index + 1).padStart(2, "0")}`);
}

function elapsedMs(started) {
  return Number(process.hrtime.bigint() - started) / 1e6;
}

function integer(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function number(value, fallback) {
  const parsed = Number.parseFloat(String(value ?? ""));
  return Number.isFinite(parsed) ? parsed : fallback;
}

function json(response, statusCode, value, headers = {}) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  response.end(body);
}
