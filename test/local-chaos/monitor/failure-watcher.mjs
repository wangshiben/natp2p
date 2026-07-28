import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

process.umask(0o077);

const runDir = path.resolve(process.env.RUN_DIR ?? "");
const pollIntervalMs = boundedInteger(process.env.POLL_INTERVAL_MS, 1000, 50, 10000);
const heartbeatIntervalMs = boundedInteger(process.env.HEARTBEAT_INTERVAL_MS, 5000, 100, 60000);
const alertLimit = boundedInteger(process.env.ALERT_LIMIT, 20, 1, 100);
const watchPid = boundedInteger(process.env.WATCH_PID, 0, 0, Number.MAX_SAFE_INTEGER);
const transfersPath = path.join(runDir, "transfers.tsv");
const serverPoolPath = path.join(runDir, "server-pool.tsv");
const phasePath = path.join(runDir, "phase");
const snapshotPath = path.join(runDir, "failure-watcher.json");
const statusPath = path.join(runDir, "failure-watcher.status");
const alertPath = path.join(runDir, "failure-watcher.alert");
const lockPath = path.join(runDir, "failure-watcher.lock");
const requiredColumns = [
  "timestamp",
  "transfer_id",
  "client",
  "ingress_relay",
  "server",
  "requested_mib",
  "rc",
  "bytes",
  "seconds",
  "sha256_ok",
];
const terminalPhases = new Set(["COMPLETED", "FAILED", "RESOURCE_LIMIT", "STOPPED"]);
const readChunkBytes = 256 * 1024;

let lockHandle;
let stopping = false;
let stopReason = "";
let header = [];
let lastSnapshotWrite = 0;
let snapshot = emptySnapshot();

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    stopping = true;
    stopReason = signal.toLowerCase();
  });
}

try {
  validateConfiguration();
  await acquireLock();
  await restoreSnapshot();
  await scanTransfers();
  if (snapshot.observed.newFailureRecords > 0) await publishFailureSentinel();
  await publishSnapshot(true);
  process.stdout.write(`BNFS failure watcher running for ${path.basename(runDir)}\n`);

  while (!stopping) {
    await delay(pollIntervalMs);
    if (await watchedRunnerExited()) {
      stopping = true;
      stopReason = "runner_exited";
      break;
    }
    const phase = (await readText(phasePath)).trim();
    if (terminalPhases.has(phase)) {
      stopping = true;
      stopReason = `phase_${phase.toLowerCase()}`;
      break;
    }
    try {
      await scanTransfers();
      snapshot.status = snapshot.source.available ? "RUNNING" : "WAITING_FOR_SOURCE";
      snapshot.lastError = null;
    } catch (error) {
      snapshot.status = "DEGRADED";
      snapshot.lastError = {
        at: new Date().toISOString(),
        code: failureCode(error),
      };
    }
    await publishSnapshot(false);
  }

  snapshot.status = "STOPPED";
  snapshot.stopReason = stopReason || "requested";
  await publishSnapshot(true);
} catch (error) {
  snapshot.status = "FAILED";
  snapshot.lastError = {
    at: new Date().toISOString(),
    code: failureCode(error),
  };
  if (lockHandle) {
    try {
      await publishSnapshot(true);
    } catch {
      // The primary error is reported below.
    }
  }
  process.stderr.write(`failure watcher failed: ${safeErrorMessage(error)}\n`);
  process.exitCode = 1;
} finally {
  if (lockHandle) {
    await lockHandle.close().catch(() => {});
    await fs.unlink(lockPath).catch(() => {});
  }
}

function validateConfiguration() {
  if (!process.env.RUN_DIR || runDir === path.parse(runDir).root) {
    throw codedError("invalid_run_dir", "RUN_DIR must identify one run directory");
  }
  if (watchPid === process.pid) {
    throw codedError("invalid_watch_pid", "WATCH_PID must not be the watcher PID");
  }
}

function emptySnapshot() {
  const now = new Date().toISOString();
  return {
    schemaVersion: 1,
    status: "STARTING",
    startedAt: now,
    monitoringSince: "",
    heartbeatAt: now,
    lastScanAt: "",
    stopReason: "",
    source: {
      name: "transfers.tsv",
      identity: "",
      available: false,
      sizeBytes: 0,
      offsetBytes: 0,
    },
    baseline: {
      transferRecords: 0,
      failureRecords: 0,
    },
    observed: {
      transferRecords: 0,
      failureRecords: 0,
      newFailureRecords: 0,
    },
    alerts: {
      limit: alertLimit,
      total: 0,
      retained: 0,
      lastAlertAt: "",
      recent: [],
    },
    lastError: null,
  };
}

async function acquireLock() {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      lockHandle = await fs.open(lockPath, "wx", 0o600);
      await lockHandle.writeFile(`${JSON.stringify({ pid: process.pid, startedAt: snapshot.startedAt })}\n`);
      return;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const owner = await readJson(lockPath);
      if (processAlive(integer(owner.pid, 0))) {
        throw codedError("watcher_already_running", "another failure watcher owns the run lock");
      }
      await fs.unlink(lockPath).catch(() => {});
    }
  }
  throw codedError("watcher_lock_failed", "unable to acquire failure watcher lock");
}

async function restoreSnapshot() {
  const restored = await readJson(snapshotPath);
  if (restored.schemaVersion !== 1 || restored.source?.name !== "transfers.tsv") return;
  snapshot = {
    ...emptySnapshot(),
    monitoringSince: publicTimestamp(restored.monitoringSince),
    source: {
      ...emptySnapshot().source,
      identity: String(restored.source?.identity ?? ""),
      available: Boolean(restored.source?.available),
      sizeBytes: nonnegativeInteger(restored.source?.sizeBytes),
      offsetBytes: nonnegativeInteger(restored.source?.offsetBytes),
    },
    baseline: {
      transferRecords: nonnegativeInteger(restored.baseline?.transferRecords),
      failureRecords: nonnegativeInteger(restored.baseline?.failureRecords),
    },
    observed: {
      transferRecords: nonnegativeInteger(restored.observed?.transferRecords),
      failureRecords: nonnegativeInteger(restored.observed?.failureRecords),
      newFailureRecords: nonnegativeInteger(restored.observed?.newFailureRecords),
    },
    alerts: restoreAlerts(restored.alerts),
  };
}

function restoreAlerts(value = {}) {
  const recent = Array.isArray(value.recent)
    ? value.recent.map(publicAlert).filter(Boolean).slice(0, alertLimit)
    : [];
  return {
    limit: alertLimit,
    total: Math.max(nonnegativeInteger(value.total), recent.length),
    retained: recent.length,
    lastAlertAt: publicTimestamp(value.lastAlertAt),
    recent,
  };
}

async function scanTransfers() {
  let stat;
  try {
    stat = await fs.stat(transfersPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    snapshot.source.available = false;
    snapshot.status = "WAITING_FOR_SOURCE";
    snapshot.lastScanAt = new Date().toISOString();
    return;
  }

  const identity = `${stat.dev}:${stat.ino}`;
  const canResume = snapshot.source.identity === identity
    && snapshot.source.offsetBytes <= stat.size
    && snapshot.monitoringSince;
  header = await readHeaderColumns();
  validateHeader(header);

  if (!canResume) {
    snapshot = {
      ...emptySnapshot(),
      source: {
        name: "transfers.tsv",
        identity,
        available: true,
        sizeBytes: stat.size,
        offsetBytes: 0,
      },
    };
    const baselineEnd = stat.size;
    await readUntil(baselineEnd, false);
    snapshot.baseline.transferRecords = snapshot.observed.transferRecords;
    snapshot.baseline.failureRecords = snapshot.observed.failureRecords;
    snapshot.monitoringSince = new Date().toISOString();
  } else {
    snapshot.source.available = true;
    snapshot.source.sizeBytes = stat.size;
    await readUntil(stat.size, true);
  }

  snapshot.source.sizeBytes = stat.size;
  snapshot.lastScanAt = new Date().toISOString();
  snapshot.status = "RUNNING";
}

async function readUntil(endOffset, emitAlerts) {
  const handle = await fs.open(transfersPath, "r");
  try {
    while (snapshot.source.offsetBytes < endOffset) {
      const requested = Math.min(readChunkBytes, endOffset - snapshot.source.offsetBytes);
      const buffer = Buffer.alloc(requested);
      const { bytesRead } = await handle.read(buffer, 0, requested, snapshot.source.offsetBytes);
      if (bytesRead === 0) break;
      const content = buffer.subarray(0, bytesRead);
      const newline = content.lastIndexOf(0x0a);
      if (newline < 0) break;
      const complete = content.subarray(0, newline + 1).toString("utf8");
      let alertAdded = false;
      for (const line of complete.split(/\n/)) {
        if (!line) continue;
        if (await consumeLine(line.replace(/\r$/, ""), emitAlerts)) alertAdded = true;
      }
      snapshot.source.offsetBytes += newline + 1;
      if (alertAdded) {
        await publishFailureSentinel();
        await publishSnapshot(true);
      }
    }
  } finally {
    await handle.close();
  }
}

async function consumeLine(line, emitAlerts) {
  if (line.startsWith("timestamp\ttransfer_id\t")) return false;
  const values = line.split("\t");
  const transfer = Object.fromEntries(header.map((name, index) => [name, values[index] ?? ""]));
  if (!publicTimestamp(transfer.timestamp)) return false;
  snapshot.observed.transferRecords += 1;
  if (transferSucceeded(transfer)) return false;
  snapshot.observed.failureRecords += 1;
  if (!emitAlerts) return false;

  const alert = await buildAlert(transfer);
  snapshot.observed.newFailureRecords += 1;
  snapshot.alerts.total += 1;
  snapshot.alerts.lastAlertAt = alert.observedAt;
  snapshot.alerts.recent.unshift(alert);
  snapshot.alerts.recent = snapshot.alerts.recent.slice(0, alertLimit);
  snapshot.alerts.retained = snapshot.alerts.recent.length;
  return true;
}

async function buildAlert(transfer) {
  const observedAt = new Date().toISOString();
  const client = serviceName(transfer.client, "natclient");
  const ingressRelay = serviceName(transfer.ingress_relay, "relay");
  const server = serviceName(transfer.server, "natserver");
  const serverRelay = await targetRelay(server);
  const requestedMiB = nonnegativeNumber(transfer.requested_mib);
  const bytes = nonnegativeInteger(transfer.bytes);
  const seconds = nonnegativeNumber(transfer.seconds);
  const expectedBytes = requestedMiB * 1048576;
  const progressPct = expectedBytes > 0 ? Math.min(100, bytes / expectedBytes * 100) : 0;
  const signals = await inspectSignals(transfer, client);
  const classification = classifyFailure(transfer, { bytes, seconds, expectedBytes }, signals);
  return {
    sequence: snapshot.alerts.total + 1,
    observedAt,
    timestamp: publicTimestamp(transfer.timestamp),
    severity: classification.severity,
    category: classification.category,
    stage: classification.stage,
    message: classification.message,
    client,
    ingressRelay,
    server,
    serverRelay,
    route: [client, ingressRelay, serverRelay, server],
    rc: integer(transfer.rc, -1),
    requestedMiB: round(requestedMiB, 3),
    bytes,
    seconds: round(seconds, 3),
    progressPct: round(progressPct, 2),
    signals,
  };
}

async function inspectSignals(transfer, client) {
  const transferId = safeFileComponent(transfer.transfer_id);
  if (!transferId || client === "unknown") return [];
  const [clientLog, serverLog, errorLog] = await Promise.all([
    readTail(path.join(runDir, "transfer-logs", `${transferId}-client.log`), 256 * 1024),
    readTail(path.join(runDir, "transfer-logs", `${transferId}-server.log`), 256 * 1024),
    readTail(path.join(runDir, "transfer-errors", `${client}-${transferId}.log`), 64 * 1024),
  ]);
  const endpointLogs = `${clientLog}\n${serverLog}`;
  const signals = [];
  if (/invalid byte(?::?\s*U\+004E)?\s*['"]N['"]/i.test(serverLog)) signals.push("public_key_parser_rejected_N");
  if (/KCP[^\n]*(?:context deadline exceeded|重连拨号失败)/i.test(endpointLogs)) signals.push("kcp_reconnect_timeout");
  if (/resume leg slot (?:already )?occupied/i.test(endpointLogs)) signals.push("resume_leg_slot_occupied");
  if (/curl:\s*\(28\)[^\n]*(?:900000|900001)\s+milliseconds/i.test(errorLog)) signals.push("curl_900s_timeout");
  return signals;
}

function classifyFailure(transfer, metrics, signals) {
  const rc = integer(transfer.rc, -1);
  if (signals.includes("public_key_parser_rejected_N")) {
    return {
      severity: "critical",
      category: "handshake_first_frame_contamination",
      stage: "tunnel_setup",
      message: "隧道建立前出现握手首帧公钥解析异常",
    };
  }
  if (metrics.bytes > 0 && metrics.expectedBytes > metrics.bytes && metrics.seconds >= 899) {
    return {
      severity: "critical",
      category: "data_path_stall",
      stage: "data_transfer",
      message: "业务传输收到部分数据后停滞至超时",
    };
  }
  const fallbacks = {
    2: ["client_tunnel_not_ready", "tunnel_setup", "客户端隧道未在就绪窗口完成建立"],
    3: ["server_registration_failed", "registration", "服务端身份或 Relay 注册检查失败"],
    4: ["client_entry_relay_unresolved", "ingress_detection", "客户端入口 Relay 未能识别"],
  };
  const fallback = fallbacks[rc];
  return fallback
    ? { severity: "warning", category: fallback[0], stage: fallback[1], message: fallback[2] }
    : { severity: "warning", category: "transfer_failed", stage: "unknown", message: "传输失败，等待进一步诊断" };
}

async function targetRelay(server) {
  if (server === "unknown") return "unknown";
  const text = await readText(serverPoolPath);
  for (const line of text.split(/\r?\n/)) {
    const [candidate, relay] = line.split("\t");
    if (candidate === server) return serviceName(relay, "relay");
  }
  return "unknown";
}

async function publishSnapshot(force) {
  const now = Date.now();
  if (!force && now - lastSnapshotWrite < heartbeatIntervalMs) return;
  snapshot.heartbeatAt = new Date(now).toISOString();
  snapshot.alerts.limit = alertLimit;
  snapshot.alerts.retained = snapshot.alerts.recent.length;
  await writeJsonAtomic(snapshotPath, snapshot);
  await writeStatusAtomic();
  lastSnapshotWrite = now;
}

async function publishFailureSentinel() {
  await writeJsonAtomic(alertPath, {
    schemaVersion: 1,
    status: "FAILURE_DETECTED",
    detectedAt: snapshot.alerts.lastAlertAt || new Date().toISOString(),
    newFailureRecords: snapshot.observed.newFailureRecords,
  });
}

async function writeStatusAtomic() {
  const heartbeatEpoch = Math.floor(Date.parse(snapshot.heartbeatAt) / 1000) || 0;
  const lines = [
    "schema_version=1",
    `status=${safeLabel(String(snapshot.status).toLowerCase()).toUpperCase()}`,
    `heartbeat_epoch=${heartbeatEpoch}`,
    `source_available=${snapshot.source.available ? 1 : 0}`,
    `source_size_bytes=${nonnegativeInteger(snapshot.source.sizeBytes)}`,
    `source_offset_bytes=${nonnegativeInteger(snapshot.source.offsetBytes)}`,
    `new_failure_records=${nonnegativeInteger(snapshot.observed.newFailureRecords)}`,
  ];
  const temporary = `${statusPath}.tmp-${process.pid}`;
  await fs.writeFile(temporary, `${lines.join("\n")}\n`, { mode: 0o600 });
  await fs.rename(temporary, statusPath);
}

async function writeJsonAtomic(file, value) {
  const temporary = `${file}.tmp-${process.pid}`;
  await fs.writeFile(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await fs.rename(temporary, file);
}

async function readHeaderColumns() {
  const headerLine = await readFirstLine(transfersPath, 4096);
  return headerLine.replace(/^\uFEFF/, "").split("\t");
}

function validateHeader(columns) {
  if (!requiredColumns.every((column) => columns.includes(column))) {
    throw codedError("invalid_transfer_header", "transfers.tsv is missing required columns");
  }
}

async function readFirstLine(file, maxBytes) {
  const handle = await fs.open(file, "r");
  try {
    const buffer = Buffer.alloc(maxBytes);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).toString("utf8").split(/\r?\n/, 1)[0];
  } finally {
    await handle.close();
  }
}

async function readTail(file, maxBytes) {
  try {
    const handle = await fs.open(file, "r");
    try {
      const stat = await handle.stat();
      const start = Math.max(0, stat.size - maxBytes);
      const buffer = Buffer.alloc(stat.size - start);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, start);
      return buffer.subarray(0, bytesRead).toString("utf8");
    } finally {
      await handle.close();
    }
  } catch {
    return "";
  }
}

async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return {};
  }
}

async function readText(file) {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return "";
  }
}

async function watchedRunnerExited() {
  return watchPid > 0 && !processAlive(watchPid);
}

function processAlive(pid) {
  if (pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function transferSucceeded(transfer) {
  return integer(transfer.rc, -1) === 0 && String(transfer.sha256_ok).trim().toLowerCase() === "yes";
}

function publicAlert(value) {
  if (!value || typeof value !== "object") return null;
  const categoryMessages = {
    handshake_first_frame_contamination: "隧道建立前出现握手首帧公钥解析异常",
    data_path_stall: "业务传输收到部分数据后停滞至超时",
    client_tunnel_not_ready: "客户端隧道未在就绪窗口完成建立",
    server_registration_failed: "服务端身份或 Relay 注册检查失败",
    client_entry_relay_unresolved: "客户端入口 Relay 未能识别",
    transfer_failed: "传输失败，等待进一步诊断",
  };
  const client = serviceName(value.client, "natclient");
  const ingressRelay = serviceName(value.ingressRelay, "relay");
  const server = serviceName(value.server, "natserver");
  const serverRelay = serviceName(value.serverRelay, "relay");
  const allowedSignals = new Set([
    "public_key_parser_rejected_N",
    "kcp_reconnect_timeout",
    "resume_leg_slot_occupied",
    "curl_900s_timeout",
  ]);
  const category = Object.hasOwn(categoryMessages, value.category) ? value.category : "transfer_failed";
  return {
    sequence: nonnegativeInteger(value.sequence),
    observedAt: publicTimestamp(value.observedAt),
    timestamp: publicTimestamp(value.timestamp),
    severity: ["critical", "warning"].includes(value.severity) ? value.severity : "warning",
    category,
    stage: safeLabel(value.stage),
    message: categoryMessages[category],
    client,
    ingressRelay,
    server,
    serverRelay,
    route: [client, ingressRelay, serverRelay, server],
    rc: integer(value.rc, -1),
    requestedMiB: round(nonnegativeNumber(value.requestedMiB), 3),
    bytes: nonnegativeInteger(value.bytes),
    seconds: round(nonnegativeNumber(value.seconds), 3),
    progressPct: round(Math.min(100, nonnegativeNumber(value.progressPct)), 2),
    signals: Array.isArray(value.signals) ? value.signals.filter((signal) => allowedSignals.has(signal)) : [],
  };
}

function publicTimestamp(value) {
  const timestamp = String(value ?? "");
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/.test(timestamp)
    ? timestamp
    : "";
}

function serviceName(value, role) {
  const service = String(value ?? "");
  const patterns = {
    relay: /^relay\d{2}$/,
    natserver: /^(?:natserver\d{2}|malicious-random-natserver)$/,
    natclient: /^(?:natclient\d{2}|malicious-natclient)$/,
  };
  return patterns[role]?.test(service) ? service : "unknown";
}

function safeFileComponent(value) {
  const component = String(value ?? "");
  return /^[A-Za-z0-9._-]+$/.test(component) ? component : "";
}

function safeLabel(value) {
  const label = String(value ?? "");
  return /^[a-z][a-z0-9_]{0,63}$/.test(label) ? label : "unknown";
}

function failureCode(error) {
  return safeLabel(error?.failureCode || error?.code || "watcher_error");
}

function codedError(code, message) {
  const error = new Error(message);
  error.failureCode = code;
  return error;
}

function safeErrorMessage(error) {
  return String(error?.message ?? error).replaceAll(runDir, "<run-dir>").slice(0, 240);
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function integer(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function nonnegativeInteger(value) {
  return Math.max(0, integer(value, 0));
}

function nonnegativeNumber(value) {
  const parsed = Number.parseFloat(String(value ?? ""));
  return Number.isFinite(parsed) ? Math.max(0, parsed) : 0;
}

function round(value, digits) {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
