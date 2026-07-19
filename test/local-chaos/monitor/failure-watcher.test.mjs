import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const watcherPath = fileURLToPath(new URL("./failure-watcher.mjs", import.meta.url));
const dashboardPath = fileURLToPath(new URL("./server.mjs", import.meta.url));
const header = "timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n";

test("baselines historical failures and retains only bounded redacted live alerts", async (context) => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-failure-watcher-"));
  let child;
  let dashboard;
  context.after(async () => {
    if (child?.exitCode === null) child.kill("SIGKILL");
    if (dashboard?.exitCode === null) dashboard.kill("SIGKILL");
    await fs.rm(runDir, { recursive: true, force: true });
  });

  const historicalSecret = "historical-secret-transfer-id";
  const expectedHash = "a".repeat(64);
  const actualHash = "b".repeat(64);
  await fs.mkdir(path.join(runDir, "transfer-logs"));
  await fs.mkdir(path.join(runDir, "transfer-errors"));
  await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
  await fs.writeFile(path.join(runDir, "server-pool.tsv"), "server\tingress_relay\tnode_id\nnatserver09\trelay06\t" + "c".repeat(64) + "\n");
  await fs.writeFile(path.join(runDir, "transfers.tsv"), header
    + `2026-07-18T12:00:00+08:00\tok-1\tnatclient01\trelay01\tnatserver09\t100\t0\t104857600\t20.0\t5.0\tyes\t${expectedHash}\t${expectedHash}\n`
    + `2026-07-18T12:01:00+08:00\t${historicalSecret}\tnatclient03\trelay01\tnatserver09\t100\t2\t0\t0\t0\tnot-run\t${expectedHash}\t${actualHash}\n`);

  child = spawnWatcher(runDir);

  const baseline = await waitForSnapshot(runDir, (value) => value.status === "RUNNING");
  assert.deepEqual(baseline.baseline, { transferRecords: 2, failureRecords: 1 });
  assert.equal(baseline.observed.newFailureRecords, 0);
  assert.equal(baseline.alerts.total, 0);
  assert.deepEqual(baseline.alerts.recent, []);
  const baselineStatus = await waitForStatus(runDir, (value) => value.status === "RUNNING");
  assert.equal(baselineStatus.source_available, "1");
  assert.equal(baselineStatus.new_failure_records, "0");

  const firstId = "live-first-secret-id";
  await fs.writeFile(path.join(runDir, "transfer-logs", `${firstId}-client.log`), "client not ready\n");
  await fs.writeFile(path.join(runDir, "transfer-logs", `${firstId}-server.log`), "Listen exit: encoding/hex: invalid byte U+004E 'N'\n");
  await fs.appendFile(path.join(runDir, "transfers.tsv"),
    `2026-07-18T12:02:00+08:00\t${firstId}\tnatclient03\trelay01\tnatserver09\t127\t2\t0\t0\t0\tnot-run\t${expectedHash}\t${actualHash}\n`);

  const firstAlert = await waitForSnapshot(runDir, (value) => value.alerts?.total === 1);
  assert.equal(firstAlert.alerts.recent[0].category, "handshake_first_frame_contamination");
  assert.deepEqual(firstAlert.alerts.recent[0].route, ["natclient03", "relay01", "relay06", "natserver09"]);
  const failureStatus = await waitForStatus(runDir, (value) => value.new_failure_records === "1");
  assert.equal(failureStatus.status, "RUNNING");
  const sentinel = JSON.parse(await fs.readFile(path.join(runDir, "failure-watcher.alert"), "utf8"));
  assert.equal(sentinel.status, "FAILURE_DETECTED");
  assert.equal(sentinel.newFailureRecords, 1);

  await fs.appendFile(path.join(runDir, "transfers.tsv"),
    `2026-07-18T12:03:00+08:00\tlive-second-secret-id\tnatclient04\trelay01\tnatserver09\t100\t1\t1048576\t900\t0\tno\t${expectedHash}\t${actualHash}\n`
    + `2026-07-18T12:04:00+08:00\tlive-third-secret-id\tnatclient06\trelay01\tnatserver09\t100\t4\t0\t0\t0\tnot-run\t${expectedHash}\t${actualHash}\n`);

  const bounded = await waitForSnapshot(runDir, (value) => value.alerts?.total === 3);
  assert.equal(bounded.observed.failureRecords, 4);
  assert.equal(bounded.observed.newFailureRecords, 3);
  assert.equal(bounded.alerts.retained, 2);
  assert.deepEqual(bounded.alerts.recent.map((alert) => alert.sequence), [3, 2]);
  const serialized = JSON.stringify(bounded);
  for (const secret of [historicalSecret, firstId, "live-second-secret-id", "live-third-secret-id", expectedHash, actualHash, "c".repeat(64)]) {
    assert.equal(serialized.includes(secret), false, `snapshot leaked ${secret}`);
  }

  child.kill("SIGTERM");
  await waitForExit(child);
  let stopped = JSON.parse(await fs.readFile(path.join(runDir, "failure-watcher.json"), "utf8"));
  assert.equal(stopped.status, "STOPPED");

  await fs.appendFile(path.join(runDir, "transfers.tsv"),
    `2026-07-18T12:05:00+08:00\tdowntime-secret-id\tnatclient02\trelay01\tnatserver09\t100\t2\t0\t0\t0\tnot-run\t${expectedHash}\t${actualHash}\n`);
  child = spawnWatcher(runDir);
  const recovered = await waitForSnapshot(runDir, (value) => value.status === "RUNNING" && value.alerts?.total === 4);
  assert.equal(recovered.baseline.failureRecords, 1);
  assert.equal(recovered.observed.newFailureRecords, 4);
  assert.equal(recovered.alerts.recent[0].sequence, 4);
  assert.ok(Buffer.byteLength(JSON.stringify(recovered)) < 16384);
  assert.equal(JSON.stringify(recovered).includes("downtime-secret-id"), false);

  const dashboardPort = await freePort();
  dashboard = spawn(process.execPath, [dashboardPath], {
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(dashboardPort),
      RUN_DIR: runDir,
      COMPOSE_PROJECT: "",
      COMPOSE_FILE: path.join(runDir, "runtime", "compose.json"),
      CA_PORT: "1",
    },
    stdio: "ignore",
  });
  const api = await waitForApi(dashboardPort);
  assert.equal(api.failureWatcher.healthy, true);
  assert.deepEqual(api.failureWatcher.baseline, { transferRecords: 2, failureRecords: 1 });
  assert.equal(api.failureWatcher.observed.newFailureRecords, 4);
  assert.equal(api.failureWatcher.alerts.total, 4);
  assert.equal(api.failureWatcher.alerts.recent.length, 2);
  const publicApi = JSON.stringify(api.failureWatcher);
  for (const secret of [historicalSecret, firstId, "live-second-secret-id", "live-third-secret-id", "downtime-secret-id", expectedHash, actualHash, "c".repeat(64)]) {
    assert.equal(publicApi.includes(secret), false, `API leaked ${secret}`);
  }
  dashboard.kill("SIGTERM");
  await waitForExit(dashboard);

  child.kill("SIGTERM");
  await waitForExit(child);
  stopped = JSON.parse(await fs.readFile(path.join(runDir, "failure-watcher.json"), "utf8"));
  assert.equal(stopped.status, "STOPPED");
});

test("a competing watcher cannot overwrite the active watcher's healthy snapshot", async (context) => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-failure-watcher-lock-"));
  let owner;
  let contender;
  context.after(async () => {
    if (owner?.exitCode === null) owner.kill("SIGKILL");
    if (contender?.exitCode === null) contender.kill("SIGKILL");
    await fs.rm(runDir, { recursive: true, force: true });
  });

  await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
  await fs.writeFile(path.join(runDir, "server-pool.tsv"), "server\tingress_relay\tnode_id\n");
  await fs.writeFile(path.join(runDir, "transfers.tsv"), header);
  owner = spawnWatcher(runDir);
  const healthy = await waitForSnapshot(runDir, (value) => value.status === "RUNNING");

  contender = spawnWatcher(runDir);
  const contenderExit = await waitForExit(contender);
  assert.equal(contenderExit.code, 1);
  await new Promise((resolve) => setTimeout(resolve, 150));

  const afterConflict = JSON.parse(await fs.readFile(path.join(runDir, "failure-watcher.json"), "utf8"));
  assert.equal(afterConflict.status, "RUNNING");
  assert.equal(afterConflict.startedAt, healthy.startedAt);
  const lock = JSON.parse(await fs.readFile(path.join(runDir, "failure-watcher.lock"), "utf8"));
  assert.equal(lock.pid, owner.pid);

  owner.kill("SIGTERM");
  await waitForExit(owner);
});

test("dashboard health includes watcher source availability and cursor lag", async (context) => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-failure-api-health-"));
  let dashboard;
  context.after(async () => {
    if (dashboard?.exitCode === null) dashboard.kill("SIGKILL");
    await fs.rm(runDir, { recursive: true, force: true });
  });

  await fs.mkdir(path.join(runDir, "runtime"));
  await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
  await fs.writeFile(path.join(runDir, "failure-watcher.json"), JSON.stringify({
    schemaVersion: 1,
    status: "RUNNING",
    heartbeatAt: new Date().toISOString(),
    source: { name: "transfers.tsv", available: true, sizeBytes: 101, offsetBytes: 100 },
  }));

  const dashboardPort = await freePort();
  dashboard = spawnDashboard(runDir, dashboardPort);
  const lagged = await waitForApi(dashboardPort);
  assert.equal(lagged.failureWatcher.available, true);
  assert.equal(lagged.failureWatcher.source.available, true);
  assert.equal(lagged.failureWatcher.source.lagBytes, 1);
  assert.equal(lagged.failureWatcher.healthy, false);
  const page = await fetch(`http://127.0.0.1:${dashboardPort}/`).then((response) => response.text());
  assert.match(page, /phase === 'RUNNING' && \(!data\.failureWatcher\?\.available \|\| !data\.failureWatcher\?\.healthy\)/);
  dashboard.kill("SIGTERM");
  await waitForExit(dashboard);

  await fs.writeFile(path.join(runDir, "failure-watcher.json"), JSON.stringify({
    schemaVersion: 1,
    status: "RUNNING",
    heartbeatAt: new Date().toISOString(),
    source: { name: "transfers.tsv", available: false, sizeBytes: 100, offsetBytes: 100 },
  }));
  const secondPort = await freePort();
  dashboard = spawnDashboard(runDir, secondPort);
  const unavailable = await waitForApi(secondPort);
  assert.equal(unavailable.failureWatcher.source.available, false);
  assert.equal(unavailable.failureWatcher.healthy, false);
  dashboard.kill("SIGTERM");
  await waitForExit(dashboard);
});

test("dashboard exposes redacted identity-checked worker health", async (context) => {
  const runDir = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-worker-api-"));
  let dashboard;
  let worker;
  context.after(async () => {
    if (dashboard?.exitCode === null) dashboard.kill("SIGKILL");
    if (worker?.exitCode === null) worker.kill("SIGKILL");
    await fs.rm(runDir, { recursive: true, force: true });
  });

  await fs.mkdir(path.join(runDir, "runtime"));
  await fs.writeFile(path.join(runDir, "phase"), "RUNNING\n");
  worker = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  const starttime = await waitForProcessStarttime(worker.pid);
  await fs.writeFile(path.join(runDir, "worker-pids.tsv"),
    `client\tpid\tstarttime\nnatclient01\t${worker.pid}\t${starttime}\nnatclient02\t${worker.pid}\t${Number(starttime) + 1}\n`);

  const dashboardPort = await freePort();
  dashboard = spawnDashboard(runDir, dashboardPort);
  const api = await waitForApi(dashboardPort);
  assert.equal(api.workers.expected, 6);
  assert.equal(api.workers.running, 1);
  assert.equal(api.workers.healthy, false);
  assert.deepEqual(api.workers.clients.map((item) => item.client),
    ["natclient01", "natclient02", "natclient03", "natclient04", "natclient05", "natclient06"]);
  assert.equal(api.workers.clients[0].alive, true);
  assert.equal(api.workers.clients[1].alive, false);
  const publicWorkers = JSON.stringify(api.workers);
  assert.equal(publicWorkers.includes(String(worker.pid)), false);
  assert.equal(publicWorkers.includes(starttime), false);
  const page = await fetch(`http://127.0.0.1:${dashboardPort}/`).then((response) => response.text());
  assert.match(page, /id="workerSummary"/);
  assert.match(page, /renderWorkers\(data\.workers\)/);

  dashboard.kill("SIGTERM");
  await waitForExit(dashboard);
  worker.kill("SIGTERM");
  await waitForExit(worker);
});

function spawnWatcher(runDir) {
  return spawn(process.execPath, [watcherPath], {
    env: {
      ...process.env,
      RUN_DIR: runDir,
      WATCH_PID: String(process.pid),
      POLL_INTERVAL_MS: "50",
      HEARTBEAT_INTERVAL_MS: "100",
      ALERT_LIMIT: "2",
    },
    stdio: "ignore",
  });
}

function spawnDashboard(runDir, port) {
  return spawn(process.execPath, [dashboardPath], {
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      RUN_DIR: runDir,
      COMPOSE_PROJECT: "",
      COMPOSE_FILE: path.join(runDir, "runtime", "compose.json"),
      CA_PORT: "1",
    },
    stdio: "ignore",
  });
}

async function waitForSnapshot(runDir, predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const value = JSON.parse(await fs.readFile(path.join(runDir, "failure-watcher.json"), "utf8"));
      if (predicate(value)) return value;
    } catch {
      // Atomic publication may not have happened yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("timed out waiting for failure watcher snapshot");
}

async function waitForStatus(runDir, predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const text = await fs.readFile(path.join(runDir, "failure-watcher.status"), "utf8");
      const value = Object.fromEntries(text.trim().split(/\n/).map((line) => line.split("=", 2)));
      if (predicate(value)) return value;
    } catch {
      // Atomic publication may not have happened yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("timed out waiting for failure watcher status");
}

function waitForExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null) return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for watcher exit")), timeoutMs);
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForProcessStarttime(pid, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const stat = await fs.readFile(`/proc/${pid}/stat`, "utf8");
      const closingParenthesis = stat.lastIndexOf(")");
      const fields = stat.slice(closingParenthesis + 1).trim().split(/\s+/);
      if (/^[1-9][0-9]*$/.test(fields[19] ?? "")) return fields[19];
    } catch {
      // The child may still be publishing its proc entry.
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("timed out waiting for worker process identity");
}

async function waitForApi(port, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/status`, {
        headers: { Connection: "close" },
      });
      if (response.ok) return await response.json();
    } catch {
      // Dashboard may still be binding its temporary port.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for Dashboard API");
}
