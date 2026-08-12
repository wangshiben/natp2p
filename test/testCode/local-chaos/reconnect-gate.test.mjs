import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import test from "node:test";

const gatePath = new URL("../../runtimeScript/local-chaos/reconnect-gate.mjs", import.meta.url);

async function startGate() {
  const child = spawn(process.execPath, [
    gatePath.pathname,
    "--listen",
    "127.0.0.1:0",
    "--token",
    "test-token",
    "--warmup-ms",
    "0",
    "--safe-rate",
    "10",
  ], { stdio: ["ignore", "pipe", "inherit"] });
  let output = "";
  child.stdout.setEncoding("utf8");
  const url = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`gate startup timeout: ${output}`)), 3000);
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/RECONNECT_GATE_LISTEN (http:\/\/\S+)/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1]);
      }
    });
    child.once("error", reject);
  });
  return { child, url };
}

async function stopGate(child) {
  child.kill("SIGTERM");
  await once(child, "exit");
}

async function requestDecision(url, index, token = "test-token") {
  const response = await fetch(`${url}/v1/reconnect-delay`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      relayAddress: "relay.test:9000",
      transport: "kcp",
      nodeId: `node-${index}`,
      attempt: 1,
    }),
  });
  return { response, body: await response.json() };
}

test("reconnect gate spreads a 500-request burst into bounded future slots", async () => {
  const gate = await startGate();
  try {
    const decisions = await Promise.all(
      Array.from({ length: 500 }, (_, index) => requestDecision(gate.url, index)),
    );
    assert.ok(decisions.every(({ response }) => response.status === 200));
    const granted = decisions.map(({ body }) => body).filter((body) => body.granted);
    assert.equal(granted.length, 500);
    assert.ok(granted.every((body) => body.delaySeconds >= 1 && body.delaySeconds <= 60));
    const slotCounts = new Map();
    for (const body of granted) {
      slotCounts.set(body.scheduledSecond, (slotCounts.get(body.scheduledSecond) ?? 0) + 1);
    }
    assert.ok([...slotCounts.values()].every((count) => count <= 10));
    const averageDelay = granted.reduce((total, body) => total + body.delaySeconds, 0) / granted.length;
    assert.ok(averageDelay > 10, `average delay too small: ${averageDelay}`);
    const metricsResponse = await fetch(`${gate.url}/metrics`, {
      headers: { Authorization: "Bearer test-token" },
    });
    assert.equal(metricsResponse.status, 200);
    const metrics = await metricsResponse.json();
    assert.equal(metrics.status, "ok");
    assert.equal(metrics.safeRate, 10);
    assert.equal(metrics.windowSeconds, 10);
    assert.equal(metrics.scopes.length, 1);
    assert.equal(metrics.scopes[0].granted, 500);
    assert.ok(metrics.scopes[0].futureSlots > 0);
    assert.ok(metrics.scopes[0].scheduledPerSecondPeak <= 10);
    assert.ok(metrics.scopes[0].pressure >= 0 && metrics.scopes[0].pressure <= 1);
  } finally {
    await stopGate(gate.child);
  }
});

test("reconnect gate rejects invalid credentials", async () => {
  const gate = await startGate();
  try {
    const { response } = await requestDecision(gate.url, 1, "wrong-token");
    assert.equal(response.status, 401);
  } finally {
    await stopGate(gate.child);
  }
});
