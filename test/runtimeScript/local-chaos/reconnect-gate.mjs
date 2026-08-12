import crypto from "node:crypto";
import http from "node:http";
import process from "node:process";

const argumentsList = process.argv.slice(2);
const option = (name, fallback) => {
  const index = argumentsList.indexOf(name);
  return index >= 0 && argumentsList[index + 1] !== undefined
    ? argumentsList[index + 1]
    : fallback;
};

const listenAddress = option("--listen", process.env.BNFS_RECONNECT_GATE_LISTEN ?? "127.0.0.1:0");
const token = option("--token", process.env.BNFS_RECONNECT_GATE_TOKEN ?? "");
const windowSeconds = boundedInteger(option("--window-seconds", "10"), 1, 60);
const safeRate = boundedInteger(option("--safe-rate", "10"), 1, 1000);
const warmupMilliseconds = boundedInteger(option("--warmup-ms", "5000"), 0, 60000);
const scopeLimit = boundedInteger(option("--scope-limit", "64"), 1, 1024);
const scopes = new Map();
const startedAt = Date.now();

function boundedInteger(value, minimum, maximum) {
  const number = Number.parseInt(value, 10);
  if (!Number.isInteger(number) || number < minimum || number > maximum) {
    throw new Error(`invalid integer ${value}`);
  }
  return number;
}

function parseListenAddress(address) {
  const separator = address.lastIndexOf(":");
  if (separator <= 0) {
    throw new Error(`invalid listen address ${address}`);
  }
  return { host: address.slice(0, separator), port: Number.parseInt(address.slice(separator + 1), 10) };
}

function authorizationIsValid(request) {
  if (token === "") {
    return true;
  }
  const value = request.headers.authorization ?? "";
  const expected = `Bearer ${token}`;
  const actualBuffer = Buffer.from(value);
  const expectedBuffer = Buffer.from(expected);
  return actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function scopeState(scope, nowSecond) {
  let state = scopes.get(scope);
  if (!state) {
    if (scopes.size >= scopeLimit) {
      return null;
    }
    state = {
      history: new Array(windowSeconds).fill(0),
      historySecond: nowSecond,
      future: new Map(),
      warmUntil: Date.now() + warmupMilliseconds,
      granted: 0,
      denied: 0,
    };
    scopes.set(scope, state);
  }
  rollState(state, nowSecond);
  return state;
}

function rollState(state, nowSecond) {
  const elapsed = nowSecond - state.historySecond;
  if (elapsed >= windowSeconds) {
    state.history.fill(0);
  } else if (elapsed > 0) {
    for (let offset = 1; offset <= elapsed; offset += 1) {
      state.history[(state.historySecond + offset) % windowSeconds] = 0;
    }
  }
  if (elapsed > 0) {
    state.historySecond = nowSecond;
  }
  for (const second of state.future.keys()) {
    if (second < nowSecond) {
      state.future.delete(second);
    }
  }
}

function randomInteger(minimum, maximum) {
  return crypto.randomInt(minimum, maximum + 1);
}

function chooseDelay(state, nowSecond) {
  const historyRequests = state.history.reduce((total, value) => total + value, 0) + 1;
  const capacity = safeRate * windowSeconds;
  const pressure = Date.now() < state.warmUntil
    ? 1
    : Math.min(1, historyRequests / capacity);
  const low = 1 + Math.floor(29 * pressure);
  const high = 5 + Math.floor(55 * pressure);
  const desired = randomInteger(low, high);
  const candidates = [];
  for (let offset = desired; offset <= 60; offset += 1) {
    const second = nowSecond + offset;
    if ((state.future.get(second) ?? 0) < safeRate) {
      candidates.push(second);
    }
  }
  if (candidates.length === 0) {
    for (let offset = 1; offset < desired; offset += 1) {
      const second = nowSecond + offset;
      if ((state.future.get(second) ?? 0) < safeRate) {
        candidates.push(second);
      }
    }
  }
  if (candidates.length === 0) {
    state.denied += 1;
    return {
      granted: false,
      delaySeconds: 0,
      retryAfterSeconds: randomInteger(30, 60),
      windowRequests: historyRequests,
      pressure,
    };
  }
  const scheduledSecond = candidates[randomInteger(0, candidates.length - 1)];
  state.future.set(scheduledSecond, (state.future.get(scheduledSecond) ?? 0) + 1);
  state.history[nowSecond % windowSeconds] += 1;
  state.granted += 1;
  return {
    granted: true,
    delaySeconds: Math.max(1, scheduledSecond - nowSecond),
    retryAfterSeconds: 0,
    windowRequests: historyRequests,
    pressure,
    scheduledSecond,
  };
}

async function readJson(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > 64 * 1024) {
      throw new Error("request too large");
    }
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(response, statusCode, value) {
  const payload = JSON.stringify(value);
  response.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
  });
  response.end(payload);
}

const server = http.createServer(async (request, response) => {
  if (!authorizationIsValid(request)) {
    sendJson(response, 401, { error: "unauthorized" });
    return;
  }
  if (request.method === "GET" && request.url === "/health") {
    sendJson(response, 200, {
      status: "ok",
      startedAt: new Date(startedAt).toISOString(),
      scopes: scopes.size,
      safeRate,
      windowSeconds,
    });
    return;
  }
  if (request.method === "GET" && request.url === "/metrics") {
    const nowSecond = Math.floor(Date.now() / 1000);
    const metrics = [...scopes.entries()].map(([scope, state]) => ({
      ...(() => {
        rollState(state, nowSecond);
        const futureCounts = [...state.future.values()];
        const windowRequests = state.history.reduce((total, value) => total + value, 0);
        return {
          scope,
          granted: state.granted,
          denied: state.denied,
          futureSlots: futureCounts.reduce((total, value) => total + value, 0),
          scheduledPerSecondPeak: futureCounts.reduce((maximum, value) => Math.max(maximum, value), 0),
          windowRequests,
          pressure: Math.min(1, windowRequests / (safeRate * windowSeconds)),
        };
      })(),
    }));
    sendJson(response, 200, {
      status: "ok",
      startedAt: new Date(startedAt).toISOString(),
      observedAt: new Date().toISOString(),
      safeRate,
      windowSeconds,
      scopes: metrics,
    });
    return;
  }
  if (request.method !== "POST" || request.url !== "/v1/reconnect-delay") {
    sendJson(response, 404, { error: "not_found" });
    return;
  }
  try {
    const body = await readJson(request);
    const relayAddress = typeof body.relayAddress === "string" ? body.relayAddress : "";
    const transport = typeof body.transport === "string" ? body.transport : "unknown";
    const scope = `${relayAddress}|${transport}`;
    const nowSecond = Math.floor(Date.now() / 1000);
    const state = scopeState(scope, nowSecond);
    if (!state) {
      sendJson(response, 503, { error: "scope_limit" });
      return;
    }
    sendJson(response, 200, {
      ...chooseDelay(state, nowSecond),
      scope,
      observedAt: new Date().toISOString(),
    });
  } catch (error) {
    sendJson(response, 400, { error: error instanceof Error ? error.message : "invalid_request" });
  }
});

const { host, port } = parseListenAddress(listenAddress);
server.listen(port, host, () => {
  const address = server.address();
  const actualPort = typeof address === "object" && address ? address.port : port;
  process.stdout.write(`RECONNECT_GATE_LISTEN http://${host}:${actualPort}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
