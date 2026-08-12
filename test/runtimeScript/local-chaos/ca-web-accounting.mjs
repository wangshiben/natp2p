import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const relayID = process.argv[2] ?? "";
const payerID = process.argv[3] ?? "";
const relayService = process.argv[4] ?? "";
const payerService = process.argv[5] ?? "";
const baseURL = new URL(process.env.CA_BASE_URL ?? "http://127.0.0.1:19100");
const tokenFile = process.env.CA_ADMIN_TOKEN_FILE ?? "";
const manifestFile = process.env.CA_BILLING_BOOTSTRAP_FILE
  ?? path.join(path.dirname(tokenFile), "billing-key-bootstrap.json");
const canonicalIdentifier = /^[0-9a-f]{64}$/;

try {
  validateConfiguration();
  const token = await readToken(tokenFile);
  const manifest = await readManifest(manifestFile);
  const adminSession = await adminLogin(token);
  const [overviewResponse, nodesResponse, channelsResponse, usersResponse] = await Promise.all([
    requestJSON("/api/v1/overview", adminSession),
    requestJSON("/api/v1/nodes", adminSession),
    requestJSON("/api/v1/channels?limit=500", adminSession),
    requestJSON("/api/v1/admin/users", adminSession),
  ]);
  const overview = overviewResponse?.ca;
  const nodes = nodesResponse?.items;
  const channels = channelsResponse?.items;
  const users = usersResponse?.items;
  if (!plainObject(overview) || !Array.isArray(nodes) || !Array.isArray(channels)
      || !Array.isArray(users)) {
    throw new Error("invalid CA Web accounting response");
  }
  const relay = nodes.find((node) => node?.id === relayID);
  if (!relay || relay.role !== "relay") {
    throw new Error("relay account unavailable");
  }
  const matching = channels.filter((channel) => (
    channel?.payer_node_id === payerID && channel?.relay_node_id === relayID
  ));
  const payerUserID = serviceUserID(manifest, payerService);
  const relayUserID = serviceUserID(manifest, relayService);
  const payerUser = users.find((user) => user?.id === payerUserID);
  const relayUser = users.find((user) => user?.id === relayUserID);
  if (!plainObject(payerUser) || !plainObject(relayUser)) {
    throw new Error("authorized user account unavailable");
  }
  const values = [
    integer(overview.ca_revenue_bytes),
    integer(relayUser.earned_bytes),
    integer(overview.transaction),
    matching.length,
    sum(matching, "gross_total_bytes"),
    sum(matching, "relay_total_bytes"),
    sum(matching, "ca_total_bytes"),
    integer(payerUser.consumed_bytes),
    integer(payerUser.balance_bytes),
    integer(relayUser.balance_bytes),
    payerUserID === relayUserID,
  ];
  process.stdout.write(`${values.join("\t")}\n`);
} catch {
  process.stderr.write("CA Web accounting inspection failed\n");
  process.exitCode = 1;
}

function validateConfiguration() {
  if (!canonicalIdentifier.test(relayID) || !canonicalIdentifier.test(payerID)
      || !/^relay0[1-7]$/.test(relayService)
      || !/^natserver(?:0[1-9]|1[0-3])$/.test(payerService)
      || process.argv.length !== 6 || !tokenFile || !manifestFile) {
    throw new Error("invalid accounting inspector arguments");
  }
  if (baseURL.protocol !== "http:" || !isLoopback(baseURL.hostname)
      || baseURL.username || baseURL.password || baseURL.search || baseURL.hash) {
    throw new Error("CA Web accounting URL must use loopback HTTP");
  }
}

async function adminLogin(token) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(new URL("/api/v1/auth/admin-login", baseURL), {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
      signal: controller.signal,
    });
    const body = await response.text();
    if (body.length > 65536 || !response.ok) throw new Error("CA Web admin session login rejected");
    const setCookie = typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie().join(",")
      : response.headers.get("set-cookie") ?? "";
    const match = setCookie.match(/(?:^|,\s*)quickSession=([^;,\s]+)/i);
    if (!match || !/HttpOnly/i.test(setCookie) || !/SameSite=Strict/i.test(setCookie)
        || !/Path=\//i.test(setCookie) || /Domain=/i.test(setCookie)) {
      throw new Error("CA Web admin session cookie is invalid");
    }
    return `quickSession=${match[1]}`;
  } finally {
    clearTimeout(timer);
  }
}

async function requestJSON(pathname, sessionCookie) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const headers = { Accept: "application/json" };
    if (sessionCookie) headers.Cookie = sessionCookie;
    const response = await fetch(new URL(pathname, baseURL), {
      headers,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error("CA Web request rejected");
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function readToken(filename) {
  const encoded = await fs.readFile(filename, "utf8");
  const token = encoded.trim();
  if (encoded.length > 4096 || token.length < 32 || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(token)) {
    throw new Error("invalid CA admin token");
  }
  return token;
}

async function readManifest(filename) {
  const handle = await fs.open(filename, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size <= 0 || stat.size > 65536) {
      throw new Error("invalid billing bootstrap manifest");
    }
    const manifest = JSON.parse(await handle.readFile("utf8"));
    if (manifest?.version !== 1 || !Array.isArray(manifest.users)) {
      throw new Error("invalid billing bootstrap manifest");
    }
    return manifest;
  } finally {
    await handle.close();
  }
}

function serviceUserID(manifest, service) {
  const owners = manifest.users.filter((user) => (
    typeof user?.user_id === "string" && Array.isArray(user.services) && user.services.includes(service)
  ));
  if (owners.length !== 1) throw new Error("billing service owner unavailable");
  return owners[0].user_id;
}

function sum(items, field) {
  return items.reduce((total, item) => integer(total + integer(item?.[field])), 0);
}

function integer(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid accounting integer");
  return value;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isLoopback(hostname) {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost" || normalized === "::1" || normalized.startsWith("127.");
}
