import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

process.umask(0o077);

const privateRoot = path.resolve(process.env.PRIVATE_RUNTIME_DIR ?? "");
const caBaseURL = new URL(process.env.CA_BASE_URL ?? "http://127.0.0.1:19100");
const manifestFile = path.resolve(process.env.CA_BILLING_BOOTSTRAP_FILE
  ?? path.join(privateRoot, "ca", "billing-key-bootstrap.json"));
const adminTokenFile = path.resolve(process.env.CA_ADMIN_TOKEN_FILE
  ?? path.join(privateRoot, "ca", "admin.token"));
const targetCreditBytes = boundedInteger(
  process.env.BNFS_CHAOS_USER_CREDIT_BYTES,
  2 * 1024 * 1024 * 1024 * 1024,
  0,
  Number.MAX_SAFE_INTEGER,
);
const requestTimeoutMs = boundedInteger(process.env.CA_BOOTSTRAP_TIMEOUT_MS, 10000, 1000, 120000);
const mockUsers = new Set(["demo_user", "developer", "observer"]);

try {
  validateConfiguration();
  const manifest = await readPrivateJSON(manifestFile);
  validateManifest(manifest);
  const adminSession = await adminLogin(await readToken(adminTokenFile));
  const activations = [];
  for (const user of manifest.users) {
    await ensureRegisteredKey(adminSession, user);
    if (targetCreditBytes > 0) await ensureUserCredit(adminSession, user.user_id);
    activations.push(...user.services.map((service) => ({ service, keyID: user.key_id })));
  }
  for (const activation of activations) await activateBundle(activation.service, activation.keyID);
  await writePrivateJSON(path.join(privateRoot, "ca", "billing-key-bootstrap.status.json"), {
    version: 1,
    status: "ready",
    users: manifest.users.map((user) => ({
      username: user.username,
      user_id: user.user_id,
      key_id: user.key_id,
      service_count: user.services.length,
    })),
    activated_services: activations.length,
    completed_at: new Date().toISOString(),
  });
  process.stdout.write(`billing key bootstrap complete users=${manifest.users.length} services=${activations.length}\n`);
} catch (error) {
  process.stderr.write(`billing key bootstrap failed: ${safeCode(error?.code ?? "bootstrap_failed")}\n`);
  process.exitCode = 1;
}

function validateConfiguration() {
  if (!process.env.PRIVATE_RUNTIME_DIR || privateRoot === path.parse(privateRoot).root) {
    throw codedError("private_runtime_invalid");
  }
  if (caBaseURL.protocol !== "http:" || !isLoopback(caBaseURL.hostname)
    || caBaseURL.username || caBaseURL.password || caBaseURL.search || caBaseURL.hash
    || !["", "/"].includes(caBaseURL.pathname)) {
    throw codedError("ca_url_invalid");
  }
  if (!manifestFile.startsWith(`${privateRoot}${path.sep}`)
    || !adminTokenFile.startsWith(`${privateRoot}${path.sep}`)) {
    throw codedError("private_file_outside_runtime");
  }
}

function validateManifest(manifest) {
  if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.users)
    || manifest.users.length !== 3) throw codedError("manifest_invalid");
  const usernames = new Set();
  const keyIDs = new Set();
  const services = new Set();
  for (const user of manifest.users) {
    if (!mockUsers.has(user.username)
      || !/^usr_mock_[a-z_]+$/.test(String(user.user_id ?? ""))
      || !/^[0-9a-f]{64}$/.test(String(user.key_id ?? ""))
      || !/^04[0-9a-f]{128}$/.test(String(user.public_key_hex ?? ""))
      || typeof user.label !== "string" || !Array.isArray(user.services) || user.services.length < 2) {
      throw codedError("manifest_entry_invalid");
    }
    const derivedKeyID = crypto.createHash("sha256")
      .update(Buffer.from(user.public_key_hex, "hex")).digest("hex");
    if (derivedKeyID !== user.key_id || usernames.has(user.username) || keyIDs.has(user.key_id)) {
      throw codedError("manifest_binding_invalid");
    }
    usernames.add(user.username);
    keyIDs.add(user.key_id);
    for (const service of user.services) {
      if (!/^[a-z][a-z0-9-]{1,63}$/.test(String(service ?? "")) || services.has(service)) {
        throw codedError("manifest_service_invalid");
      }
      services.add(service);
    }
  }
}

async function adminLogin(token) {
  const response = await requestJSON("POST", "/api/v1/auth/admin-login", {
    token,
  });
  const cookie = parseFrameworkSessionCookie(response, false);
  if (response.status !== 200 || response.body?.role !== "admin" || !response.body?.authenticated || !cookie) {
    throw codedError("admin_session_login_rejected");
  }
  return cookie;
}

async function ensureRegisteredKey(adminCookie, expected) {
  const response = await requestJSON("POST", "/api/v1/admin/test/billing-keys", {
    user_id: expected.user_id,
    label: expected.label,
    public_key: expected.public_key_hex,
  }, adminCookie);
  const registered = response.body?.billing_key;
  if (![200, 201].includes(response.status) || typeof response.body?.created !== "boolean") {
    throw codedError("billing_key_registration_rejected");
  }
  if (registered.status !== "active" || registered.user_id !== expected.user_id
    || registered.id !== expected.key_id || registered.public_key !== expected.public_key_hex) {
    throw codedError("billing_key_registration_mismatch");
  }
}

async function ensureUserCredit(adminCookie, userID) {
  const users = await requestJSON("POST", "/api/v1/admin/users/query", {
    limit: 10,
    search: userID,
  }, adminCookie);
  const account = Array.isArray(users.body?.items)
    ? users.body.items.find((item) => item?.id === userID)
    : null;
  const balance = Number(account?.balance_bytes);
  if (users.status !== 200 || !account || !Number.isSafeInteger(balance) || balance < 0) {
    throw codedError("user_account_invalid");
  }
  if (balance >= targetCreditBytes) return;
  const credited = await requestJSON("POST", "/api/v1/admin/users/credit", {
    user_id: userID,
    add_bytes: targetCreditBytes - balance,
    note: "local chaos strict billing bootstrap",
  }, adminCookie);
  if (credited.status !== 200 || credited.body?.user_id !== userID
    || Number(credited.body?.balance_bytes) !== targetCreditBytes) {
    throw codedError("user_credit_rejected");
  }
}

async function activateBundle(service, expectedKeyID) {
  const filename = path.join(privateRoot, service, "billing-key.json");
  const bundle = await readPrivateJSON(filename);
  validatePrivateBundle(bundle, expectedKeyID);
  if (bundle.registration_status === "active") return;
  bundle.registration_status = "active";
  await writePrivateJSON(filename, bundle);
}

function validatePrivateBundle(bundle, expectedKeyID) {
  if (!bundle || bundle.version !== 1 || bundle.algorithm !== "ECDSA_P256_SHA256"
    || bundle.key_id !== expectedKeyID || !/^04[0-9a-f]{128}$/.test(String(bundle.public_key_hex ?? ""))
    || !bundle.private_key_jwk?.d || !["pending", "active"].includes(bundle.registration_status)) {
    throw codedError("billing_bundle_invalid");
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey({ key: bundle.private_key_jwk, format: "jwk" });
  } catch {
    throw codedError("billing_bundle_private_key_invalid");
  }
  const publicJWK = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  const publicKey = Buffer.concat([
    Buffer.from([4]), Buffer.from(publicJWK.x, "base64url"), Buffer.from(publicJWK.y, "base64url"),
  ]);
  const keyID = crypto.createHash("sha256").update(publicKey).digest("hex");
  if (publicKey.toString("hex") !== bundle.public_key_hex || keyID !== bundle.key_id) {
    throw codedError("billing_bundle_binding_invalid");
  }
}

async function requestJSON(method, pathname, body, sessionCookie = "") {
  const headers = { Accept: "application/json" };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (sessionCookie) headers.Cookie = sessionCookie;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
  try {
    const response = await fetch(new URL(pathname, caBaseURL), {
      method,
      headers,
      body: body === null ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const encoded = await response.text();
    if (encoded.length > 1024 * 1024) throw codedError("ca_response_too_large");
    let decoded = {};
    try {
      decoded = encoded ? JSON.parse(encoded) : {};
    } catch {
      throw codedError("ca_response_invalid");
    }
    return { status: response.status, body: decoded, headers: response.headers };
  } catch (error) {
    if (error?.code) throw error;
    throw codedError("ca_request_failed");
  } finally {
    clearTimeout(timer);
  }
}

function parseFrameworkSessionCookie(response, secure) {
  if (!response?.headers) return "";
  const setCookie = typeof response.headers.getSetCookie === "function"
    ? response.headers.getSetCookie().join(",")
    : response.headers.get("set-cookie") ?? "";
  const match = setCookie.match(/(?:^|,\s*)quickSession=([^;,\s]+)/i);
  if (!match || !/HttpOnly/i.test(setCookie) || !/SameSite=Strict/i.test(setCookie)
    || !/Path=\//i.test(setCookie) || /Domain=/i.test(setCookie)
    || (secure ? !/Secure/i.test(setCookie) : /;\s*Secure(?:;|$)/i.test(setCookie))) {
    return "";
  }
  return `quickSession=${match[1]}`;
}

async function readToken(filename) {
  const handle = await fs.open(filename, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size > 4096) {
      throw codedError("admin_token_file_invalid");
    }
    const token = (await handle.readFile("utf8")).trim();
    if (token.length < 32 || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(token)) {
      throw codedError("admin_token_invalid");
    }
    return token;
  } finally {
    await handle.close();
  }
}

async function readPrivateJSON(filename) {
  const handle = await fs.open(filename, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size <= 0 || stat.size > 65536) {
      throw codedError("private_json_invalid");
    }
    return JSON.parse(await handle.readFile("utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) throw codedError("private_json_invalid");
    throw error;
  } finally {
    await handle.close();
  }
}

async function writePrivateJSON(filename, value) {
  await fs.mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  await fs.chmod(path.dirname(filename), 0o700);
  const temporary = `${filename}.tmp-${process.pid}`;
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, filename);
  await fs.chmod(filename, 0o600);
}

function isLoopback(hostname) {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost" || normalized === "::1" || normalized.startsWith("127.");
}

function boundedInteger(value, fallback, minimum, maximum) {
  if (value === undefined || value === "") return fallback;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw codedError("integer_configuration_invalid");
  }
  return number;
}

function codedError(code) {
  return Object.assign(new Error(code), { code });
}

function safeCode(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 64);
}
