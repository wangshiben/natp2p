import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const schemaVersion = 1;
const maximumEntries = 64;
const maximumFileBytes = 1024 * 1024;

export async function openDurableWaitSubmit(file) {
  const resolved = path.resolve(file ?? "");
  if (!path.isAbsolute(file ?? "") || resolved === path.parse(resolved).root) {
    throw codedError("waitsubmit_path_invalid");
  }
  await fs.mkdir(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const initial = await loadState(resolved);
  return queueFor(resolved, initial);
}

function queueFor(file, initial) {
  let state = initial;
  return {
    get depth() {
      return state.entries.length;
    },
    get revision() {
      return state.revision;
    },
    peek() {
      return state.entries.length > 0 ? clone(state.entries[0]) : null;
    },
    snapshot() {
      return clone(state);
    },
    async enqueue(request) {
      const entry = {
        order: state.nextOrder,
        request: validatedRequest(request),
      };
      if (state.entries.length >= maximumEntries) throw codedError("waitsubmit_capacity_exceeded");
      const next = {
        schemaVersion,
        revision: state.revision + 1,
        nextOrder: state.nextOrder + 1,
        entries: [...state.entries, entry],
      };
      await persist(file, next);
      state = next;
      return entry.order;
    },
    async removeHead(expectedOrder) {
      if (state.entries.length === 0 || state.entries[0].order !== expectedOrder) {
        throw codedError("waitsubmit_fifo_mismatch");
      }
      const next = {
        schemaVersion,
        revision: state.revision + 1,
        nextOrder: state.nextOrder,
        entries: state.entries.slice(1),
      };
      await persist(file, next);
      state = next;
    },
  };
}

async function loadState(file) {
  let encoded;
  try {
    const stat = await fs.stat(file);
    if (!stat.isFile() || stat.size <= 0 || stat.size > maximumFileBytes) {
      throw codedError("waitsubmit_file_invalid");
    }
    encoded = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { schemaVersion, revision: 0, nextOrder: 1, entries: [] };
    }
    throw error;
  }
  let value;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw codedError("waitsubmit_file_corrupt");
  }
  return validateState(value);
}

function validateState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.schemaVersion !== schemaVersion
    || !safeNonnegativeInteger(value.revision)
    || !safePositiveInteger(value.nextOrder)
    || !Array.isArray(value.entries)
    || value.entries.length > maximumEntries) {
    throw codedError("waitsubmit_file_corrupt");
  }
  let previousOrder = 0;
  const entries = value.entries.map((entry) => {
    if (!entry || typeof entry !== "object" || !safePositiveInteger(entry.order)
      || entry.order <= previousOrder || entry.order >= value.nextOrder) {
      throw codedError("waitsubmit_file_corrupt");
    }
    previousOrder = entry.order;
    return { order: entry.order, request: validatedRequest(entry.request) };
  });
  return {
    schemaVersion,
    revision: value.revision,
    nextOrder: value.nextOrder,
    entries,
  };
}

function validatedRequest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codedError("waitsubmit_request_invalid");
  }
  const keys = Object.keys(value).sort();
  const expected = ["canonical_voucher", "payer_cert", "payer_public_key", "relay_cert", "relay_public_key"];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw codedError("waitsubmit_request_invalid");
  }
  if (!canonicalBase64(value.canonical_voucher)
    || !canonicalPublicKey(value.payer_public_key)
    || !canonicalPublicKey(value.relay_public_key)
    || !validCertificate(value.payer_cert)
    || !validCertificate(value.relay_cert)) {
    throw codedError("waitsubmit_request_invalid");
  }
  const cloned = clone(value);
  if (Buffer.byteLength(JSON.stringify(cloned)) > 64 * 1024) {
    throw codedError("waitsubmit_request_invalid");
  }
  return cloned;
}

function canonicalBase64(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 8192 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return false;
  }
  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}

function canonicalPublicKey(value) {
  return typeof value === "string" && /^04[0-9a-f]{128}$/.test(value);
}

function validCertificate(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !value.cert || typeof value.cert !== "object" || Array.isArray(value.cert)
    || typeof value.sig !== "string" || value.sig.length === 0 || value.sig.length > 512) {
    return false;
  }
  const cert = value.cert;
  return /^[0-9a-f]{64}$/.test(String(cert.subject_node_id ?? ""))
    && canonicalPublicKey(cert.subject_pubkey)
    && ["server", "relay"].includes(cert.role)
    && safeInteger(cert.not_before)
    && safeInteger(cert.not_after)
    && typeof cert.nonce === "string"
    && cert.nonce.length > 0
    && cert.nonce.length <= 256
    && (cert.issuer === undefined || (typeof cert.issuer === "string" && cert.issuer.length <= 256));
}

async function persist(file, value) {
  const encoded = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(encoded) > maximumFileBytes) throw codedError("waitsubmit_capacity_exceeded");
  const temporary = `${file}.tmp-${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(encoded);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, file);
    const directory = await fs.open(path.dirname(file), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function safeInteger(value) {
  return Number.isSafeInteger(Number(value));
}

function safeNonnegativeInteger(value) {
  return safeInteger(value) && Number(value) >= 0;
}

function safePositiveInteger(value) {
  return safeInteger(value) && Number(value) > 0;
}

function codedError(code) {
  return Object.assign(new Error(code), { code });
}
