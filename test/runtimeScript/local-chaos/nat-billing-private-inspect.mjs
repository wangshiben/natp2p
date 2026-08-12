import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const snapshotPath = process.argv[2];
const maximumSnapshotBytes = 1 << 20;
const canonicalIdentifier = /^[0-9a-f]{64}$/;

if (!snapshotPath || process.argv.length !== 3) {
  process.stderr.write("usage: nat-billing-private-inspect.mjs SNAPSHOT_PATH\n");
  process.exit(2);
}

try {
  const parent = await fs.lstat(path.dirname(path.resolve(snapshotPath)));
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o777) !== 0o700) {
    throw new Error("invalid private directory");
  }
  const handle = await fs.open(snapshotPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let encoded;
  try {
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o777) !== 0o600 || info.size <= 0 || info.size > maximumSnapshotBytes) {
      throw new Error("invalid private snapshot file");
    }
    encoded = await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
  const snapshot = parseSnapshot(JSON.parse(encoded));
  process.stdout.write(`${[
    snapshot.version,
    snapshot.billingEnabled,
    snapshot.activeSessionCount,
    snapshot.observedBytes,
    snapshot.cosignedBytes,
    snapshot.fullyConfirmed,
    snapshot.generatedEpochMilliseconds,
  ].join("\t")}\n`);
} catch {
  process.stderr.write("NAT billing snapshot inspection failed\n");
  process.exit(1);
}

function parseSnapshot(value) {
  if (!plainObject(value) || value.version !== 1 || typeof value.billing_enabled !== "boolean"
      || !Array.isArray(value.sessions)) {
    throw new Error("invalid snapshot");
  }
  const activeSessionCount = nonNegativeSafeInteger(value.active_session_count);
  const observedBytes = nonNegativeSafeInteger(value.cumulative_observed_bytes);
  const cosignedBytes = nonNegativeSafeInteger(value.last_cosigned_cumulative);
  if (activeSessionCount !== value.sessions.length || cosignedBytes > observedBytes) {
    throw new Error("invalid aggregate");
  }

  const sessionIDs = new Set();
  let observedTotal = 0;
  let cosignedTotal = 0;
  let fullyConfirmed = true;
  for (const session of value.sessions) {
    if (!plainObject(session) || !canonicalIdentifier.test(session.session_id ?? "")
        || sessionIDs.has(session.session_id)) {
      throw new Error("invalid session");
    }
    sessionIDs.add(session.session_id);
    const sessionObserved = nonNegativeSafeInteger(session.cumulative_observed_bytes);
    const lastRecordSequence = nonNegativeSafeInteger(session.last_record_sequence);
    const confirmedSequence = nonNegativeSafeInteger(session.confirmed_sequence);
    const sessionCosigned = nonNegativeSafeInteger(session.last_cosigned_cumulative);
    if (confirmedSequence > lastRecordSequence || sessionCosigned > sessionObserved) {
      throw new Error("invalid session watermark");
    }
    observedTotal = checkedAdd(observedTotal, sessionObserved);
    cosignedTotal = checkedAdd(cosignedTotal, sessionCosigned);
    fullyConfirmed &&= confirmedSequence === lastRecordSequence;
  }
  if (observedTotal !== observedBytes || cosignedTotal !== cosignedBytes) {
    throw new Error("aggregate mismatch");
  }
  const generatedEpochMilliseconds = Date.parse(value.generated_at);
  if (!Number.isSafeInteger(generatedEpochMilliseconds) || generatedEpochMilliseconds <= 0) {
    throw new Error("invalid generated timestamp");
  }
  return {
    version: 1,
    billingEnabled: value.billing_enabled,
    activeSessionCount,
    observedBytes,
    cosignedBytes,
    fullyConfirmed,
    generatedEpochMilliseconds,
  };
}

function checkedAdd(left, right) {
  return nonNegativeSafeInteger(left + right);
}

function nonNegativeSafeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid non-negative integer");
  return value;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
