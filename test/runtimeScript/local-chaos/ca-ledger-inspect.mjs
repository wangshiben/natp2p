import crypto from "node:crypto";
import fs from "node:fs/promises";
import process from "node:process";

const snapshotPath = process.argv[2];
const relayID = process.argv[3];
const payerID = process.argv[4];
const sessionID = process.argv[5];
const walHeader = Buffer.from("BNFSCAW1\n");
const maximumRecordBytes = 4 << 20;
const canonicalIdentifier = /^[0-9a-f]{64}$/;

if (!snapshotPath || !canonicalIdentifier.test(relayID ?? "")
    || (payerID !== undefined && !canonicalIdentifier.test(payerID))
    || (sessionID !== undefined && (!payerID || !canonicalIdentifier.test(sessionID)))
    || process.argv.length > 6) {
  process.stderr.write("usage: ca-ledger-inspect.mjs SNAPSHOT_PATH RELAY_NODE_ID [PAYER_NODE_ID [SESSION_ID]]\n");
  process.exit(2);
}

try {
  const state = await readSnapshot(snapshotPath, relayID);
  await replayWAL(`${snapshotPath}.wal`, state, relayID);
  const globalFields = [state.caRevenue, state.relayIncome, state.sequence];
  if (payerID === undefined) {
    process.stdout.write(`${globalFields.join("\t")}\n`);
  } else {
    const channel = summarizeChannels(state.channels, payerID, relayID, sessionID);
    process.stdout.write(`${[...globalFields, channel.count, channel.grossTotal, channel.relayTotal, channel.caTotal].join("\t")}\n`);
  }
} catch {
  process.stderr.write("CA ledger inspection failed\n");
  process.exit(1);
}

async function readSnapshot(file, relay) {
  let encoded;
  try {
    encoded = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return emptyState();
    throw error;
  }
  const value = JSON.parse(encoded);
  if (!plainObject(value) || value.version !== 3 || !plainObject(value.relay_income)) {
    throw new Error("invalid ledger snapshot");
  }
  return {
    caRevenue: nonNegativeSafeInteger(value.ca_revenue),
    relayIncome: nonNegativeSafeInteger(value.relay_income[relay] ?? 0),
    sequence: nonNegativeSafeInteger(value.transaction_sequence),
    channels: readChannelMap(value.channels),
  };
}

async function replayWAL(file, state, relay) {
  let encoded;
  try {
    encoded = await fs.readFile(file);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (encoded.length < walHeader.length || !encoded.subarray(0, walHeader.length).equals(walHeader)) {
    throw new Error("invalid WAL header");
  }
  let offset = walHeader.length;
  let previousSequence = 0;
  while (offset < encoded.length) {
    if (encoded.length - offset < 4) throw new Error("incomplete WAL length");
    const length = encoded.readUInt32BE(offset);
    offset += 4;
    if (length === 0 || length > maximumRecordBytes || encoded.length - offset < length + 32) {
      throw new Error("invalid WAL frame");
    }
    const payload = encoded.subarray(offset, offset + length);
    const checksum = encoded.subarray(offset + length, offset + length + 32);
    offset += length + 32;
    const actualChecksum = crypto.createHash("sha256").update(payload).digest();
    if (!actualChecksum.equals(checksum)) throw new Error("invalid WAL checksum");
    const transaction = JSON.parse(payload.toString("utf8"));
    const sequence = positiveSafeInteger(transaction?.sequence);
    if (!plainObject(transaction) || transaction.version !== 1 || (previousSequence > 0 && sequence !== previousSequence + 1)) {
      throw new Error("invalid WAL transaction");
    }
    const channelDelete = readChannelDelete(transaction.channel_delete);
    const channelSet = readChannelSet(transaction.channel_set);
    previousSequence = sequence;
    if (sequence <= state.sequence) continue;
    if (sequence !== state.sequence + 1) throw new Error("WAL does not follow snapshot");
    if (transaction.ca_revenue_changed === true) {
      state.caRevenue = nonNegativeSafeInteger(transaction.ca_revenue);
    }
    if (Array.isArray(transaction.relay_income_delete) && transaction.relay_income_delete.includes(relay)) {
      state.relayIncome = 0;
    }
    if (plainObject(transaction.relay_income_set) && Object.hasOwn(transaction.relay_income_set, relay)) {
      state.relayIncome = nonNegativeSafeInteger(transaction.relay_income_set[relay]);
    }
    for (const key of channelDelete) state.channels.delete(key);
    for (const [key, channel] of channelSet) state.channels.set(key, channel);
    state.sequence = sequence;
  }
}

function emptyState() {
  return { caRevenue: 0, relayIncome: 0, sequence: 0, channels: new Map() };
}

function readChannelMap(value) {
  if (value === undefined || value === null) return new Map();
  if (!plainObject(value)) throw new Error("invalid channel map");
  return new Map(Object.entries(value).map(([key, channel]) => readChannelEntry(key, channel)));
}

function readChannelSet(value) {
  if (value === undefined || value === null) return [];
  if (!plainObject(value)) throw new Error("invalid channel set");
  return Object.entries(value).map(([key, channel]) => readChannelEntry(key, channel));
}

function readChannelDelete(value) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((key) => typeof key !== "string" || key.length === 0)) {
    throw new Error("invalid channel delete");
  }
  return value;
}

function readChannelEntry(key, value) {
  if (key.length === 0 || !plainObject(value)
      || !canonicalIdentifier.test(value.session_id ?? "")
      || !canonicalIdentifier.test(value.payer_node_id ?? "")
      || !canonicalIdentifier.test(value.relay_node_id ?? "")) {
    throw new Error("invalid channel identity");
  }
  return [key, {
    sessionID: value.session_id,
    payerID: value.payer_node_id,
    relayID: value.relay_node_id,
    grossTotal: nonNegativeSafeInteger(value.gross_total),
    relayTotal: nonNegativeSafeInteger(value.relay_total),
    caTotal: nonNegativeSafeInteger(value.ca_total),
  }];
}

function summarizeChannels(channels, payer, relay, session) {
  const summary = { count: 0, grossTotal: 0, relayTotal: 0, caTotal: 0 };
  for (const channel of channels.values()) {
    if (channel.payerID !== payer || channel.relayID !== relay
        || (session !== undefined && channel.sessionID !== session)) continue;
    summary.count = checkedAdd(summary.count, 1);
    summary.grossTotal = checkedAdd(summary.grossTotal, channel.grossTotal);
    summary.relayTotal = checkedAdd(summary.relayTotal, channel.relayTotal);
    summary.caTotal = checkedAdd(summary.caTotal, channel.caTotal);
  }
  return summary;
}

function checkedAdd(left, right) {
  return nonNegativeSafeInteger(left + right);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonNegativeSafeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid non-negative integer");
  return value;
}

function positiveSafeInteger(value) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("invalid positive integer");
  return value;
}
