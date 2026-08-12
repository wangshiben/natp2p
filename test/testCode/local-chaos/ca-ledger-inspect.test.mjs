import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const inspector = fileURLToPath(new URL("../../runtimeScript/local-chaos/ca-ledger-inspect.mjs", import.meta.url));
const relayID = "a".repeat(64);
const payerID = "b".repeat(64);
const otherPayerID = "c".repeat(64);
const firstSessionID = "d".repeat(64);
const secondSessionID = "e".repeat(64);
const otherSessionID = "f".repeat(64);

test("CA ledger inspector replays revenue and Relay income without writing", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-ca-ledger-inspect-"));
  const snapshot = path.join(directory, "ledger.json");
  try {
    await fs.writeFile(snapshot, JSON.stringify({
      version: 3,
      transaction_sequence: 2,
      relay_income: { [relayID]: 950 },
      ca_revenue: 50,
    }));
    await fs.writeFile(`${snapshot}.wal`, Buffer.concat([
      Buffer.from("BNFSCAW1\n"),
      frame({
        version: 1,
        sequence: 3,
        relay_income_set: { [relayID]: 1995 },
        ca_revenue_changed: true,
        ca_revenue: 105,
      }),
      frame({ version: 1, sequence: 4, balance_set: { payer: 1 } }),
    ]));
    const beforeSnapshot = await fs.readFile(snapshot);
    const beforeWAL = await fs.readFile(`${snapshot}.wal`);
    const { stdout, stderr } = await execFileAsync(process.execPath, [inspector, snapshot, relayID]);
    assert.equal(stdout, "105\t1995\t4\n");
    assert.equal(stderr, "");
    assert.deepEqual(await fs.readFile(snapshot), beforeSnapshot);
    assert.deepEqual(await fs.readFile(`${snapshot}.wal`), beforeWAL);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("CA ledger inspector fails closed on malformed or incomplete WAL frames", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-ca-ledger-invalid-"));
  const snapshot = path.join(directory, "ledger.json");
  try {
    await fs.writeFile(snapshot, JSON.stringify({
      version: 3,
      transaction_sequence: 0,
      relay_income: {},
      ca_revenue: 0,
    }));
    const corrupted = frame({ version: 1, sequence: 1, ca_revenue_changed: true, ca_revenue: 1 });
    corrupted[corrupted.length - 1] ^= 0xff;
    for (const wal of [corrupted, frame({ version: 1, sequence: 1 }).subarray(0, 7)]) {
      await fs.writeFile(`${snapshot}.wal`, Buffer.concat([Buffer.from("BNFSCAW1\n"), wal]));
      await assert.rejects(execFileAsync(process.execPath, [inspector, snapshot, relayID]));
    }
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("CA ledger inspector replays channel set and delete without mixing concurrent CA revenue", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-ca-ledger-channels-"));
  const snapshot = path.join(directory, "ledger.json");
  try {
    await fs.writeFile(snapshot, JSON.stringify({
      version: 3,
      transaction_sequence: 2,
      relay_income: { [relayID]: 2090000 },
      ca_revenue: 160000,
      channels: {
        "target-first": channel(firstSessionID, payerID, relayID, 1000000, 950000, 50000),
        "target-deleted": channel(secondSessionID, payerID, relayID, 200000, 190000, 10000),
        noise: channel(otherSessionID, otherPayerID, relayID, 1000000, 950000, 50000),
      },
    }));
    await fs.writeFile(`${snapshot}.wal`, Buffer.concat([
      Buffer.from("BNFSCAW1\n"),
      frame({
        version: 1,
        sequence: 3,
        relay_income_set: { [relayID]: 8550000 },
        ca_revenue_changed: true,
        ca_revenue: 550000,
        channel_set: {
          "target-first": channel(firstSessionID, payerID, relayID, 2000000, 1900000, 100000),
          noise: channel(otherSessionID, otherPayerID, relayID, 7000000, 6650000, 350000),
        },
      }),
      frame({
        version: 1,
        sequence: 4,
        channel_delete: ["target-deleted"],
        channel_set: {
          "target-second": channel(secondSessionID, payerID, relayID, 500000, 475000, 25000),
        },
      }),
    ]));

    const aggregate = await execFileAsync(process.execPath, [inspector, snapshot, relayID, payerID]);
    assert.equal(aggregate.stdout, "550000\t8550000\t4\t2\t2500000\t2375000\t125000\n");
    assert.equal(aggregate.stderr, "");

    const oneSession = await execFileAsync(process.execPath, [
      inspector, snapshot, relayID, payerID, firstSessionID,
    ]);
    assert.equal(oneSession.stdout, "550000\t8550000\t4\t1\t2000000\t1900000\t100000\n");
    assert.equal(oneSession.stderr, "");
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("CA ledger inspector exposes a target-channel shortfall despite sufficient global revenue", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-ca-ledger-shortfall-"));
  const snapshot = path.join(directory, "ledger.json");
  const authorizedBytes = 4000000;
  try {
    await fs.writeFile(snapshot, JSON.stringify({
      version: 3,
      transaction_sequence: 1,
      relay_income: { [relayID]: 11400000 },
      ca_revenue: 600000,
      channels: {
        target: channel(firstSessionID, payerID, relayID, 3000000, 2850000, 150000),
        noise: channel(otherSessionID, otherPayerID, relayID, 9000000, 8550000, 450000),
      },
    }));

    const { stdout } = await execFileAsync(process.execPath, [inspector, snapshot, relayID, payerID]);
    const [globalCARevenue, , , channelCount, grossTotal, relayTotal, caTotal] = stdout.trim().split("\t").map(Number);
    assert.equal(channelCount, 1);
    assert.equal(grossTotal, 3000000);
    assert.equal(relayTotal, 2850000);
    assert.equal(caTotal, 150000);
    assert.ok(globalCARevenue > authorizedBytes * 0.05);
    assert.ok(grossTotal < authorizedBytes);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("CA ledger inspector rejects unsafe accounting values", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-ca-ledger-unsafe-"));
  const snapshot = path.join(directory, "ledger.json");
  try {
    await fs.writeFile(snapshot, '{"version":3,"transaction_sequence":0,"relay_income":{},"ca_revenue":9007199254740992}');
    await assert.rejects(execFileAsync(process.execPath, [inspector, snapshot, relayID]));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("CA ledger inspector requires canonical lowercase filter identifiers", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-ca-ledger-identifiers-"));
  const snapshot = path.join(directory, "ledger.json");
  try {
    await fs.writeFile(snapshot, JSON.stringify({
      version: 3,
      transaction_sequence: 0,
      relay_income: {},
      ca_revenue: 0,
      channels: {},
    }));
    await assert.rejects(execFileAsync(process.execPath, [inspector, snapshot, relayID.toUpperCase()]));
    await assert.rejects(execFileAsync(process.execPath, [inspector, snapshot, relayID, payerID.toUpperCase()]));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

function frame(value) {
  const payload = Buffer.from(JSON.stringify(value));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length);
  return Buffer.concat([length, payload, crypto.createHash("sha256").update(payload).digest()]);
}

function channel(sessionID, payer, relay, grossTotal, relayTotal, caTotal) {
  return {
    session_id: sessionID,
    payer_node_id: payer,
    relay_node_id: relay,
    gross_total: grossTotal,
    relay_total: relayTotal,
    ca_total: caTotal,
  };
}
