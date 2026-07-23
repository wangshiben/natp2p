import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { test } from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const inspector = fileURLToPath(new URL("./nat-billing-private-inspect.mjs", import.meta.url));

test("private NAT billing inspector emits only aggregate watermarks", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-nat-billing-private-"));
  const snapshot = path.join(directory, "billing-meter.json");
  await fs.chmod(directory, 0o700);
  try {
    const value = validSnapshot();
    await fs.writeFile(snapshot, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    const { stdout, stderr } = await execFileAsync(process.execPath, [inspector, snapshot]);
    assert.match(stdout, /^1\ttrue\t2\t1500\t1200\ttrue\t[1-9][0-9]*\n$/);
    assert.equal(stderr, "");
    assert.equal(stdout.includes(value.sessions[0].session_id), false);
    assert.equal(stdout.includes(snapshot), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("private NAT billing inspector rejects inconsistent or unsafe snapshots", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-nat-billing-invalid-"));
  const snapshot = path.join(directory, "billing-meter.json");
  await fs.chmod(directory, 0o700);
  try {
    const cases = [
      { ...validSnapshot(), active_session_count: 1 },
      { ...validSnapshot(), cumulative_observed_bytes: 1499 },
      { ...validSnapshot(), last_cosigned_cumulative: 1501 },
      { ...validSnapshot(), generated_at: "not-a-time" },
      { ...validSnapshot(), sessions: [{ ...validSnapshot().sessions[0], confirmed_sequence: 3 }] },
    ];
    for (const value of cases) {
      await fs.writeFile(snapshot, `${JSON.stringify(value)}\n`, { mode: 0o600 });
      await assert.rejects(execFileAsync(process.execPath, [inspector, snapshot]));
    }
    await fs.chmod(snapshot, 0o644);
    await assert.rejects(execFileAsync(process.execPath, [inspector, snapshot]));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("private NAT billing inspector refuses symlink snapshots", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bnfs-nat-billing-symlink-"));
  const target = path.join(directory, "target.json");
  const snapshot = path.join(directory, "billing-meter.json");
  await fs.chmod(directory, 0o700);
  try {
    await fs.writeFile(target, `${JSON.stringify(validSnapshot())}\n`, { mode: 0o600 });
    await fs.symlink(target, snapshot);
    await assert.rejects(execFileAsync(process.execPath, [inspector, snapshot]));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

function validSnapshot() {
  return {
    version: 1,
    generated_at: "2026-07-20T00:00:00.123Z",
    billing_enabled: true,
    active_session_count: 2,
    cumulative_observed_bytes: 1500,
    last_cosigned_cumulative: 1200,
    sessions: [
      {
        session_id: "a".repeat(64),
        cumulative_observed_bytes: 1000,
        last_record_sequence: 2,
        confirmed_sequence: 2,
        last_cosigned_cumulative: 900,
      },
      {
        session_id: "b".repeat(64),
        cumulative_observed_bytes: 500,
        last_record_sequence: 1,
        confirmed_sequence: 1,
        last_cosigned_cumulative: 300,
      },
    ],
  };
}
