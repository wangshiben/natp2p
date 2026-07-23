import { spawn } from "node:child_process";
import path from "node:path";

const maximumLineBytes = 16 * 1024;
const safeTokenPattern = /^[a-z0-9_-]{1,64}$/;
const packageAllowlist = new Set([
  "billingcontrol",
  "billingqueue",
  "billingrecord",
  "billingvoucher",
]);
const resultKeys = [
  "checks",
  "failureCode",
  "limitations",
  "productionPackages",
  "scenario",
  "schemaVersion",
  "status",
];

export function createBillingComponentProbe({ binaryPath, stateDir, timeoutMs = 3000 }) {
  if (typeof binaryPath !== "string" || !path.isAbsolute(binaryPath)) {
    throw codedError("component_probe_binary_invalid");
  }
  if (typeof stateDir !== "string" || !path.isAbsolute(stateDir) || stateDir === path.parse(stateDir).root) {
    throw codedError("component_probe_state_dir_invalid");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) {
    throw codedError("component_probe_timeout_invalid");
  }
  return new BillingComponentProbe(binaryPath, stateDir, timeoutMs);
}

class BillingComponentProbe {
  constructor(binaryPath, stateDir, timeoutMs) {
    this.timeoutMs = timeoutMs;
    this.pending = null;
    this.output = "";
    this.fatalCode = "";
    this.closing = false;
    this.child = spawn(binaryPath, ["-state-dir", stateDir], {
      stdio: ["pipe", "pipe", "ignore"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => this.consume(chunk));
    this.child.once("error", () => this.fail("component_probe_unavailable"));
    this.child.once("exit", () => {
      if (!this.closing) this.fail("component_probe_exited", false);
    });
    this.child.stdin.on("error", () => this.fail("component_probe_unavailable"));
  }

  run(scenario, nonce) {
    if (this.closing) return Promise.reject(codedError("component_probe_closed"));
    if (this.fatalCode) return Promise.reject(codedError(this.fatalCode));
    if (this.child.exitCode !== null || this.child.signalCode !== null) {
      return Promise.reject(codedError("component_probe_exited"));
    }
    if (this.pending) return Promise.reject(codedError("component_probe_busy"));
    if (!safeTokenPattern.test(String(scenario)) || !/^[A-Za-z0-9_-]{1,160}$/.test(String(nonce))) {
      return Promise.reject(codedError("component_probe_request_invalid"));
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail("component_probe_timeout"), this.timeoutMs);
      const pending = { scenario, resolve, reject, timer };
      this.pending = pending;
      const request = `${JSON.stringify({ scenario, nonce })}\n`;
      this.child.stdin.write(request, (error) => {
        if (error && this.pending === pending) this.fail("component_probe_unavailable");
      });
    });
  }

  consume(chunk) {
    if (this.fatalCode || this.closing) return;
    this.output += chunk;
    if (Buffer.byteLength(this.output) > maximumLineBytes) {
      this.fail("component_probe_output_oversize");
      return;
    }
    while (true) {
      const newline = this.output.indexOf("\n");
      if (newline < 0) return;
      const line = this.output.slice(0, newline);
      this.output = this.output.slice(newline + 1);
      if (!this.pending) {
        this.fail("component_probe_unsolicited_output");
        return;
      }
      let parsed;
      try {
        parsed = JSON.parse(line);
        validateResult(parsed, this.pending.scenario);
      } catch {
        this.fail("component_probe_output_invalid");
        return;
      }
      const pending = this.pending;
      this.pending = null;
      clearTimeout(pending.timer);
      pending.resolve(parsed);
    }
  }

  fail(code, terminate = true) {
    if (!this.fatalCode) this.fatalCode = code;
    const pending = this.pending;
    this.pending = null;
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(codedError(this.fatalCode));
    }
    if (terminate && this.child.exitCode === null && this.child.signalCode === null) {
      this.child.kill("SIGKILL");
    }
  }

  async close() {
    if (this.closing) return;
    this.closing = true;
    const pending = this.pending;
    this.pending = null;
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(codedError("component_probe_closed"));
    }
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    this.child.stdin.end();
    const exited = new Promise((resolve) => this.child.once("exit", resolve));
    const graceful = await Promise.race([
      exited.then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 1000)),
    ]);
    if (graceful) return;
    this.child.kill("SIGKILL");
    await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(resolve, 1000)),
    ]);
  }
}

function validateResult(value, expectedScenario) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid result");
  const keys = Object.keys(value).sort();
  if (keys.length !== resultKeys.length || keys.some((key, index) => key !== resultKeys[index])) {
    throw new Error("invalid result fields");
  }
  if (value.schemaVersion !== 1 || value.scenario !== expectedScenario || !["PASS", "FAIL"].includes(value.status)) {
    throw new Error("invalid result identity");
  }
  if (typeof value.failureCode !== "string"
    || (value.status === "PASS" ? value.failureCode !== "" : !safeTokenPattern.test(value.failureCode))) {
    throw new Error("invalid failure code");
  }
  validateTokenArray(value.checks, 1, 16, safeTokenPattern);
  validateTokenArray(value.productionPackages, 1, packageAllowlist.size, safeTokenPattern);
  if (value.productionPackages.some((name) => !packageAllowlist.has(name))) {
    throw new Error("invalid production package");
  }
  validateTokenArray(value.limitations, 1, 8, safeTokenPattern);
}

function validateTokenArray(value, minimum, maximum, pattern) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum
    || value.some((item) => typeof item !== "string" || !pattern.test(item))
    || new Set(value).size !== value.length) {
    throw new Error("invalid token array");
  }
}

function codedError(code) {
  return Object.assign(new Error(code), { code });
}
