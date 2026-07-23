# BNFS local chaos deployment suite

This suite is the mandatory local-deployment regression entry point. It uses Shell and dependency-free JavaScript; Python is intentionally not used.

## Run

From the repository root:

```bash
bash scripts/local-deploy-test.sh
```

The default command builds the current source, creates the complete topology, runs all three scenarios, writes evidence under `test/local-chaos/.runtime/`, and returns non-zero when any scenario fails.

Development-only options:

```bash
# Run one scenario while editing the harness.
bash scripts/local-deploy-test.sh --scenario 1

# Reuse the already-built local image.
bash scripts/local-deploy-test.sh --no-build

# Preserve containers for manual inspection.
bash scripts/local-deploy-test.sh --scenario 3 --keep

# Execute all scenarios but do not propagate known failures to the shell.
bash scripts/local-deploy-test.sh --no-build --allow-failures
```

`--scenario` and `--allow-failures` are diagnostic options. They do not qualify as a complete local-deployment sign-off.

## Continuous 12-hour stability run

The soak runner starts CA Web, Index, all seven Relays and the NAT containers
once, fixes one randomly selected fault profile for the whole run, and keeps
the same core container identities alive until completion:

```bash
bash scripts/local-chaos-stability.sh run
```

`run` is the unattended/CI entry point. It uses `43200` steady-state seconds
(12 hours) by default, prints a concise progress snapshot every 30 seconds, and
returns zero only for internally consistent `COMPLETED / duration_complete`
evidence. `FAILED`, `RESOURCE_LIMIT`, `STOPPED`, a dead runner without terminal
evidence, or inconsistent terminal files return non-zero. The interval and
duration are configurable for a short environment check:

```bash
bash scripts/local-chaos-stability.sh run --validation-mode smoke \
  --duration-seconds 300 --wait-interval-seconds 5
```

Validation is explicit. `--validation-mode full` is the default at every
duration, including the canonical 43200-second run; duration never silently
downgrades its gates. A short topology diagnostic may opt into
`--validation-mode smoke`. Full mode gives each admitted random attempt a
900-second absolute deadline, while smoke mode uses 180 seconds. The selected
mode, attempt deadline and derived worker-drain timeout are retained in
`metadata.env`.

For a run that must survive the observing shell, use detached `start`, confirm
that startup reaches `RUNNING`, and then attach the same fail-closed waiter:

```bash
bash scripts/local-chaos-stability.sh start
bash scripts/local-chaos-stability.sh status
bash scripts/local-chaos-stability.sh wait --interval-seconds 30
```

`start` returning success while the phase is still `BUILDING`,
`STARTING_CLUSTER`, `CONFIGURING_PROFILE`, or `VERIFYING_BILLING` is not startup
acceptance. A valid 12-hour round must reach `RUNNING`, retain its recorded
`duration_seconds=43200`, and later pass `wait`.

Use `--max-inflight N` to cap the global number of heavy transfer attempts;
the default is two. All six NatClient workers remain active, and each file
transfer shares a 5 MiB/s aggregate workload budget by default. Use
`--workload-limit-mibps N` to change that budget, or zero to disable it. The
runner divides the budget evenly across the in-flight slots; the default two
slots therefore receive 2 MiB/s each. A single in-flight slot receives the full
5 MiB/s budget. Lower concurrency values trade aggregate
coverage for additional CPU headroom under the 55% resource limit. The total
budget and effective per-transfer ceiling are recorded in `metadata.env` and
`workload.env` for later audit.

The live dashboard listens on `127.0.0.1:8911` by default; open
`http://127.0.0.1:8911/` locally. Remote access must be enabled explicitly with
`--dashboard-host 0.0.0.0` and protected by the surrounding network policy. It shows
the phase and countdown, CA reachability, every container's health/start time
and restart count, end-to-end probes, CPU/memory/disk history, the complete
CA/Index/Relay/NAT topology, the current business path, and a 19 x 7
NAT-to-Relay reachability matrix. Matrix states distinguish direct KCP+TCP,
TCP-only after a UDP/KCP blackhole, runtime-blocked, unknown, and no shared
network. The matrix is explicitly a reachability inference: all pairs use
Compose network membership, while the two active business NATs additionally
use cached runtime iptables rules. It does not claim an active per-pair probe.
The API and page also report the six random Client worker lanes as `alive` or
`stopped`. Worker PID, process start-time, and process-group values remain
private evidence and are never exposed by `/api/status`.

The Dashboard runs in an independent process session. If the soak reaches
`COMPLETED`, `FAILED`, or `RESOURCE_LIMIT`, the runner stops the workload and
Compose project but leaves the evidence page available with the terminal phase,
failure diagnosis, and four-hop paths. `stop` safely reclaims the Dashboard by
matching its recorded PID, process start time, and command line; a subsequent
`start` performs the same identity-checked cleanup before reusing the port.
Immediately before publishing `COMPLETED`, the runner revalidates that same
Dashboard process identity and performs one final `/api/status` JSON probe. A
missing process or invalid API response changes the terminal result to `FAILED`.
Operational commands:

```bash
bash scripts/local-chaos-stability.sh status
bash scripts/local-chaos-stability.sh wait
bash scripts/local-chaos-stability.sh stop
```

The default resource guard forcibly ends only the soak Compose project when
project CPU exceeds 55% of host capacity, project memory exceeds 40% of host
memory, or the Docker/evidence filesystem exceeds 40% usage. Evidence and the
19 private NAT identities used by this isolated workload are kept under
`test/local-chaos/.soak/runs/<run-id>/` and are ignored by Git.

Every random worker runs in its own process group. Its PID, process start time,
PGID, and per-run token are stored only in the private run directory. If the
supervisor is killed, the independent resource guard closes that registry,
validates every live group before sending `TERM`/`KILL`, and cleans the Compose
project. An identity mismatch is never signalled; it instead leaves explicit
`FAILED` evidence and a non-zero guard result so the round cannot be accepted.

For the requested first-hour operator audit, run the dependency-free checker
after the detached round reaches `RUNNING`. Its default 21 samples cover the
initial state and every three-minute boundary through one hour; results are
written to `first-hour-audit.tsv` and `first-hour-audit.status` in that run:

```bash
bash test/local-chaos/first-hour-audit.sh /path/to/current/run
```

Each steady-state transfer independently selects an integer payload size from
100 through 200 MiB. The evidence and dashboard retain the requested size,
actual byte count, curl transfer seconds, MiB/s, SHA-256 result, and final
pass/fail status. Checksum computation is excluded from the bandwidth timing.
With the defaults, two transfers may run concurrently at up to 2 MiB/s each,
keeping aggregate application payload at or below 5 MiB/s. Scenario setup may
still apply a lower temporary limit when fault injection requires a long-lived
in-flight transfer.

### Random global workload

The stability workload starts one independent worker lane for each of
`natclient01` through `natclient06`. Before each transfer, a lane filters the
13 NatServers to those hosted by its entry Relay or by a direct control
neighbor, then randomly selects from that one-hop-reachable subset. The lanes
therefore retain different candidate pools where the control topology is
partitioned; their combined successful records, rather than each individual
lane, provide global coverage of all 13 Servers.

The six lanes run concurrently with randomized initial delay and cooldown, but
the global `--max-inflight` gate limits how many lanes may concurrently perform
the Client handshake and transfer a file. Waiting for this gate is deadline-
aware. Each lane owns a separate process group whose leader PID, start time, and
PGID must agree before it is tracked. The duration boundary stops admission of
new attempts; every already-admitted attempt retains one absolute deadline
shared by Client readiness, checksum lookup, payload curl and Server re-arm.
Each step receives only the remaining budget. The runner derives its drain
timeout from that attempt SLA plus the verified process-group stop grace rather
than using an unrelated shorter timeout. A payload deadline records curl-style
`rc=28` evidence with elapsed time instead of leaving the initial `rc=125`
crash-recovery placeholder. If a worker still exceeds the derived drain bound,
the runner sends `TERM` and then
`KILL` to the verified whole group, including a blocked `docker compose exec`
child, converts its durable pending placeholder to `rc=28` with measured elapsed
time, and then reconciles that record. Terminating a run uses the
same group cleanup and releases every slot.
Each lane independently samples its one-hop-reachable Server subset with
replacement across transfers. When
several lanes select the same Server they first queue on its per-Server lock,
because one `tunserver` process serves tunnel sessions sequentially rather than
concurrently. Only the lane holding that Server lock may consume a global slot,
so same-target contention cannot occupy several slots. After an established
Client stops, that lane retains the lock until the Relay records a relative
two-leg registration generation and the Server reports three consecutive fresh
billing-ready snapshots. Normal reuse never cold-restarts `tunserver`; a missing
re-arm fails the worker closed. The selection is retained rather than silently
replaced with an unlocked Server. Consequently this workload exercises random
target contention but does not claim that one NatServer serves multiple tunnel
sessions simultaneously.

### Per-client transfer records

`transfers.tsv` in the run evidence directory is the append-only source for
the Dashboard and `/api/status` `clientTransfers` object. The Dashboard always
renders a card for each of the six NatClients. Each card shows its latest ten
completed attempts in newest-first order, including:

- the runtime-detected ingress Relay;
- the selected target NatServer;
- the actual transferred byte count;
- the average transfer bandwidth in MiB/s;
- the SHA-256 verification result.

The ingress Relay is resolved from the Client network namespace's established
TCP connection to port `9000`; it is not inferred from the selected Server's
partition. An unavailable observation is recorded as `unknown` (or the
transfer is rejected before it starts) instead of fabricating a runtime path.
An attempt that never transferred bytes is shown as `未校验`, not as a checksum
mismatch. In fault profile 2, the migrated pair keeps using `relay02` while the
remaining random workers continue through `relay01`.
`workload.env` records this as `random_ingress_override=natclient04:relay02`;
profiles without a Client ingress override record `random_ingress_override=none`.
Each lane samples only Servers hosted by the same Relay or a direct control
neighbor. This preserves the one-hop FIND boundary: in profile 2, `natclient04`
uses the local `natserver02`, while the bridge-Relay lanes cover the remaining
Server pool without inventing `relay02 -> index -> relay01 -> leaf` reachability.
At normal duration completion, the run is accepted only if every NatClient has
at least one successful transfer with a correct SHA-256 result in every control
partition reachable from its entry Relay, and the successful global records
cover all 13 NatServers. Fault profile 2 additionally requires every successful
`natclient04` record to show the runtime-detected `relay02` ingress and every
other Client success to show `relay01`; configured table values alone do not
satisfy this gate.

Smoke mode does not claim the 12-hour coverage result. It still requires one
successful SHA-256 transfer from every Client lane, rejects every non-one-hop
route, enforces the scenario-specific runtime ingress, and requires collective
coverage of every control partition present in the Server pool. Only full mode
requires each Client's reachable-partition coverage and global 13/13 Server
coverage; the default 12-hour command always remains in that mode.

### Live failure watcher

Each stability run starts a dependency-free Node watcher beside the Dashboard.
It incrementally follows complete rows appended to `transfers.tsv`; it does not
restart workers, containers, or any part of the test topology. Records already
present on the watcher's first attachment are counted as the historical
baseline and are not reported as new alerts. A restarted watcher resumes from
its persisted cursor, so failures appended while it was down are detected as
new observations.

`failure-watcher.json` is an atomically replaced, fixed-size snapshot. It keeps
at most 20 recent live alerts by default while separately retaining cumulative
baseline and observed counters. Alert records contain only timestamps, logical
service names, the four-hop logical route, return code, byte/second progress,
an allow-listed failure category, and boolean evidence signals. Transfer IDs,
NodeIDs, addresses, hashes, credentials, and raw log text are never copied into
the snapshot. `/api/status` exposes the same data through the whitelisted
`failureWatcher` object, including heartbeat health, source lag, baseline
counts, live failure counts, and the bounded recent-alert ring.

The runner treats watcher startup or unexpected watcher exit as an explicit
failure instead of silently continuing an unmonitored soak. Normal completion
and `stop` terminate the watcher with the other run-scoped workload processes;
its final bounded snapshot remains available through the persistent terminal
Dashboard. A fast isolated regression can be run without Docker or Python:

```bash
node --test test/local-chaos/monitor/failure-watcher.test.mjs
bash test/local-chaos/dashboard-lifecycle.test.sh
bash test/local-chaos/client-credit-order.test.sh
bash test/local-chaos/client-entry-relay.test.sh
bash test/local-chaos/stability-wait.test.sh
bash test/local-chaos/resource-guard-worker-cleanup.test.sh
```

### Billing recovery gate and malicious nodes

Before any random worker or billing-adversary sidecar starts, the stability
runner executes a fail-closed production `waitSubmit` gate against the real
Compose NatServer and Relay processes. It establishes a fresh tunnel, pauses
the CA settlement service, transfers 4 MiB through the data plane, and requires
the Relay's real queue inspector to observe at least three complete double-signed
vouchers. It then sends `SIGKILL` to that Relay and, while the CA is still
paused, runs the host inspector against the bind-mounted WAL. Queue depth,
payload bytes, incomplete-tail state, and a private whole-file digest must be
unchanged across the crash boundary.

The Relay certificate is currently obtained at process startup and is not
persisted, so the harness does not claim that a Relay can start while the CA is
offline. After the crash-persistence observation, it resumes the CA and starts
the same Relay container. The gate requires the queue to drain to zero, the
payer debit to be no greater than the verified transfer size, and the unbilled
Record-boundary tail to be strictly less than the 1 MiB window. A checksum-
verifying, read-only ledger inspector then requires both the Relay balance and
Relay income to increase by `floor(payer debit * 95 / 100)`, while CA revenue
increases by the remaining 5 percent. It then captures a new core-container
identity baseline. Any missing observation, malformed WAL, overcharge,
excessive tail, transfer failure, changed crash snapshot, recovery timeout, or
accounting mismatch fails startup; there is no model-only fallback.

Because the production gate deliberately restarts its Relay, every affected
random-workload NatServer must pass a recovery barrier before any random worker
starts. The gate Server, `REAL_BILLING_GATE_SERVER` (`natserver06` by default),
has already completed a recovery transfer and can retain a sub-window usage tail.
It is therefore never cold-restarted a second time: the runner waits for the same
process and billing meter to re-arm both TCP legs and report three consecutive
fresh billing snapshots. Other affected Servers have carried no gate payload,
so the runner may cold-restart them and additionally requires retained NodeID,
a new two-leg registration generation, one Tunnel Server process, and the same
stable billing-ready evidence. The gate Server is intentionally not marked as a
fresh channel after this barrier.

The stability Compose model also starts two billing-conformance fixture
containers on a dedicated bridge. After the CA becomes healthy, a host
provisioner supplies each fixture with a role-bound certificate through its
private state directory and credits only the isolated NatServer account. CA
enrollment and administration tokens are never mounted into either fixture.
The fixtures have no production NAT/Relay identity, account, private state, or
network attachment. They communicate only with each other over HTTP and with
the local test CA, and cover four NatServer and five Relay behaviors, including
identity forgery. This is container HTTP/CA conformance evidence, not a complete
P2P payload-socket or production-session-state-machine test.

Only after the production gate passes does the runner start the isolated
billing-adversary sidecar and its long-lived Go component helper. The sidecar
first requires fresh, internally consistent 9/9 snapshots from both container
fixtures, then rechecks them on every heartbeat. Missing coverage, stale or
malformed status, fixture exit, or a reported containment violation is surfaced
as an explicit `billing_container_probe_*` failure. The API layer
creates one synthetic NatServer identity and one synthetic Relay identity,
obtains 24-hour local test certificates, and confines all requests to the
loopback CA. For every API attack, the helper independently executes the same
scenario against the production `billingrecord`, `billingvoucher`,
`billingcontrol`, and, where applicable, `billingqueue` packages. A scenario is
contained only when both layers pass. A missing, exited, timed-out, malformed,
or FAIL-returning helper is fail-closed and reaches the existing `enforce`
failure path. No production identity, credential, NodeID, address, key, run
directory, executable path, command, container ID, PID, or process start time is
copied to its snapshot or the Dashboard API.

Before the sidecar can report healthy both layers execute all nine required scenarios:
Relay usage inflation, voucher replay, fee-policy override, a sequence exceeding
the 1 MiB window, a stale NatServer watermark, a same-sequence NatServer fork,
NatServer signature refusal, Relay record-root tampering, and an Index-link
disconnect followed by FIFO recovery and a tail replay. It then selects one of
the nine scenarios randomly every interval. The API disconnect probe uses an
unreachable loopback target, persists each failed submission with an atomic file
replacement and directory sync, reopens that file to simulate a sidecar restart,
then drains it in strict FIFO order to the real local CA. Every head removal is
persisted, and a final tail replay verifies CA idempotency. In parallel, the Go
helper queues three real double-signed 1 MiB vouchers with `billingqueue`, closes
and reopens its WAL after every enqueue, verifies FIFO identity and duplicate
protection, and closes and reopens after every durable removal.

The helper is a production-package component probe, not a full malicious
NatServer or Relay container. It derives real `billingrecord.Record` IDs and
record-set digests, authenticates a Relay claim, compares it with an independent
Nat meter snapshot, applies the Nat signature, parses and verifies the canonical
double-signed voucher, and injects the selected mutation. It also verifies
voucher-chain session binding and payer Ready-proof binding. It does not create
the complete P2P socket path or instantiate the Nat/Relay in-memory session-reset
state machines; those paths remain covered by the real production gate and the
Nat/Relay package race tests. The Dashboard must not present component-helper
coverage as evidence of the complete P2P socket path. Likewise, the container
fixture must be labeled as isolated HTTP/CA conformance and not as payload-path
coverage.

Every malicious request is checked against both synthetic account balances.
Acceptance, any rejected-request balance mutation, a non-idempotent replay,
failure to freeze a same-sequence fork, an unavailable voucher API, incomplete
coverage, a stale heartbeat, or a sidecar exit is a security failure. In the
default `enforce` mode the runner writes a `billing_adversary_*` failure detail
and ends the soak. `--billing-adversary report` retains the red Dashboard result
for a recorded containment violation without ending a transport-only diagnostic
run; missing coverage, stale/malformed evidence, and fixture lifecycle failures
remain fatal harness errors. `off` omits the fixtures and sidecar and does not
qualify as billing-security coverage.

Each tunnel server writes a service-private `billing-meter.json` snapshot with
mode `0600` under its `0700` bind mount. The snapshot is atomically refreshed
every 100 ms and on billing state changes; it contains only session watermarks
and numeric aggregates, and is never served over HTTP. The production gate
validates that private NAT evidence, verifies the canonical double-signed
target-channel chain directly from the frozen production WAL, and replays the
CA ledger by payer and Relay so unrelated channel revenue cannot affect the
result. It atomically replaces `billing-production-gate.json` with schema
version 2, status, a strictly whitelisted detail code, three aggregate queue
depths, separate HTTP body/NAT-observed/WAL-authorized/debited byte counts, the
unsettled tail, target-channel Relay/CA deltas, the amount and split verdicts,
and an observation timestamp. The sidecar atomically replaces
`billing-adversary.json` and `billing-adversary.status`. Its bounded
`componentProbe` summary contains only schema, lifecycle status, executed/failed
counts, and required/covered scenario counts. Its separate `containerProbe`
view strictly whitelists the two fixture roles, nine scenario counters, bounded
recent verdicts, fixed transport labels, and a fixed limitation stating that no
full P2P payload socket is instantiated. The Dashboard
shows the real production gate separately from the model scenario and exposes
only whitelisted views with two dedicated `malicious-natserver` and
`malicious-relay` cards. Each card combines the fixed service name, container
running/health/restart state, per-role probe coverage and the latest sanitized
attack verdict; container IDs, addresses, NodeIDs, keys and private paths are
never exposed. The surrounding security panel also retains
per-actor and per-scenario execution, prevented, missed/FAIL, prevention rate,
and bounded recent verdicts. Fast regressions are:

The full P2P evidence uses a separate mixed path rather than treating the two
isolated fixtures as a network topology. `malicious-natserver` registers with a
real normal Relay in `control_partition_a` or `control_partition_b`, while
Relay03 maintains a real control peer with `malicious-relay`. A normal tunnel
client initially traverses the malicious Relay toward the malicious NatServer.
The controller consumes every new NatServer-side and Relay-side contained
event in sequence. For each event it isolates the affected process, selects a
different normal Relay03–Relay07, restores the live normal-partition
attachment, and verifies a real 1 MiB payload by SHA-256. NatServer migrations
use a newly generated P-256 network identity, a freshly issued certificate and
new credit so returning to a previously used Relay never requires weakening
the Relay's fail-closed stale-tail checks. The Dashboard continues to aggregate
these identities as the single logical `malicious-natserver` node and never
exposes enrollment credentials or private identity material.

At the duration boundary the runner requests a mixed-path drain. The controller
finishes the active migration, stops accepting new events and publishes
`drain_complete=1` before terminal validation. The terminal gate requires at
least nine verified migrations, all 9/9 malicious scenarios exercised against
normal partitions, zero containment violations, one network event and verified
migration per generation, and current post-migration payload evidence. The
main topology contains only normal-Relay-to-malicious-node edges; the isolated
fixture's malicious-to-malicious HTTP exchange remains separate protocol
evidence and is never presented as a P2P topology edge.

```bash
node --test test/local-chaos/monitor/billing-adversary.test.mjs
node --test test/local-chaos/monitor/billing-container-probe.test.mjs
node --test test/local-chaos/provision-adversaries.test.mjs
go test -race ./test/local-chaos/billingadversary ./cmd/billing-adversary-probe
go test ./cmd/billing-adversary-node
node --test test/local-chaos/ca-ledger-inspect.test.mjs
node --test test/local-chaos/nat-billing-private-inspect.test.mjs
node --test test/local-chaos/generate-compose.test.mjs
bash test/local-chaos/billing-adversary-gate.test.sh
bash test/local-chaos/billing-production-gate.test.sh
bash test/local-chaos/mixed-path-gate.test.sh
bash test/local-chaos/post-gate-server-recovery.test.sh
```

## Topology

The generated Compose model contains 27 containers and 10 isolated bridge
networks. A stability run additionally enables CA Web, two isolated billing-
conformance fixture containers, the CA host-access bridge, and the fixture
bridge, bringing that run to 30 containers and 12 networks.

All containers retain the shared `/artifacts` mount for transfer payloads and
test evidence. A second, nested bind mount overlays `/artifacts/.private` with
only that service's private directory. CA keys and ledger state, Index/Relay
identity keys and `waitSubmit` queues, and stability NAT identity keys therefore
remain unavailable to sibling containers even though shared workload artifacts
remain visible.

| Role | Count |
|---|---:|
| Index | 1 |
| Relay | 7 |
| NatServer | 13 |
| NatClient | 6 |

Control topology:

```text
                          control_index 10.200.0.0/24
                    ┌──────── Index ────────┐
                    │                       │
             Relay01 (bridge)                 Relay02
                    │                            │
                    ├────────────────────────────┘
                    │
                    ├── control_partition_a 10.200.1.0/24: Relay02–Relay05
                    └── control_partition_b 10.200.2.0/24: Relay06–Relay07
```

`Index` has no interface in either partition, so it cannot directly connect to Relay03–Relay07. Relay01 is the application-level bridge attached to both partitions and maintains direct control links to every leaf Relay. Relay01 and Relay02 remain the two Index-visible entry candidates used by the failover scenario. Relay02–Relay05 share partition A exactly as exercised by the stability workload.

Each Relay also owns an isolated access network `10.201.N.0/24`. NatServer containers are distributed across Relay01 and Relay03–Relay07, while the six NatClient containers enter through bridge Relay01 so every client can select a server from either partition without assuming unsupported multi-hop FIND. The failover pair remains attached to `control_index` so it can reach Relay01 and Relay02. Docker bridge isolation is therefore the first connectivity boundary; service-level FIND behavior is verified separately.

The generated ranges are isolated from host and production networks. Host-specific
Flannel, Kubernetes, Docker, LAN, and other infrastructure ranges are intentionally
omitted from this repository; deployment checks select non-overlapping ranges at
runtime.

## Mandatory scenarios

### 1. Partition and bridge Relay

The scenario verifies all of the following:

- Index cannot directly connect to a partitioned leaf Relay;
- a leaf-side NAT node can connect only to its assigned Relay network;
- two NAT nodes on the same leaf Relay can communicate;
- a NAT client entering through bridge Relay01 can reach a server hosted by Relay03;
- a client entering through ordinary leaf Relay04 cannot use it as an unauthorized bridge to Relay03.

### 2. Entry Relay loss during transfer

NatServer02 and NatClient04 initially see Relay02 as unreachable, so both select Relay01. During a rate-limited 50MiB transfer the suite stops Relay01, restores Relay02 reachability, and requires:

- both NAT nodes to switch their retained candidate generation and register with Relay02 within 45 seconds;
- the in-flight transfer to recover and finish with the expected byte count.

Each NAT node shares one ordered candidate cursor across registration and business legs. A Relay address receives five TCP reconnect attempts before the cursor advances; candidates are tried until exhausted. UDP/KCP failure alone never advances the Relay cursor because a healthy TCP leg proves that the Relay itself remains reachable.

The large payload prevents socket/application buffering from creating a false pass after Relay01 has stopped.

### 3. KCP to TCP under UDP blackhole

NatServer03 registers through Relay03 and NatClient05 enters through bridge
Relay01. Before fault injection, an iptables counter must observe more than 20
outbound KCP packets during an active download. The suite then drops outbound
UDP/9000 for both NAT nodes while leaving TCP untouched and requires:

- the existing TCP Relay connection to remain alive;
- the 5MiB transfer to complete;
- source and destination SHA-256 hashes to match.

This precondition prevents a TCP-primary connection from being mislabeled as a KCP-to-TCP failover success.

## Build and security

The runner builds static Go binaries on the host and creates the test image from the already-present `centos:centos7` image. This avoids the configured external image mirror and ensures `.credentials/` never enters the Docker build context. A static BusyBox supplies local network probes; iptables fault injection is executed by the host through `nsenter` into the selected container's network namespace.

The suite does not mount production credentials, does not contact the production CA, and does not publish container ports to the host or LAN.

## Evidence

Each scenario records:

- NAT application logs;
- complete Compose logs;
- download result and return code;
- per-container CPU, memory and PID snapshots;
- host load, memory and running-container count;
- a top-level `summary.tsv`.

Runtime evidence is intentionally ignored by Git. Stable conclusions belong in `BASELINE.md`.
