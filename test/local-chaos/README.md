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
bash scripts/local-chaos-stability.sh start
```

Use `--max-inflight N` to cap the global number of heavy transfer attempts;
the default is two. All six NatClient workers remain active, and each file
transfer shares a 10 MiB/s aggregate workload budget by default. Use
`--workload-limit-mibps N` to change that budget, or zero to disable it. The
runner divides the budget evenly across the in-flight slots; the default two
slots therefore receive 5 MiB/s each. Lower concurrency values trade aggregate
coverage for additional CPU headroom under the 55% resource limit. The total
budget and effective per-transfer ceiling are recorded in `metadata.env` and
`workload.env` for later audit.

The live dashboard listens on the configured host interface at port `8911` by
default; open `http://<dashboard-host>:8911/` from an authorized machine. It shows
the phase and countdown, CA reachability, every container's health/start time
and restart count, end-to-end probes, CPU/memory/disk history, the complete
CA/Index/Relay/NAT topology, the current business path, and a 19 x 7
NAT-to-Relay reachability matrix. Matrix states distinguish direct KCP+TCP,
TCP-only after a UDP/KCP blackhole, runtime-blocked, unknown, and no shared
network. The matrix is explicitly a reachability inference: all pairs use
Compose network membership, while the two active business NATs additionally
use cached runtime iptables rules. It does not claim an active per-pair probe.
The API and page also report the six random Client worker lanes as `alive` or
`stopped`. Worker PID and process start-time values remain private evidence and
are never exposed by `/api/status`.

The Dashboard runs in an independent process session. If the soak reaches
`COMPLETED`, `FAILED`, or `RESOURCE_LIMIT`, the runner stops the workload and
Compose project but leaves the evidence page available with the terminal phase,
failure diagnosis, and four-hop paths. `stop` safely reclaims the Dashboard by
matching its recorded PID, process start time, and command line; a subsequent
`start` performs the same identity-checked cleanup before reusing the port.
Operational commands:

```bash
bash scripts/local-chaos-stability.sh status
bash scripts/local-chaos-stability.sh stop
```

The default resource guard forcibly ends only the soak Compose project when
project CPU exceeds 55% of host capacity, project memory exceeds 40% of host
memory, or the Docker/evidence filesystem exceeds 40% usage. Evidence and the
19 private NAT identities used by this isolated workload are kept under
`test/local-chaos/.soak/runs/<run-id>/` and are ignored by Git.

Each steady-state transfer independently selects an integer payload size from
100 through 200 MiB. The evidence and dashboard retain the requested size,
actual byte count, curl transfer seconds, MiB/s, SHA-256 result, and final
pass/fail status. Checksum computation is excluded from the bandwidth timing.
With the defaults, two transfers may run concurrently at up to 5 MiB/s each,
keeping aggregate application payload at or below 10 MiB/s. Scenario setup may
still apply a lower temporary limit when fault injection requires a long-lived
in-flight transfer.

### Random global workload

The stability workload starts one independent worker lane for each of
`natclient01` through `natclient06`. Every lane reshuffles the same complete
pool of 13 NatServers before each transfer, without filtering candidates by
the Client's or Server's control partition. A Client can therefore choose any
currently accessible NatServer in either partition; this is a global random
workload, not partition-local traffic.

The six lanes run concurrently with randomized initial delay and cooldown, but
the global `--max-inflight` gate limits how many lanes may concurrently restart
a Server, perform the Client handshake, and transfer a file. Waiting for this
gate is deadline-aware; terminating a run closes the lock descriptors and
releases every slot. Each lane independently samples one of the 13 Servers with
replacement. When several lanes select the same Server they first queue on its
per-Server lock, because the current `tunserver` process supports one tunnel
session at a time. Only the lane holding that Server lock may consume a global
slot, so same-target contention cannot occupy several slots. The selection is
retained rather than silently replaced with an unlocked Server. Consequently
this workload exercises random target contention but does not claim that one
NatServer serves multiple tunnel sessions simultaneously.

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
At normal duration completion, the run is accepted only if every NatClient has
at least one successful transfer with a correct SHA-256 result in both control
partitions and the successful global records cover all 13 NatServers.

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
```

## Topology

The generated Compose model contains 27 containers and 10 isolated bridge
networks. A stability run additionally enables CA Web and its host-access
bridge, bringing that run to 28 containers and 11 networks.

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

NatServer03 and NatClient05 use Relay02. Before fault injection, an iptables counter must observe more than 20 outbound KCP packets during an active download. The suite then drops outbound UDP/9000 for both NAT nodes while leaving TCP untouched and requires:

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
