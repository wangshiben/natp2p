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

## Topology

The generated Compose model contains 37 containers and 11 isolated bridge networks:

| Role | Count |
|---|---:|
| Index | 1 |
| Relay | 9 |
| NatServer | 17 |
| NatClient | 10 |

Control topology:

```text
                         control_index 10.200.0.0/24
                 ┌──────── Index ────────┐
                 │                       │
             Relay01                 Relay02
                 │
        control_partition 10.200.1.0/24
      ┌──────┬──────┬──────┬──────┬──────┐
   Relay03 Relay04 Relay05 Relay06 ... Relay09
```

`Index` has no network interface in `control_partition`, so it cannot directly connect to Relay03–Relay09. Relay01 is the only application-level bridge with direct control links to all leaf Relays. Relay01 and Relay02 are the two Index-visible entry candidates used by the failover scenario.

Each Relay also owns an isolated access network `10.201.N.0/24`. NAT containers are attached only to their permitted access network, except the failover pair, which is attached to `control_index` so it can reach Relay01 and Relay02. Docker bridge isolation is therefore the first connectivity boundary; service-level FIND behavior is verified separately.

The ranges do not overlap the current host's Flannel `10.244.0.0/16`, Kubernetes Service `10.96.0.0/12`, Docker `172.17.0.0/16` / `172.29.0.0/16`, or LAN `192.168.1.0/24` networks.

## Mandatory scenarios

### 1. Partition and bridge Relay

The scenario verifies all of the following:

- Index cannot directly connect to a partitioned leaf Relay;
- a NAT node can connect only to its assigned Relay network;
- two NAT nodes on the same leaf Relay can communicate;
- a NAT client entering through Relay01 can reach a server hosted by Relay03;
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
