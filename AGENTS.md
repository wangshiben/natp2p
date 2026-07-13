# Repository Agent Instructions

## Local deployment verification

When the user requests a local deployment test, local deployment verification, or equivalent wording, run:

```bash
bash scripts/local-deploy-test.sh
```

The default run must cover all three mandatory scenarios:

1. partitioned NAT/Relay networks with only bridge Relays providing limited reachability;
2. an entry Relay disappearing during transfer and NAT nodes migrating to another Relay;
3. a healthy KCP data path becoming unusable during transfer and TCP taking over.

Do not report the local deployment as passing if any scenario was skipped or failed. A scenario-specific run is allowed while developing the harness, but the full default command is required before final local-deployment sign-off unless the user explicitly narrows the scope.

Do not introduce Python into the local deployment harness. Prefer POSIX/Bash shell and dependency-free JavaScript.
