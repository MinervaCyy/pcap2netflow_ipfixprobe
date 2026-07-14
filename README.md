# pcap2netflow_ipfixprobe

Reproducible ARM64 pipeline for converting PCAP files into bidirectional flow records with ipfixprobe.

## Validation status

Pipeline version: **1.3**

- P1a: Native ARM64 build and smoke test passed
- P1b: Docker ARM64 build and smoke test passed
- P1c: Native versus Docker comparison passed

Evidence manifests:

- manifests/p1a_native_smoke.json
- manifests/p1b_docker_smoke.json
- manifests/p1c_native_docker_comparison.json

## Commands

Native build:

    ./scripts/00_build_native_ipfixprobe.sh

Native smoke test:

    ./scripts/00_native_smoke.sh

Docker smoke and comparison:

    sg docker -c ./scripts/00_docker_smoke.sh

## Data policy

Raw PCAPs, intermediate files, generated flow records, logs, and telemetry are excluded from Git.

A non-zero FlowEndReason:Collision counter fails the prerequisite gate because it may indicate silent flow splitting.
