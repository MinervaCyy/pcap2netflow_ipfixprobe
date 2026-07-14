# Implementation Notes

## Current scope

The repository currently covers prerequisite validation only:

- P1a: native ARM64 build and smoke test;
- P1b: Docker ARM64 build and smoke test; and
- P1c: native-versus-Docker equivalence.

Dataset conversion, label alignment, daily processing, and final export validation are not yet implemented.

## Important operational notes

- The tested host is NVIDIA DGX Spark on Ubuntu 24.04 ARM64.
- ipfixprobe requires an explicit plugins path.
- Telemetry uses FUSE.
- Docker telemetry requires /dev/fuse, SYS_ADMIN, and an unconfined AppArmor profile.
- The current shell may require sg docker until a new login session inherits Docker group membership.
- Generated PCAPs, outputs, logs, telemetry, build trees, and staging directories are intentionally excluded from Git.

## Smoke-test cache settings

- size exponent: 17
- line exponent: 4
- active timeout: 300 seconds
- inactive timeout: 65 seconds

The FlowEndReason:Collision counter must remain zero.
