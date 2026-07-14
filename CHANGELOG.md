# Changelog

## 1.3 - 2026-07-14

### Added

- Native ARM64 ipfixprobe build workflow.
- Native synthetic-PCAP smoke test.
- Pinned ARM64 Docker build.
- Docker smoke test with FUSE telemetry.
- Native-versus-Docker reproducibility comparison.
- Machine-readable P1a, P1b, and P1c validation manifests.
- Shared dependency pins in docker/versions.env.

### Validated

- ipfixprobe v5.7.0 at commit f0f16888c426eced7adeed8fc2158362aca1a271.
- 11 packets parsed into 3 biflows.
- Zero packet drops.
- Zero output drops.
- Zero FlowEndReason:Collision events.
- Byte-identical native and Docker flow output, runtime log, and cache telemetry.
