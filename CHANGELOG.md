# Changelog

## Unreleased - 1.4 development

### Added

- Blocking IPFIX/TCP loopback transport from ipfixprobe to IPFIXcol2.
- IPFIXcol2 JSON Lines output as the public machine-readable interface.
- Pinned libfds 0.6.0 and IPFIXcol2 2.8.0 source revisions.
- Reproducible GCC 14 native collector build.
- Reproducible ARM64 Docker image build driven by `docker/versions.env`.
- Versioned biflow schema at
  `schemas/ipfixcol2-biflow-v1.schema.json`.
- Standard-library JSON contract validator with duplicate-key detection.
- Native IPFIX-to-JSON smoke test.
- Native-versus-Docker JSON parity test.
- P1d provenance manifest and portable verification evidence bundle.
- Collector configuration and schema hashes in provenance evidence.

### Changed

- The text output plugin is retained only for diagnostics and legacy smoke
  regression.
- The machine-readable path is now ipfixprobe to blocking IPFIX/TCP to
  IPFIXcol2 to JSON.
- `splitBiflow=false` is a mandatory semantic contract.
- Reverse fields are consumed using their literal IPFIXcol2 names.
- Timestamp values are documented and validated as Unix milliseconds despite
  retained Information Element names containing `Microseconds`.
- Every JSON run uses a fresh output directory and checks that JSON record count
  equals `TotalExportedFlows`.

### Validated

- ipfixprobe 5.7.0 at commit
  `f0f16888c426eced7adeed8fc2158362aca1a271`.
- libfds 0.6.0 at commit
  `0f148edede1743d6961527965930cf558e9a411e`.
- IPFIXcol2 2.8.0 at commit
  `4fffd44fbe6ecfe7ae7ad88d2caf53f83a3dd1d0`.
- TCP input plugin 3.0.0 and JSON output plugin 2.2.0.
- GCC 14 native and Docker collector builds.
- Three exported biflow JSON records from the eleven-packet smoke fixture.
- Zero packet drops, output drops, and collision events.
- Schema validation with nineteen observed and zero undeclared fields.
- Native and Docker sorted JSON output is byte-identical.
- Fixed smoke JSON SHA-256:
  `16f87326ebda807198aa59c5e8e87eb79fca150334ceb57ab8f162e1f0567b62`.

### Release status

The implementation is versioned 1.4 and remains in development. An annotated
`v1.4` tag will mark the released revision.

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
