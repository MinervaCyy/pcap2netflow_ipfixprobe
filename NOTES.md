# Implementation Notes

## Current scope

The repository currently covers:

- P1a: native ARM64 ipfixprobe build and text-output smoke test;
- P1b: Docker ARM64 ipfixprobe build and text-output smoke test;
- P1c: native-versus-Docker text-output equivalence; and
- P1d: native-versus-Docker IPFIX-to-JSON schema and byte-parity validation.

The v1.4-dev output implementation is complete:

    ipfixprobe
    -> blocking IPFIX over TCP loopback
    -> IPFIXcol2
    -> JSON Lines

Native and Docker builds, collector lifecycle handling, flow-count
cross-checks, collision checks, schema validation, deterministic sorted-output
comparison, and provenance publication have all passed.

The implementation is versioned 1.4 but remains in development until an
annotated `v1.4` tag is created. The tag is the release boundary; no separate
freeze commit or release ceremony is required.

The P1a-P1c manifests remain historical v1.3 evidence and must not be rewritten
as v1.4 results.

Dataset conversion, label alignment, daily processing, and final export
validation are not yet implemented.

## v1.4-dev validation commands

The reproducible validation sequence is:

    ./scripts/00_build_native_ipfixprobe.sh
    ./scripts/00_build_native_collector.sh
    ./scripts/00_build_docker_image.sh
    ./scripts/01_native_ipfix_json_smoke.sh
    ./scripts/02_docker_ipfix_json_parity.sh

The parity test also invokes the versioned flow validator. Successful evidence
can be published with `scripts/03_publish_ipfix_json_verification.py`.

The fixed synthetic JSON baseline contains three biflow records and has
SHA-256:

    16f87326ebda807198aa59c5e8e87eb79fca150334ceb57ab8f162e1f0567b62

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

## Output interface notes

The ipfixprobe text output is retained for diagnostics and smoke testing only.

In the tested ipfixprobe v5.7.0 build, the text header describes seven logical
columns:

    mac conversation packets bytes tcp-flags time extensions

When extensions are empty, records contain only six whitespace-separated
fields. The conversation field also combines addresses, ports, and direction
markers into one string, which is unsuitable as the public machine-readable
interface and can become ambiguous for IPv6.

UniRec was investigated but is intentionally not implemented. The format is
technically strong and provides typed fields and native IP address handling.
However, enabling it would require rebuilding the already validated ipfixprobe
binary, source-building the NEMEA dependency chain on ARM64, and adding either
pytrap or Nemea-Modules for consumption.

The selected interface is:

    ipfixprobe
    -> blocking IPFIX over TCP
    -> IPFIXcol2
    -> JSON

The upstream IPFIXcol2 JSON plugin links librdkafka even when only local file
output is used. The project accepts `librdkafka-dev` as an inert build
dependency and does not require a Kafka service, broker, port, or runtime
configuration.

See `docs/adr/0001-output-interface.md` for the complete decision record.

## JSON schema warnings

With the tested JSON configuration:

- `timestamp=unix` emits Unix timestamps in milliseconds, even when the
  Information Element name contains `Microseconds`;
- reverse fields use literal names such as
  `iana@reverse:octetDeltaCount@reverse`;
- `splitBiflow=false` is mandatory because downstream labeling and count checks
  assume one record per bidirectional flow;
- parsers must use an explicit required-field map and fail loudly when required
  fields are absent; and
- deterministic comparisons are performed on sorted JSON record content, not
  rotated filenames or original write order.

## v1.4 robustness gate

The complete Tcpreplay `bigFlows.pcap` capture passed the v1.4 robustness
gate on DGX Spark ARM64. Provenance, version pins, capture metadata, run
durations, record counts, hashes, determinism results, and native/Docker parity
are recorded in:

    manifests/robustness_bigflows_v1.4.json

The published Tcpreplay flow count is only an order-of-magnitude reference:
this pipeline exports bidirectional flows with a 300-second active timeout and
a 65-second inactive timeout, so equality with the published count is not
asserted.

An earlier characterization of `smallFlows.pcap` as real traffic was
incorrect. Tcpreplay describes it as a synthetic combination of captures;
`bigFlows.pcap` is the real busy-network capture used for this gate.

Engineering decision rule: when patch complexity is greater than or equal to
refactor complexity, regression tests exist, and there are no downstream
dependents, prefer the clearer refactor. This rule motivated replacing the
recursive invariant-run implementation with the function-based design.
