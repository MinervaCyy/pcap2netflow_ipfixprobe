# pcap2netflow_ipfixprobe

Reproducible ARM64 pipeline for converting PCAP files into bidirectional flow
records with ipfixprobe.

## Validation status

Pipeline version: **1.4**

Release state: **development**

Completed validation stages:

- P1a: native ARM64 ipfixprobe build and text-output smoke test;
- P1b: Docker ARM64 ipfixprobe build and text-output smoke test;
- P1c: native-versus-Docker text-output equivalence;
- P1d: native-versus-Docker IPFIX-to-JSON schema and byte-parity validation.

The v1.4-dev machine-readable path is:

    ipfixprobe
    -> blocking IPFIX over TCP loopback
    -> IPFIXcol2
    -> JSON Lines

The text output remains available for diagnostics and legacy regression tests,
but it is not the public machine-readable interface.

Evidence manifests:

- `manifests/p1a_native_smoke.json`
- `manifests/p1b_docker_smoke.json`
- `manifests/p1c_native_docker_comparison.json`
- `manifests/p1d_ipfix_json_parity.json`

The P1a-P1c manifests remain historical v1.3 evidence. The P1d manifest
records the current v1.4 development implementation. An annotated `v1.4` tag
is the release boundary.

## Reproducible commands

Build native ipfixprobe:

    ./scripts/00_build_native_ipfixprobe.sh

Build native libfds and IPFIXcol2:

    ./scripts/00_build_native_collector.sh

Build and verify the ARM64 Docker image:

    ./scripts/00_build_docker_image.sh

Run the legacy native text smoke test:

    ./scripts/00_native_smoke.sh

Run the legacy Docker text parity test:

    ./scripts/00_docker_smoke.sh

Run the native IPFIX-to-JSON smoke test:

    ./scripts/01_native_ipfix_json_smoke.sh

Run native-versus-Docker JSON parity:

    ./scripts/02_docker_ipfix_json_parity.sh

The JSON parity script checks the collector lifecycle, schema contract,
exported-flow count, collision counter, fixed smoke SHA-256, and byte-identical
native and Docker output.

## Interface contract

Collector configuration:

- `config/ipfixcol2-tcp-json.xml`

Versioned flow schema:

- `schemas/ipfixcol2-biflow-v1.schema.json`

Important contract points:

- `splitBiflow=false`;
- `numericNames=false`;
- reverse Information Elements retain their literal IPFIXcol2 names;
- timestamp values are Unix milliseconds even though the retained Information
  Element names contain `Microseconds`;
- every run uses a fresh output directory;
- the number of JSON records must equal `TotalExportedFlows`;
- a non-zero `FlowEndReason:Collision` counter is a hard failure.

See `docs/adr/0001-output-interface.md` for the output-interface decision.

## Data policy

Raw PCAPs, intermediate files, generated flow records, temporary run
directories, logs, telemetry, build trees, and staging directories are
excluded from Git.

Published synthetic verification evidence is stored under:

- `verification/ipfix_json_parity/`
