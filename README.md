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

## Generate labelled CICIDS2018 brute-force flows

The validated labelling pilot uses the first 200,000 packets from the
CICIDS2018 14 February brute-force capture.

The workflow is:

    PCAP
    -> ipfixprobe bidirectional flows
    -> IPFIX over TCP
    -> IPFIXcol2 JSON Lines
    -> CIC GT2 connection-level labelling
    -> labelled JSON Lines

The flow records are generated only by ipfixprobe. `GT2.csv` supplies ground
truth labels but does not generate or modify the flow features.

Place the local input files at:

- `raw/cicids2018/2018-02-14/BruteForce20180214_200Kpkts.pcap`
- `raw/cicids2018/ground_truth/GT2.csv`

These files are excluded from Git.

Generate and validate the unlabelled biflows:

    ./scripts/01_native_ipfix_json_smoke.sh \
      raw/cicids2018/2018-02-14/BruteForce20180214_200Kpkts.pcap

The command prints a dynamically generated `run_dir` and `sorted_json` path.
Use the reported `sorted_json` file as the labeller input. For example:

    ./scripts/10_label_gt2_bruteforce.py \
      --flows .tmp/native-ipfix-json.<RUN_ID>/native.sorted.json \
      --gt2 raw/cicids2018/ground_truth/GT2.csv \
      --output .tmp/BruteForce20180214_200Kpkts.labeled.jsonl

The labeller matches each ipfixprobe biflow against GT2 using:

- a canonical bidirectional five-tuple;
- flow-time overlap;
- a default matching tolerance of one second;
- dataset-local time interpreted as UTC-04:00.

The official GT2 SSH records store afternoon timestamps as `02:xx:xx`.
For `SSH-Bruteforce` rows, the labeller therefore normalises hour 02 to
hour 14. The final GT2 row is truncated and is reported and skipped.

Matched flows receive fields such as:

    "Attack": "SSH-Bruteforce"
    "Label": 1
    "label_source": "CIC-GT2"
    "gt2_match_count": 1
    "gt2_flow_ids": [...]

Unmatched flows receive:

    "Attack": "0"
    "Label": 0
    "label_source": "CIC-GT2"
    "gt2_match_count": 0
    "gt2_flow_ids": []

Here, `Label=0` means that the flow was not listed as an official FTP or SSH
brute-force connection in the relevant GT2 reference. It does not establish
that the traffic is universally benign.

The validated 200,000-packet pilot produced:

- 4,400 ipfixprobe biflows;
- 4,386 `SSH-Bruteforce` flows;
- 14 unmatched background flows;
- zero conflicting labels;
- byte-identical repeated flow generation and labelling.

The evidence is recorded in:

- `manifests/gt2_bruteforce_pilot_v1.4.json`

This pilot validates the tested 14 February SSH brute-force segment only. It
does not yet establish GT2 coverage for every CICIDS2018 attack day.

## Data policy

Raw PCAPs, intermediate files, generated flow records, temporary run
directories, logs, telemetry, build trees, and staging directories are
excluded from Git.

Published synthetic verification evidence is stored under:

- `verification/ipfix_json_parity/`
