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

## v1.4 post-release closure

The v1.4 instrumentation phase is complete. The Git tag, robustness manifest,
golden and invariant validation, and complete bigFlows gate are closed with no
known correctness issues.

A local Docker release alias was added:

    pcap2netflow-ipfixprobe:v1.4-arm64

It points to the same ARM64 image as `v1.4-dev-arm64`:

    sha256:1c60217a458044d56c101b15560c07a89a929d8718132234cf5f9ebea15204ff

This alias is local to DGX-1 unless it is later pushed to a container registry.
The next workstream begins with the three dataset freezes: the 2018 rules
schema, DistriNet expected counts, and pilot-day timezone anchors.

## CICIDS2018 pilot input freeze

The three selected corrected CSE-CIC-IDS-2018 pilot days are frozen against
DistriNet `CNS2022_Code` commit `f0ce502818e59e6cd062720ab2286c5ff6f2bdec`:

- `Wednesday-14-02-2018`
- `Thursday-15-02-2018`
- `Thursday-22-02-2018`

Frozen artifacts:

- `configs/rules_2018.yaml`: 21 ordered labelling rules, preprocessing
  semantics, inclusive nanosecond intervals, payload filters, and additional
  field predicates.
- `configs/cicids2018_pilot_timezone_anchors.yaml`: explicit UTC midnight and
  attack-window anchors for the three pilot days.
- `tests/expected/cicids2018_pilot_counts.json`: DistriNet notebook reference
  counts before preprocessing, after preprocessing, by label, and by attempted
  category.
- `scripts/04_validate_cicids2018_freeze.py`: fail-closed cross-document
  validation.

The `.yaml` files deliberately use JSON-compatible YAML 1.2 syntax so the
freeze validator requires only the Python standard library.

The expected counts are reference fixtures extracted from the saved outputs of
the pinned DistriNet notebook. They have not yet been independently reproduced
from the locally downloaded CICIDS2018 PCAP and generated flow data. Exact
reproduction is the acceptance gate for the upcoming pilot-day labelling run.

All source CSV timestamps and rule epochs are interpreted as UTC. No local-time
or daylight-saving adjustment is applied.

### Pilot-day drift correction

Commit `38687a8` accidentally froze `Friday-16-02-2018` as the third pilot
day even though the selected pilot set was `14-Feb`, `15-Feb`, and `22-Feb`.
Repository history contained no approval for this substitution. The drift was
detected and corrected before any CSE-CIC-IDS-2018 data was downloaded.

`Thursday-22-02-2018` retains its intended role as the subtle and rare-class
Web-attack pilot. Its pinned DistriNet output contains only 208 non-BENIGN
flows after preprocessing:

- 76 Web Attack - Brute Force - Attempted
- 69 Web Attack - Brute Force
- 40 Web Attack - XSS
- 16 Web Attack - SQL
- 4 Web Attack - SQL - Attempted
- 3 Web Attack - XSS - Attempted

The 4V trace-validation rare-class objective is assigned to this day. The
incorrect `16-Feb` freeze is not used as a pilot input and may be considered
separately only through a future explicit decision.

## CICIDS2018 acquisition and normalization freeze

The acquisition policy was frozen before any formal S3 inventory or dataset
download. A read-only reconnaissance listing is permitted only after this
freeze and must be labelled `reconnaissance_not_frozen_inventory`. It cannot
serve as the formal inventory, and no object may be downloaded during it.

The formal inventory must subsequently repeat the complete S3 ListObjectsV2
operation, follow all continuation tokens, record request and object
provenance, apply the frozen PCAP-subtree selection rule, and be hashed with
SHA-256 before download begins.

Every input capture is inspected with `capinfos`, passed through an
unconditional `pcapfix -d` attempt on an isolated working copy, selected using
the explicit repaired-or-original branch, unconditionally processed by
`reordercap`, merged deterministically, and checked again with `capinfos`.
Because pcapfix may produce no repaired artifact for a valid capture, absence
of an output file is not by itself an error. The original working copy is
selected only when pcapfix succeeds and reports that the file is fine; all
ambiguous outcomes fail for manual review. Per-file pcapfix elapsed time is
recorded.

ETag is retained only as auxiliary upstream identity and change-detection
evidence. SHA-256 is the primary local integrity evidence.

DistriNet flow counts are diagnostic references rather than exact acceptance
criteria because exporter and timeout semantics can change flow partitioning.
For `Thursday-22-02-2018`, count differences trigger 4V trace review rather
than automatic labeler failure. All 16 SQL and 4 SQL-attempted reference flows
are eligible for full tracing; sampling is not permitted. The 4V packet and
flow trace is the final arbiter.

The frozen pcapfix package version is `1.1.7-2`.

## pcapfix repaired-or-original control-flow gate

The pinned Ubuntu `pcapfix 1.1.7-2` behaviour was measured using isolated
copies of `tests/data/smoke.pcap`.

For a valid capture, pcapfix exited with status zero, printed
`Your pcap file looks proper. Nothing to fix!` to standard output, removed its
prospective repaired output, and left the working input unchanged.

For a copy truncated by 32 bytes, `capinfos` reported a final packet cut short.
Pcapfix exited with status zero, generated a distinct repaired artifact,
reported one corrected corruption, and left the truncated working input
unchanged.

For a missing input, pcapfix returned status 254 and wrote the open failure to
standard error.

`scripts/06_pcapfix_select.py` implements the frozen branch semantics using an
explicit `-o repaired.pcap` path:

- a successful non-empty repaired artifact is selected with `touched=true`;
- successful no-output plus the pinned no-repair marker selects the unchanged
  working copy with `touched=false`;
- every other result emits a manifest and returns
  `fail_for_manual_review`.

The selector records hashes before and after processing, the exact invocation,
exit status, stdout, stderr, elapsed time, artifact state, branch decision, and
selected-output SHA-256. Its integration tests cover the valid, truncated, and
non-zero-exit branches before any CICIDS2018 download.

The pcapfix healthy-file no-output path and the capinfos cut-short `rc=1` path establish a general rule: external-tool return-code and output contracts must be measured with fixtures before real-data execution, never inferred from convention.

## CICIDS2018 Stage 2 cleaning gate

`scripts/09_cicids2018_stage2_clean_day.py` implements the frozen per-day
normalization order:

`capinfos_pre` → `pcapfix_attempt` →
`select_repaired_or_original` → `reordercap` → `mergecap` →
`capinfos_post`.

Inputs are supplied through an explicit manifest and sorted by their original
source keys. Each raw input is hashed before and after processing, pcapfix
operates only on an isolated working copy, reordercap runs unconditionally,
and mergecap explicitly emits classic PCAP format. The merged candidate is
published atomically only after final capinfos validation reports strict time
order.

The pre-repair capinfos gate has one pinned exception measured with Wireshark
4.2.2. Exit code 1 is accepted only when stdout contains a complete parseable
summary, the reported size matches the filesystem, and stderr contains only
the measured mid-packet cut-short diagnostic family. Unrelated exit-code-1
results and compound diagnostics fail closed. The post-merge capinfos gate
does not use this exception and still requires exit code zero and strict time
order. The day manifest exposes accepted cut-short inputs through the
`cut_short_inputs` count.

Seven dedicated offline fixtures cover healthy untouched selection, truncated
repair selection, non-zero pcapfix manual review, the real cut-short pre-check,
an unrelated exit-code-1 rejection, compound-diagnostic rejection, and strict
post-check rejection. The complete repository regression ran 34 tests and
passed. The dedicated Stage 2 fixture-log SHA-256 was
`c2813dff349c5b7da4c68c24e6f3e8b48ab4c703d30ec3b1a5a90c3d509bd724`;
the complete regression-log SHA-256 was
`fd7c50f3c7d70cb6dd642cdf0c5daf5cf3ed31074003aa0082faa2a293890649`.

These gates used only the synthetic smoke PCAP and temporary directories.
No CICIDS2018 archive was inspected, extracted or processed.

## CICIDS2018 selector revision from reconnaissance

A read-only ListObjectsV2 reconnaissance was completed for all three pilot
days after acquisition policy 1.0 was frozen. The report was explicitly marked
`reconnaissance_not_frozen_inventory`, was not inventory-eligible, and
downloaded zero objects. Its SHA-256 was `abdb88606fa48d0008253fd8f677fdb4eeaf1fb8fab59ebac5e1d1e45e4dc5b0`.

Each pilot-day prefix contained exactly three entries: one zero-byte directory
marker, one direct-child `logs.zip`, and one direct-child `pcap.zip`. There was
no `PCAP` or `PCAPs` subtree. The earlier subtree-based selector was therefore
revised before formal inventory or download.

Acquisition policy 1.1 selects exactly one direct-child object whose basename
is `pcap.zip`, explicitly excludes `logs.zip`, ignores zero-byte directory
markers, rejects nested objects, and fails for manual review on any other
non-marker object.

The reconnaissance output is retained only as selector-design evidence. It
cannot be promoted or copied into the formal inventory. Formal ListObjectsV2
collection must be repeated under policy 1.1.

## CICIDS2018 formal inventory collector gate

The formal inventory collector is frozen before the provenance-producing S3
request is executed.

`scripts/07_cicids2018_formal_inventory.py` reads acquisition policy 1.1 and
uses the pinned selector without widening it. It invokes `curl` only for
anonymous ListObjectsV2 requests and never downloads selected dataset objects.

For every request page it records the endpoint, query parameters, UTC request
interval, exact curl version, raw XML SHA-256, S3 KeyCount, parsed Contents
count, truncation state, and continuation-token progression. KeyCount
mismatches and truncated pages without continuation tokens fail closed.

For every pilot day it requires exactly one non-empty direct-child `pcap.zip`,
explicitly excludes `logs.zip`, ignores one zero-byte day-prefix marker, and
fails on nested or otherwise unexpected non-marker objects.

The generated formal inventory records the repository commit, policy and
collector hashes, selected object key, size, ETag and LastModified values,
complete totals, and zero object downloads. The canonical JSON receives a
separate SHA-256 sidecar. Generated inventory directories remain under the
ignored `manifests/` runtime area; a compact verification record may be
committed only after successful collection.

## CICIDS2018 formal inventory completed

The formal three-day S3 inventory was collected from repository commit
`ae42ac1d47c0ac7432441f46b8b7ba2e7c12ad0f` under acquisition policy 1.1. The canonical
inventory SHA-256 is `7730f4b7479b1c2a7d42635e58eadd1393dc291bcbf7470d495920547b0ea858`.

The inventory selected exactly one `pcap.zip` for each pilot day, selected
three objects totalling `131437674117` bytes
(`122.411` GiB), observed no
unexpected non-marker objects, and downloaded zero dataset objects.

A compact committed record is stored in
`verification/cicids2018_formal_inventory.json` with a corresponding Markdown
summary. The full inventory and raw XML responses remain in the ignored
runtime manifest directory.

The download gate remains closed. The next candidate is the Wednesday
`pcap.zip`; its execution command and archive-handling path must be reviewed
against the committed inventory record before download begins.

## CICIDS2018 Wednesday download preflight passed

The Wednesday download preflight completed from repository commit
`e0ec5e224d2dc20993186adf229a3cf6df45b87b` with no warnings and zero object downloads. The canonical
runtime preflight SHA-256 is `c7b35285552f6ea292013c5ee593e5e8fa2dd86abd22e04e2a530c41384bf211`.

The remote object identity matched the committed formal inventory:
`39913353098` bytes, ETag `845cbc33e555f5906ea5c9bc520113ab-2380`, and Last-Modified
`2018-10-11T12:22:03Z`. The request returned HTTP 200 with no redirect and
advertised byte-range support.

The shared ext4 data filesystem had
`2886.540` GiB available. Both the
`47.172` GiB download-only gate and the
conservative 600 GiB three-day lifecycle gate passed.

Python, unzip and zipinfo passed the synthetic ZIP64 compatibility probe. The
HTTP clock check differed by only
`0.742` seconds. Multipart ETag diagnostics
reported 2,380 parts at approximately
`15.993420` MiB per part.

The dataset download remains unopened. The next gate is to freeze and test a
Wednesday downloader that revalidates the remote identity before every fresh
or resumed transfer, uses a `.part` file, bounded retries and total timeout,
performs exact-size verification and atomically publishes the completed
archive only after validation.

## CICIDS2018 Wednesday downloader gate

The Wednesday archive downloader is frozen and tested before any CICIDS2018
object transfer begins.

`scripts/08_cicids2018_download_archive.py` consumes the committed download
preflight verification record and refuses to run unless the preflight passed,
the dataset download remains `not_started`, all warnings are resolved, and the
extraction gate remains closed.

Before every fresh or resumed transfer attempt, the downloader performs a new
HEAD request and requires the exact pinned URL, HTTP 200, zero redirects,
Content-Length, ETag, Last-Modified and `Accept-Ranges: bytes` to match the
formal-inventory evidence. Any identity mismatch removes the active `.part`
file from the resume path by quarantining it and fails for manual review.

Each GET also uses `If-Match` and `If-Unmodified-Since`. A resumed request must
return HTTP 206, while a fresh request must return HTTP 200. Rejected ranges,
conditional failures, unexpected redirects, URL changes, oversized partial
files and non-retryable curl failures fail closed.

Network failures use explicit bounded attempts and exponential backoff. Curl
does not perform hidden internal retries, so every retry receives a fresh
identity check and a separate manifest entry. Transfer rate, low-speed
threshold, retry count, backoff and total session timeout are explicit
execution parameters.

The archive is written adjacent to the final path as `pcap.zip.part`. It is
published with an atomic rename only after reaching the exact inventory size
and receiving a local SHA-256. The downloader writes a SHA-256 sidecar and a
complete attempt manifest. Archive inspection and extraction remain
unauthorised.

Local HTTP fixture tests cover a fresh transfer, an interrupted transfer
resumed only after another HEAD check, remote identity mismatch with partial
file quarantine, and bounded retry exhaustion with the resumable partial file
retained.

## CICIDS2018 Wednesday download completed

The Wednesday archive download completed under frozen downloader commit
`90cfe50d0d92a9617499a333a571b754a8ed3af9`. The downloader exit-code file
contained `0`, and the runtime manifest reported `complete` with no error.

Both transfer attempts performed a fresh HEAD identity check matching the
frozen object size, ETag and Last-Modified values. The first resumed GET
returned HTTP 206 and ended with curl exit code 18 after retaining a valid
partial archive. After the configured backoff, the second fresh identity check
passed and the resumed HTTP 206 transfer completed with curl exit code 0.

The final archive was published atomically from `.part` as
`raw/cicids2018/Wednesday-14-02-2018/pcap.zip`. Its exact size is
`39913353098` bytes and its independently recomputed SHA-256 is
`5632de8f837991e448bf75432fc07d9b3b1f23fc16e8a32189dacf772b759eaa`,
matching both the runtime manifest and the adjacent SHA-256 sidecar.

The resume session added `37568307082` bytes in `78668.314387` seconds,
corresponding to a wall-clock average of `0.455430 MiB/s`. A full-acquisition
wall-clock average was not calculated because the interruption record does not
contain the first session's initial start timestamp.

Compact committed evidence is stored in
`verification/cicids2018_wednesday_download_complete.json` and
`verification/cicids2018_wednesday_download_complete.md`. Their SHA-256 values
are respectively
`12e57876efed5964925128d5a56d7679caaa06076ca11f98dfb052df302c2f50`
and
`566e7dc95fe857ab59562a726ebe28ea3d13c271a55662bf5642c33c926b7d42`.

The download gate and final-path metadata gate passed. No ZIP member listing,
archive-content inspection or extraction was performed. Archive inspection
remains `not_started`, extraction remains closed, and Stage 2 processing has
not started.
