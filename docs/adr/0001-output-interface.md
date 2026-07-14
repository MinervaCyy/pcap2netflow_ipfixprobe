# ADR 0001: Output interface for machine-readable flow records

## Status

Accepted and implemented for v1.4; annotated release tag pending.

The architecture decision is complete, but the v1.4 release is not frozen until
native and Docker parity, schema validation, lifecycle checks, manifests, and
documentation are completed together.

## Context

This project requires a stable, machine-readable interface between flow
generation and downstream labeling.

The original implementation used the ipfixprobe text output plugin for smoke
testing. That format is useful for human inspection, but it is not suitable as
the long-term public data interface.

In the tested ipfixprobe v5.7.0 build, the text output header describes seven
logical columns:

    mac conversation packets bytes tcp-flags time extensions

When the extensions field is empty, a record contains only six
whitespace-separated fields. The conversation field also combines addresses,
ports, direction markers, and arrows in one string. This is fragile to parse and
can become ambiguous for IPv6 addresses.

The public interface must therefore satisfy the following requirements:

- preserve the already validated ipfixprobe binary;
- represent fields with stable types;
- support IPv4 and IPv6 without composite string parsing;
- preserve one bidirectional flow as one record;
- surface unknown fields rather than silently discard them;
- support deterministic offline processing;
- remain understandable outside a project-specific ecosystem; and
- work identically in native ARM64 and Docker ARM64 paths.

## Options considered

### Option A: ipfixprobe text output with a strict parser

Advantages:

- already compiled into the validated ipfixprobe binary;
- simple to inspect manually;
- no additional collector process or dependency.

Disadvantages:

- header and row shape differ when extensions are absent;
- the conversation field is composite rather than structured;
- IPv6 parsing is potentially ambiguous;
- optional extensions complicate positional parsing;
- the format is intended for human inspection rather than as a stable machine
  contract.

### Option B: UniRec output

Advantages:

- typed fields;
- native IP address representation;
- technically elegant;
- well integrated with the NEMEA ecosystem.

Disadvantages:

- UniRec output is not enabled in the existing validated ipfixprobe v5.7.0
  build;
- enabling it requires rebuilding ipfixprobe and repeating the Stage 0 binary
  evidence;
- it requires source-building Nemea-Framework on ARM64;
- it introduces libtrap and UniRec runtime dependencies;
- a consumer still requires pytrap or an additional Nemea-Modules repository;
- native and Docker shared-library stacks would need to be maintained together;
- the public interface would be less accessible to users outside the NEMEA
  ecosystem.

UniRec is not rejected because of a technical deficiency in the format. Its
typed representation is strong. It is rejected because the dependency and
maintenance cost is disproportionate for this offline conversion pipeline.

### Option C: IPFIX over TCP to IPFIXcol2, followed by JSON

Advantages:

- uses the existing validated ipfixprobe binary without modification;
- preserves the existing Stage 0 evidence;
- uses IPFIX as the standards-based transport boundary;
- uses JSON as the public data boundary;
- preserves typed IPFIX Information Elements;
- supports IPv4 and IPv6;
- preserves biflow records;
- supports raw numeric protocol, flag, and timestamp values;
- exposes unknown fields rather than silently dropping them;
- has been demonstrated to produce deterministic sorted output for the smoke
  fixture.

Disadvantages:

- adds pinned libfds and IPFIXcol2 dependencies;
- adds a collector process and lifecycle management;
- the upstream JSON plugin links librdkafka even when only file output is used;
- requires an explicit JSON schema contract;
- requires a fresh per-run output directory and exporter-to-collector count
  cross-check.

## Comparison

| Criterion | Text output | UniRec | IPFIX + IPFIXcol2 + JSON |
|---|---|---|---|
| Uses existing validated ipfixprobe binary | Yes | No | Yes |
| Structured typed fields | No | Yes | Yes |
| Native IPv4/IPv6 representation | No | Yes | Yes |
| Public standard at transport boundary | No | No | Yes, IPFIX |
| Publicly familiar storage format | No | Limited | Yes, JSON |
| Extra source-built ecosystem | None | Nemea stack | libfds + IPFIXcol2 |
| Additional consumer dependency | Custom parser | pytrap or Nemea-Modules | Standard JSON parser |
| Preserves biflow semantics | Yes | Yes | Yes |
| Deterministic offline path demonstrated | Text-only smoke | No | Yes |
| Long-term maintenance burden | Parser fragility | High | Moderate |

## Decision

Use:

    ipfixprobe
    -> blocking IPFIX over TCP
    -> IPFIXcol2
    -> JSON

The reasons, in priority order, are:

1. It does not invalidate the already verified ipfixprobe binary or Stage 0
   evidence.
2. It avoids adopting a larger ecosystem solely to obtain a more convenient
   record representation.
3. It exposes standards and broadly understood formats at the public boundary:
   IPFIX and JSON.
4. It preserves the required one-record-per-bidirectional-flow semantics.
5. It has already produced byte-identical sorted JSON records across repeated
   native runs of the smoke fixture.

## Consequences

- libfds and IPFIXcol2 become pinned build dependencies.
- The upstream librdkafka build dependency is accepted and documented; the
  project will not maintain a patch to remove it.
- ipfixprobe and IPFIXcol2 run in the same container for the Docker path.
- TCP is blocking and bound to loopback.
- The text output plugin remains available only for smoke tests and human
  debugging.
- UniRec is intentionally unsupported in v1.4.
- `splitBiflow=false` is mandatory because the labeling rules, direction
  convention, count checks, and model semantics assume one record per
  bidirectional flow.
- JSON field names, types, timestamp units, and required fields form a versioned
  schema contract.
- With `timestamp=unix`, values are Unix milliseconds even when the Information
  Element name contains `Microseconds`.
- Reverse fields are consumed using their literal names, including forms such
  as `iana@reverse:octetDeltaCount@reverse`.
- Determinism is defined over sorted JSON record content, not rotated filenames
  or original write order.
- Every run uses a fresh temporary output directory. A non-empty directory is a
  hard failure.
- The wrapper starts the collector, waits until it is ready, runs ipfixprobe,
  waits for exporter completion, allows collector flush, terminates the
  collector, validates the JSON output, and then publishes the result.
- The number of JSON flow records must equal ipfixprobe's
  `TotalExportedFlows` counter.
- Run manifests must record the ipfixprobe, libfds, and IPFIXcol2 revisions and
  the collector configuration hash.
- The project remains `v1.4-dev` until native and Docker parity and all release
  checks are completed in one freeze commit.
