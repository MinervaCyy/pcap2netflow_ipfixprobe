# Verification Trace

## P1a Native ARM64

Status: passed

- ipfixprobe version: 5.7.0
- commit: f0f16888c426eced7adeed8fc2158362aca1a271
- parsed packets: 11
- exported biflows: 3
- collision count: 0
- manifest: manifests/p1a_native_smoke.json

## P1b Docker ARM64

Status: passed

- image: pcap2netflow-ipfixprobe:p1b-arm64
- image ID: sha256:9b5eeb80bca185c0281b31edf47ca9b2691dc2307cfb602e1479873abd306635
- parsed packets: 11
- exported biflows: 3
- collision count: 0
- manifest: manifests/p1b_docker_smoke.json

## P1c Native versus Docker

Status: passed

The native and Docker executions produced identical:

- flow CSV output;
- runtime log; and
- cache telemetry.

Shared checksums:

- flow output: 7a09fb9d32959b59b15576ab0c604d6e30a09ba0a4e50f8e444c29d78064f438
- runtime log: dbdad484c88bb528a3d42f5946632ecdc79e506dd4b6433a55881ea93f3a2c38
- cache telemetry: 97d4f7a5c1718f4737d60cc18516933709cf35bd420c1d7489ec742781b1ece1

Manifest: manifests/p1c_native_docker_comparison.json
