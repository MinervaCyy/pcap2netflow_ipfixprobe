# CICIDS2018 Wednesday download preflight

The Wednesday archive download preflight completed without warnings.
No dataset object was downloaded.

## Provenance

- Runtime preflight: `.tmp/cicids2018_wednesday_preflight_20260716T075914Z/preflight.json`
- Preflight SHA-256: `c7b35285552f6ea292013c5ee593e5e8fa2dd86abd22e04e2a530c41384bf211`
- Repository commit: `e0ec5e224d2dc20993186adf229a3cf6df45b87b`
- Formal inventory SHA-256: `7730f4b7479b1c2a7d42635e58eadd1393dc291bcbf7470d495920547b0ea858`
- Policy SHA-256: `160cd0b26e155855edee8670cc6fddb2f71d19e315b0e2407f68c6a51db44b32`

## Selected object

- Key: `Original Network Traffic and Log data/Wednesday-14-02-2018/pcap.zip`
- Size: `39913353098` bytes (`37.172 GiB`)
- ETag: `845cbc33e555f5906ea5c9bc520113ab-2380`
- Last-Modified: `2018-10-11T12:22:03Z`

## Capacity

- Raw filesystem available: `2886.540 GiB`
- Download-only requirement: `47.172 GiB`
- Download capacity gate: passed
- Conservative three-day lifecycle budget: `600.000 GiB`
- Unique data-filesystem availability: `2886.540 GiB`
- Lifecycle capacity gate: passed
- `raw`, `work`, `clean`, `output`, and `manifests` use the same ext4 filesystem

## ZIP64 and tools

- curl: `curl 8.5.0 (aarch64-unknown-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) libssh/0.10.6/openssl/zlib nghttp2/1.59.0 librtmp/2.3 OpenLDAP/2.6.10`
- unzip: `UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.`
- zipinfo: `ZipInfo 3.00 of 20 April 2009, by Greg Roelofs and the Info-ZIP group.`
- Python: `Python 3.12.3`
- File-size soft limit: unlimited
- Python ZIP64 probe: passed
- unzip ZIP64 probe: passed
- zipinfo ZIP64 probe: passed

## Remote identity

- HTTP status: `200`
- Redirect count: `0`
- Effective URL: `https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/Wednesday-14-02-2018/pcap.zip`
- Content-Length: `39913353098`
- ETag: `845cbc33e555f5906ea5c9bc520113ab-2380`
- Last-Modified: `2018-10-11T12:22:03Z`
- Accept-Ranges: `bytes`
- Endpoint and object path match: passed
- Formal-inventory identity match: passed

## Clock and multipart diagnostics

- HTTP server minus local time: `0.742` seconds
- Clock warning: false
- Multipart part count: `2380`
- Average diagnostic part size: `15.993420 MiB`
- Multipart calculation is diagnostic only

## Gate state

- Preflight: passed
- Downloader freeze: not started
- Dataset download: not started
- Archive inspection: not started
- Extraction: closed

The downloader must revalidate Content-Length, ETag and Last-Modified
before every fresh or resumed transfer. Extraction remains a separate
gate driven by a post-download ZIP content inventory.
