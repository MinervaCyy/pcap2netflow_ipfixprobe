# Platform verification

## DGX-1 Ubuntu ports connectivity

Verified on 2026-07-16:

- outbound HTTP/IPv4 access to `ports.ubuntu.com` timed out;
- HTTPS/IPv4 access to the same Ubuntu ports endpoint succeeded;
- the active source `/etc/apt/sources.list.d/ubuntu.sources` was changed from
  HTTP to `https://ports.ubuntu.com/ubuntu-ports/`;
- the original source was preserved as
  `/etc/apt/sources.list.d/ubuntu.sources.20260716T071643Z.bak`;
- a standard `apt-get update` completed successfully after the change;
- `pcapfix` package version `1.1.7-2` was installed from the Ubuntu
  Noble ARM64 repository.

This is treated as a platform repair because the machine's current network
path does not provide usable outbound HTTP access. Future Ubuntu package
operations should use the HTTPS source.
