# CICIDS2018 acquisition reconnaissance

This document records evidence used to revise the frozen object selector.
It is not a formal inventory and is not eligible for download provenance.

- Role: `reconnaissance_not_frozen_inventory`
- Source report: `cicids2018_pilot_layout_recon_20260716T074037Z.json`
- Source report SHA-256: `abdb88606fa48d0008253fd8f677fdb4eeaf1fb8fab59ebac5e1d1e45e4dc5b0`
- Formal inventory eligible: `false`
- Object downloads performed: `0`
- Client: Python `urllib` with `xml.etree.ElementTree`
- Pagination check: S3 `KeyCount` equalled parsed `Contents` entries

## Observed pilot-day layout

| Day | Selected archive | Size (bytes) | Excluded archive | Size (bytes) |
|---|---:|---:|---:|---:|
| `Wednesday-14-02-2018` | `pcap.zip` | 39913353098 | `logs.zip` | 140178796 |
| `Thursday-15-02-2018` | `pcap.zip` | 41283382768 | `logs.zip` | 149507154 |
| `Thursday-22-02-2018` | `pcap.zip` | 50240938251 | `logs.zip` | 204766212 |

Each prefix contained exactly one additional zero-byte directory marker.

The earlier selector requiring a `PCAP` or `PCAPs` path component was
therefore incorrect for the official S3 layout. The revised selector
accepts exactly one direct-child object named `pcap.zip`, explicitly
excludes `logs.zip`, and rejects every other non-marker object.

The reconnaissance report cannot be promoted to the formal inventory.
The complete ListObjectsV2 request must be repeated under policy 1.1.

The multipart-style ETags observed for the large archives are retained
only as auxiliary upstream identity evidence and are not interpreted
as MD5 hashes.
