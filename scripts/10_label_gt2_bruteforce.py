#!/usr/bin/env python3

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


def canonical_key(src_ip, src_port, dst_ip, dst_port, protocol):
    endpoint_a = (str(src_ip), int(src_port))
    endpoint_b = (str(dst_ip), int(dst_port))
    return tuple(sorted((endpoint_a, endpoint_b))), int(protocol)


def load_gt2(path):
    records = {}
    skipped_rows = 0

    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            required = [
                row.get("Timestamp"),
                row.get("Label"),
                row.get("Src IP"),
                row.get("Src Port"),
                row.get("Dst IP"),
                row.get("Dst Port"),
                row.get("Protocol"),
            ]

            if not all(required):
                skipped_rows += 1
                continue

            timestamp = datetime.strptime(
                row["Timestamp"].strip(),
                "%d/%m/%Y %H:%M:%S",
            )

            # Official GT2 stores SSH afternoon times as 02:xx without PM.
            if row["Label"] == "SSH-Bruteforce" and timestamp.hour == 2:
                timestamp = timestamp.replace(hour=14)

            key = canonical_key(
                row["Src IP"],
                row["Src Port"],
                row["Dst IP"],
                row["Dst Port"],
                row["Protocol"],
            )

            records.setdefault(key, []).append(
                {
                    "timestamp": timestamp,
                    "label": row["Label"],
                    "flow_id": row.get("Flow ID", ""),
                }
            )

    return records, skipped_rows


def main():
    parser = argparse.ArgumentParser(
        description="Label ipfixprobe biflows using official CIC GT2 records."
    )
    parser.add_argument("--flows", required=True, type=Path)
    parser.add_argument("--gt2", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timezone-offset", type=int, default=-4)
    parser.add_argument("--tolerance-seconds", type=float, default=1.0)
    args = parser.parse_args()

    gt2, skipped_rows = load_gt2(args.gt2)
    dataset_timezone = timezone(timedelta(hours=args.timezone_offset))
    tolerance = timedelta(seconds=args.tolerance_seconds)

    totals = Counter()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.flows.open(encoding="utf-8") as source, \
            args.output.open("w", encoding="utf-8") as destination:

        for line_number, line in enumerate(source, start=1):
            flow = json.loads(line)

            key = canonical_key(
                flow["iana:sourceIPv4Address"],
                flow["iana:sourceTransportPort"],
                flow["iana:destinationIPv4Address"],
                flow["iana:destinationTransportPort"],
                flow["iana:protocolIdentifier"],
            )

            start = datetime.fromtimestamp(
                flow["iana:flowStartMicroseconds"] / 1000,
                tz=timezone.utc,
            ).astimezone(dataset_timezone).replace(tzinfo=None)

            end = datetime.fromtimestamp(
                flow["iana:flowEndMicroseconds"] / 1000,
                tz=timezone.utc,
            ).astimezone(dataset_timezone).replace(tzinfo=None)

            candidates = [
                record
                for record in gt2.get(key, [])
                if start - tolerance
                <= record["timestamp"]
                <= end + tolerance
            ]

            distinct_labels = sorted(
                {record["label"] for record in candidates}
            )

            if len(distinct_labels) > 1:
                raise RuntimeError(
                    f"Conflicting GT2 labels at JSON line {line_number}: "
                    f"{distinct_labels}"
                )

            if distinct_labels:
                attack = distinct_labels[0]
                binary_label = 1
                totals[attack] += 1
            else:
                attack = "0"
                binary_label = 0
                totals["BACKGROUND"] += 1

            flow["Attack"] = attack
            flow["Label"] = binary_label
            flow["label_source"] = "CIC-GT2"
            flow["gt2_match_count"] = len(candidates)
            flow["gt2_flow_ids"] = sorted(
                {record["flow_id"] for record in candidates}
            )

            destination.write(
                json.dumps(flow, separators=(",", ":")) + "\n"
            )

    print("GT2 labeling passed")
    print(f"skipped_incomplete_gt2_rows={skipped_rows}")
    print(f"total_flows={sum(totals.values())}")
    print(f"label_counts={dict(totals)}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
