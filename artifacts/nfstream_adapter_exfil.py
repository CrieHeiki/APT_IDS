from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable

from inference import APTStageDetector


def flow_to_record(flow: Any, expected_fields: Iterable[str]) -> Dict[str, Any]:
    """Convert an NFStream flow object to a dictionary.

    The adapter never silently claims missing fields are valid. Missing fields
    remain absent and are reported by detector.schema_report().
    """
    record: Dict[str, Any] = {}
    for name in expected_fields:
        if hasattr(flow, name):
            record[name] = getattr(flow, name)

    for name in (
        "src_ip",
        "source_ip",
        "ip_src",
        "bidirectional_first_seen_ms",
        "bidirectional_first_seen",
        "first_seen_ms",
        "first_seen",
        "timestamp",
    ):
        if hasattr(flow, name):
            record[name] = getattr(flow, name)
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, help="Đường dẫn deployment_bundle")
    parser.add_argument("--source", required=True, help="PCAP hoặc interface, ví dụ eth0")
    parser.add_argument("--schema-check-only", action="store_true")
    args = parser.parse_args()

    try:
        from nfstream import NFStreamer
    except ImportError as exc:
        raise SystemExit("Chưa cài nfstream. Chạy: pip install nfstream") from exc

    detector = APTStageDetector(Path(args.bundle))
    streamer = NFStreamer(
        source=args.source,
        statistical_analysis=True,
        splt_analysis=0,
        idle_timeout=120,
        active_timeout=1800,
	n_meters=1,
    )

    first = True
    for flow in streamer:
        record = flow_to_record(flow, detector.all_features)
        if first:
            report = detector.schema_report(record)
            print("Schema report:", json.dumps(report, ensure_ascii=False, indent=2))
            first = False
            if args.schema_check_only:
                return

        result = detector.push_flow(record)
        if result is not None:
            print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
