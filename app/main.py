from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from .cicflowmeter_runner import CICFlowMeterRunner
from .feature_adapter import CICFlowMeterFeatureAdapter, FeatureMappingError
from .flow_reader import FlowReader
from .logging_utils import JsonlWriter, iso_timestamp, setup_logging
from .predictor import Predictor
from .preprocessing import ArtifactBundle, FlowPreprocessor
from .window_manager import WindowManager


LOGGER = logging.getLogger(__name__)


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_path(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def build_result(
    *,
    metadata: dict[str, Any],
    model_version: str,
    preprocessing_error: str | None,
    timestamp_unix_s: float | None = None,
    entity: str | None = None,
    prediction: Any | None = None,
) -> dict[str, Any]:
    record = {
        "timestamp": iso_timestamp(timestamp_unix_s),
        "timestamp_unix_s": timestamp_unix_s,
        "source_ip": metadata.get("src_ip"),
        "destination_ip": metadata.get("dst_ip"),
        "source_port": metadata.get("src_port"),
        "destination_port": metadata.get("dst_port"),
        "protocol": metadata.get("protocol"),
        "entity": entity,
        "predicted_apt_stage": None,
        "confidence": None,
        "probabilities": None,
        "attack_score": None,
        "threshold": None,
        "model_version": model_version,
        "preprocessing_error": preprocessing_error,
    }
    if prediction is not None:
        record.update(
            {
                "predicted_apt_stage": prediction.stage,
                "confidence": prediction.confidence,
                "probabilities": prediction.probabilities,
                "attack_score": prediction.attack_score,
                "threshold": prediction.threshold,
            }
        )
    return record


class Pipeline:
    def __init__(self, config: dict[str, Any], root: Path):
        artifacts_cfg = config.get("artifacts", {})
        bundle_dir = resolve_path(root, artifacts_cfg.get("bundle_dir", "artifacts"))
        model_file = artifacts_cfg.get("model_file", "model.keras")
        self.bundle = ArtifactBundle.load(bundle_dir, model_file=model_file)
        self.adapter = CICFlowMeterFeatureAdapter(
            self.bundle.all_features,
            self.bundle.selected_features,
            config.get("column_mapping", {}),
        )
        self.preprocessor = FlowPreprocessor(self.bundle)
        self.windows = WindowManager(self.bundle.sequence_length, self.bundle.sequence_stride)
        self.predictor = Predictor(self.bundle)

    def process(self, raw_record: dict[str, Any], writer: JsonlWriter) -> bool:
        metadata = self.adapter.metadata_from_raw(raw_record)
        try:
            adapted = self.adapter.adapt(raw_record)
            metadata.update({key: adapted.get(key) for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")})
            entity, timestamp = self.preprocessor.entity_and_time(adapted)
            vector = self.preprocessor.preprocess_one(adapted, entity, timestamp)
            sequence = self.windows.push(entity, vector)
        except FeatureMappingError as exc:
            result = build_result(
                metadata=metadata,
                model_version=self.bundle.model_version,
                preprocessing_error=str(exc),
            )
            writer.write(result)
            print(json.dumps(result, ensure_ascii=False))
            LOGGER.error("Feature mapping error: %s", exc)
            return False
        except Exception as exc:
            result = build_result(
                metadata=metadata,
                model_version=self.bundle.model_version,
                preprocessing_error=repr(exc),
            )
            writer.write(result)
            print(json.dumps(result, ensure_ascii=False))
            LOGGER.exception("Preprocessing error")
            return False

        if sequence is None:
            return False

        prediction = self.predictor.predict_sequence(sequence)
        result = build_result(
            metadata=metadata,
            model_version=self.bundle.model_version,
            preprocessing_error=None,
            timestamp_unix_s=timestamp,
            entity=entity,
            prediction=prediction,
        )
        writer.write(result)
        print(json.dumps(result, ensure_ascii=False))
        return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="APT IDS CICFlowMeter deployment runner")
    parser.add_argument("--mode", choices=("live", "pcap"), required=True)
    parser.add_argument("--interface", help="Network interface for live mode, for example ens33")
    parser.add_argument("--pcap", help="PCAP path for pcap mode")
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--schema-check-only", action="store_true")
    parser.add_argument(
        "--skip-cicflowmeter",
        action="store_true",
        help="Read existing CICFlowMeter CSV files from the configured output directory.",
    )
    parser.add_argument("--max-polls", type=int, default=0, help="Testing aid for live mode; 0 means forever.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = project_root()
    config_path = resolve_path(root, args.config)
    config = load_config(config_path)

    runtime_cfg = config.get("runtime", {})
    log_dir = resolve_path(root, runtime_cfg.get("log_dir", "logs"))
    state_dir = resolve_path(root, runtime_cfg.get("state_dir", "state"))
    setup_logging(log_dir, runtime_cfg.get("log_level", "INFO"))

    if args.mode == "live" and not args.interface:
        raise SystemExit("--interface is required for live mode.")
    if args.mode == "pcap" and not args.pcap:
        raise SystemExit("--pcap is required for pcap mode.")

    pipeline = Pipeline(config, root)
    writer = JsonlWriter(log_dir / runtime_cfg.get("predictions_file", "predictions.jsonl"))

    cic_cfg = config.get("cicflowmeter", {})
    flow_dir = resolve_path(root, cic_cfg.get("output_dir", "work/cicflowmeter"))
    pattern = cic_cfg.get("flow_glob", "*.csv")
    checkpoint = state_dir / "flow_reader_state.json"
    reader = FlowReader(flow_dir, pattern, checkpoint)
    runner = CICFlowMeterRunner(cic_cfg, root)
    stop = False

    def request_stop(signum: int, frame: Any) -> None:
        nonlocal stop
        LOGGER.info("Received signal %s; stopping after current poll.", signum)
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    if args.mode == "pcap":
        if not args.skip_cicflowmeter:
            runner.run_pcap(resolve_path(root, args.pcap), flow_dir, log_dir)
        reader.reset()
        records = reader.read_new_records(save_state=False)
        if records:
            LOGGER.info("Read %d flow records from CICFlowMeter output.", len(records))
            report = pipeline.adapter.schema_report(records[0])
            LOGGER.info("CICFlowMeter schema report: %s", json.dumps(report, ensure_ascii=False))
            if args.schema_check_only:
                print(json.dumps(report, ensure_ascii=False, indent=2))
                return 0
        for record in records:
            pipeline.process(record, writer)
        return 0

    polls = 0
    schema_reported = False
    with runner.live(args.interface, flow_dir, log_dir):
        while not stop:
            records = reader.read_new_records()
            if records:
                LOGGER.info("Read %d new flow records.", len(records))
                if not schema_reported:
                    report = pipeline.adapter.schema_report(records[0])
                    LOGGER.info("CICFlowMeter schema report: %s", json.dumps(report, ensure_ascii=False))
                    schema_reported = True
                    if args.schema_check_only:
                        print(json.dumps(report, ensure_ascii=False, indent=2))
                        return 0
                for record in records:
                    pipeline.process(record, writer)
            polls += 1
            if args.max_polls and polls >= args.max_polls:
                break
            time.sleep(float(runtime_cfg.get("poll_interval_seconds", 2.0)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
