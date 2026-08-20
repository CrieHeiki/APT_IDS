from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd


TIMESTAMP_CANDIDATES = [
    "bidirectional_first_seen_ms",
    "bidirectional_first_seen",
    "first_seen_ms",
    "first_seen",
    "timestamp",
    "Timestamp",
    "time",
]
SOURCE_IP_CANDIDATES = ["src_ip", "source_ip", "ip_src"]


class ArtifactError(RuntimeError):
    """Raised when model/preprocessing artifacts are inconsistent."""


def first_present(mapping: dict[str, Any], candidates: Iterable[str]) -> str | None:
    normalized = {str(key).strip().lower(): key for key in mapping}
    for candidate in candidates:
        if candidate in mapping:
            return candidate
        key = candidate.strip().lower()
        if key in normalized:
            return normalized[key]
    return None


def unix_seconds(value: Any, name: str) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        parsed = pd.to_datetime(value, utc=True, errors="raise")
        return float(parsed.timestamp())

    magnitude = abs(numeric)
    key = str(name).strip().lower()
    if key.endswith("_ns") or magnitude > 1e17:
        return numeric / 1e9
    if key.endswith("_us") or magnitude > 1e14:
        return numeric / 1e6
    if key.endswith("_ms") or magnitude > 1e11:
        return numeric / 1e3
    return numeric


@dataclass
class ArtifactBundle:
    bundle_dir: Path
    model_path: Path
    model_version: str
    config: dict[str, Any]
    schema: dict[str, Any]
    imputer: Any
    scaler: Any
    label_encoder: Any
    all_features: list[str]
    selected_features: list[str]
    selected_indices: np.ndarray
    categorical_columns: list[str]
    frequency_maps: dict[str, Any]
    zscore_stats: dict[str, Any]
    threshold: float
    class_names: list[str]

    @classmethod
    def load(cls, bundle_dir: str | Path, model_file: str = "model.keras") -> "ArtifactBundle":
        bundle_dir = Path(bundle_dir)
        preprocessor_path = bundle_dir / "preprocessor_bundle.joblib"
        if not preprocessor_path.exists():
            raise ArtifactError(f"Missing preprocessing artifact: {preprocessor_path}")
        pre = joblib.load(preprocessor_path)

        threshold_path = bundle_dir / "threshold.json"
        if not threshold_path.exists():
            raise ArtifactError(f"Missing threshold artifact: {threshold_path}")
        threshold_info = json.loads(threshold_path.read_text(encoding="utf-8"))

        model_path = bundle_dir / model_file
        if not model_path.exists():
            raise ArtifactError(f"Missing model artifact: {model_path}")

        manifest_path = bundle_dir / "deployment_manifest.json"
        manifest = {}
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        config = dict(pre["config"])
        schema = dict(pre["feature_schema"])
        all_features = [str(value) for value in pre["all_feature_columns"]]
        selected_features = [str(value) for value in pre["selected_features"]]
        selected_indices = np.asarray(pre["selected_feature_indices"], dtype=np.int64)
        categorical_columns = [str(value) for value in pre["categorical_columns"]]
        class_names = [str(value) for value in pre["label_encoder"].classes_]

        if len(selected_features) != len(selected_indices):
            raise ArtifactError("Selected feature names and selected indices have different lengths.")
        if tuple(config["sequence"]["input_shape"]) != (
            int(config["sequence"]["length"]),
            len(selected_features),
        ):
            raise ArtifactError("Configured sequence input shape does not match selected feature count.")
        if class_names != [str(value) for value in config.get("classes", class_names)]:
            raise ArtifactError("Label encoder classes do not match preprocessing_config classes.")
        label_mapping_path = bundle_dir / "label_mapping.csv"
        if label_mapping_path.exists():
            with label_mapping_path.open("r", encoding="utf-8", newline="") as handle:
                mapping_names = [row["class"] for row in csv.DictReader(handle)]
            if mapping_names != class_names:
                raise ArtifactError("label_mapping.csv does not match label_encoder classes.")

        return cls(
            bundle_dir=bundle_dir,
            model_path=model_path,
            model_version=str(manifest.get("bundle_version", "unraveled-v4.5-safe")),
            config=config,
            schema=schema,
            imputer=pre["imputer"],
            scaler=pre["scaler"],
            label_encoder=pre["label_encoder"],
            all_features=all_features,
            selected_features=selected_features,
            selected_indices=selected_indices,
            categorical_columns=categorical_columns,
            frequency_maps=dict(pre["frequency_maps"]),
            zscore_stats=dict(pre["zscore_stats"]),
            threshold=float(threshold_info["threshold"]),
            class_names=class_names,
        )

    @property
    def sequence_length(self) -> int:
        return int(self.config["sequence"]["length"])

    @property
    def sequence_stride(self) -> int:
        return int(self.config["sequence"]["stride"])

    @property
    def input_shape(self) -> tuple[int, int]:
        shape = self.config["sequence"]["input_shape"]
        return int(shape[0]), int(shape[1])


class FlowPreprocessor:
    """Apply the exact preprocessing artifacts from training."""

    def __init__(self, bundle: ArtifactBundle):
        self.bundle = bundle
        self.last_timestamp: dict[str, float] = {}

    def entity_and_time(self, record: dict[str, Any]) -> tuple[str, float]:
        source_key = first_present(record, SOURCE_IP_CANDIDATES)
        timestamp_key = first_present(record, TIMESTAMP_CANDIDATES)
        if timestamp_key is None:
            raise KeyError("Flow record is missing a timestamp column.")
        entity = str(record.get(source_key, "__GLOBAL__")) if source_key else "__GLOBAL__"
        timestamp = unix_seconds(record[timestamp_key], timestamp_key)
        return entity, timestamp

    def preprocess_one(self, record: dict[str, Any], entity: str, timestamp: float) -> np.ndarray:
        values = dict(record)
        previous = self.last_timestamp.get(entity)
        delta = 0.0 if previous is None else max(0.0, min(86400.0, timestamp - previous))
        self.last_timestamp[entity] = timestamp

        dt = pd.to_datetime(timestamp, unit="s", utc=True)
        hour = float(dt.hour)
        day_of_week = float(dt.dayofweek)
        values["entity_time_delta_s"] = delta
        values["hour_sin"] = float(np.sin(2 * np.pi * hour / 24))
        values["hour_cos"] = float(np.cos(2 * np.pi * hour / 24))
        values["dow_sin"] = float(np.sin(2 * np.pi * day_of_week / 7))
        values["dow_cos"] = float(np.cos(2 * np.pi * day_of_week / 7))

        frame = pd.DataFrame(
            [{name: values.get(name, np.nan) for name in self.bundle.all_features}]
        )

        for column in self.bundle.categorical_columns:
            mapping = self.bundle.frequency_maps.get(column, {})
            raw = frame[column].astype("string").fillna("__MISSING__")
            frame[column] = raw.map(mapping).fillna(0.0).astype(np.float32)

        for column in self.bundle.all_features:
            if column not in self.bundle.categorical_columns:
                frame[column] = pd.to_numeric(frame[column], errors="coerce")

        frame.replace([np.inf, -np.inf], np.nan, inplace=True)
        matrix = self.bundle.imputer.transform(frame[self.bundle.all_features]).astype(np.float32)

        feature_index = {name: index for index, name in enumerate(self.bundle.all_features)}
        for name, stats in self.bundle.zscore_stats.items():
            index = feature_index.get(name)
            if index is not None:
                matrix[:, index] = np.clip(
                    matrix[:, index],
                    float(stats["lower"]),
                    float(stats["upper"]),
                )

        selected = matrix[:, self.bundle.selected_indices]
        scaled = self.bundle.scaler.transform(selected).astype(np.float32)
        vector = scaled[0]
        if vector.shape != (len(self.bundle.selected_features),):
            raise ArtifactError(
                f"Preprocessing produced shape {vector.shape}, expected {(len(self.bundle.selected_features),)}."
            )
        return vector

