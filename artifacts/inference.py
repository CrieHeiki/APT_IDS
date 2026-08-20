from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf


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


def _first_present(mapping: Dict[str, Any], candidates: Iterable[str]) -> Optional[str]:
    normalized = {str(k).strip().lower(): k for k in mapping}
    for candidate in candidates:
        if candidate in mapping:
            return candidate
        key = candidate.strip().lower()
        if key in normalized:
            return normalized[key]
    return None


def _unix_seconds(value: Any, name: str) -> float:
    numeric = float(value)
    magnitude = abs(numeric)
    key = str(name).strip().lower()
    if key.endswith("_ns") or magnitude > 1e17:
        return numeric / 1e9
    if key.endswith("_us") or magnitude > 1e14:
        return numeric / 1e6
    if key.endswith("_ms") or magnitude > 1e11:
        return numeric / 1e3
    return numeric


class APTStageDetector:
    """Stateful detector for flow records.

    One source entity owns one rolling sequence. A prediction is emitted only
    after sequence_length flows and then every sequence_stride new flows.
    """

    def __init__(self, bundle_dir: str | Path):
        self.bundle_dir = Path(bundle_dir)
        self.model = tf.keras.models.load_model(
            self.bundle_dir / "model.keras",
            compile=False,
            safe_mode=True,
        )
        self.pre = joblib.load(self.bundle_dir / "preprocessor_bundle.joblib")
        self.config = self.pre["config"]
        self.schema = self.pre["feature_schema"]
        self.imputer = self.pre["imputer"]
        self.scaler = self.pre["scaler"]
        self.label_encoder = self.pre["label_encoder"]
        self.all_features = list(self.pre["all_feature_columns"])
        self.selected_features = list(self.pre["selected_features"])
        self.selected_indices = np.asarray(
            self.pre["selected_feature_indices"], dtype=np.int64
        )
        self.categorical_columns = list(self.pre["categorical_columns"])
        self.frequency_maps = dict(self.pre["frequency_maps"])
        self.zscore_stats = dict(self.pre["zscore_stats"])

        threshold_info = json.loads(
            (self.bundle_dir / "threshold.json").read_text(encoding="utf-8")
        )
        self.threshold = float(threshold_info["threshold"])

        self.class_names = [str(x) for x in self.label_encoder.classes_]
        self.benign_id = self.class_names.index("BENIGN")
        natural_counts = np.asarray(
            self.config["balancing"]["natural_train_window_counts"], dtype=np.float64
        )
        sampled_counts = np.asarray(
            self.config["balancing"]["sampled_train_window_counts"], dtype=np.float64
        )
        natural_prior = natural_counts / natural_counts.sum()
        sampled_prior = sampled_counts / sampled_counts.sum()
        self.prior_ratio = np.divide(
            natural_prior,
            sampled_prior,
            out=np.ones_like(natural_prior),
            where=sampled_prior > 0,
        )

        sequence_cfg = self.config["sequence"]
        self.sequence_length = int(sequence_cfg["length"])
        self.sequence_stride = int(sequence_cfg["stride"])

        self.last_timestamp: Dict[str, float] = {}
        self.buffers: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.sequence_length)
        )
        self.entity_counts: Dict[str, int] = defaultdict(int)

    def schema_report(self, record: Dict[str, Any]) -> Dict[str, Any]:
        missing = [
            feature
            for feature in self.all_features
            if feature not in record
            and feature not in {
                "entity_time_delta_s",
                "hour_sin",
                "hour_cos",
                "dow_sin",
                "dow_cos",
            }
        ]
        return {
            "required_feature_count": len(self.all_features),
            "present_feature_count": len(self.all_features) - len(missing),
            "missing_features": missing,
        }

    def _entity_and_time(self, record: Dict[str, Any]) -> tuple[str, float]:
        source_key = _first_present(record, SOURCE_IP_CANDIDATES)
        timestamp_key = _first_present(record, TIMESTAMP_CANDIDATES)
        if timestamp_key is None:
            raise KeyError(
                "Flow record thiếu timestamp. Cần một trong: "
                + ", ".join(TIMESTAMP_CANDIDATES)
            )

        entity = str(record.get(source_key, "__GLOBAL__")) if source_key else "__GLOBAL__"
        timestamp = _unix_seconds(record[timestamp_key], timestamp_key)
        return entity, timestamp

    def _preprocess_one(self, record: Dict[str, Any], entity: str, timestamp: float) -> np.ndarray:
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

        frame = pd.DataFrame([{name: values.get(name, np.nan) for name in self.all_features}])

        for column in self.categorical_columns:
            mapping = self.frequency_maps.get(column, {})
            raw = frame[column].astype("string").fillna("__MISSING__")
            frame[column] = raw.map(mapping).fillna(0.0).astype(np.float32)

        for column in self.all_features:
            if column not in self.categorical_columns:
                frame[column] = pd.to_numeric(frame[column], errors="coerce")

        frame.replace([np.inf, -np.inf], np.nan, inplace=True)
        matrix = self.imputer.transform(frame[self.all_features]).astype(np.float32)

        feature_index = {name: index for index, name in enumerate(self.all_features)}
        for name, stats in self.zscore_stats.items():
            index = feature_index.get(name)
            if index is not None:
                matrix[:, index] = np.clip(
                    matrix[:, index],
                    float(stats["lower"]),
                    float(stats["upper"]),
                )

        selected = matrix[:, self.selected_indices]
        scaled = self.scaler.transform(selected).astype(np.float32)
        return scaled[0]

    def _prior_correct(self, probabilities: np.ndarray) -> np.ndarray:
        corrected = probabilities.astype(np.float64) * self.prior_ratio
        corrected /= max(float(corrected.sum()), 1e-12)
        return corrected.astype(np.float32)

    def push_flow(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        entity, timestamp = self._entity_and_time(record)
        vector = self._preprocess_one(record, entity, timestamp)
        self.buffers[entity].append(vector)
        self.entity_counts[entity] += 1

        if len(self.buffers[entity]) < self.sequence_length:
            return None

        count_after_warmup = self.entity_counts[entity] - self.sequence_length
        if count_after_warmup % self.sequence_stride != 0:
            return None

        sequence = np.asarray(self.buffers[entity], dtype=np.float32)[None, ...]
        raw_probability = self.model.predict(sequence, verbose=0)[0]
        probability = self._prior_correct(raw_probability)

        attack_score = float(1.0 - probability[self.benign_id])
        if attack_score < self.threshold:
            prediction_id = self.benign_id
        else:
            non_benign = probability.copy()
            non_benign[self.benign_id] = -1.0
            prediction_id = int(np.argmax(non_benign))

        return {
            "entity": entity,
            "timestamp_unix_s": timestamp,
            "stage": self.class_names[prediction_id],
            "class_id": prediction_id,
            "confidence": float(probability[prediction_id]),
            "attack_score": attack_score,
            "threshold": self.threshold,
            "probabilities": {
                name: float(probability[index])
                for index, name in enumerate(self.class_names)
            },
        }
