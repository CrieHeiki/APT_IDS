from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Iterable


DERIVED_TIME_FEATURES = {
    "entity_time_delta_s",
    "hour_sin",
    "hour_cos",
    "dow_sin",
    "dow_cos",
}

TEXT_FEATURES = {
    "application_name",
    "application_category_name",
    "content_type",
}

TIME_UNIT_TO_MS = {
    "microsecond": 0.001,
    "microseconds": 0.001,
    "us": 0.001,
    "millisecond": 1.0,
    "milliseconds": 1.0,
    "ms": 1.0,
    "second": 1000.0,
    "seconds": 1000.0,
    "s": 1000.0,
}


class FeatureMappingError(ValueError):
    """Raised when CICFlowMeter output cannot satisfy selected model features."""

    def __init__(self, missing_features: list[str], message: str | None = None):
        self.missing_features = missing_features
        detail = ", ".join(missing_features)
        super().__init__(message or f"Missing required CICFlowMeter/model features: {detail}")


@dataclass(frozen=True)
class FeatureSpec:
    aliases: tuple[str, ...] = ()
    sum_alias_groups: tuple[tuple[str, ...], ...] = ()
    scale: float = 1.0


def normalize_column_name(name: str) -> str:
    lowered = str(name).strip().lower()
    lowered = lowered.replace("/", " per ")
    return re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")


def _base_specs(time_scale: float) -> dict[str, FeatureSpec]:
    return {
        "protocol": FeatureSpec(("Protocol",)),
        "bidirectional_duration_ms": FeatureSpec(
            ("Flow Duration", "Flow Duration us", "flow_duration"), scale=time_scale
        ),
        "src2dst_duration_ms": FeatureSpec(("Fwd IAT Tot", "Fwd IAT Total"), scale=time_scale),
        "dst2src_duration_ms": FeatureSpec(("Bwd IAT Tot", "Bwd IAT Total"), scale=time_scale),
        "bidirectional_packets": FeatureSpec(
            ("Total Packets", "Tot Packets"),
            (("Tot Fwd Pkts", "Total Fwd Packets"), ("Tot Bwd Pkts", "Total Backward Packets")),
        ),
        "src2dst_packets": FeatureSpec(("Tot Fwd Pkts", "Total Fwd Packets", "Fwd Packets")),
        "dst2src_packets": FeatureSpec(("Tot Bwd Pkts", "Total Backward Packets", "Bwd Packets")),
        "bidirectional_bytes": FeatureSpec(
            ("Total Length of Packets", "Packet Length Total"),
            (
                ("TotLen Fwd Pkts", "Total Length of Fwd Packets", "Fwd Packet Length Total"),
                ("TotLen Bwd Pkts", "Total Length of Bwd Packets", "Bwd Packet Length Total"),
            ),
        ),
        "src2dst_bytes": FeatureSpec(("TotLen Fwd Pkts", "Total Length of Fwd Packets", "Fwd Packet Length Total")),
        "dst2src_bytes": FeatureSpec(("TotLen Bwd Pkts", "Total Length of Bwd Packets", "Bwd Packet Length Total")),
        "bidirectional_min_ps": FeatureSpec(("Pkt Len Min", "Packet Length Min", "Min Packet Length")),
        "bidirectional_mean_ps": FeatureSpec(("Pkt Len Mean", "Packet Length Mean")),
        "bidirectional_stddev_ps": FeatureSpec(("Pkt Len Std", "Packet Length Std")),
        "bidirectional_max_ps": FeatureSpec(("Pkt Len Max", "Packet Length Max", "Max Packet Length")),
        "src2dst_min_ps": FeatureSpec(("Fwd Pkt Len Min", "Fwd Packet Length Min")),
        "src2dst_mean_ps": FeatureSpec(("Fwd Pkt Len Mean", "Fwd Packet Length Mean")),
        "src2dst_stddev_ps": FeatureSpec(("Fwd Pkt Len Std", "Fwd Packet Length Std")),
        "src2dst_max_ps": FeatureSpec(("Fwd Pkt Len Max", "Fwd Packet Length Max")),
        "dst2src_min_ps": FeatureSpec(("Bwd Pkt Len Min", "Bwd Packet Length Min")),
        "dst2src_mean_ps": FeatureSpec(("Bwd Pkt Len Mean", "Bwd Packet Length Mean")),
        "dst2src_stddev_ps": FeatureSpec(("Bwd Pkt Len Std", "Bwd Packet Length Std")),
        "dst2src_max_ps": FeatureSpec(("Bwd Pkt Len Max", "Bwd Packet Length Max")),
        "bidirectional_min_piat_ms": FeatureSpec(("Flow IAT Min",), scale=time_scale),
        "bidirectional_mean_piat_ms": FeatureSpec(("Flow IAT Mean",), scale=time_scale),
        "bidirectional_stddev_piat_ms": FeatureSpec(("Flow IAT Std",), scale=time_scale),
        "bidirectional_max_piat_ms": FeatureSpec(("Flow IAT Max",), scale=time_scale),
        "src2dst_min_piat_ms": FeatureSpec(("Fwd IAT Min",), scale=time_scale),
        "src2dst_mean_piat_ms": FeatureSpec(("Fwd IAT Mean",), scale=time_scale),
        "src2dst_stddev_piat_ms": FeatureSpec(("Fwd IAT Std",), scale=time_scale),
        "src2dst_max_piat_ms": FeatureSpec(("Fwd IAT Max",), scale=time_scale),
        "dst2src_min_piat_ms": FeatureSpec(("Bwd IAT Min",), scale=time_scale),
        "dst2src_mean_piat_ms": FeatureSpec(("Bwd IAT Mean",), scale=time_scale),
        "dst2src_stddev_piat_ms": FeatureSpec(("Bwd IAT Std",), scale=time_scale),
        "dst2src_max_piat_ms": FeatureSpec(("Bwd IAT Max",), scale=time_scale),
        "bidirectional_syn_packets": FeatureSpec(("SYN Flag Cnt", "SYN Flag Count")),
        "bidirectional_cwr_packets": FeatureSpec(("CWE Flag Count", "CWR Flag Count", "CWR Flag Cnt")),
        "bidirectional_ece_packets": FeatureSpec(("ECE Flag Cnt", "ECE Flag Count")),
        "bidirectional_urg_packets": FeatureSpec(("URG Flag Cnt", "URG Flag Count")),
        "bidirectional_ack_packets": FeatureSpec(("ACK Flag Cnt", "ACK Flag Count")),
        "bidirectional_psh_packets": FeatureSpec(("PSH Flag Cnt", "PSH Flag Count")),
        "bidirectional_rst_packets": FeatureSpec(("RST Flag Cnt", "RST Flag Count")),
        "bidirectional_fin_packets": FeatureSpec(("FIN Flag Cnt", "FIN Flag Count")),
        "src2dst_syn_packets": FeatureSpec(("Fwd SYN Flags", "Fwd SYN Flag Cnt", "Fwd SYN Flag Count")),
        "src2dst_cwr_packets": FeatureSpec(("Fwd CWR Flags", "Fwd CWR Flag Cnt", "Fwd CWR Flag Count")),
        "src2dst_ece_packets": FeatureSpec(("Fwd ECE Flags", "Fwd ECE Flag Cnt", "Fwd ECE Flag Count")),
        "src2dst_urg_packets": FeatureSpec(("Fwd URG Flags", "Fwd URG Flag Cnt", "Fwd URG Flag Count")),
        "src2dst_ack_packets": FeatureSpec(("Fwd ACK Flags", "Fwd ACK Flag Cnt", "Fwd ACK Flag Count")),
        "src2dst_psh_packets": FeatureSpec(("Fwd PSH Flags", "Fwd PSH Flag Cnt", "Fwd PSH Flag Count")),
        "src2dst_rst_packets": FeatureSpec(("Fwd RST Flags", "Fwd RST Flag Cnt", "Fwd RST Flag Count")),
        "src2dst_fin_packets": FeatureSpec(("Fwd FIN Flags", "Fwd FIN Flag Cnt", "Fwd FIN Flag Count")),
        "dst2src_syn_packets": FeatureSpec(("Bwd SYN Flags", "Bwd SYN Flag Cnt", "Bwd SYN Flag Count")),
        "dst2src_ack_packets": FeatureSpec(("Bwd ACK Flags", "Bwd ACK Flag Cnt", "Bwd ACK Flag Count")),
        "dst2src_psh_packets": FeatureSpec(("Bwd PSH Flags", "Bwd PSH Flag Cnt", "Bwd PSH Flag Count")),
        "dst2src_rst_packets": FeatureSpec(("Bwd RST Flags", "Bwd RST Flag Cnt", "Bwd RST Flag Count")),
        "dst2src_fin_packets": FeatureSpec(("Bwd FIN Flags", "Bwd FIN Flag Cnt", "Bwd FIN Flag Count")),
        "application_name": FeatureSpec(("Application Name", "Application")),
        "application_category_name": FeatureSpec(("Application Category Name", "Application Category")),
        "application_is_guessed": FeatureSpec(("Application Is Guessed",)),
        "content_type": FeatureSpec(("Content Type",)),
    }


METADATA_ALIASES = {
    "timestamp": (
        "Timestamp",
        "Flow Start Time",
        "Start Time",
        "bidirectional_first_seen_ms",
        "first_seen_ms",
        "time",
    ),
    "src_ip": ("Src IP", "Source IP", "Source", "src_ip", "source_ip", "ip_src"),
    "dst_ip": ("Dst IP", "Destination IP", "Destination", "dst_ip", "destination_ip", "ip_dst"),
    "src_port": ("Src Port", "Source Port", "src_port"),
    "dst_port": ("Dst Port", "Destination Port", "dst_port"),
    "protocol": ("Protocol", "protocol"),
}


class CICFlowMeterFeatureAdapter:
    """Convert CICFlowMeter CSV rows into the model feature schema."""

    def __init__(
        self,
        all_features: Iterable[str],
        selected_features: Iterable[str],
        mapping_config: dict[str, Any] | None = None,
    ):
        mapping_config = mapping_config or {}
        unit = str(mapping_config.get("cicflowmeter_time_unit", "microseconds")).lower()
        time_scale = float(mapping_config.get("time_scale_to_ms", TIME_UNIT_TO_MS.get(unit, 0.001)))
        self.all_features = [str(feature) for feature in all_features]
        self.selected_features = [str(feature) for feature in selected_features]
        self.required_features = [
            feature for feature in self.selected_features if feature not in DERIVED_TIME_FEATURES
        ]
        self.specs = _base_specs(time_scale)
        for feature, aliases in mapping_config.get("additional_aliases", {}).items():
            aliases_tuple = tuple(str(alias) for alias in aliases)
            existing = self.specs.get(str(feature), FeatureSpec())
            self.specs[str(feature)] = FeatureSpec(
                aliases=existing.aliases + aliases_tuple,
                sum_alias_groups=existing.sum_alias_groups,
                scale=existing.scale,
            )

    def _index_raw(self, raw_record: dict[str, Any]) -> dict[str, tuple[str, Any]]:
        return {normalize_column_name(key): (key, value) for key, value in raw_record.items()}

    def _get_alias(self, raw_index: dict[str, tuple[str, Any]], aliases: Iterable[str]) -> Any | None:
        for alias in aliases:
            normalized = normalize_column_name(alias)
            if normalized in raw_index:
                return raw_index[normalized][1]
        return None

    def _number(self, value: Any) -> float:
        if value is None:
            return math.nan
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if text == "":
            return math.nan
        try:
            return float(text.replace(",", ""))
        except ValueError:
            return math.nan

    def _feature_value(self, feature: str, raw_index: dict[str, tuple[str, Any]]) -> tuple[bool, Any]:
        canonical = self._get_alias(raw_index, (feature,))
        if canonical is not None:
            return True, canonical if feature in TEXT_FEATURES else self._number(canonical)

        spec = self.specs.get(feature)
        if spec is None:
            return False, None

        direct = self._get_alias(raw_index, spec.aliases)
        if direct is not None:
            if feature in TEXT_FEATURES:
                return True, str(direct)
            return True, self._number(direct) * spec.scale

        if spec.sum_alias_groups:
            values: list[float] = []
            for alias_group in spec.sum_alias_groups:
                value = self._get_alias(raw_index, alias_group)
                if value is None:
                    return False, None
                values.append(self._number(value))
            return True, sum(values) * spec.scale

        return False, None

    def metadata_from_raw(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        raw_index = self._index_raw(raw_record)
        metadata: dict[str, Any] = {}
        for target, aliases in METADATA_ALIASES.items():
            value = self._get_alias(raw_index, aliases)
            if value is not None:
                metadata[target] = value
        return metadata

    def adapt(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        raw_index = self._index_raw(raw_record)
        adapted: dict[str, Any] = {}

        for feature in self.all_features:
            found, value = self._feature_value(feature, raw_index)
            if found:
                adapted[feature] = value

        metadata = self.metadata_from_raw(raw_record)
        adapted.update(metadata)

        missing = [feature for feature in self.required_features if feature not in adapted]
        if missing:
            raise FeatureMappingError(missing)
        return adapted

    def schema_report(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        raw_index = self._index_raw(raw_record)
        mapped = []
        for feature in self.all_features:
            found, _ = self._feature_value(feature, raw_index)
            if found:
                mapped.append(feature)
        missing_required = [feature for feature in self.required_features if feature not in mapped]
        return {
            "raw_columns": list(raw_record.keys()),
            "mapped_feature_count": len(mapped),
            "mapped_features": mapped,
            "required_selected_feature_count": len(self.required_features),
            "missing_required_selected_features": missing_required,
        }
