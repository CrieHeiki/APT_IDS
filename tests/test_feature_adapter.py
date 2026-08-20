from __future__ import annotations

import pytest

from app.feature_adapter import CICFlowMeterFeatureAdapter, FeatureMappingError
from tests.conftest import fake_cicflow_row


def test_cicflowmeter_column_mapping_for_selected_features(artifact_bundle):
    adapter = CICFlowMeterFeatureAdapter(
        artifact_bundle.all_features,
        artifact_bundle.selected_features,
        {"cicflowmeter_time_unit": "microseconds"},
    )
    adapted = adapter.adapt(fake_cicflow_row())

    assert adapted["bidirectional_bytes"] == 3900
    assert adapted["bidirectional_duration_ms"] == pytest.approx(2000.0)
    assert adapted["bidirectional_mean_piat_ms"] == pytest.approx(10.0)
    assert adapted["src2dst_rst_packets"] == 1
    assert adapted["dst2src_ack_packets"] == 5
    assert set(artifact_bundle.selected_features).issubset(adapted.keys())


def test_missing_required_selected_feature_is_reported(artifact_bundle):
    adapter = CICFlowMeterFeatureAdapter(
        artifact_bundle.all_features,
        artifact_bundle.selected_features,
        {"cicflowmeter_time_unit": "microseconds"},
    )
    row = fake_cicflow_row()
    row.pop("Fwd RST Flags")

    with pytest.raises(FeatureMappingError) as exc_info:
        adapter.adapt(row)
    assert "src2dst_rst_packets" in exc_info.value.missing_features


def test_schema_report_lists_missing_required_features(artifact_bundle):
    adapter = CICFlowMeterFeatureAdapter(
        artifact_bundle.all_features,
        artifact_bundle.selected_features,
        {"cicflowmeter_time_unit": "microseconds"},
    )
    row = fake_cicflow_row()
    row.pop("Bwd ACK Flags")
    report = adapter.schema_report(row)
    assert "dst2src_ack_packets" in report["missing_required_selected_features"]

