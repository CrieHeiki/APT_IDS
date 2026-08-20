from __future__ import annotations

import json

import pytest

from tests.conftest import ARTIFACTS_DIR


def test_artifact_bundle_loads_and_label_mapping(artifact_bundle):
    assert artifact_bundle.sequence_length == 50
    assert artifact_bundle.sequence_stride == 10
    assert artifact_bundle.input_shape == (50, 21)
    assert artifact_bundle.threshold == pytest.approx(0.4)
    assert artifact_bundle.class_names == [
        "BENIGN",
        "COVER UP",
        "DATA EXFILTRATION",
        "ESTABLISH FOOTHOLD",
        "LATERAL MOVEMENT",
        "RECONNAISSANCE",
    ]


def test_feature_order_matches_schema(artifact_bundle):
    schema = json.loads((ARTIFACTS_DIR / "feature_schema.json").read_text(encoding="utf-8"))
    assert artifact_bundle.selected_features == schema["selected_feature_columns"]
    assert len(artifact_bundle.selected_indices) == 21


def test_model_loads_and_input_shape(artifact_bundle):
    pytest.importorskip("tensorflow")
    from app.predictor import Predictor

    predictor = Predictor(artifact_bundle)
    assert tuple(predictor.model.input_shape) == (None, 50, 21)

