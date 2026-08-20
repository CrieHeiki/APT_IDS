from __future__ import annotations

import numpy as np

from app.feature_adapter import CICFlowMeterFeatureAdapter
from app.preprocessing import FlowPreprocessor
from tests.conftest import fake_cicflow_row


def test_preprocessing_output_dimension_and_finite_values(artifact_bundle):
    adapter = CICFlowMeterFeatureAdapter(
        artifact_bundle.all_features,
        artifact_bundle.selected_features,
        {"cicflowmeter_time_unit": "microseconds"},
    )
    preprocessor = FlowPreprocessor(artifact_bundle)
    adapted = adapter.adapt(fake_cicflow_row())
    entity, timestamp = preprocessor.entity_and_time(adapted)
    vector = preprocessor.preprocess_one(adapted, entity, timestamp)

    assert vector.shape == (21,)
    assert np.isfinite(vector).all()


def test_nan_and_infinity_are_handled_by_training_imputer(artifact_bundle):
    adapter = CICFlowMeterFeatureAdapter(
        artifact_bundle.all_features,
        artifact_bundle.selected_features,
        {"cicflowmeter_time_unit": "microseconds"},
    )
    row = fake_cicflow_row()
    row["Flow IAT Mean"] = "Infinity"
    row["Bwd IAT Std"] = ""
    adapted = adapter.adapt(row)

    preprocessor = FlowPreprocessor(artifact_bundle)
    entity, timestamp = preprocessor.entity_and_time(adapted)
    vector = preprocessor.preprocess_one(adapted, entity, timestamp)

    assert vector.shape == (21,)
    assert np.isfinite(vector).all()

