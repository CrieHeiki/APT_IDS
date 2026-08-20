from __future__ import annotations

import numpy as np
import pytest


def test_fake_batch_inference_succeeds(artifact_bundle):
    pytest.importorskip("tensorflow")
    from app.predictor import Predictor

    predictor = Predictor(artifact_bundle)
    sequence = np.zeros((1, 50, 21), dtype=np.float32)
    prediction = predictor.predict_sequence(sequence)

    assert prediction.stage in artifact_bundle.class_names
    assert set(prediction.probabilities) == set(artifact_bundle.class_names)
    assert 0.0 <= prediction.confidence <= 1.0

