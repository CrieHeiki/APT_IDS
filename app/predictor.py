from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from .preprocessing import ArtifactBundle, ArtifactError


@dataclass
class Prediction:
    stage: str
    class_id: int
    confidence: float
    attack_score: float
    threshold: float
    probabilities: dict[str, float]


class Predictor:
    """Load the Keras model and apply the trained deployment decision rule."""

    def __init__(self, bundle: ArtifactBundle):
        self.bundle = bundle
        self.model = self._load_model()
        self._validate_model_shape()
        self.benign_id = self.bundle.class_names.index("BENIGN")
        natural_counts = np.asarray(
            self.bundle.config["balancing"]["natural_train_window_counts"], dtype=np.float64
        )
        sampled_counts = np.asarray(
            self.bundle.config["balancing"]["sampled_train_window_counts"], dtype=np.float64
        )
        natural_prior = natural_counts / natural_counts.sum()
        sampled_prior = sampled_counts / sampled_counts.sum()
        self.prior_ratio = np.divide(
            natural_prior,
            sampled_prior,
            out=np.ones_like(natural_prior),
            where=sampled_prior > 0,
        )

    def _load_model(self) -> Any:
        import tensorflow as tf

        return tf.keras.models.load_model(
            self.bundle.model_path,
            compile=False,
            safe_mode=True,
        )

    def _validate_model_shape(self) -> None:
        shape = tuple(self.model.input_shape)
        expected = (None, self.bundle.sequence_length, len(self.bundle.selected_features))
        if shape != expected:
            raise ArtifactError(f"Model input shape {shape} does not match expected {expected}.")

    def _prior_correct(self, probabilities: np.ndarray) -> np.ndarray:
        corrected = probabilities.astype(np.float64) * self.prior_ratio
        corrected /= max(float(corrected.sum()), 1e-12)
        return corrected.astype(np.float32)

    def predict_sequence(self, sequence: np.ndarray) -> Prediction:
        expected_tail = (self.bundle.sequence_length, len(self.bundle.selected_features))
        if tuple(sequence.shape[1:]) != expected_tail:
            raise ValueError(f"Sequence shape {sequence.shape} does not match (*, {expected_tail}).")

        raw_probability = self.model.predict(sequence.astype(np.float32), verbose=0)[0]
        probability = self._prior_correct(raw_probability)

        attack_score = float(1.0 - probability[self.benign_id])
        if attack_score < self.bundle.threshold:
            prediction_id = self.benign_id
        else:
            non_benign = probability.copy()
            non_benign[self.benign_id] = -1.0
            prediction_id = int(np.argmax(non_benign))

        return Prediction(
            stage=self.bundle.class_names[prediction_id],
            class_id=prediction_id,
            confidence=float(probability[prediction_id]),
            attack_score=attack_score,
            threshold=self.bundle.threshold,
            probabilities={
                name: float(probability[index])
                for index, name in enumerate(self.bundle.class_names)
            },
        )

