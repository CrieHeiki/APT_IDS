from __future__ import annotations

import numpy as np

from app.window_manager import WindowManager


def test_sliding_window_length_and_stride():
    manager = WindowManager(sequence_length=50, sequence_stride=10)
    vector = np.zeros((21,), dtype=np.float32)

    emitted_at = []
    for index in range(60):
        sequence = manager.push("10.0.0.10", vector + index)
        if sequence is not None:
            emitted_at.append(index + 1)
            assert sequence.shape == (1, 50, 21)

    assert emitted_at == [50, 60]

