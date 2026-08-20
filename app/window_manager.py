from __future__ import annotations

from collections import defaultdict, deque

import numpy as np


class WindowManager:
    """Maintain per-entity rolling flow sequences."""

    def __init__(self, sequence_length: int, sequence_stride: int):
        self.sequence_length = int(sequence_length)
        self.sequence_stride = int(sequence_stride)
        self.buffers: dict[str, deque[np.ndarray]] = defaultdict(
            lambda: deque(maxlen=self.sequence_length)
        )
        self.entity_counts: dict[str, int] = defaultdict(int)

    def push(self, entity: str, vector: np.ndarray) -> np.ndarray | None:
        self.buffers[entity].append(vector)
        self.entity_counts[entity] += 1

        if len(self.buffers[entity]) < self.sequence_length:
            return None

        count_after_warmup = self.entity_counts[entity] - self.sequence_length
        if count_after_warmup % self.sequence_stride != 0:
            return None

        return np.asarray(self.buffers[entity], dtype=np.float32)[None, ...]

