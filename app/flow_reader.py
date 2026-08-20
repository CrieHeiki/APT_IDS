from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger(__name__)


class FlowReader:
    """Read only new rows from CICFlowMeter CSV outputs."""

    def __init__(self, flow_dir: Path, pattern: str, checkpoint_path: Path | None):
        self.flow_dir = flow_dir
        self.pattern = pattern
        self.checkpoint_path = checkpoint_path
        self.offsets: dict[str, int] = {}
        self._load_state()

    def _key(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.flow_dir.resolve()))
        except ValueError:
            return str(path.resolve())

    def _load_state(self) -> None:
        if not self.checkpoint_path or not self.checkpoint_path.exists():
            return
        try:
            payload = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            self.offsets = {str(key): int(value) for key, value in payload.get("offsets", {}).items()}
        except (OSError, ValueError, TypeError) as exc:
            LOGGER.warning("Could not read flow checkpoint %s: %s", self.checkpoint_path, exc)
            self.offsets = {}

    def save_state(self) -> None:
        if not self.checkpoint_path:
            return
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"offsets": self.offsets}
        self.checkpoint_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def reset(self) -> None:
        self.offsets = {}
        if self.checkpoint_path and self.checkpoint_path.exists():
            self.checkpoint_path.unlink()

    def _csv_files(self) -> list[Path]:
        if not self.flow_dir.exists():
            return []
        return sorted(
            (path for path in self.flow_dir.glob(self.pattern) if path.is_file()),
            key=lambda path: (path.stat().st_mtime, path.name),
        )

    def read_new_records(self, save_state: bool = True) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for path in self._csv_files():
            key = self._key(path)
            start_at = self.offsets.get(key, 0)
            current_row = 0
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames:
                    continue
                for row in reader:
                    current_row += 1
                    if current_row <= start_at:
                        continue
                    cleaned = {
                        str(name).strip(): value
                        for name, value in row.items()
                        if name is not None and str(name).strip()
                    }
                    if any(value not in (None, "") for value in cleaned.values()):
                        records.append(cleaned)
            if current_row < start_at:
                LOGGER.info("Flow CSV %s was truncated; resetting its checkpoint.", path)
            self.offsets[key] = current_row
        if save_state:
            self.save_state()
        return records

