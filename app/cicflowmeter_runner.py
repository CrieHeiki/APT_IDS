from __future__ import annotations

import logging
import shlex
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


LOGGER = logging.getLogger(__name__)


class CICFlowMeterError(RuntimeError):
    """Raised when the external CICFlowMeter command cannot run."""


class CICFlowMeterRunner:
    """Small subprocess wrapper for an external CICFlowMeter installation."""

    def __init__(self, config: dict[str, Any], project_root: Path):
        self.config = config
        self.project_root = project_root
        self.process: subprocess.Popen[str] | None = None

    def _resolve(self, value: str | None) -> Path | None:
        if not value:
            return None
        path = Path(value)
        return path if path.is_absolute() else self.project_root / path

    def _command_template(self, mode: str) -> list[str]:
        commands = self.config.get("commands", {})
        template = commands.get(mode)
        if template is None:
            raise CICFlowMeterError(f"Missing CICFlowMeter command template for mode '{mode}'.")
        if isinstance(template, str):
            return shlex.split(template)
        if isinstance(template, list):
            return [str(part) for part in template]
        raise CICFlowMeterError(f"Invalid CICFlowMeter command template type for mode '{mode}'.")

    def _build_command(self, mode: str, **values: Any) -> list[str]:
        output_dir = Path(values["output_dir"]).resolve()
        values = {key: str(value) for key, value in values.items()}
        values["output_dir"] = str(output_dir)
        command = [part.format(**values) for part in self._command_template(mode)]
        return command

    def _open_log(self, log_dir: Path, name: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        return (log_dir / name).open("a", encoding="utf-8")

    @contextmanager
    def live(self, interface: str, output_dir: Path, log_dir: Path) -> Iterator[None]:
        output_dir.mkdir(parents=True, exist_ok=True)
        command = self._build_command("live", interface=interface, output_dir=output_dir)
        cwd = self._resolve(self.config.get("working_dir"))
        LOGGER.info("Starting CICFlowMeter live command: %s", " ".join(command))
        stdout = self._open_log(log_dir, "cicflowmeter_live.stdout.log")
        stderr = self._open_log(log_dir, "cicflowmeter_live.stderr.log")
        try:
            self.process = subprocess.Popen(
                command,
                cwd=str(cwd) if cwd else None,
                stdout=stdout,
                stderr=stderr,
                text=True,
            )
        except FileNotFoundError as exc:
            stdout.close()
            stderr.close()
            raise CICFlowMeterError(
                "CICFlowMeter command was not found. Install CICFlowMeter or update "
                "config/config.yaml cicflowmeter.commands.live."
            ) from exc
        try:
            yield
        finally:
            self.stop()
            stdout.close()
            stderr.close()

    def run_pcap(self, pcap: Path, output_dir: Path, log_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        command = self._build_command("pcap", pcap=pcap, output_dir=output_dir)
        cwd = self._resolve(self.config.get("working_dir"))
        LOGGER.info("Running CICFlowMeter PCAP command: %s", " ".join(command))
        with self._open_log(log_dir, "cicflowmeter_pcap.stdout.log") as stdout, self._open_log(
            log_dir, "cicflowmeter_pcap.stderr.log"
        ) as stderr:
            try:
                completed = subprocess.run(
                    command,
                    cwd=str(cwd) if cwd else None,
                    stdout=stdout,
                    stderr=stderr,
                    text=True,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise CICFlowMeterError(
                    "CICFlowMeter command was not found. Install CICFlowMeter or update "
                    "config/config.yaml cicflowmeter.commands.pcap."
                ) from exc
        if completed.returncode != 0:
            raise CICFlowMeterError(
                f"CICFlowMeter PCAP command exited with code {completed.returncode}. "
                "Check logs/cicflowmeter_pcap.stderr.log."
            )

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is not None:
            self.process = None
            return
        timeout = float(self.config.get("stop_timeout_seconds", 10))
        LOGGER.info("Stopping CICFlowMeter process.")
        self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            LOGGER.warning("CICFlowMeter did not stop within %.1fs; killing it.", timeout)
            self.process.kill()
            self.process.wait(timeout=timeout)
        finally:
            self.process = None

