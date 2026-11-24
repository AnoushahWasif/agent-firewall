"""Tool pinning: a tool whose definition changes after it was trusted is withheld (decision 3).

A "rug pull" is a server that shows a harmless tool, gets approved, then changes the description
to something malicious. Each tool's definition is fingerprinted (description, schemas,
annotations, title) and the first one seen is pinned. A later change blocks the tool until a
person approves the new version.

The pin file is JSON, written atomically. A pin file that can't be read stops the firewall from
starting rather than being treated as empty, which would trust every tool again.
"""

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import mcp_types as types

from agent_firewall.checks.verdict import Decision, Verdict

Status = Literal["new", "same", "changed"]


class PinFileError(RuntimeError):
    pass


def fingerprint(tool: types.Tool) -> str:
    """SHA-256 of everything about a tool that the model reads or that changes what it does."""
    material = {
        "title": tool.title,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "output_schema": tool.output_schema,
        "annotations": tool.annotations.model_dump(mode="json") if tool.annotations else None,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class PinStore:
    """Pins by public tool name. `path=None` keeps them in memory (tests, throwaway runs)."""

    path: Path | None = None

    def __post_init__(self):
        self._pins: dict[str, dict[str, str]] = {}
        if self.path is not None and self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                pins = data["pins"]
                if data.get("version") != 1 or not isinstance(pins, dict):
                    raise ValueError("unknown format")
                for name, entry in pins.items():
                    if not isinstance(entry, dict) or len(entry.get("sha256", "")) != 64:
                        raise ValueError(f"bad entry for {name}")
                self._pins = pins
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise PinFileError(f"can't read the pin file {self.path}: {exc}") from exc

    def status(self, name: str, digest: str) -> Status:
        entry = self._pins.get(name)
        if entry is None:
            return "new"
        return "same" if entry["sha256"] == digest else "changed"

    def pin(self, name: str, digest: str) -> None:
        self._pins[name] = {"sha256": digest, "pinned_at": datetime.now(UTC).isoformat()}
        self._save()

    def _save(self) -> None:
        if self.path is None:
            return
        body = json.dumps({"version": 1, "pins": self._pins}, indent=2, sort_keys=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp = tempfile.mkstemp(dir=self.path.parent, prefix=".pins-", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as f:
                f.write(body)
            os.replace(temp, self.path)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise


def check_pin(store: PinStore, name: str, tool: types.Tool) -> Decision | None:
    """Trust on first use: a new tool is pinned; a changed one is blocked (PIN01)."""
    digest = fingerprint(tool)
    match store.status(name, digest):
        case "new":
            store.pin(name, digest)
            return None
        case "same":
            return None
        case _:
            return Decision(Verdict.BLOCK, "PIN01", "the definition changed since it was approved")
