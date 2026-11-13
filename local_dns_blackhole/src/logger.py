"""Append-only JSON Lines request logging and simple statistics."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class RequestLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, domain: str, query_type: str, action: str, response_ms: float) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "query_type": query_type,
            "action": action,
            "response_ms": round(response_ms, 3),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        result = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    result.append(item)
            except json.JSONDecodeError:
                continue
        return result

    def stats(self) -> dict[str, int]:
        entries = self.entries()
        return {
            "total": len(entries),
            "blocked": sum(item.get("action") == "blocked" for item in entries),
            "forwarded": sum(item.get("action") == "forwarded" for item in entries),
            "errors": sum(item.get("action") == "error" for item in entries),
        }
