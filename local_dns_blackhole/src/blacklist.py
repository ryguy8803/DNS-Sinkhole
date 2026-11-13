"""JSON-backed domain blacklist with safe normalization."""

from __future__ import annotations

import json
from pathlib import Path


def normalize_domain(domain: str) -> str:
    """Normalize DNS names so comparisons are case-insensitive and dot-safe."""
    value = domain.strip().lower().rstrip(".")
    if not value or len(value) > 253 or any(not part for part in value.split(".")):
        raise ValueError(f"Invalid domain name: {domain!r}")
    return value


class Blacklist:
    """Store blocked domains in a small human-editable JSON document."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.domains: set[str] = set()
        self.keywords: set[str] = set()
        self.load()

    def load(self) -> set[str]:
        if not self.path.exists():
            self.domains = set()
            return self.domains
        with self.path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
        values = document.get("blocked_domains", []) if isinstance(document, dict) else document
        keyword_values = document.get("blocked_keywords", []) if isinstance(document, dict) else []
        if not isinstance(values, list):
            raise ValueError("Blacklist JSON must contain a blocked_domains list")
        if not isinstance(keyword_values, list):
            raise ValueError("Blacklist JSON blocked_keywords must be a list")
        self.domains = {normalize_domain(item) for item in values if isinstance(item, str)}
        self.keywords = {item.strip().lower() for item in keyword_values if isinstance(item, str) and item.strip()}
        return self.domains

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump({"blocked_domains": sorted(self.domains), "blocked_keywords": sorted(self.keywords)}, handle, indent=2)
            handle.write("\n")

    def add(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        changed = normalized not in self.domains
        self.domains.add(normalized)
        self.save()
        return changed

    def remove(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        changed = normalized in self.domains
        self.domains.discard(normalized)
        self.save()
        return changed

    def is_blocked(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        exact_match = any(normalized == blocked or normalized.endswith("." + blocked) for blocked in self.domains)
        keyword_match = any(keyword in normalized for keyword in self.keywords)
        return exact_match or keyword_match
