"""Scope configuration for the Autonomous Pentesting Agent."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

_ALL_MODULES = [
    "auth",
    "injection",
    "access",
    "headers",
    "disclosure",
    "ratelimit",
]


class ScopeConfig(BaseModel):
    """Runtime scope constraints loaded from a YAML file.

    YAML example::

        allowed_hosts:
          - api.example.com
        excluded_paths:
          - /admin
          - /health
        max_requests_per_tool: 30
        enabled_modules:
          - headers
          - injection
        disabled_modules: []
        severity_threshold: medium
    """

    allowed_hosts: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    max_requests_per_tool: int = 50
    enabled_modules: list[str] = Field(
        default_factory=lambda: list(_ALL_MODULES)
    )
    disabled_modules: list[str] = Field(default_factory=list)
    severity_threshold: str = "low"

    @property
    def active_modules(self) -> list[str]:
        return [
            m for m in self.enabled_modules
            if m not in self.disabled_modules
        ]

    def to_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["active_modules"] = self.active_modules
        return d


def load_scope(path: str | None) -> ScopeConfig:
    """Load a ScopeConfig from *path*; return defaults when path is None."""
    if path is None:
        return ScopeConfig()
    raw = Path(path).read_text(encoding="utf-8")
    data: dict[str, Any] = yaml.safe_load(raw) or {}
    return ScopeConfig(**data)
