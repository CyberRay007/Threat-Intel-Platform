"""
Integration adapter framework.

Every external integration (SIEM, SOAR, firewall, etc.) must implement
IntegrationAdapter.  This enforces a single contract and makes adding
new integrations a small, isolated change.

Usage:
    from app.services.integrations.base import IntegrationAdapter
    from app.services.integrations.splunk import SplunkAdapter

    adapter = SplunkAdapter(config)
    adapter.health_check()
    adapter.push_iocs(iocs)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PushResult:
    success: bool
    pushed: int = 0
    failed: int = 0
    error: str | None = None
    raw_response: Any = None


class IntegrationAdapter(ABC):
    """Abstract base for all outbound integrations."""

    name: str = "unnamed"

    @abstractmethod
    def health_check(self) -> bool:
        """
        Return True if the remote endpoint is reachable and configured.
        Must NOT raise — return False on failure.
        """

    @abstractmethod
    def push_iocs(self, iocs: list[dict]) -> PushResult:
        """
        Push a list of IOC dicts to the remote system.

        Each IOC dict contains at minimum:
            type (str), value (str), confidence (float), source (str)
        """

    @abstractmethod
    def push_alerts(self, alerts: list[dict]) -> PushResult:
        """
        Push a list of alert dicts to the remote system.

        Each alert dict contains at minimum:
            id (int), severity (str), title (str), observable_value (str)
        """
