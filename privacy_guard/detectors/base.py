from __future__ import annotations
from abc import ABC, abstractmethod
from ..models import Finding


class BaseDetector(ABC):
    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        """Return all findings in text."""
        ...
