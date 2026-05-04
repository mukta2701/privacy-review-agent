from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from privacy_review_agent.config import Settings
from privacy_review_agent.models import Finding


@dataclass
class DetectorContext:
    settings: Settings


class Detector:
    name = "base"

    def scan(self, files: list[Path], context: DetectorContext) -> list[Finding]:
        raise NotImplementedError
