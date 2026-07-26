"""Command-line preflight for the Phase 4 isolated Android sandbox."""

from __future__ import annotations

import json

from app.core.config import get_settings
from app.dynamic_analysis.capabilities import SandboxCapabilityProbe
from app.dynamic_analysis.policy import SandboxPolicy


def main() -> int:
    settings = get_settings()
    capability = SandboxCapabilityProbe(settings).report()
    policy = SandboxPolicy(settings).response()
    payload = {
        "policy": policy.model_dump(mode="json"),
        "capabilities": capability.model_dump(mode="json"),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if capability.ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
