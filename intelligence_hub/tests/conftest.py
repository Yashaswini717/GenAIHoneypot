"""Test setup shared by the hub's suites.

`config.Settings()` is built the first time anything imports `config`, reads
the environment, and refuses a published HMAC secret. So the environment is
fixed here, before any test module imports the backend, and it is set rather
than defaulted: a developer's shell with HMAC_SECRET=dev must not decide
whether the suite can even start.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

os.environ.update({
    "POSTGRES_USER": "test",
    "POSTGRES_PASSWORD": "test",
    "POSTGRES_DB": "test",
    "NEO4J_PASSWORD": "test",
    "HMAC_SECRET": "hub-test-secret-not-published-anywhere",
    "INSECURE_DEV_MODE": "false",
    "OPERATOR_TOKEN": "",
    "ALLOW_UNSIGNED_BATCH": "false",
    "ALLOW_LEGACY_SIGNATURES": "false",
    "INGEST_CLOCK_SKEW_SECONDS": "300",
    "INGEST_DEDUP_TTL_SECONDS": "86400",
})
