"""
Configuration loader for the Malpedia Samples connector.
Reads from environment variables (Docker) or config.yml (manual deployment).
"""

import os
import yaml


class ConnectorConfig:
    def __init__(self):
        # ── OpenCTI ──────────────────────────────────────────────────────
        self.opencti_url: str = self._get("OPENCTI_URL", required=True)
        self.opencti_token: str = self._get("OPENCTI_TOKEN", required=True)

        # ── Connector ────────────────────────────────────────────────────
        self.connector_id: str = self._get("CONNECTOR_ID", required=True)
        self.connector_name: str = self._get("CONNECTOR_NAME", default="Malpedia Samples")
        self.connector_scope: str = self._get("CONNECTOR_SCOPE", default="artifact,malware")
        self.connector_log_level: str = self._get("CONNECTOR_LOG_LEVEL", default="info")
        self.connector_duration_period: str = self._get(
            "CONNECTOR_DURATION_PERIOD", default="P7D"
        )  # ISO 8601 — default weekly

        # ── Malpedia ─────────────────────────────────────────────────────
        self.malpedia_auth_key: str = self._get("MALPEDIA_AUTH_KEY", required=True)

        # Sample format: "raw" | "zip" | "both"
        self.malpedia_sample_format: str = self._get(
            "MALPEDIA_SAMPLE_FORMAT", default="both"
        )
        # Comma-separated list of family IDs to restrict import (empty = all)
        _families = self._get("MALPEDIA_FAMILIES_FILTER", default="")
        self.malpedia_families_filter: list = (
            [f.strip() for f in _families.split(",") if f.strip()]
            if _families
            else []
        )
        # Only import unpacked/dumped samples (cleaner for analysis)
        self.malpedia_unpacked_only: bool = self._get_bool(
            "MALPEDIA_UNPACKED_ONLY", default=False
        )
        # Labels to attach to every artifact (comma-separated)
        _labels = self._get("MALPEDIA_LABELS", default="malpedia")
        self.malpedia_labels: list = [l.strip() for l in _labels.split(",") if l.strip()]
        self.malpedia_labels_color: str = self._get(
            "MALPEDIA_LABELS_COLOR", default="#7f3b08"
        )
        # TLP marking to apply to artifacts
        self.malpedia_tlp: str = self._get("MALPEDIA_TLP", default="TLP:AMBER")

        # Relationships
        self.malpedia_import_intrusion_sets: bool = self._get_bool(
            "MALPEDIA_IMPORT_INTRUSION_SETS", default=True
        )
        self.malpedia_import_yara: bool = self._get_bool(
            "MALPEDIA_IMPORT_YARA", default=True
        )
        # Delay between sample downloads (seconds) to be polite to the API
        self.malpedia_download_delay: float = float(
            self._get("MALPEDIA_DOWNLOAD_DELAY", default="1")
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _get(env_key: str, default: str = None, required: bool = False) -> str:
        value = os.environ.get(env_key)
        if value is None and required:
            raise ValueError(
                f"Required environment variable '{env_key}' is not set."
            )
        return value if value is not None else default

    @staticmethod
    def _get_bool(env_key: str, default: bool = False) -> bool:
        value = os.environ.get(env_key, str(default)).strip().lower()
        return value in ("true", "1", "yes")
