"""
Unit tests for the Malpedia Samples connector.
Uses mocks — no live Malpedia or OpenCTI instance required.
"""

import io
import sys
import os
import zipfile
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

# Make src importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from malpedia_samples.config import ConnectorConfig
from malpedia_samples.malpedia_client import MalpediaClient


# ─────────────────────────────────────────────────────────────────────────────
# ConnectorConfig
# ─────────────────────────────────────────────────────────────────────────────

class TestConnectorConfig:
    def _env(self, monkeypatch, overrides=None):
        defaults = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token123",
            "CONNECTOR_ID": "aaaaaaaa-0000-0000-0000-000000000001",
            "MALPEDIA_AUTH_KEY": "testkey",
        }
        if overrides:
            defaults.update(overrides)
        for k, v in defaults.items():
            monkeypatch.setenv(k, v)

    def test_defaults(self, monkeypatch):
        self._env(monkeypatch)
        cfg = ConnectorConfig()
        assert cfg.malpedia_sample_format == "both"
        assert cfg.malpedia_families_filter == []
        assert cfg.malpedia_unpacked_only is False
        assert cfg.malpedia_tlp == "TLP:AMBER"
        assert cfg.malpedia_import_intrusion_sets is True
        assert cfg.malpedia_import_yara is True
        assert cfg.malpedia_download_delay == 1.0

    def test_families_filter_parsed(self, monkeypatch):
        self._env(monkeypatch, {"MALPEDIA_FAMILIES_FILTER": "win.cobalt_strike, win.mimikatz"})
        cfg = ConnectorConfig()
        assert cfg.malpedia_families_filter == ["win.cobalt_strike", "win.mimikatz"]

    def test_labels_parsed(self, monkeypatch):
        self._env(monkeypatch, {"MALPEDIA_LABELS": "malpedia,apt,sample"})
        cfg = ConnectorConfig()
        assert cfg.malpedia_labels == ["malpedia", "apt", "sample"]

    def test_bool_true(self, monkeypatch):
        self._env(monkeypatch, {"MALPEDIA_UNPACKED_ONLY": "true"})
        cfg = ConnectorConfig()
        assert cfg.malpedia_unpacked_only is True

    def test_bool_false(self, monkeypatch):
        self._env(monkeypatch, {"MALPEDIA_UNPACKED_ONLY": "false"})
        cfg = ConnectorConfig()
        assert cfg.malpedia_unpacked_only is False

    def test_missing_required_raises(self, monkeypatch):
        monkeypatch.delenv("OPENCTI_URL", raising=False)
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
        monkeypatch.delenv("CONNECTOR_ID", raising=False)
        monkeypatch.delenv("MALPEDIA_AUTH_KEY", raising=False)
        with pytest.raises(ValueError, match="OPENCTI_URL"):
            ConnectorConfig()


# ─────────────────────────────────────────────────────────────────────────────
# MalpediaClient
# ─────────────────────────────────────────────────────────────────────────────

class TestMalpediaClient:
    def _client(self):
        return MalpediaClient(auth_key="faketoken")

    def test_auth_header_set(self):
        client = self._client()
        assert "Authorization" in client._session.headers
        assert client._session.headers["Authorization"] == "apitoken faketoken"

    def test_get_families_calls_correct_endpoint(self):
        client = self._client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"win.cobalt_strike": {"common_name": "Cobalt Strike"}}
        with patch.object(client._session, "get", return_value=mock_resp) as mock_get:
            result = client.get_families()
            mock_get.assert_called_once()
            assert "api/get/families" in mock_get.call_args[0][0]
            assert "win.cobalt_strike" in result

    def test_list_samples_calls_correct_endpoint(self):
        client = self._client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"sha256": "abc123", "status": "unpacked", "version": ""},
        ]
        with patch.object(client._session, "get", return_value=mock_resp) as mock_get:
            result = client.list_samples("win.cobalt_strike")
            assert "api/list/samples/win.cobalt_strike" in mock_get.call_args[0][0]
            assert result[0]["sha256"] == "abc123"

    def test_get_sample_raw_returns_bytes(self):
        client = self._client()
        fake_bytes = b"\x4d\x5a\x90\x00"  # MZ header
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = fake_bytes
        with patch.object(client._session, "get", return_value=mock_resp):
            result = client.get_sample_raw("abc123")
            assert result == fake_bytes

    def test_get_sample_zip_returns_bytes(self):
        client = self._client()
        # Build a minimal valid ZIP in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("sample.bin", b"\x4d\x5a")
        zip_bytes = buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = zip_bytes
        with patch.object(client._session, "get", return_value=mock_resp):
            result = client.get_sample_zip("abc123")
            assert result[:2] == b"PK"  # ZIP magic bytes

    def test_http_error_raises(self):
        client = self._client()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = Exception("403 Forbidden")
        with patch.object(client._session, "get", return_value=mock_resp):
            with pytest.raises(Exception, match="403"):
                client.get_families()

    def test_get_yara_returns_dict(self):
        client = self._client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "tlp_white": [{"rule_name": "CobaltStrike_1", "raw_rule": "rule CobaltStrike_1 {}"}]
        }
        with patch.object(client._session, "get", return_value=mock_resp):
            result = client.get_yara("win.cobalt_strike")
            assert "tlp_white" in result
            assert result["tlp_white"][0]["rule_name"] == "CobaltStrike_1"


# ─────────────────────────────────────────────────────────────────────────────
# Connector integration stubs
# ─────────────────────────────────────────────────────────────────────────────

class TestConnectorLogic:
    """
    Light integration tests using fully mocked pycti + Malpedia client.
    Validates the processing pipeline without real network calls.
    """

    def _make_connector(self, monkeypatch):
        """Instantiate MalpediaSamplesConnector with all external deps mocked."""
        monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "token")
        monkeypatch.setenv("CONNECTOR_ID", "aaaaaaaa-0000-0000-0000-000000000001")
        monkeypatch.setenv("MALPEDIA_AUTH_KEY", "fakekey")
        monkeypatch.setenv("MALPEDIA_DOWNLOAD_DELAY", "0")

        with patch("malpedia_samples.connector.OpenCTIConnectorHelper") as mock_helper_cls, \
             patch("malpedia_samples.connector.MalpediaClient") as mock_client_cls:

            mock_helper = MagicMock()
            mock_helper_cls.return_value = mock_helper
            mock_helper.get_state.return_value = {}
            mock_helper.connect_id = "connector-id"
            mock_helper.api.work.initiate_work.return_value = "work-id"
            mock_helper.api.marking_definition.read.return_value = {"id": "marking-amber"}

            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            from malpedia_samples.connector import MalpediaSamplesConnector
            connector = MalpediaSamplesConnector()
            return connector, mock_helper, mock_client

    def test_process_skips_already_uploaded(self, monkeypatch):
        connector, mock_helper, mock_client = self._make_connector(monkeypatch)

        # State already has this hash
        mock_helper.get_state.return_value = {"uploaded_hashes": ["deadbeef" * 8]}

        mock_client.get_families.return_value = {
            "win.test_family": {
                "common_name": "Test Family",
                "description": "",
                "aliases": [],
                "attribution": [],
            }
        }
        mock_client.list_samples.return_value = [
            {"sha256": "deadbeef" * 8, "status": "unpacked", "version": ""},
        ]
        mock_helper.api.malware.read.return_value = {"id": "malware-id"}

        connector._process()

        # No download should have happened
        mock_client.get_sample_raw.assert_not_called()
        mock_client.get_sample_zip.assert_not_called()

    def test_process_uploads_new_sample(self, monkeypatch):
        connector, mock_helper, mock_client = self._make_connector(monkeypatch)
        monkeypatch.setenv("MALPEDIA_SAMPLE_FORMAT", "raw")

        mock_helper.get_state.return_value = {}
        mock_client.get_families.return_value = {
            "win.test_family": {
                "common_name": "Test Family",
                "description": "Test description",
                "aliases": ["TestFam"],
                "attribution": [],
            }
        }
        sha = "a" * 64
        mock_client.list_samples.return_value = [
            {"sha256": sha, "status": "unpacked", "version": "1.0"},
        ]
        mock_client.get_yara.return_value = {}
        mock_client.get_sample_raw.return_value = b"\x4d\x5a\x00\x00"
        mock_helper.api.malware.read.return_value = None
        mock_helper.api.malware.create.return_value = {"id": "malware-new-id"}
        mock_helper.api.label.create.return_value = {"id": "label-id"}
        mock_helper.api.stix_cyber_observable.upload_artifact.return_value = {
            "id": "artifact-id"
        }

        connector._process()

        mock_client.get_sample_raw.assert_called_once_with(sha)
        mock_helper.api.stix_cyber_observable.upload_artifact.assert_called_once()

    def test_family_filter_applied(self, monkeypatch):
        monkeypatch.setenv("MALPEDIA_FAMILIES_FILTER", "win.wanted_family")
        connector, mock_helper, mock_client = self._make_connector(monkeypatch)

        mock_helper.get_state.return_value = {}
        mock_client.get_families.return_value = {
            "win.wanted_family": {"common_name": "Wanted", "description": "", "aliases": [], "attribution": []},
            "win.other_family": {"common_name": "Other", "description": "", "aliases": [], "attribution": []},
        }
        mock_client.list_samples.return_value = []

        connector._process()

        # list_samples should only be called for the filtered family
        calls = [c[0][0] for c in mock_client.list_samples.call_args_list]
        assert "win.wanted_family" in calls
        assert "win.other_family" not in calls
