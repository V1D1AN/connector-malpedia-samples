"""
Malpedia REST API client.
Wraps authenticated calls to https://malpedia.caad.fkie.fraunhofer.de/api/
"""

import requests
from urllib.parse import urljoin


MALPEDIA_BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de/"


class MalpediaClient:
    """Minimal Malpedia API client focused on sample retrieval."""

    def __init__(self, auth_key: str):
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"apitoken {auth_key}"})

    def _get(self, path: str, raw: bool = False):
        url = urljoin(MALPEDIA_BASE_URL, path)
        response = self._session.get(url, timeout=60)
        response.raise_for_status()
        if raw:
            return response.content
        return response.json()

    # ------------------------------------------------------------------ #
    # Families
    # ------------------------------------------------------------------ #

    def get_families(self) -> dict:
        """
        Returns a dict keyed by family_id with metadata for every family.
        Each entry contains: updated, description, common_name, urls, aliases, attribution.
        """
        return self._get("api/get/families")

    def get_family(self, family_id: str) -> dict:
        """Return metadata for a single family."""
        return self._get(f"api/get/family/{family_id}")

    # ------------------------------------------------------------------ #
    # Samples
    # ------------------------------------------------------------------ #

    def list_samples(self, family_id: str) -> list:
        """
        List all known samples for a family.
        Each entry: {"sha256": "...", "status": "unpacked"|"packed"|"dumped", "version": "..."}
        """
        return self._get(f"api/list/samples/{family_id}")

    def get_sample_raw(self, sha256: str) -> bytes:
        """Download the raw binary for a sample (requires trust-group account)."""
        return self._get(f"api/get/sample/{sha256}/raw", raw=True)

    def get_sample_zip(self, sha256: str) -> bytes:
        """
        Download a password-protected ZIP containing the sample.
        Password is always 'infected'.
        """
        return self._get(f"api/get/sample/{sha256}/zip", raw=True)

    # ------------------------------------------------------------------ #
    # YARA
    # ------------------------------------------------------------------ #

    def get_yara(self, family_id: str) -> dict:
        """
        Return YARA rules for a family.
        Dict: {"tlp_white": [...], "tlp_green": [...], "tlp_amber": [...]}
        Each rule is a dict with keys: rule_name, raw_rule, tlp.
        Output varies with access level.
        """
        return self._get(f"api/get/yara/{family_id}")

    # ------------------------------------------------------------------ #
    # Actors / Intrusion Sets
    # ------------------------------------------------------------------ #

    def list_actors(self) -> list:
        """Return list of all actor IDs."""
        return self._get("api/list/actors")

    def get_actor(self, actor_id: str) -> dict:
        """
        Return metadata for an actor.
        Contains: description, names, country, cfr_type_of_incident, cfr_target_categories,
                  meta (uuid, refs, synonyms), families.
        """
        return self._get(f"api/get/actor/{actor_id}")

    # ------------------------------------------------------------------ #
    # Version
    # ------------------------------------------------------------------ #

    def get_version(self) -> dict:
        """Return current Malpedia commit/date."""
        return self._get("api/get/version")
