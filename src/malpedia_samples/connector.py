"""
Malpedia Samples connector for OpenCTI.

For each malware family on Malpedia:
  1. Retrieve all known samples (sha256 + packed status)
  2. Download each sample (raw binary and/or password-protected ZIP)
  3. Upload it to OpenCTI as an Artifact
  4. Link the Artifact to:
       - The Malware entity (family)
       - The associated Intrusion Sets (actors)
       - YARA Indicators for the family (if enabled)
  5. Apply labels and TLP markings

Strategy: full periodic re-scan of all families. Already-uploaded artifacts
are skipped via a local SHA256 state set stored in the connector state.
"""

import io
import time
import zipfile
import logging

from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
)

from .config import ConnectorConfig
from .malpedia_client import MalpediaClient


logger = logging.getLogger(__name__)


# TLP mapping: string → OpenCTI marking definition name
TLP_MARKING_MAP = {
    "TLP:WHITE": "TLP:WHITE",
    "TLP:CLEAR": "TLP:CLEAR",
    "TLP:GREEN": "TLP:GREEN",
    "TLP:AMBER": "TLP:AMBER",
    "TLP:RED": "TLP:RED",
}


class MalpediaSamplesConnector:
    def __init__(self):
        self.config = ConnectorConfig()

        # pycti helper — reads OPENCTI_URL, OPENCTI_TOKEN, connector meta from env
        self.helper = OpenCTIConnectorHelper({
            "opencti": {
                "url": self.config.opencti_url,
                "token": self.config.opencti_token,
            },
            "connector": {
                "id": self.config.connector_id,
                "type": "EXTERNAL_IMPORT",
                "name": self.config.connector_name,
                "scope": self.config.connector_scope,
                "log_level": self.config.connector_log_level,
                "duration_period": self.config.connector_duration_period,
            },
        })

        self.malpedia = MalpediaClient(self.config.malpedia_auth_key)

        # Resolve TLP marking definition from OpenCTI
        self._tlp_marking = self._resolve_tlp(self.config.malpedia_tlp)

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    def run(self):
        self.helper.log_info("Starting Malpedia Samples connector …")
        self.helper.schedule_iso(self._process, self.config.connector_duration_period)

    # ------------------------------------------------------------------ #
    # Main processing loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Full sweep: iterate families → samples → upload artifacts."""
        state = self.helper.get_state() or {}
        uploaded_hashes: set = set(state.get("uploaded_hashes", []))

        self.helper.log_info("Fetching Malpedia family list …")
        try:
            families = self.malpedia.get_families()
        except Exception as e:
            self.helper.log_error(f"Failed to fetch families: {e}")
            return

        # Optional family filter
        if self.config.malpedia_families_filter:
            families = {
                k: v
                for k, v in families.items()
                if k in self.config.malpedia_families_filter
            }
            self.helper.log_info(
                f"Filtering to {len(families)} families: {list(families.keys())}"
            )

        self.helper.log_info(f"Processing {len(families)} families …")

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Malpedia Samples import — {len(families)} families",
        )

        total_new = 0
        total_skipped = 0

        for family_id, family_meta in families.items():
            try:
                new, skipped = self._process_family(
                    family_id, family_meta, uploaded_hashes, work_id
                )
                total_new += new
                total_skipped += skipped
            except Exception as e:
                self.helper.log_error(f"[{family_id}] Unexpected error: {e}")
                continue

        # Persist updated state
        state["uploaded_hashes"] = list(uploaded_hashes)
        self.helper.set_state(state)

        message = (
            f"Import complete — {total_new} new artifacts uploaded, "
            f"{total_skipped} already present."
        )
        self.helper.log_info(message)
        self.helper.api.work.to_processed(work_id, message)

    # ------------------------------------------------------------------ #
    # Per-family processing
    # ------------------------------------------------------------------ #

    def _process_family(
        self,
        family_id: str,
        family_meta: dict,
        uploaded_hashes: set,
        work_id: str,
    ) -> tuple:
        """Process one malware family. Returns (new_count, skipped_count)."""
        self.helper.log_info(f"[{family_id}] Fetching sample list …")

        try:
            samples = self.malpedia.list_samples(family_id)
        except Exception as e:
            self.helper.log_warning(f"[{family_id}] Could not list samples: {e}")
            return 0, 0

        if not samples:
            return 0, 0

        # Filter packed if requested
        if self.config.malpedia_unpacked_only:
            samples = [s for s in samples if s.get("status") in ("unpacked", "dumped")]

        # Ensure/create the Malware entity in OpenCTI
        malware_id = self._ensure_malware_entity(family_id, family_meta)

        # Intrusion sets for this family
        intrusion_set_ids = []
        if self.config.malpedia_import_intrusion_sets:
            intrusion_set_ids = self._ensure_intrusion_sets(family_id, family_meta)

        # YARA indicators for this family
        yara_indicator_ids = []
        if self.config.malpedia_import_yara:
            yara_indicator_ids = self._ensure_yara_indicators(family_id, malware_id)

        new_count = 0
        skipped_count = 0

        for sample in samples:
            sha256 = sample.get("sha256", "").lower()
            if not sha256:
                continue

            if sha256 in uploaded_hashes:
                skipped_count += 1
                continue

            success = self._upload_sample(
                sha256=sha256,
                sample_meta=sample,
                family_id=family_id,
                family_meta=family_meta,
                malware_id=malware_id,
                intrusion_set_ids=intrusion_set_ids,
                yara_indicator_ids=yara_indicator_ids,
                work_id=work_id,
            )

            if success:
                uploaded_hashes.add(sha256)
                new_count += 1

            # Be polite to the Malpedia API
            time.sleep(self.config.malpedia_download_delay)

        self.helper.log_info(
            f"[{family_id}] Done — {new_count} new, {skipped_count} skipped."
        )
        return new_count, skipped_count

    # ------------------------------------------------------------------ #
    # Sample download & artifact upload
    # ------------------------------------------------------------------ #

    def _upload_sample(
        self,
        sha256: str,
        sample_meta: dict,
        family_id: str,
        family_meta: dict,
        malware_id: str,
        intrusion_set_ids: list,
        yara_indicator_ids: list,
        work_id: str,
    ) -> bool:
        """Download sample from Malpedia and upload as OpenCTI Artifact."""
        status = sample_meta.get("status", "unknown")
        version = sample_meta.get("version") or ""
        file_name_base = f"{sha256}"
        if version:
            file_name_base += f"_{version}"

        fmt = self.config.malpedia_sample_format  # "raw", "zip", "both"

        # Build label list: base labels + family + packed status
        labels = list(self.config.malpedia_labels)
        labels.append(family_id.replace("/", "-"))
        labels.append(status)
        label_ids = self._ensure_labels(labels)

        uploaded_any = False

        # ── RAW binary ───────────────────────────────────────────────────
        if fmt in ("raw", "both"):
            try:
                raw_bytes = self.malpedia.get_sample_raw(sha256)
                artifact_id = self._create_artifact(
                    data=raw_bytes,
                    file_name=f"{file_name_base}.bin",
                    mime_type="application/octet-stream",
                    sha256=sha256,
                    label_ids=label_ids,
                    work_id=work_id,
                )
                if artifact_id:
                    self._link_artifact(
                        artifact_id, malware_id, intrusion_set_ids, yara_indicator_ids
                    )
                    uploaded_any = True
                    self.helper.log_info(f"[{family_id}] Uploaded raw: {sha256[:12]}…")
            except Exception as e:
                self.helper.log_warning(f"[{family_id}] Raw download failed for {sha256[:12]}…: {e}")

        # ── ZIP (password: infected) ──────────────────────────────────────
        if fmt in ("zip", "both"):
            try:
                zip_bytes = self.malpedia.get_sample_zip(sha256)
                artifact_id = self._create_artifact(
                    data=zip_bytes,
                    file_name=f"{file_name_base}.zip",
                    mime_type="application/zip",
                    sha256=sha256,
                    label_ids=label_ids,
                    work_id=work_id,
                )
                if artifact_id:
                    self._link_artifact(
                        artifact_id, malware_id, intrusion_set_ids, yara_indicator_ids
                    )
                    uploaded_any = True
                    self.helper.log_info(f"[{family_id}] Uploaded zip: {sha256[:12]}…")
            except Exception as e:
                self.helper.log_warning(f"[{family_id}] ZIP download failed for {sha256[:12]}…: {e}")

        return uploaded_any

    # ------------------------------------------------------------------ #
    # OpenCTI helpers — Artifact
    # ------------------------------------------------------------------ #

    def _create_artifact(
        self,
        data: bytes,
        file_name: str,
        mime_type: str,
        sha256: str,
        label_ids: list,
        work_id: str,
    ) -> str | None:
        """Upload binary data as an OpenCTI Artifact, then apply labels and markings."""
        try:
            # Step 1: Upload the artifact (basic fields only)
            artifact = self.helper.api.stix_cyber_observable.upload_artifact(
                file_name=file_name,
                data=io.BytesIO(data),
                mime_type=mime_type,
                x_opencti_description=(
                    f"Malpedia sample — SHA256: {sha256}"
                ),
            )
            if not artifact:
                return None

            artifact_id = artifact.get("id")
            if not artifact_id:
                return None

            # Step 2: Apply TLP marking
            if self._tlp_marking:
                try:
                    self.helper.api.stix_cyber_observable.add_marking_definition(
                        id=artifact_id,
                        marking_definition_id=self._tlp_marking["id"],
                    )
                except Exception as e:
                    self.helper.log_warning(
                        f"Could not apply TLP marking to {file_name}: {e}"
                    )

            # Step 3: Apply labels
            for label_id in label_ids:
                try:
                    self.helper.api.stix_cyber_observable.add_label(
                        id=artifact_id,
                        label_id=label_id,
                    )
                except Exception as e:
                    self.helper.log_warning(
                        f"Could not apply label {label_id} to {file_name}: {e}"
                    )

            return artifact_id

        except Exception as e:
            self.helper.log_error(f"Artifact upload failed ({file_name}): {e}")
            return None

    # ------------------------------------------------------------------ #
    # OpenCTI helpers — Relationships
    # ------------------------------------------------------------------ #

    def _link_artifact(
        self,
        artifact_id: str,
        malware_id: str,
        intrusion_set_ids: list,
        yara_indicator_ids: list,
    ):
        """Create all relationships from an Artifact to related objects."""

        # Artifact → related-to → Malware
        if malware_id:
            self._create_relationship(
                from_id=artifact_id,
                to_id=malware_id,
                rel_type="related-to",
            )

        # Artifact → related-to → Intrusion Set
        for iset_id in intrusion_set_ids:
            self._create_relationship(
                from_id=artifact_id,
                to_id=iset_id,
                rel_type="related-to",
            )

        # Indicator (YARA) → based-on → Artifact
        for yara_id in yara_indicator_ids:
            self._create_relationship(
                from_id=yara_id,
                to_id=artifact_id,
                rel_type="based-on",
            )

    def _create_relationship(self, from_id: str, to_id: str, rel_type: str):
        try:
            self.helper.api.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type=rel_type,
                object_marking_refs=[self._tlp_marking["id"]]
                if self._tlp_marking
                else [],
            )
        except Exception as e:
            self.helper.log_warning(
                f"Relationship {from_id} -{rel_type}→ {to_id} failed: {e}"
            )

    # ------------------------------------------------------------------ #
    # OpenCTI helpers — Malware entity
    # ------------------------------------------------------------------ #

    def _ensure_malware_entity(self, family_id: str, family_meta: dict) -> str | None:
        """
        Get or create a Malware entity for the given Malpedia family.
        Returns the OpenCTI entity ID.
        """
        common_name = family_meta.get("common_name") or family_id
        description = family_meta.get("description", "")
        aliases = family_meta.get("aliases", [])
        malpedia_url = f"https://malpedia.caad.fkie.fraunhofer.de/details/{family_id}"

        try:
            # Try to find existing entity by name
            existing = self.helper.api.malware.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [common_name]}],
                    "filterGroups": [],
                }
            )
            if existing:
                return existing.get("id")

            # Create new
            malware = self.helper.api.malware.create(
                name=common_name,
                description=description,
                aliases=aliases if aliases else [],
                is_family=True,
                externalReferences=[
                    {
                        "source_name": "Malpedia",
                        "url": malpedia_url,
                        "external_id": family_id,
                    }
                ],
                object_marking_refs=[self._tlp_marking["id"]]
                if self._tlp_marking
                else [],
            )
            return malware.get("id") if malware else None
        except Exception as e:
            self.helper.log_warning(f"[{family_id}] Malware entity error: {e}")
            return None

    # ------------------------------------------------------------------ #
    # OpenCTI helpers — Intrusion Sets
    # ------------------------------------------------------------------ #

    def _ensure_intrusion_sets(self, family_id: str, family_meta: dict) -> list:
        """
        Create/resolve Intrusion Set entities for actors attributed to this family.
        Returns list of OpenCTI IDs.
        """
        attribution = family_meta.get("attribution", [])
        ids = []

        for actor_id in attribution:
            try:
                actor_data = self.malpedia.get_actor(actor_id)
            except Exception as e:
                self.helper.log_warning(
                    f"[{family_id}] Could not fetch actor {actor_id}: {e}"
                )
                continue

            actor_name = actor_data.get("value") or actor_id
            actor_description = actor_data.get("description", "")
            actor_aliases = []
            meta = actor_data.get("meta", {})
            if meta:
                actor_aliases = meta.get("synonyms", [])

            try:
                existing = self.helper.api.intrusion_set.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "name", "values": [actor_name]}],
                        "filterGroups": [],
                    }
                )
                if existing:
                    ids.append(existing.get("id"))
                    continue

                iset = self.helper.api.intrusion_set.create(
                    name=actor_name,
                    description=actor_description,
                    aliases=actor_aliases,
                    externalReferences=[
                        {
                            "source_name": "Malpedia",
                            "url": f"https://malpedia.caad.fkie.fraunhofer.de/actor/{actor_id}",
                            "external_id": actor_id,
                        }
                    ],
                    object_marking_refs=[self._tlp_marking["id"]]
                    if self._tlp_marking
                    else [],
                )
                if iset:
                    ids.append(iset.get("id"))
            except Exception as e:
                self.helper.log_warning(
                    f"[{family_id}] Intrusion set error for {actor_id}: {e}"
                )

        return ids

    # ------------------------------------------------------------------ #
    # OpenCTI helpers — YARA Indicators
    # ------------------------------------------------------------------ #

    def _ensure_yara_indicators(self, family_id: str, malware_id: str) -> list:
        """
        Fetch YARA rules for a family and create Indicator entities in OpenCTI.
        Returns list of OpenCTI Indicator IDs.
        """
        try:
            yara_data = self.malpedia.get_yara(family_id)
        except Exception as e:
            self.helper.log_warning(f"[{family_id}] Could not fetch YARA rules: {e}")
            return []

        ids = []
        # yara_data is a dict: {tlp_level: [{"rule_name": ..., "raw_rule": ...}, ...]}
        for tlp_level, rules in yara_data.items():
            if not isinstance(rules, list):
                continue
            for rule in rules:
                rule_name = rule.get("rule_name") or rule.get("name", "")
                raw_rule = rule.get("raw_rule") or rule.get("rule", "")
                if not raw_rule or not rule_name:
                    continue

                try:
                    existing = self.helper.api.indicator.read(
                        filters={
                            "mode": "and",
                            "filters": [{"key": "name", "values": [rule_name]}],
                            "filterGroups": [],
                        }
                    )
                    if existing:
                        ids.append(existing.get("id"))
                        continue

                    indicator = self.helper.api.indicator.create(
                        name=rule_name,
                        description=f"YARA rule for {family_id} (TLP: {tlp_level})",
                        pattern_type="yara",
                        pattern=raw_rule,
                        x_opencti_main_observable_type="StixFile",
                        indicates=[malware_id] if malware_id else [],
                        object_marking_refs=[self._tlp_marking["id"]]
                        if self._tlp_marking
                        else [],
                    )
                    if indicator:
                        ids.append(indicator.get("id"))
                except Exception as e:
                    self.helper.log_warning(
                        f"[{family_id}] YARA indicator error ({rule_name}): {e}"
                    )

        return ids

    # ------------------------------------------------------------------ #
    # OpenCTI helpers — Labels
    # ------------------------------------------------------------------ #

    def _ensure_labels(self, label_values: list) -> list:
        """Get or create labels and return their IDs."""
        ids = []
        for label in label_values:
            try:
                result = self.helper.api.label.create(
                    value=label,
                    color=self.config.malpedia_labels_color,
                )
                if result:
                    ids.append(result.get("id"))
            except Exception as e:
                self.helper.log_warning(f"Label '{label}' error: {e}")
        return ids

    # ------------------------------------------------------------------ #
    # OpenCTI helpers — TLP
    # ------------------------------------------------------------------ #

    def _resolve_tlp(self, tlp_string: str) -> dict | None:
        """Resolve a TLP string to an OpenCTI marking definition dict."""
        name = TLP_MARKING_MAP.get(tlp_string.upper(), "TLP:AMBER")
        try:
            markings = self.helper.api.marking_definition.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "definition", "values": [name]}],
                    "filterGroups": [],
                }
            )
            if markings:
                return markings
        except Exception as e:
            self.helper.log_warning(f"Could not resolve TLP marking '{name}': {e}")
        return None