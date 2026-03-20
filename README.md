# connector-malpedia-samples

[![CI](https://github.com/V1D1AN/connector-malpedia-samples/actions/workflows/ci.yml/badge.svg)](https://github.com/V1D1AN/connector-malpedia-samples/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-compatible-orange)](https://github.com/OpenCTI-Platform/opencti)

OpenCTI `external-import` connector that downloads malware samples from
[Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) and imports them as
**Artifacts** in OpenCTI, with full enrichment (Malware family, Intrusion Sets, YARA rules).

> **Prérequis** : compte Malpedia de confiance (groupe invite-only — [https://malpedia.caad.fkie.fraunhofer.de](https://malpedia.caad.fkie.fraunhofer.de)).
> Sans clé API authentifiée, les endpoints de téléchargement de samples sont inaccessibles.

---

## Table of contents

- [Overview](#overview)
- [What gets imported](#what-gets-imported)
- [Data flow](#data-flow)
- [Quick start](#quick-start)
- [Configuration reference](#configuration-reference)
- [State management](#state-management)
- [Integration with AssemblyLine](#integration-with-assemblyline)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This connector performs a **full periodic sweep** of all Malpedia families:

1. Fetches the complete family list from Malpedia
2. For each family, lists all known samples (SHA256 + packed status)
3. Downloads each new sample — as raw binary, password-protected ZIP, or both
4. Uploads each sample to OpenCTI as an **Artifact** (stored in MinIO)
5. Creates or resolves all related intelligence objects and links them

---

## What gets imported

| OpenCTI object | Source | Details |
|---|---|---|
| **Artifact** | `GET /api/get/sample/{sha256}/raw` or `/zip` | Raw binary or ZIP (pwd: `infected`) |
| **Malware** | `GET /api/get/families` | Family name, aliases, description, external ref |
| **Intrusion Set** | `GET /api/get/actor/{actor_id}` | Attributed actors with aliases |
| **Indicator** (YARA) | `GET /api/get/yara/{family_id}` | Rules per TLP level |
| **Relationships** | — | `Artifact→Malware`, `Artifact→IntrusionSet`, `YARA→Artifact` |

---

## Data flow

```
Malpedia API
  └── /api/get/families              → all families with metadata
       └── /api/list/samples/{id}   → SHA256 list + packed status
            ├── /api/get/sample/{sha256}/raw  → raw binary
            ├── /api/get/sample/{sha256}/zip  → ZIP (pwd: infected)
            ├── /api/get/yara/{id}            → YARA rules (by TLP)
            └── /api/get/actor/{actor_id}     → intrusion set metadata

OpenCTI (pycti)
  ├── Artifact         ← stored in MinIO
  ├── Malware          ← get_or_create by family name
  ├── Intrusion Set    ← get_or_create by actor name
  ├── Indicator (YARA) ← get_or_create by rule name
  └── Relationships
```

---

## Quick start

### Docker Compose (recommended)

```bash
git clone https://github.com/V1D1AN/connector-malpedia-samples
cd connector-malpedia-samples

# Edit docker-compose.yml and set your values, then:
docker compose up -d
```

Minimum required variables:

```yaml
environment:
  - OPENCTI_URL=http://opencti:8080
  - OPENCTI_TOKEN=<your-opencti-token>
  - CONNECTOR_ID=<uuidgen>
  - MALPEDIA_AUTH_KEY=<your-malpedia-api-key>
```

### Build locally

```bash
docker build -t connector-malpedia-samples:latest .
```

### Manual deployment

```bash
cp config.yml.sample config.yml
# Edit config.yml with your values
pip install -r src/requirements.txt
python src/main.py
```

---

## Configuration reference

| Environment variable | Default | Description |
|---|---|---|
| `OPENCTI_URL` | _(required)_ | OpenCTI platform URL |
| `OPENCTI_TOKEN` | _(required)_ | OpenCTI admin token |
| `CONNECTOR_ID` | _(required)_ | Unique UUIDv4 for this connector instance |
| `CONNECTOR_NAME` | `Malpedia Samples` | Display name in OpenCTI |
| `CONNECTOR_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warning`, `error` |
| `CONNECTOR_DURATION_PERIOD` | `P7D` | Run interval in ISO 8601 duration format |
| `MALPEDIA_AUTH_KEY` | _(required)_ | Malpedia API token (trust-group account) |
| `MALPEDIA_SAMPLE_FORMAT` | `both` | `raw` · `zip` · `both` |
| `MALPEDIA_FAMILIES_FILTER` | _(empty = all)_ | Comma-separated list of family IDs to import |
| `MALPEDIA_UNPACKED_ONLY` | `false` | If `true`, only import `unpacked` and `dumped` samples |
| `MALPEDIA_TLP` | `TLP:AMBER` | TLP marking applied to all created objects |
| `MALPEDIA_LABELS` | `malpedia` | Comma-separated labels applied to each Artifact |
| `MALPEDIA_LABELS_COLOR` | `#7f3b08` | Color for created labels |
| `MALPEDIA_IMPORT_INTRUSION_SETS` | `true` | Create/resolve Intrusion Set entities |
| `MALPEDIA_IMPORT_YARA` | `true` | Create YARA Indicator entities |
| `MALPEDIA_DOWNLOAD_DELAY` | `1` | Seconds to wait between sample downloads |

### Recommended settings

**For AssemblyLine integration** (submit raw binaries directly):
```yaml
MALPEDIA_SAMPLE_FORMAT=raw
MALPEDIA_UNPACKED_ONLY=true
```

**For restricted/filtered import** (e.g. only APT tooling):
```yaml
MALPEDIA_FAMILIES_FILTER=win.cobalt_strike,win.mimikatz,win.meterpreter
```

**For conservative API usage**:
```yaml
MALPEDIA_DOWNLOAD_DELAY=2
CONNECTOR_DURATION_PERIOD=P14D
```

---

## State management

The connector persists a set of already-uploaded SHA256 hashes in the OpenCTI
connector state slot. On each run, samples already present in that set are
skipped without re-downloading.

To force a full re-import, reset the connector state from the OpenCTI UI:

**Data → Connectors → Malpedia Samples → ↺ Reset state**

---

## Integration with AssemblyLine

Once Artifacts are stored in OpenCTI (MinIO), the
[connector-assemblyline](https://github.com/V1D1AN/S1EM) submission connector
can automatically pick them up and submit them for dynamic/static analysis.

Recommended setup for this pipeline:

```
Malpedia Samples connector
  └── Artifacts in OpenCTI/MinIO
        └── AssemblyLine submission connector
              └── Analysis results → enriched Artifact in OpenCTI
```

---

## Development

```bash
# Install dev dependencies
pip install -r src/requirements.txt
pip install flake8 black isort pytest pytest-cov

# Run tests (no live API required)
pytest tests/ -v --cov=src/malpedia_samples

# Lint
flake8 src/ --max-line-length=120
black --check --line-length=120 src/
isort --check-only --profile=black src/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[Apache 2.0](LICENSE) — © 2026 V1D1AN
