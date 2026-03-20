# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.0.0] - 2026-03-20

### Added
- Initial release
- Full periodic import of all Malpedia families and their samples
- Support for `raw`, `zip` (pwd: `infected`) and `both` sample formats (configurable)
- Automatic creation/resolution of `Malware` entities per family
- Automatic creation/resolution of `Intrusion Set` entities for attributed actors
- YARA rules imported as `Indicator` entities (linked via `based-on` relationship)
- Relationships: `Artifact → related-to → Malware`, `Artifact → related-to → Intrusion Set`, `Indicator → based-on → Artifact`
- Labels per artifact: base labels + family ID + packed status
- TLP marking configurable (`TLP:WHITE` → `TLP:RED`)
- SHA256-based state persistence — already-uploaded samples are skipped
- Optional family filter (`MALPEDIA_FAMILIES_FILTER`)
- Optional unpacked/dumped-only filter (`MALPEDIA_UNPACKED_ONLY`)
- Configurable download delay (`MALPEDIA_DOWNLOAD_DELAY`) to respect Malpedia API rate limits
- Docker Compose and manual deployment support
- GitHub Actions CI: lint (flake8, black, isort) + unit tests + Docker build
