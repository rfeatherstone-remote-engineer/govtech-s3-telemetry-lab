# govtech-s3-telemetry-lab

[![GovTech Python SRE Telemetry CI](https://github.com)](https://github.com)

Zero-dependency Python 3 (`stdlib`-only) detective & corrective SRE telemetry pipeline for **GovTech & Defense** aligned to **FedRAMP High / NIST SP 800-53 Rev. 5**, **DoD SRG (IL4/IL5)**, and **NIST SP 800-218 (SSDF)**.

> **Companion Repository:** Pairs with [`fedramp-s3-golden-path`](https://github.com) for preventive Terraform S3 & KMS guardrails.

## Capabilities & Architecture

* **In-Memory CUI & PII Redaction (`compliance/cui_sanitizer.py`):** Recursively scrubs Controlled Unclassified Information (`CUI//...`), SSNs, and 10-digit DoD EDIPI identifiers across nested dicts, lists, and keys before disk persistence (`AU-9` / `SI-12`).
* **Multi-Window SLO Burn-Rate Engine (`detections/alert_rules.py`):** Evaluates a `99.9%` availability SLO (`43.2` min/month error budget) using `14.4x` fast-burn and `3.0x` slow-burn thresholds alongside KMS encryption drift detection.
* **Circuit-Breaker Self-Healer (`remediation/self_healer.py`):** Quarantines sanitized incident evidence into `0700`/`0600` atomic state directories with a `300s` per-rule cooldown and deterministic artifact pruning.
* **Blameless RCA Automation (`compliance/postmortem_gen.py`):** Generates structured Markdown root-cause reports mapped to operational runbooks (`RB-001` – `RB-003`).

## Quickstart & Chaos Fault Injection

```bash
# Run unit test suite
python3 -m unittest discover -s tests -v

# Dry-run CUI spill detection & redaction
python3 -m remediation.self_healer --inject-fault cui_leak

# Execute quarantined remediation with 300s circuit breaker
python3 -m remediation.self_healer --inject-fault slo_burn --execute --state-dir .state
```

## CI Supply-Chain Provenance
Every push executes unit tests, end-to-end fault injection (`cui_leak`, `slo_burn`), SHA-256 manifest generation (`SHA256SUMS`), and an **SPDX 2.3 SBOM** (`sbom.spdx.json`).
