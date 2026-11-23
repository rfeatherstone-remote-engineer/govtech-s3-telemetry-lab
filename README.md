# govtech-s3-telemetry-lab

[![GovTech Python SRE Telemetry CI](https://://github.comrfeatherstone-remote-engineer/govtech-s3-telemetry-lab/actions/workflows/ci.yml/badge.svg)](https://://github.comrfeatherstone-remote-engineer/govtech-s3-telemetry-lab/actions/workflows/ci.yml)

Zero-dependency Python 3 (`stdlib`-only) detective & corrective SRE telemetry pipeline for **GovTech & Defense** aligned to **FedRAMP High / NIST SP 800-53 Rev. 5**, **DoD SRG (IL4/IL5)**, and **NIST SP 800-218 (SSDF)**.

> **Companion Repository:** Pairs with [`fedramp-s3-golden-path`](https://://github.comrfeatherstone-remote-engineer/fedramp-s3-golden-path) for preventive Terraform S3 & KMS guardrails.

## Pipeline Architecture

```text
  [ Host / S3 OTel Telemetry (core/system_monitor.py) ]
                          │
                          ▼
  [ In-Memory CUI / SSN / DoD EDIPI Sanitizer (AU-9 / SI-12) ]
                          │
                          ▼
  [ Multi-Window SLO Burn & Drift Detector (99.9% / 43.2m) ]
                          │
                          ▼
  [ 300s Circuit-Breaker Self-Healer (remediation/self_healer.py) ]
            ├──► Quarantine JSON (.state/quarantine/, 0600)
            └──► Blameless RCA Report (.state/triage/, RB-001..003)
```

## Quickstart & Chaos Fault Injection

```bash
python3 -m unittest discover -s tests -v
python3 -m remediation.self_healer --inject-fault cui_leak
python3 -m remediation.self_healer --inject-fault slo_burn --execute --state-dir .state
```

## Sample CLI Output

```json
{
  "actions": [
    {
      "artifact": "/tmp/demo-state/quarantine/INC-1795450120412-FEDRAMP-SLO-002.json",
      "rule_id": "FEDRAMP-SLO-002",
      "runbook": "RB-002",
      "status": "REMEDIATED"
    }
  ],
  "mode": "EXECUTE",
  "redactions": [],
  "sanitized_event": {
    "cloud.partition": "aws-us-gov",
    "event.body": "FAULT_INJECTED: Elevated S3 PutObject 5xx error rate",
    "event.severity": "ERROR",
    "s3.request.error_rate": 0.025,
    "service.namespace": "fedramp-high"
  }
}
```

## CI Supply-Chain Provenance
Every push executes unit tests, end-to-end fault injection (`cui_leak`, `slo_burn`), SHA-256 manifest generation (`SHA256SUMS`), and an **SPDX 2.3 SBOM** (`sbom.spdx.json`).
