#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime as dt, json, os, socket, sys
from typing import Any

def read_memory_utilization() -> float:
    if not os.path.exists("/proc/meminfo"):
        return 42.0
    values: dict[str, int] = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        for line in handle:
            if ":" in line:
                k, v = line.split(":", 1)
                tok = next(iter(v.strip().split()), "")
                if tok.isdigit():
                    values[k.strip()] = int(tok)
    total = values.get("MemTotal", 0)
    avail = values.get("MemAvailable", values.get("MemFree", 0))
    return round(((total - avail) / total) * 100.0, 2) if total > 0 else 0.0

def collect_otel_event(inject_fault: str | None = None) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc)
    mem_util, error_rate, kms_ok = read_memory_utilization(), 0.0002, True
    note = "Routine FedRAMP High S3 telemetry heartbeat"
    if inject_fault == "slo_burn":
        error_rate, mem_util, note = 0.025, 94.8, "FAULT_INJECTED: Elevated S3 PutObject 5xx error rate"
    elif inject_fault == "cui_leak":
        note = "FAULT_INJECTED: CUI//SP-CTI leak detected for DoD_ID=1234567890 SSN=123-45-6789 on bucket dod-agency-cui-telemetry-vault-001"
    elif inject_fault == "drift":
        kms_ok, note = False, "FAULT_INJECTED: S3 default KMS encryption drift detected"
    return {
        "timestamp": now.isoformat(), "unix_ts": int(now.timestamp()),
        "service.name": "govtech-s3-telemetry-pipeline", "service.namespace": "fedramp-high",
        "host.name": socket.gethostname(), "cloud.provider": "aws", "cloud.partition": "aws-us-gov",
        "aws.account.id": "123456789012", "system.memory.utilization": mem_util,
        "s3.request.error_rate": error_rate, "s3.security.kms_enforced": kms_ok,
        "event.severity": "ERROR" if inject_fault else "INFO", "event.body": note,
    }

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--inject-fault", choices=["slo_burn", "cui_leak", "drift"], default=None)
    args = p.parse_args(argv)
    sys.stdout.write(json.dumps(collect_otel_event(args.inject_fault), sort_keys=True) + "\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
