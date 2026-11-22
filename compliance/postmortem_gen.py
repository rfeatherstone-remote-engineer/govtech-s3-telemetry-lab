#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, os
from typing import Any
from detections.alert_rules import AlertFinding

def generate_blameless_rca(template_path: str, output_path: str, incident_id: str, alerts: list[AlertFinding], sanitized_event: dict[str, Any]) -> str:
    with open(template_path, "r", encoding="utf-8") as handle:
        tpl = handle.read()
    lines = "\n".join(f"- **[{a.severity}] {a.rule_id}** ({a.runbook}): {a.summary}" for a in alerts)
    rendered = (tpl.replace("{{INCIDENT_ID}}", incident_id)
                .replace("{{TIMESTAMP_UTC}}", dt.datetime.now(dt.timezone.utc).isoformat())
                .replace("{{SERVICE_NAME}}", str(sanitized_event.get("service.name", "unknown")))
                .replace("{{PARTITION}}", str(sanitized_event.get("cloud.partition", "aws-us-gov")))
                .replace("{{ALERT_SUMMARY}}", lines or "- None")
                .replace("{{SANITIZED_BODY}}", str(sanitized_event.get("event.body", ""))))
    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    os.chmod(out_dir, 0o700)
    tmp = f"{output_path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    os.chmod(tmp, 0o600)
    os.replace(tmp, output_path)
    return output_path
