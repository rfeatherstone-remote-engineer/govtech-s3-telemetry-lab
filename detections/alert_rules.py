#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

SLO_TARGET, WINDOW_DAYS = 0.999, 30
ERROR_BUDGET_MINUTES = round(WINDOW_DAYS * 24 * 60 * (1.0 - SLO_TARGET), 2)
ERROR_BUDGET_FRACTION = round(1.0 - SLO_TARGET, 6)
FAST_BURN_MULTIPLIER, SLOW_BURN_MULTIPLIER = 14.4, 3.0

@dataclass(frozen=True)
class AlertFinding:
    rule_id: str
    severity: str
    runbook: str
    summary: str
    burn_rate: float
    budget_minutes_remaining: float

def compute_burn_rate(observed_error_rate: float) -> float:
    return round(observed_error_rate / ERROR_BUDGET_FRACTION, 2) if observed_error_rate > 0 else 0.0

def evaluate_event(event: dict[str, Any], redaction_findings: list[str], consumed: float = 0.0) -> list[AlertFinding]:
    alerts: list[AlertFinding] = []
    burn = compute_burn_rate(float(event.get("s3.request.error_rate", 0.0)))
    rem = max(0.0, round(ERROR_BUDGET_MINUTES - consumed, 2))
    if redaction_findings:
        alerts.append(AlertFinding("FEDRAMP-AU9-001", "CRITICAL", "RB-001", f"Scrubbed: {', '.join(redaction_findings)}", burn, rem))
    if burn >= FAST_BURN_MULTIPLIER:
        alerts.append(AlertFinding("FEDRAMP-SLO-002", "CRITICAL", "RB-002", f"Fast SLO burn {burn}x on 99.9% SLO ({ERROR_BUDGET_MINUTES}m)", burn, rem))
    elif burn >= SLOW_BURN_MULTIPLIER:
        alerts.append(AlertFinding("FEDRAMP-SLO-002W", "HIGH", "RB-002", f"Slow SLO burn {burn}x on 99.9% SLO", burn, rem))
    if event.get("s3.security.kms_enforced") is False:
        alerts.append(AlertFinding("FEDRAMP-SC28-003", "CRITICAL", "RB-003", "KMS encryption guardrail drift detected", burn, rem))
    return alerts
