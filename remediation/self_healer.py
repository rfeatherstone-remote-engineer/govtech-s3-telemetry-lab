#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, time
from pathlib import Path
from typing import Any
from compliance.cui_sanitizer import sanitize_record
from compliance.postmortem_gen import generate_blameless_rca
from core.system_monitor import collect_otel_event
from detections.alert_rules import evaluate_event

COOLDOWN_SECONDS, MAX_ARTIFACTS = 300, 50

def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)

def atomic_write_json(target: Path, payload: dict[str, Any]) -> None:
    ensure_private_dir(target.parent)
    tmp = target.parent / f".{target.name}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)

def prune_bounded(directory: Path, limit: int = MAX_ARTIFACTS) -> None:
    if not directory.exists():
        return
    files = sorted((p for p in directory.iterdir() if p.is_file()), key=lambda p: (p.stat().st_mtime_ns, p.name))
    while len(files) > limit:
        next(iter(files)).unlink(missing_ok=True)
        files.pop(0)

def check_cb(state_file: Path, rule_id: str, now: float) -> bool:
    if not state_file.exists():
        return True
    try:
        with open(state_file, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        return (now - float(state.get("last_exec", {}).get(rule_id, 0.0))) >= COOLDOWN_SECONDS
    except (OSError, ValueError, json.JSONDecodeError):
        return True

def record_cb(state_file: Path, rule_id: str, now: float) -> None:
    state: dict[str, Any] = {"last_exec": {}}
    if state_file.exists():
        try:
            with open(state_file, "r", encoding="utf-8") as handle:
                state = json.load(handle)
        except (OSError, json.JSONDecodeError):
            pass
    state.setdefault("last_exec", {})[rule_id] = now
    atomic_write_json(state_file, state)

def process_event(raw_event: dict[str, Any], state_dir: Path, execute: bool = False, now_epoch: float | None = None) -> dict[str, Any]:
    now = now_epoch if now_epoch is not None else time.time()
    ensure_private_dir(state_dir)
    q_dir, t_dir = state_dir / "quarantine", state_dir / "triage"
    ensure_private_dir(q_dir)
    ensure_private_dir(t_dir)
    sanitized, redactions = sanitize_record(raw_event)
    alerts = evaluate_event(sanitized, redactions)
    cb_file = state_dir / "circuit_breaker.json"
    actions: list[dict[str, Any]] = []
    for alert in alerts:
        if not check_cb(cb_file, alert.rule_id, now):
            actions.append({"rule_id": alert.rule_id, "status": "SKIPPED_CIRCUIT_BREAKER_COOLDOWN"})
            continue
        inc_id = f"INC-{int(now * 1000)}-{alert.rule_id}"
        art_path = q_dir / f"{inc_id}.json"
        if execute:
            atomic_write_json(art_path, {"incident_id": inc_id, "rule_id": alert.rule_id, "summary": alert.summary, "sanitized_event": sanitized})
            prune_bounded(q_dir)
            tpl = Path(__file__).resolve().parent.parent / "templates" / "blameless_rca.md"
            if tpl.exists():
                generate_blameless_rca(str(tpl), str(t_dir / f"{inc_id}-RCA.md"), inc_id, [alert], sanitized)
                prune_bounded(t_dir)
            record_cb(cb_file, alert.rule_id, now)
        actions.append({"rule_id": alert.rule_id, "runbook": alert.runbook, "status": "REMEDIATED" if execute else "WOULD_REMEDIATE", "artifact": str(art_path)})
    return {"mode": "EXECUTE" if execute else "DRY_RUN", "redactions": redactions, "actions": actions, "sanitized_event": sanitized}

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--execute", action="store_true", default=False)
    p.add_argument("--inject-fault", choices=["slo_burn", "cui_leak", "drift"], default=None)
    p.add_argument("--state-dir", default=".state")
    args = p.parse_args(argv)
    print(json.dumps(process_event(collect_otel_event(args.inject_fault), Path(args.state_dir), args.execute), indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
