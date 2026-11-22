import stat, tempfile, unittest
from pathlib import Path
from core.system_monitor import collect_otel_event
from remediation.self_healer import COOLDOWN_SECONDS, process_event

class TestSelfHealer(unittest.TestCase):
    def test_dry_run_and_circuit_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sdir = Path(tmp) / "state"
            ev = collect_otel_event("slo_burn")
            dry = process_event(ev, sdir, execute=False)
            self.assertEqual(next(iter(dry["actions"]))["status"], "WOULD_REMEDIATE")
            first = process_event(ev, sdir, execute=True, now_epoch=1000.0)
            self.assertEqual(next(iter(first["actions"]))["status"], "REMEDIATED")
            self.assertEqual(stat.S_IMODE(sdir.stat().st_mode), 0o700)
            self.assertEqual(len(list((sdir / "triage").glob("*-RCA.md"))), 1)
            second = process_event(ev, sdir, execute=True, now_epoch=1100.0)
            self.assertEqual(next(iter(second["actions"]))["status"], "SKIPPED_CIRCUIT_BREAKER_COOLDOWN")
            third = process_event(ev, sdir, execute=True, now_epoch=1000.0 + COOLDOWN_SECONDS + 1.0)
            self.assertEqual(next(iter(third["actions"]))["status"], "REMEDIATED")
