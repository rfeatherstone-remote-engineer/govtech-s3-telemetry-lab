import unittest
from compliance.cui_sanitizer import sanitize_record, sanitize_text

class TestCUISanitizer(unittest.TestCase):
    def test_redacts_cui_edipi_and_ssn(self) -> None:
        cleaned, findings = sanitize_text("CUI//SP-CTI DoD_ID=1234567890 SSN=123-45-6789")
        self.assertEqual(findings, ["CUI_MARKING", "DOD_EDIPI", "SSN"])
        self.assertNotIn("1234567890", cleaned)
        self.assertNotIn("123-45-6789", cleaned)

    def test_redacts_nested_lists_and_preserves_account_ids(self) -> None:
        cleaned, findings = sanitize_record({
            "unix_ts": 1795212000,
            "aws.account.id": "123456789012",
            "nested": ["ok", {"secret": "SSN=123-45-6789"}],
        })
        self.assertEqual(findings, ["SSN"])
        self.assertEqual(cleaned["aws.account.id"], "123456789012")
        _, nested_dict = cleaned["nested"]
        self.assertEqual(nested_dict["secret"], "SSN=[REDACTED:SSN]")
