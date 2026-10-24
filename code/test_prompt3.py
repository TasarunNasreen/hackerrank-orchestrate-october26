"""Focused offline tests for the completed Prompt 3 pipeline."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit import CaseAudit, is_deletion_request
from planner import Planner
from policy import Policy
from validate import validate_rows
from audit import ResourceObservation


UTC = timezone.utc
AT = datetime(2026, 9, 1, tzinfo=UTC)


class Prompt3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = Policy([
            {"data_category": "USER_PROFILE", "required_action": "DELETE", "condition": "Always"},
            {"data_category": "SECURITY_AUDIT_LOG", "required_action": "RETAIN", "condition": "retention"},
            {"data_category": "BACKUP_ARCHIVE", "required_action": "RETAIN", "condition": "blockable"},
        ])

    def test_non_deletion_language(self) -> None:
        self.assertFalse(is_deletion_request("Please reset the login. Do not close the account."))
        self.assertTrue(is_deletion_request("Please delete my account."))

    def test_incomplete_findings_and_remediation(self) -> None:
        account = ResourceObservation("account_service", "account_1", "USER_PROFILE", "PRESENT", {"evidence_01"})
        backup = ResourceObservation("backup_service", "backup_1", "BACKUP_ARCHIVE", "ACTIVE", {"evidence_02"})
        audit = CaseAudit(True, ["user_1"], [account], AT, [backup])
        status, steps = Planner(self.policy).plan(audit)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps[0]["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(steps[1]["operation"], "REPORT_RESTORE_RISK")
        self.assertEqual(steps[2]["operation"], "BLOCK_RESTORE")
        self.assertEqual(steps[2]["evidence_id"], "")

    def test_complete_retained_record(self) -> None:
        retained = ResourceObservation("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", "PRESENT", {"evidence_03"})
        status, steps = Planner(self.policy).plan(CaseAudit(True, ["user_1"], [retained], AT))
        self.assertEqual(status, "COMPLETE")
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(steps[0]["evidence_id"], "evidence_03")

    def test_output_contract(self) -> None:
        rows = [{"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}]
        validate_rows(rows, ["case_1"], {"evidence_01"})


if __name__ == "__main__":
    unittest.main()
