"""Focused verifier regressions; run with python -m unittest discover -s tests."""

from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import verify
from runtime import runner as runner_service


class DeclaredStateTests(unittest.TestCase):
    def setUp(self):
        self.check = verify.Verification.__new__(verify.Verification)
        self.key_id = "cfd01ce9-0000-4000-8000-000000000001"
        self.key_arn = f"arn:aws:kms:us-east-1:{verify.ACCOUNT}:key/{self.key_id}"
        self.manifest = {
            "key": self.key_arn, "topic": "arn:aws:sns:us-east-1:111111111111:orders",
            "functions": {name: name for name in verify.FUNCTIONS},
            "tables": {name: f"{name}-deliveries" for name in verify.CONSUMERS},
            "queues": {name: f"http://aws:4566/{verify.ACCOUNT}/{name}" for name in verify.CONSUMERS},
            "dlqs": {name: f"http://aws:4566/{verify.ACCOUNT}/{name}-dlq" for name in verify.CONSUMERS},
            "callers": {name: {"access_key_id": f"AKIA-{name}"} for name in verify.CALLERS},
        }
        clients = {name: Mock() for name in ("kms", "iam", "lambda", "dynamodb")}
        clients["kms"].describe_key.return_value = {
            "KeyMetadata": {"KeyId": self.key_id, "Arn": self.key_arn}}
        clients["lambda"].get_function_configuration.side_effect = lambda FunctionName: {
            "FunctionArn": f"arn:aws:lambda:us-east-1:{verify.ACCOUNT}:function:{FunctionName}"}
        clients["dynamodb"].describe_table.side_effect = lambda TableName: {
            "Table": {"TableArn": f"arn:aws:dynamodb:us-east-1:{verify.ACCOUNT}:table/{TableName}"}}
        clients["iam"].get_role.side_effect = lambda RoleName: {"Role": {"Arn": f"role/{RoleName}"}}
        clients["iam"].get_user.side_effect = lambda UserName: {"User": {"Arn": f"user/{UserName}"}}
        self.check.client = clients.__getitem__
        self.check.mapping = lambda m, c: {"UUID": f"mapping-{c}"}
        self.check.subscription = lambda m, c: {"SubscriptionArn": f"subscription-{c}"}
        self.check.role_name = lambda m, name: f"{name}-role"
        self.check.caller_users = lambda m: {name: f"{name}-user" for name in verify.CALLERS}
        self.ids = {self.manifest["topic"]}
        for field in ("functions", "tables", "queues", "dlqs"):
            self.ids.update(self.manifest[field].values())
        self.ids.update(f"AKIA-{name}" for name in verify.CALLERS)
        self.ids.update(f"{name}-user" for name in verify.CALLERS)
        self.ids.update(f"{name}-role" for name in verify.FUNCTIONS)
        self.ids.update(f"mapping-{name}" for name in verify.CONSUMERS)
        self.ids.update(f"subscription-{name}" for name in verify.CONSUMERS)

    def test_kms_bare_id_and_arn_are_equivalent(self):
        for identifier in (self.key_id, self.key_arn):
            with self.subTest(identifier=identifier):
                self.check.assert_declared(self.manifest, self.ids | {identifier})

    def test_missing_or_different_kms_key_is_rejected(self):
        for identifier in ("unrelated-key", self.key_arn.replace(verify.ACCOUNT, "222222222222")):
            with self.subTest(identifier=identifier):
                with self.assertRaisesRegex(AssertionError, "live resources missing"):
                    self.check.assert_declared(self.manifest, self.ids | {identifier})

    def test_queue_host_tolerance_is_preserved_with_kms_arn(self):
        ids = {value.replace("http://aws:4566", "https://sqs.us-east-1.amazonaws.com") for value in self.ids}
        self.check.assert_declared(self.manifest, ids | {self.key_arn})


class RecoveryIsolationTests(unittest.TestCase):
    def test_secret_exposure_remains_scored_after_reset_removes_the_file(self):
        check = verify.Verification.__new__(verify.Verification)
        check.secrets = {"caller-secret-access-key"}
        check.exposed_secret_files = set()
        scans = [
            {"files": [{"path": "old/terraform.tfstate", "mode": 0o644}]},
            {"files": [{"path": "manifest.json", "mode": 0o600}]},
        ]
        with patch.object(verify, "runner", side_effect=scans):
            check.record_secret_exposures()
            with self.assertRaisesRegex(AssertionError, "old/terraform.tfstate"):
                check.private_secrets()

    def test_recovery_precedes_failed_drift_checks_without_changing_scoring(self):
        check = verify.Verification.__new__(verify.Verification)
        check.prefix = "test"
        check.manifest = {}
        check.results = []
        calls = []
        methods = (
            "create_sentinels", "inventory", "deploy", "contract_and_state", "topology",
            "routing_and_queues", "selective_delivery", "idempotency", "caller_isolation",
            "execution_roles", "encryption", "poison_and_replay", "independent_deployments",
            "state_loss_adoption", "unreadable_state_recovery", "lossless_repair",
            "addition_convergence", "private_secrets", "cleanup", "redeploy_after_destroy",
            "tidy_injections", "write_report",
        )
        def record(name):
            def call(*args):
                calls.append(name)
                if name in ("lossless_repair", "addition_convergence"):
                    raise AssertionError("unrepaired TTL and redrive drift")
                if name in ("state_loss_adoption", "unreadable_state_recovery"):
                    self.assertNotIn("lossless_repair", calls)
            return call
        for name in methods:
            setattr(check, name, record(name))
        with redirect_stdout(io.StringIO()):
            check.run()
        self.assertEqual(len(check.results), 17)
        self.assertEqual(sum(row["points"] for row in check.results), 100)
        for name in ("state-loss adoption", "unreadable state recovery"):
            result = next(row for row in check.results if row["name"] == name)
            self.assertEqual(result["earned"], result["points"])
        self.assertIn("cleanup", calls)

    def test_dirty_baseline_is_detected_before_local_state_is_damaged(self):
        check = verify.Verification.__new__(verify.Verification)
        check.manifest = {}
        check.topology = Mock(side_effect=AssertionError("TTL is on"))
        damage = Mock()
        with self.assertRaisesRegex(AssertionError, "TTL is on"):
            check.damage_and_recover(damage, "analytics", 300)
        damage.assert_not_called()

    def test_runner_reset_clears_local_files_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, work, scratch = (root / name for name in ("source", "work", "scratch"))
            for path in (source, work, scratch):
                path.mkdir()
            (source / "deploy.sh").write_text("#!/bin/bash\n")
            for name in ("terraform.tfstate", "manifest.json"):
                (work / name).write_text("local secret")
            (scratch / "backup").write_text("local backup")
            with patch.multiple(runner_service, SOURCE=source, WORK=work,
                                SCRATCH=(scratch,), PREPARED=True), \
                    patch.object(runner_service, "stop_leftover_processes"), \
                    patch.dict(runner_service.os.environ, {"TF_PLUGIN_CACHE_DIR": str(scratch / "cache")}):
                runner_service.reset()
                self.assertFalse(runner_service.PREPARED)
                self.assertEqual(list(work.iterdir()), [])
                self.assertFalse((scratch / "backup").exists())
                runner_service.prepare()
                self.assertEqual([path.name for path in work.iterdir()], ["deploy.sh"])
                self.assertTrue((source / "deploy.sh").exists())


if __name__ == "__main__":
    unittest.main()
