import os
import shutil
import tempfile
import unittest
from pathlib import Path

from src.storage.broker_store import BrokerStore
from src.storage.benchmark_suite import BenchmarkSuite, run_benchmark


class TestBenchmarkSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_benchmark_")
        self.db_path = os.path.join(self.test_dir, "bench_test.db")
        self.store = BrokerStore(db_path=self.db_path)

        # Create mock contracts dir
        self.contracts_dir = os.path.join(self.test_dir, "contracts")
        os.makedirs(self.contracts_dir, exist_ok=True)
        with open(os.path.join(self.contracts_dir, "TestVault.sol"), "w") as f:
            f.write("// SPDX-License-Identifier: MIT\ncontract TestVault {}")

        self.suite = BenchmarkSuite(contracts_dir=self.contracts_dir, broker_store=self.store)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_discover_sample_contracts(self):
        contracts = self.suite.discover_sample_contracts()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["name"], "TestVault")
        self.assertGreater(contracts[0]["size_bytes"], 0)

    def test_benchmark_ingestion_throughput(self):
        res = self.suite.benchmark_ingestion_throughput(count=10)
        self.assertEqual(res["finding_count"], 10)
        self.assertGreater(res["throughput_ops_per_sec"], 0)
        self.assertEqual(len(self.store.list_findings()), 10)

    def test_historical_fixtures_loading(self):
        fixtures = self.suite.load_historical_fixtures()
        self.assertGreaterEqual(len(fixtures), 50, "Must load 50+ historical exploit fixtures")

    def test_empirical_evaluation_targets_met(self):
        eval_res = self.suite.evaluate_historical_dataset()
        self.assertGreaterEqual(eval_res["total_fixtures"], 50)
        # P15A-004 targets: P > 92%, R > 88%, PoC > 80%, MTTR < 45s
        self.assertGreater(eval_res["precision"], 0.92, "Precision must exceed 92%")
        self.assertGreater(eval_res["recall"], 0.88, "Recall must exceed 88%")
        self.assertGreater(eval_res["poc_pass_rate"], 0.80, "Autonomous PoC pass rate must exceed 80%")
        self.assertLess(eval_res["mttr_seconds"], 45.0, "MTTR must be under 45 seconds")
        self.assertIn("hardware_specs", eval_res)
        self.assertIn("model_versions", eval_res)

    def test_forensic_metrics_recorded(self):
        # P15A-005 targets
        f_res = self.suite.evaluate_forensic_metrics()
        self.assertEqual(f_res["integrity_pass_rate"], 1.0, "Integrity verification pass rate must be 100%")
        self.assertGreater(f_res["ioc_extraction_accuracy"], 0.90)
        self.assertLess(f_res["time_to_timeline_ms"], 100.0)

    def test_run_benchmark_full_pipeline(self):
        report = self.suite.run_benchmark()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["phase"], "phase-15a-empirical")
        self.assertEqual(report["target_contract"], "TestVault")
        self.assertIn("metrics", report)
        self.assertGreater(report["metrics"]["precision"], 0.92)
        self.assertIn("historical_evaluation", report)
        self.assertIn("forensic_metrics", report)

    def test_module_level_run_benchmark(self):
        report = run_benchmark()
        self.assertIsInstance(report, dict)
        self.assertEqual(report["status"], "completed")


if __name__ == "__main__":
    unittest.main()
