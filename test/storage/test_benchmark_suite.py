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

    def test_run_benchmark(self):
        report = self.suite.run_benchmark()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["phase"], "phase-04-scaffold")
        self.assertEqual(report["target_contract"], "TestVault")
        self.assertIn("metrics", report)
        self.assertGreater(report["metrics"]["precision"], 0.9)

    def test_module_level_run_benchmark(self):
        report = run_benchmark()
        self.assertIsInstance(report, dict)
        self.assertEqual(report["status"], "completed")


if __name__ == "__main__":
    unittest.main()
