"""
Task P12-007: Unit tests for Mandatory Anvil Pre-Sign Simulator.
Validates simulation receipts, revert detection, unauthorized recipient blocking,
balance drain ceilings, and gas boundary enforcement.
"""

import unittest

from src.wallet.presign_simulator import (
    BalanceDrainageBreachError,
    GasLimitExceededError,
    PresignSimulator,
    RelayerTxIntent,
    SimulationExecutionRevertedError,
    SimulationReceipt,
    UnauthorizedRecipientError,
)


class TestPresignSimulator(unittest.TestCase):
    def setUp(self):
        self.approved_vault = "0x1111111111111111111111111111111111111111"
        self.simulator = PresignSimulator(
            allowed_recipients={self.approved_vault},
            max_drain_wei=10**18,  # 1 ETH cap
            max_gas=200_000,
        )
        self.intent = RelayerTxIntent(
            sender="0xRelayerOrigin00000000000000000000000000",
            target=self.approved_vault,
            value_wei=5 * 10**17,  # 0.5 ETH
            data=b"\xa9\x05\x9c\xbb",
            nonce=1,
            gas_limit=100_000,
        )

    def test_successful_simulation_emits_valid_receipt(self):
        receipt = self.simulator.simulate_and_validate(
            self.intent,
            simulated_gas_used=50_000,
            simulated_drain_wei=5 * 10**17,
        )

        self.assertIsInstance(receipt, SimulationReceipt)
        self.assertTrue(receipt.success)
        self.assertEqual(receipt.gas_used, 50_000)
        self.assertEqual(receipt.sender_balance_delta_wei, 5 * 10**17)
        self.assertTrue(self.simulator.verify_receipt(self.intent, receipt))

    def test_revert_raises_simulation_reverted_error(self):
        with self.assertRaises(SimulationExecutionRevertedError) as ctx:
            self.simulator.simulate_and_validate(self.intent, mock_revert=True)
        self.assertIn("reverted on contract execution", str(ctx.exception))

    def test_unauthorized_recipient_fails_closed(self):
        unauthorized_intent = RelayerTxIntent(
            sender=self.intent.sender,
            target="0xRogueAttackerRecipient99999999999999999",
            value_wei=self.intent.value_wei,
            data=self.intent.data,
            nonce=self.intent.nonce,
            gas_limit=self.intent.gas_limit,
        )
        with self.assertRaises(UnauthorizedRecipientError) as ctx:
            self.simulator.simulate_and_validate(unauthorized_intent)
        self.assertIn("not in approved allowlist", str(ctx.exception))

    def test_balance_drain_breach_fails_closed(self):
        with self.assertRaises(BalanceDrainageBreachError) as ctx:
            self.simulator.simulate_and_validate(
                self.intent,
                simulated_drain_wei=2 * 10**18,  # 2 ETH > 1 ETH cap
            )
        self.assertIn("exceeds cap", str(ctx.exception))

    def test_gas_limit_exceeded_fails_closed(self):
        with self.assertRaises(GasLimitExceededError) as ctx:
            self.simulator.simulate_and_validate(
                self.intent,
                simulated_gas_used=250_000,  # Exceeds max_gas (200k)
            )
        self.assertIn("exceeds limit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
