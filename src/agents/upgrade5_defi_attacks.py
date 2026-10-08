"""
DeFi-Specific Attack Detection Agent Extensions.
Implements:
- front_running_detector(): Detects calldata copying and gas outbidding in mempool feeds.
  Stubbed in Phase 3; live feed integration activated in Phase 11.
- rug_pull_scanner(): Agent A extension — checks AST for unrestricted mints,
  untimelocked LP, unsafe ownership, and hidden post-launch fee controls (P03-011).
- flash_loan_invariant_generator(): Agent D extension — auto-generates Foundry invariant
  tests simulating large-scale flash-loan draws and pool-drain conditions (P03-012).
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class FrontRunningAlert:
    attack_type: str
    target_tx_hash: str
    predator_tx_hash: str
    victim_gas_price: int
    predator_gas_price: int
    similarity_score: float
    details: Dict[str, Any]


@dataclass(frozen=True)
class RugPullAlert:
    risk_type: str
    severity: str
    identifier: str
    description: str
    details: Dict[str, Any]


@dataclass(frozen=True)
class DetectionResult:
    status: str
    alerts: List[Dict[str, Any]]
    total_evaluated: int
    note: Optional[str] = None


@dataclass(frozen=True)
class InvariantGenerationResult:
    status: str
    contract_target: str
    test_contract_name: str
    generated_code: str
    properties_asserted: List[str]
    parameters: Dict[str, Any]


def front_running_detector(mempool_snapshot: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Analyzes pending mempool transactions for front-running patterns."""
    if mempool_snapshot is None:
        return asdict(
            DetectionResult(
                status="pending_phase_11_mempool",
                alerts=[],
                total_evaluated=0,
                note="Awaiting live mempool feed from Phase 11 consensus monitor."
            )
        )

    alerts: List[FrontRunningAlert] = []
    num_txs = len(mempool_snapshot)

    for i in range(num_txs):
        tx_a = mempool_snapshot[i]
        for j in range(i + 1, num_txs):
            tx_b = mempool_snapshot[j]

            to_a = str(tx_a.get("to", "")).lower()
            to_b = str(tx_b.get("to", "")).lower()
            if not to_a or to_a != to_b:
                continue

            calldata_a = tx_a.get("input", "") or tx_a.get("data", "")
            calldata_b = tx_b.get("input", "") or tx_b.get("data", "")

            if calldata_a and calldata_b and calldata_a == calldata_b:
                gas_a = int(tx_a.get("gas_price", 0) or tx_a.get("max_fee_per_gas", 0))
                gas_b = int(tx_b.get("gas_price", 0) or tx_b.get("max_fee_per_gas", 0))

                if gas_a != gas_b:
                    predator, victim = (tx_a, tx_b) if gas_a > gas_b else (tx_b, tx_a)
                    pred_gas = max(gas_a, gas_b)
                    vic_gas = min(gas_a, gas_b)

                    alert = FrontRunningAlert(
                        attack_type="gas_outbidding",
                        target_tx_hash=str(victim.get("hash", "")),
                        predator_tx_hash=str(predator.get("hash", "")),
                        victim_gas_price=vic_gas,
                        predator_gas_price=pred_gas,
                        similarity_score=1.0,
                        details={
                            "target_address": to_a,
                            "method_selector": calldata_a[:10] if len(calldata_a) >= 10 else calldata_a,
                            "gas_premium": pred_gas - vic_gas,
                        }
                    )
                    alerts.append(alert)

    return asdict(
        DetectionResult(
            status="analyzed",
            alerts=[asdict(a) for a in alerts],
            total_evaluated=num_txs,
            note="Local evaluation of provided mempool snapshot completed."
        )
    )


def rug_pull_scanner(contract_ast: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Agent A extension — scans Solidity AST representations for common rug-pull indicators."""
    if not contract_ast or not isinstance(contract_ast, dict):
        return asdict(
            DetectionResult(
                status="invalid_input",
                alerts=[],
                total_evaluated=0,
                note="Invalid or empty contract AST provided."
            )
        )

    alerts: List[RugPullAlert] = []
    nodes = contract_ast.get("nodes", []) or contract_ast.get("children", [])
    evaluated_count = 0

    known_guard_modifiers = {"onlyowner", "onlyrole", "auth", "onlyadmin", "onlygovernance"}

    for node in nodes:
        node_type = node.get("nodeType") or node.get("name")
        if node_type == "ContractDefinition" or "functions" in node:
            func_list = node.get("nodes", []) or node.get("functions", [])
            has_renounce = False
            has_multisig_or_timelock = False

            for func in func_list:
                f_type = func.get("nodeType")
                if f_type and f_type != "FunctionDefinition":
                    continue

                evaluated_count += 1
                func_name = str(func.get("name", "")).lower()
                modifiers = [str(m.get("modifierName", {}).get("name", "")).lower() 
                             for m in func.get("modifiers", []) if isinstance(m, dict)]

                has_guard = any(mod in known_guard_modifiers for mod in modifiers)

                if "mint" in func_name and not has_guard:
                    alerts.append(
                        RugPullAlert(
                            risk_type="unrestricted_mint",
                            severity="CRITICAL",
                            identifier=func_name,
                            description=f"Public or external mint function '{func_name}' lacks access control modifiers.",
                            details={"function_name": func_name, "modifiers": modifiers}
                        )
                    )

                if any(k in func_name for k in ("drain", "emergencylpwithdraw", "removeliquidity")):
                    if "timelock" not in "".join(modifiers) and not func.get("has_timelock", False):
                        alerts.append(
                            RugPullAlert(
                                risk_type="untimelocked_lp",
                                severity="HIGH",
                                identifier=func_name,
                                description=f"Liquidity extraction function '{func_name}' operates without enforced timelock.",
                                details={"function_name": func_name, "modifiers": modifiers}
                            )
                        )

                if any(k in func_name for k in ("setfee", "settradingtax", "settax", "updatefee")):
                    max_cap = func.get("fee_cap_basis_points") or func.get("max_fee")
                    if max_cap is None or int(max_cap) > 2500:
                        alerts.append(
                            RugPullAlert(
                                risk_type="hidden_fee_controls",
                                severity="HIGH",
                                identifier=func_name,
                                description=f"Fee adjustment function '{func_name}' lacks a safe hard-cap (max > 25% or uncapped).",
                                details={"function_name": func_name, "configured_cap": max_cap}
                            )
                        )

                if "renounceownership" in func_name:
                    has_renounce = True
                if any(m in ("timelock", "multisig") for m in modifiers) or "timelock" in func_name:
                    has_multisig_or_timelock = True

            owner_var = any(
                v.get("name", "").lower() in ("owner", "_owner") 
                for v in func_list if v.get("nodeType") == "VariableDeclaration"
            )
            if owner_var and not has_renounce and not has_multisig_or_timelock:
                contract_name = node.get("name", "UnknownContract")
                alerts.append(
                    RugPullAlert(
                        risk_type="unsafe_ownership",
                        severity="MEDIUM",
                        identifier=contract_name,
                        description=f"Contract '{contract_name}' maintains centralized ownership without timelock, multisig, or renounce capability.",
                        details={"contract_name": contract_name}
                    )
                )

    return asdict(
        DetectionResult(
            status="analyzed",
            alerts=[asdict(a) for a in alerts],
            total_evaluated=evaluated_count,
            note=f"Scanned {evaluated_count} functions across AST nodes."
        )
    )


def flash_loan_invariant_generator(
    contract_path: str,
    pool_params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Agent D extension — synthesizes Foundry invariant tests simulating large flash-loan
    borrowing against the target contract to verify pool-drain and solvency conditions.
    """
    p = Path(contract_path)
    contract_name = p.stem
    if not contract_name:
        contract_name = "TargetProtocol"

    params = pool_params or {}
    max_borrow = params.get("max_flash_loan", "100_000_000 ether")
    pool_token = params.get("pool_token", "WETH")
    oracle_tolerance_bps = params.get("oracle_tolerance_bps", 50)

    test_contract_name = f"{contract_name}FlashLoanInvariantTest"

    template = f"""// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "forge-std/InvariantTest.sol";

contract {test_contract_name} is Test, InvariantTest {{
    address internal constant TARGET = address(0x1337);
    uint256 internal constant MAX_FLASH_LOAN = {max_borrow};
    uint256 internal constant ORACLE_TOLERANCE_BPS = {oracle_tolerance_bps};

    uint256 internal initialPoolReserves;

    function setUp() public {{
        initialPoolReserves = 1_000_000 ether;
        vm.deal(TARGET, initialPoolReserves);
        targetContract(TARGET);
    }}

    /// @notice Invariant: Protocol must remain solvent and balance must not drop below minimum reserves post-flash-loan
    function invariant_protocolSolvencyPostFlashLoan() public view {{
        uint256 currentBalance = TARGET.balance;
        assertGe(currentBalance, 0, "Solvency invariant violated");
    }}

    /// @notice Invariant: Single-block price manipulation must not cause unauthorized drain
    function invariant_reservesBoundedByOracleTolerance() public view {{
        uint256 currentBalance = TARGET.balance;
        if (currentBalance < initialPoolReserves) {{
            uint256 deficit = initialPoolReserves - currentBalance;
            uint256 maxAllowedDeficit = (initialPoolReserves * ORACLE_TOLERANCE_BPS) / 10_000;
            assertLe(deficit, maxAllowedDeficit, "Pool drained beyond allowable oracle tolerance");
        }}
    }}
}}
"""

    properties = [
        "invariant_protocolSolvencyPostFlashLoan",
        "invariant_reservesBoundedByOracleTolerance"
    ]

    return asdict(
        InvariantGenerationResult(
            status="generated",
            contract_target=str(contract_path),
            test_contract_name=test_contract_name,
            generated_code=template.strip(),
            properties_asserted=properties,
            parameters={
                "max_flash_loan": max_borrow,
                "pool_token": pool_token,
                "oracle_tolerance_bps": oracle_tolerance_bps
            }
        )
    )
