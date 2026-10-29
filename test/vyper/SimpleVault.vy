# @version 0.4.3
# Section E (EduQual L6 Topic 124) -- minimal real Vyper fixture.
# Deliberately contains ONE clear issue (reentrancy-shaped): withdraw() sends
# ETH via raw_call BEFORE zeroing the caller's balance, the same bug class as
# contracts/solidity/VulnerableVault.sol, written in Vyper to exercise a real
# Vyper compile + check step in Stage 2. Never deploy or fund.

balances: public(HashMap[address, uint256])

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "insufficient balance"
    # VULNERABILITY: external call happens before the balance is zeroed,
    # exactly like VulnerableVault.sol's withdraw() -- a reentrant callback
    # can re-enter withdraw() while self.balances[msg.sender] is still unchanged.
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
