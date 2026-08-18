# Mind Map

## To ensure user safety, this first version of the bridge has a few security mechanisms in place

1. The owner of the bridge can pause operations in emergency situations. `🕵️‍♂️by any chance can we be the owner?`
2. Because deposits are permissionless, there's an strict limit of tokens that can be deposited. `🕵️‍♂️is there a way for us to deposit more than the limit?`
3. Withdrawals must be approved by a bridge operator. `🕵️‍♂️How can we obtain administravie priviliges like this?`

### Actors/Roles

**Bridge Owner**: A `centralized` bridge owner who can: `🕵️‍♂️There are problems involved with centralized administrative privileges and can be exploited in various ways👨‍🏫`
pause/unpause the bridge in the event of an emergency
set Signers (see below)
**Signer**: Users who can "send" a token from L2 -> L1.
**Vault**: The contract owned by the bridge that holds the tokens.
**Users**: Users mainly only call depositTokensToL2, when they want to send tokens from L1 -> L2.

This is the **Boss Bridge** codebase — a genuinely rich one for an audit, since it touches signature verification, cross-chain trust assumptions, and a vault sitting behind an unlimited approval. Let me go through it contract by contract and pull out everything that stands out.

## L1BossBridge.sol — the big one

### 🔴 Critical: `depositTokensToL2` lets anyone move tokens *out of any address that has approved the bridge*

```solidity
function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
    ...
    token.safeTransferFrom(from, address(vault), amount);
    emit Deposit(from, l2Recipient, amount);
}
```

`from` is a **caller-supplied parameter**, not `msg.sender`. Anyone can call this function specifying *any* address as `from`, as long as that address has ever approved the bridge to spend its tokens — which is exactly the normal, expected user flow for a bridge (approve once, deposit many times).

**The exploit:** Attacker watches for any address with an active approval to the bridge (extremely common — most users leave bridge approvals standing). Attacker calls `depositTokensToL2(victim, attacker's_own_L2_address, victimsFullBalance)`. The victim's tokens move into the vault exactly as if they'd deposited themselves — but the L2 mint goes to the **attacker's** address, since `l2Recipient` is also freely chosen by the caller. The off-chain service watching for `Deposit` events has no way to know this wasn't the victim's own legitimate deposit. This is a complete theft of any approved user's tokens, and it costs the attacker nothing but gas.

### 🔴 Critical: `sendToL1` is an unrestricted arbitrary-call function, gated only by a signature with no scope

```solidity
function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
    address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);
    if (!signers[signer]) revert L1BossBridge__Unauthorized();

    (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));
    (bool success,) = target.call{ value: value }(data);
    if (!success) revert L1BossBridge__CallFailed();
}
```

Walking through this line by line, as you asked: it recovers a signer's address from an arbitrary `message`, checks that address is an authorized signer, then decodes `target`/`value`/`data` **straight out of that same message** and executes `target.call(data)` — **as the bridge contract itself.**

This means `sendToL1` isn't really "process a withdrawal" — it's "execute *any* function, on *any* contract, with the bridge's own identity and permissions, as long as one signer signed the bytes." `withdrawTokensToL1` is just one specific, narrow *use* of this — but the function is `public`, so nothing stops it from being called directly with a completely different `target`/`data`.

**Why this is catastrophic combined with the constructor:**

```solidity
constructor(IERC20 _token) Ownable(msg.sender) {
    token = _token;
    vault = new L1Vault(token);
    vault.approveTo(address(this), type(uint256).max);
}
```

The vault gives the bridge **unlimited standing approval** at deployment. So any signer — or anyone who obtains a single leaked signer private key — can sign a message with `target = address(token)`, `data = transferFrom(vault, attacker, entireVaultBalance)`, and drain the *entire vault in one call*, completely bypassing the intended `withdrawTokensToL1` flow, its amount semantics, everything. The "signer" trust model was presumably meant to authorize *withdrawals*, but the actual code grants signers the power to do **anything** the bridge contract is capable of.

### 🔴 High: No replay protection on signed messages — a valid withdrawal signature can be reused indefinitely

Nowhere in `sendToL1` (or `withdrawTokensToL1`) is there a nonce, a "used signatures" mapping, or an expiry timestamp. The signature only proves *a signer once authorized this exact message* — it does nothing to prevent that same signed message from being submitted **again, and again, and again.**

**The exploit:** A legitimate signer signs a valid withdrawal for `1000 tokens` to a user. That transaction executes once as intended. But since nothing marks that `(v, r, s, message)` tuple as "spent," anyone who observes it on-chain (it's public calldata) can resubmit the exact same call to `sendToL1`, and it will succeed again — and again — until the vault is empty. This is structurally the same root cause as the real Poly Network bridge hack: a valid authorization, replayed without a nonce, drains funds far beyond what was actually authorized.

### 🟠 Medium: `DEPOSIT_LIMIT` can be permanently griefed via direct token transfers

```solidity
if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
    revert L1BossBridge__DepositLimitReached();
}
```

This check reads the **raw token balance** of the vault, not a tracked "total deposited via this function" counter. Since `token` is a standard ERC20, *anyone* can call `token.transfer(address(vault), hugeAmount)` directly — completely bypassing `depositTokensToL2` — which still increases `balanceOf(vault)`. An attacker can permanently push the vault's balance at or above `DEPOSIT_LIMIT`, causing every future legitimate `depositTokensToL2` call to revert, indefinitely denying service to the entire bridge for the cost of the tokens transferred (which the attacker doesn't even lose — they're just sitting in the vault).

### 🟡 Low/Informational: Missing reentrancy guard on `depositTokensToL2`

`sendToL1` is protected with `nonReentrant`, but `depositTokensToL2` isn't, despite calling `safeTransferFrom` on an externally-supplied token contract. If `token` were ever an ERC777-style or hook-bearing token (not the case for the provided `L1Token.sol`, but worth flagging since `token` is set once in the constructor and can't be changed — still worth defense-in-depth), a reentrant callback during the transfer could re-enter `depositTokensToL2` before the balance-based limit check reflects the first transfer, potentially allowing the deposit limit to be bypassed.

### 🟡 Low: Centralization risk — a single compromised owner key cascades into total protocol compromise

`setSigner` is `onlyOwner`, with no timelock, multisig requirement, or any other safeguard:

```solidity
function setSigner(address account, bool enabled) external onlyOwner {
    signers[account] = enabled;
}
```

Combined with the `sendToL1` arbitrary-call issue above, compromising the single `owner` key doesn't just let an attacker pause/unpause the bridge — it lets them **appoint themselves as a signer**, and from there drain the vault entirely via the arbitrary-call path. There is no separation of powers here; owner compromise is a full protocol compromise.

---

## L1Vault.sol

### 🟡 Low: `approveTo` is a generic, unrestricted approval-granting function

```solidity
function approveTo(address target, uint256 amount) external onlyOwner {
    token.approve(target, amount);
}
```

This is only callable by the vault's owner (the bridge contract), so it's not independently exploitable — but it's worth flagging as the *mechanism* that makes the `sendToL1` arbitrary-call bug so severe. The vault has no independent safety checks of its own; it fully trusts whatever the bridge tells it to do. This is a design choice worth documenting explicitly in the report, since it's the root enabler of the Critical findings above.

---

## TokenFactory.sol

### 🟡 Low: `deployToken` doesn't verify the deployed address is non-zero

```solidity
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
    assembly {
        addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
    }
    s_tokenToAddress[symbol] = addr;
    emit TokenDeployed(symbol, addr);
}
```

Raw `create` returns `address(0)` on deployment failure (e.g., malformed bytecode, insufficient gas), but this isn't checked. A failed deployment silently records `address(0)` as the token's address in `s_tokenToAddress[symbol]`, and emits a `TokenDeployed` event claiming success. Any downstream logic trusting `getTokenAddressFromSymbol` would then interact with the zero address, likely reverting unexpectedly or behaving unpredictably. `onlyOwner`-gated, so severity is low, but a cheap, worthwhile fix (`require(addr != address(0))`).

---

## Summary table

| # | Finding | Severity |
| --- | --- | --- |
| 1 | `depositTokensToL2`'s arbitrary `from` allows stealing any approved user's tokens | Critical |
| 2 | `sendToL1` permits fully arbitrary calls as the bridge, given any one signer's signature | Critical |
| 3 | No replay protection — signed withdrawal messages can be resubmitted indefinitely | High |
| 4 | `DEPOSIT_LIMIT` check is griefable via direct token transfers to the vault (DoS) | Medium |
| 5 | No reentrancy guard on `depositTokensToL2` | Low |
| 6 | Single owner key compromise cascades to full vault drain via signer appointment | Low (centralization) |
| 7 | `L1Vault::approveTo` grants unrestricted approval power with no independent checks | Low (design/architecture) |
| 8 | `TokenFactory::deployToken` doesn't verify successful deployment | Low |

Findings 1-3 are the real headline issues here — each is independently a complete fund-drain vector, and 2+3 compound each other (an arbitrary call combined with no replay protection is about as bad as it gets for a bridge).

```javascript
function test_poc_attackVector4_vaultAndLiquidityExhaustion() public {
        address victim2 = makeAddr("victim2");

        // Transfer 500e18 tokens from user (who has 1000e18) to victim2
        vm.prank(user);
        token.transfer(victim2, 500e18);

        // Both victims approve the bridge contract
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        vm.prank(victim2);
        token.approve(address(tokenBridge), type(uint256).max);

        // Attacker sweeps liquidity from both victims
        vm.startPrank(attacker);
        tokenBridge.depositTokensToL2(user, attackerInL2, token.balanceOf(user));
        tokenBridge.depositTokensToL2(victim2, attackerInL2, token.balanceOf(victim2));
        vm.stopPrank();

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(victim2), 0);
        assertEq(token.balanceOf(address(vault)), 1000e18);
    }
```
