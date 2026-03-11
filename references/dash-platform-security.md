# Dash Platform Security Guide
*Claris AI — V3.0 Reference · Semper Fortis*

---

## Overview

Dash Platform (Evolution) represents a unique security surface distinct from traditional smart contract blockchains. Unlike Ethereum-compatible chains, Dash Platform combines a Layer 2 application platform (Drive) with a public API layer (DAPI), all secured by Evolution Masternodes (evonodes) requiring 4,000 DASH collateral. Understanding this architecture is essential for building secure applications on Dash.

This guide covers the full security attack surface: identity systems, data contracts, DAPI endpoints, evonode operations, and consensus mechanisms.

---

## Architecture Security Model

### Three-Layer Security Surface

**Layer 1 (Dash Core):** The base chain provides consensus, ChainLocks (instant finality), and InstantSend (fast confirmations). The primary trust anchor.

**Layer 2 (Dash Platform/Drive):** A decentralized data storage and application layer. State Transitions are the equivalent of transactions — they create identities, register data contracts, and submit documents. Platform is secured by evonodes participating in a quorum system.

**Layer 3 (DAPI):** The public HTTP/gRPC API exposing Platform functionality to clients. Nodes are publicly accessible, creating an unauthenticated attack surface.

### Trust Model

In Dash Platform, **identity = ownership**. Unlike Ethereum smart contracts where ownership can be complex multi-sig or governance systems, Platform data contracts are simply owned by the identity that created them. This creates a critical single point of trust: **compromise an identity key → control all its data contracts, documents, and DPNS names permanently**.

---

## Identity System Attacks

### Identity Key Compromise (DP01 — CRITICAL)

The most impactful attack on Dash Platform. Each identity has cryptographic keys at different security levels:

- **Authentication keys** — Used for document submissions
- **High-security keys** — Used for data contract operations  
- **Master keys** — Used for key rotation and identity transfers

**Attack Vectors:**
- Seed phrase phishing via fake Dash mobile wallet websites
- Malware exfiltrating keys from device storage
- Insecure environment variable handling (`DASH_PRIVATE_KEY=...` in shell history)
- Cloud storage sync of wallet files without encryption

**Secure Key Management Patterns:**
```javascript
// BAD: Key in environment variable (visible in process list)
const identity = await client.platform.identities.get(process.env.DASH_IDENTITY_ID);

// BETTER: Use Dash client with encrypted wallet, never expose raw keys
const client = new Dash.Client({
  wallet: {
    mnemonic: null, // Never hardcode
    adapter: SecureEncryptedAdapter, // Use encrypted storage
  }
});
```

**Remediation Checklist:**
- Store mnemonics in hardware wallets or encrypted keystores only
- Use different identity keys for development vs. production
- Implement key rotation procedures before suspected exposure
- Monitor identity key usage via Platform Explorer for unexpected activity

---

## Data Contract Vulnerabilities

### Schema Injection and Unbounded Fields (DP02 — HIGH)

Data contract schemas define what documents can be stored. Poorly designed schemas create denial-of-service attack surfaces and data integrity issues.

**Vulnerable Schema Example:**
```json
{
  "profile": {
    "type": "object",
    "properties": {
      "bio": {
        "type": "string"
      },
      "tags": {
        "type": "array",
        "items": { "type": "string" }
      }
    }
  }
}
```
*Problems: `bio` has no maxLength (attacker submits 100KB strings). `tags` has no maxItems (attacker submits 10,000 tags). No `required` fields means empty documents are valid.*

**Secure Schema Pattern:**
```json
{
  "profile": {
    "type": "object",
    "properties": {
      "bio": {
        "type": "string",
        "maxLength": 512,
        "minLength": 1
      },
      "tags": {
        "type": "array",
        "items": { 
          "type": "string",
          "maxLength": 32
        },
        "maxItems": 20,
        "minItems": 0
      },
      "username": {
        "type": "string",
        "maxLength": 63,
        "pattern": "^[a-zA-Z0-9_-]+$"
      }
    },
    "required": ["bio", "username"],
    "additionalProperties": false
  }
}
```

### Data Contract Ownership Risks (DP07 — CRITICAL)

Unlike Ethereum where you can renounce ownership or use a DAO multisig, Dash Platform contracts are controlled by a single identity. Schema updates that break existing documents can corrupt entire applications.

**Attack Scenario:** If the owner identity is compromised, an attacker can:
1. Update the schema to invalidate all existing documents
2. Add new required fields breaking all existing data
3. Transfer the contract to an attacker-controlled identity

**Mitigation:** Use a dedicated high-security identity for contract ownership. Never use a hot wallet identity. Consider contracts where schema updates are minimized post-launch.

---

## DAPI Attack Surface

### Public Endpoint Abuse (DP03 — HIGH)

DAPI exposes gRPC and HTTP/JSON endpoints without authentication. Every endpoint callable by any IP address. This enables:

**State Transition Flooding:** Broadcasting thousands of malformed or invalid state transitions to consume evonode processing capacity. Each state transition requires validation work from the quorum.

**Expensive Query DoS:** Queries for documents with complex conditions or across large datasets can be resource-intensive. Unthrottled clients can target DAPI with high-cost queries.

**Malformed State Transition Attacks:** Crafted state transitions that pass initial validation but fail deep in the processing pipeline, wasting evonode resources.

**Defensive Patterns:**
```javascript
// Client-side rate limiting wrapper
class RateLimitedDAPIClient {
  constructor(client, maxTPS = 5) {
    this.client = client;
    this.minInterval = 1000 / maxTPS;
    this.lastCall = 0;
  }
  
  async broadcastStateTransition(transition) {
    const now = Date.now();
    const elapsed = now - this.lastCall;
    if (elapsed < this.minInterval) {
      await sleep(this.minInterval - elapsed);
    }
    this.lastCall = Date.now();
    return this.client.platform.broadcastStateTransition(transition);
  }
}

// Always set document query limits
const documents = await client.platform.documents.get('app.profile', {
  limit: 10,  // Always paginate — never open-ended queries
  startAt: cursor,
  where: [['$updatedAt', '>', lastSeen]]
});
```

---

## DPNS Security Considerations

### Username Squatting (DP04 — MEDIUM)

Dash Platform Name Service (DPNS) is first-come-first-served. Brand names, project names, and high-value usernames are vulnerable to squatting before legitimate owners register them.

**Squatting Risk Matrix:**
- Organization names (e.g., `semble`, `timely`, `votus`)
- Common misspellings of registered names
- Celebrity names
- Short premium names (3-5 characters)

**Protection Strategy:**
1. Register organization name and common variants immediately at launch
2. Monitor DPNS registrations for typosquats
3. Report impersonation to the Dash community
4. Consider registering across multiple TLDs (`.dash`)

---

## ChainLock and InstantSend Security

### Quorum Integrity (DP06 — HIGH)

ChainLocks provide instant finality via LLMQ (Long-Living Masternode Quorum) signing. InstantSend enables fast transaction confirmations. Both rely on a threshold of masternodes signing messages.

**Theoretical Attack Requirements:**
To compromise ChainLock quorum, an attacker needs control of > 60% of the LLMQ members for a given quorum. With thousands of masternodes, this requires substantial Dash collateral (a deterrent).

**Evolution Masternode (Evonode) Specific Risks:**
Evonodes (4,000 DASH collateral, ~$280,000 at current prices) represent higher-value targets than regular masternodes (1,000 DASH). Evonode operators must:
- Secure their server against compromise (SSH hardening, firewall)
- Protect their BLS masternode private key
- Keep Platform node software updated
- Monitor for unexpected participation in quorum signing

**Evonode Hardening:**
```bash
# Restrict DAPI/RPC to necessary interfaces only
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Firewall: only allow necessary ports
ufw allow 9999/tcp  # Dash P2P
ufw allow 443/tcp   # DAPI HTTPS
ufw deny 9998/tcp   # Block external RPC

# SSH: key-based auth only
PasswordAuthentication no
PubkeyAuthentication yes
```

---

## State Transition Security

### Replay Attack Prevention (DP05 — HIGH)

State transitions include identity nonces to prevent replay attacks. Proper nonce management is critical:

```javascript
// Always fetch current nonce before submitting
const identityNonce = await client.platform.identities.getNonce(
  identity.getId()
);

// Include in state transition
const stateTransition = await client.platform.documents.broadcast({
  create: [document],
  nonce: identityNonce + 1  // Increment from current
});
```

**Common Nonce Mistakes:**
- Caching nonces locally without checking for remote changes
- Parallel submissions with the same nonce (only one succeeds)
- Not handling nonce-out-of-order errors gracefully

---

## Secure Dash Platform Development Checklist

### Schema Design
- [ ] All string fields have `maxLength` ≤ 1024 (user text) or ≤ 63 (identifiers)
- [ ] All array fields have `maxItems` defined
- [ ] `additionalProperties: false` on all objects
- [ ] `required` array lists all mandatory fields
- [ ] Pattern validation on identifier/username fields
- [ ] Schema tested with maximum-size valid inputs

### Identity Management
- [ ] Production identity keys stored in hardware wallet or encrypted keystore
- [ ] Separate identities for development and production
- [ ] Data contract ownership identity is air-gapped where possible
- [ ] Key rotation procedure documented and tested
- [ ] DPNS names registered for all project handles

### DAPI Integration
- [ ] Client-side rate limiting implemented (≤5 TPS for writes)
- [ ] All document queries include explicit `limit` parameter
- [ ] State transition broadcasting has retry logic with backoff
- [ ] Nonce management handles concurrent requests safely
- [ ] Error handling for all state transition failures

### Operational Security (Evonode)
- [ ] RPC bound to localhost only
- [ ] SSH key-based authentication enforced
- [ ] Firewall configured (allow P2P, DAPI; deny RPC externally)
- [ ] Automatic security updates enabled
- [ ] Monitoring for unexpected evonode behavior
- [ ] BLS masternode key stored separately from hot server

### Application Security
- [ ] Input validation before creating Platform documents
- [ ] DPNS username availability checked before registration attempts
- [ ] Platform state handled gracefully during network degradation
- [ ] No private keys or mnemonics in application code or logs

---

*Reference maintained by Claris AI · V3.0 · ~Claris*
