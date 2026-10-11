# Shamir Secret Sharing Key Protection & Reconstruction Procedure

## 1. Scope & Objective
This procedure defines the cryptographic partitioning, custody distribution, and ephemeral reconstruction of high-value evidence-signing keys and master root keys in Zone 7 (Wallet and Key Management Security). It ensures:
- No single individual or compromised system possesses the root evidence-signing private key.
- Key material is never stored in persistent disk storage in unpartitioned form.
- Ephemeral reconstruction occurs strictly in volatile memory within a protected execution boundary and is purged immediately following signature creation.

---

## 2. Cryptographic Threshold Model

### 2.1 Threshold Parameters (3-of-5)
- **Threshold (k)**: 3 shares required for reconstruction.
- **Total Shares (n)**: 5 distinct cryptographic shares.
- **Finite Field**: Prime field $GF(p)$ where $p = 2^{256} - 189$ (or 256-bit safe prime exceeding key space), or polynomial field $GF(2^8)$ with authenticated integrity tags.
- **Information Theoretic Security**: Any subset of $k-1$ (2 or fewer) shares provides zero mathematical advantage in deriving the secret key.

### 2.2 Mathematical Basis
A random polynomial $f(x)$ of degree $k - 1 = 2$ is generated:
$$f(x) = S + a_1 x + a_2 x^2 \pmod p$$
Where:
- $S = f(0)$ represents the root secret key.
- Coefficients $a_1, a_2$ are sampled from a cryptographically secure pseudorandom number generator (CSPRNG).
- Shares are coordinate pairs $(x_i, f(x_i))$ for $i \in \{1, 2, 3, 4, 5\}$ with $x_i \neq 0$.

Reconstruction uses Lagrange interpolation evaluated at $x = 0$:
$$S = \sum_{j=1}^k y_j \ell_j(0) \pmod p, \quad \ell_j(0) = \prod_{m \neq j, m=1}^k \frac{-x_m}{x_j - x_m} \pmod p$$

---

## 3. Share Custody & Distribution Matrix

| Share ID | Designated Custodian Role | Storage Medium | Operational Context |
|---|---|---|---|
| Share #1 | Primary SOC Lead | Air-gapped Hardware Token | Incident response operations |
| Share #2 | Forensic Investigator | Encrypted Key Vault / YubiKey | Evidence sealing & chain-of-custody |
| Share #3 | Compliance & Legal Officer | Physical Safe (Paper Backup QR) | Regulatory sign-off & compliance audit |
| Share #4 | Backup Security Officer | Dedicated Air-gapped HSM | Disaster recovery / failover |
| Share #5 | Executive Witness / CISO | Cold Storage Safety Deposit Box | Emergency quorum recovery |

---

## 4. Ephemeral In-Memory Reconstruction Procedure

+------------------+    +------------------+    +------------------+
| Custodian 1 (x1) |    | Custodian 2 (x2) |    | Custodian 3 (x3) |
+------------------+    +------------------+    +------------------+
|                       |                       |
+-----------------------+-----------------------+
|
v
+-------------------------------------------+
|   Isolated Ephemeral Execution Sandbox    |
|  - Lagrange Interpolation in RAM only     |
|  - Sign Target Artifact / Evidence Report |
|  - Zero-Fill / Memory Purge (memset_s)    |
+-------------------------------------------+
|
v
+----------------------------+
| Signed Evidentiary Output  |
| (Private Key Annihilated)  |
+----------------------------+


### 4.1 Step-by-Step Operator Checklist
1. **Quorum Authorization**: Three authorized custodians assemble at the designated secure air-gapped terminal.
2. **Terminal Verification**: Verify machine is disconnected from all external networks (radio, Ethernet, Bluetooth disabled).
3. **Input Shares**: Each custodian inputs their share via authenticated ephemeral stdin pipe or hardware token reader.
4. **Digest Binding & Signing**:
   - Reconstruct secret $S$ in volatile memory buffer.
   - Execute signature over the computed artifact/evidence digest.
5. **Immediate Memory Destruction**:
   - Overwrite key buffers with cryptographic randomness and zero-fill (`memset_s` / `bytearray` zeroing).
   - Trigger Python garbage collection (`gc.collect()`).
6. **Audit Attestation**: Record cryptographic audit event documenting Share IDs used, timestamp, artifact digest, and custodian signatures. Zero share content is logged.

---

## 5. Security Invariants & Prohibitions

1. **NO_SHARE_PERSISTENCE**: Neither shares nor reconstructed secrets shall ever be written to disk, swap space, or persistent cache.
2. **ZERO_AGENT_ACCESS**: Autonomous agents (Agents A through G) are strictly prohibited from holding shares, initiating reconstruction, or accessing the ephemeral signing workspace.
3. **SUB_THRESHOLD_REJECTION**: Presentation of fewer than 3 valid shares aborts immediately without attempting key reconstruction.
4. **INTEGRITY_CHECK**: Shares incorporate SHA-256 integrity checksums to detect input tampering prior to polynomial interpolation.
