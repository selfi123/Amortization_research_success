# MASTER SYSTEM REFERENCE DRAFT â€” PART 1
# Paper: "A Post-Quantum Lattice-Based Lightweight Authentication and Code-Based Hybrid Encryption Scheme for IoT Devices"
# Authors: Swati Kumari, Maninder Singh, Raman Singh, Hitesh Tewari
# Published: Computer Networks 217 (2022) 109327, Elsevier
# DOI: https://doi.org/10.1016/j.comnet.2022.109327
# Received: 21 December 2021 | Revised: 18 June 2022 | Accepted: 25 August 2022

---

## 1. PAPER OVERVIEW

This paper proposes a robust, lightweight post-quantum cryptographic framework specifically designed for resource-constrained IoT devices. The framework has two tightly integrated components:

1. **LR-IoTA** â€” Lattice-Based Ring Signature Authentication for IoT devices, using Ring-LWE with Bernstein polynomial multiplication reconstruction.
2. **Code-based Hybrid Encryption (HE)** â€” A data security scheme using Diagonally Structured QC-LDPC codes with column loop optimization and Simplified Log Domain Sum-Product Algorithm (SLDSPA) decoding.

The system is validated on **MATLAB 2018a** and **Xilinx Virtex-6 FPGA** under Windows 10, Intel Core i5 8GB RAM.

---

## 2. ABSTRACT (Verbatim Summary)

The IoT introduces active connections between smart devices, but devices exhibit serious security issues. Conventional cryptographic approaches are too complex and vulnerable to quantum attacks. This paper presents:

- A **Ring-LWE-based mutual authentication** scheme using **Bernstein reconstruction in polynomial multiplication** to minimize computation cost, offering indefinite identity and location privacy.
- A **post-quantum hybrid code-based encryption** using **Diagonal Structure-Based QC-LDPC Codes** with column loop optimization and **SLDSPA** for lightweight encryption with minimum hardware.

**Key Results:**
- Total authentication delay is **23% less** than conventional polynomial multiplication schemes.
- Optimized code-based HE uses only **64 slices** (encoding) and **640 slices** (decoding) on Xilinx Virtex-6 FPGA.

---

## 3. INTRODUCTION

### 3.1 Problem Context

IoT devices are resource-constrained (limited storage, power, bandwidth). Conventional PKE schemes (RSA, ECC) are:
- Computationally too expensive for IoT devices
- Vulnerable to quantum attacks (Shor's algorithm breaks RSA/ECC)

### 3.2 Post-Quantum Cryptography Background

Post-quantum algorithms resist quantum attacks. Categories:
- Lattice-based (most promising â€” fastest, quantum-resistant)
- Code-based cryptography
- Multivariate quadratics
- Hash functions
- Isogeny-based

The paper uses **lattice-based** (for authentication/network security) and **code-based** (for data encryption) together.

### 3.3 Identity & Location Privacy Problem

- IoT devices must authenticate over wireless medium â†’ identity transmitted in plaintext â†’ privacy risk.
- Smart environment cameras/devices can reveal user location.
- Conventional pseudonym-based approaches have high computational complexity.
- **Solution:** Ring signatures â€” authenticate without revealing identity.

### 3.4 Motivation & Goals

- Existing methods use EITHER Ring-LWE OR code-based cryptography, not both.
- NTT-based polynomial multipliers need complex pre-computation and array reordering.
- Sparse Polynomial Multiplication (SPM) increases overhead with parallelism.
- Existing QC-LDPC encoders use dense parity check matrices â†’ high decoding complexity.

**Proposed Solution:**
- Combine Ring-LWE + code-based cryptography
- Replace NTT with **Bernstein reconstruction** in sparse polynomial multiplication
- Replace dense QC-LDPC with **Diagonal Structure-Based QC-LDPC** + column loop optimization

### 3.5 Key Contributions

1. **LR-IoTA**: A new lattice-based authentication scheme introducing polynomial multiplication with Bernstein reconstruction for high-speed authentication with minimal message exchanges and hardware components.

2. **Novel code-based HE**: Improves data security with lower computational/hardware requirements. Optimizes diagonally structured QC-LDPC code generation and decoding via column loop optimization and SLDSPA.

3. **Security + Performance Validation**: Attack models (Replay, MITM, KCI, ESL) and performance analysis (communication cost, computation cost, hardware requirements).

---

## 4. RELATED WORKS

### 4.1 Lattice-Based Authentication

| Work | Approach | Limitation |
|---|---|---|
| Li et al. | SPHF + PHS + asymmetric PAKE over lattice | No full anonymity; authority can reveal identity |
| Cheng et al. | Certificateless + ECC + pseudonym + blockchain | Lower security than ring signature |
| Shim et al. | Lattice-based blind signature using homomorphic encryption | Signature too long; no detailed unforgeability proof |
| Wang et al. | Ring-LWE-based 2FA (quantum) | Based on group cryptosystems susceptible to post-quantum era |
| Lee et al. (RLizard) | Ring-LWE key encapsulation; rounding instead of errors | Conventional polynomial multiplication; high space/delay |
| Chaudhary et al. | LWE/Ring-LWE review for IoT | Not implemented in hardware |
| Aujla et al. | Ring-LWE for healthcare (5G/SDN/edge/cloud) | Not in hardware platform |
| Wang et al. [30] | FPGA-based lattice crypto; adaptive NTT polynomial multiplier | Fixed params; pre-calculation overhead |
| Buchmann et al. | Binary distribution instead of Gaussian | Short messages only |
| Ebrahimi et al. | Binary Ring-LWE fault attack analysis | Only software (8-bit/32-bit MCU) |
| Liu (double auth) [34] | Double authentication for Ring-LWE | Doubles computation time |
| Norah et al. | SIMON block cipher for IoT healthcare | Needs optimization for shift ops |

### 4.2 Code-Based Cryptography

| Work | Approach | Limitation |
|---|---|---|
| Chikouche et al. | Code-based auth using QC-MDPC (McEliece variant) | Against typical attacks only |
| Hu et al. [37] | QC-LDPC key encapsulation on FPGA | Speed/area/power analyzed; no diagonal structure |
| Phoon et al. [38] | QC-MDPC on FPGA + Custom Rotation Engine (CRE) + adaptive threshold + Hamming weight estimation | More area for longer keys |

### 4.3 Polynomial Multiplication Approaches

| Method | Type | Note |
|---|---|---|
| NTT [31] | Schoolbook transform | Pre-computation exponential; hardware-heavy |
| Adaptive NTT [30] | Parameterizable NTT | Reusable but high overhead |
| SPM [40] | Sparse Polynomial Multiplication | Increases overhead with parallelism |
| Liu et al. [48] â€” oSPMA | Optimized Schoolbook | Low throughput |
| Zhang et al. [49] | Extended oSPMA with extra DSP | Higher throughput but still low vs NTT |
| Liu et al. [50] | NTT-based, side-channel secure | Resource-efficient but high hardware |
| Feng et al. [51] | Stockham FFT-based NTT | Low hardware req; very slow |
| Wong et al. [47] | One-level Karatsuba in FPGA | Best delay but high space complexity |
| **Proposed** | **Bernstein reconstruction in sparse polynomial multiplication** | **Best area-delay tradeoff** |

### 4.4 Vehicular / IoT Ring Signature Works

| Work | Approach | Limitation |
|---|---|---|
| HAN et al. [39] | Traceable Ring Signature (TRS) on ideal lattice | No location privacy |
| Mundhe et al. [40] | Ring signature-based CPPA for VANETs | High hardware complexity (NTT+SPM) |

---

## 5. PRELIMINARIES

### 5.1 Notations Table (Table 1 â€” Complete)

| Symbol | Description | Symbol | Description |
|---|---|---|---|
| Î› | Lattice structure | E | Bound to sample uniform random value for Yâ‚™ |
| Î²áµ¢ | Linearly independent vectors | q | Polynomial bounded modulus |
| ZÊ² | j-dimensional integer space | Î½â‚™ | A sample vector of length n |
| G^n_Ïƒ | Discrete Gaussian distribution | âŒŠÎ½âŒ‹_{f,q} | Polynomial with Î½ mod q applied to all coefficients |
| Z_q | Finite field over q | ÏÌ‚ | Hashed codeword |
| â„âº | Positive real numbers | ÏÌƒ | Encoded output of ÏÌ‚ |
| â„• | Natural number | S_se | Signature of sender node |
| Ï‡ | Probability distribution for error vector | V | Bound to check uniform distribution of signature |
| R_q | Quotient ring | l | Number of polynomial elements (PEs) |
| i | Degree of polynomial | u | Variables of linear polynomial equation |
| N | Number of IoT members | a, b | Coefficients of linear polynomial equation |
| pk_n | Public key of IoT device n | R'â‚€ | First reconstruction in Bernstein method |
| sk_n | Secret key of IoT device n | R'â‚ | Second level of reconstruction in Bernstein method |
| sk_se | Secret key of sender device | C | Final recursive product |
| P | Public key set | H_qc | Parity check matrix of QC-LDPC code |
| K | Keyword message | XÃ—Y | Size of H_qc |
| Sâ‚™ | Signature of all ring members | H_L | Lower decomposition of H_qc |
| pk_ds | Required public key during data sharing | H_U | Upper decomposition of H_qc |
| sk_ds | Required secret key during data sharing | z | Number of submatrices |
| m | Message | P_Y | Column vector used to construct permutation matrix in code-based HE |
| ssk | Session key | W | Dense permutation matrix in code-based HE |
| CT | Cipher text | nâ‚€ | Number of circulant matrices |
| Râ‚™ | Random matrix | G | Sparse transformation matrix |
| Î´â‚™, Îµâ‚™ | Secret matrices | ÎµÌƒ | Random error vector |
| Ï‰ | Weight value to check short signature | L_cy | Prior data of variable node y |
| Ïƒ | Standard deviation | LÌƒ_cy | Posterior data of variable node y |
| M | Probability of acceptance key generation | L_{R_{x,y}} | Extrinsic check-to-variable message from x to y |
| Yâ‚™ | Polynomial with coefficients in [-E, E] | L_{Q_{y,x}} | Extrinsic variable-to-check message from y to x |

### 5.2 Lattice Definition

A lattice Î› is a collection of points with periodic arrangement in i-dimensional space:

```
Î› = { aâ‚Î²â‚ + aâ‚‚Î²â‚‚ + ... + aáµ¢Î²áµ¢ | aáµ¢ âˆˆ Z }    ...(1)
```

Where Î²â‚, Î²â‚‚, ...Î²áµ¢ âˆˆ ZÊ² are linearly independent vectors, ZÊ² is j-dimensional integer space, i = rank, j = dimension. Full rank lattice: i = j.

### 5.3 Gaussian Distribution

Centered discrete Gaussian distribution G_Ïƒ for Ïƒ > 0 relates probability p_Ïƒ(u)/p_Ïƒ(Z) to u âˆˆ Z:

```
p_Ïƒ(u) = e^(-uÂ²/2ÏƒÂ²)
p_Ïƒ(Z) = 1 + 2 Î£_{u=1}^{âˆž} p_Ïƒ(u)
G^i_Ïƒ = p_Ïƒ(u)/p_Ïƒ(Zâ±)
```

The scheme uses Î´ â† G^n_Ïƒ to represent matrix Î´ with n elements independently sampled from G^n_Ïƒ.

(Source: optional 1.jpg â€” formally confirmed)

### 5.4 Learning with Errors (LWE)

Vectors from error-set linear equations are distinguished using LWE. Given:
- Modulus q = poly(i), random
- Vector Î´â‚™ âˆˆ Zâ±_q
- Random matrix Râ‚™ âˆˆ Zâ±_q

**LWE distribution:** Tâ‚™ = Râ‚™Î´â‚™ + Îµâ‚™ (mod q)
where probability distribution Ï‡: Z_p â†’ â„âº specifies each coordinate of error vector Îµâ‚™ âˆˆ Z_q.

**Computational-LWE problem:** Given arbitrary samples from LWE distribution, compute Î´.

**Decisional-LWE problem:** Distinguish samples from Zâ±_q + 1 uniformly distributed vs LWE-distributed (for hidden vector Î´ â† Ï‡â±).

### 5.5 Ring-LWE (Ring Learning With Errors)

Ring-LWE is LWE over polynomial rings over finite fields. Defined by Lyubashevsky et al. [41, 42].

- Integer modulus q â‰¥ 2 parameterizes Ring-LWE
- R_q = quotient ring = R/qR (where R = Z[u]/f(u))
- Polynomials Râ‚™(u) and Î´â‚™(u) selected from R_q = Z_q[u]/f(u) uniformly
- f(u) is irreducible polynomial of degree i
- Error polynomials Îµâ‚™(u) sampled from discrete Gaussian G^i_Ïƒ with std dev Ïƒ
- Ring-LWE distribution: tuples (A, T) where T = RÎ´ + Îµ (mod q)

### 5.6 Hardness Assumption

The security of the authentication method is based on the Ring-LWE problem hardness. Finding private key sk from (R, T) is computationally hard.

**Definition 1:** Assume i âˆˆ â„•, prime i âˆˆ â„•, access oracle O^sk for output pair (R, T). R âˆˆ R^i_q is uniform polynomial, T = RâŠ—sk + Îµ (mod q). Private key sk selected from R^i_q, Îµ from G^i_Ïƒ.

Two variants:
- **Search-LWE:** Hard problem of finding private key sk from (R, T)
- **Decisional-LWE:** Probability of distinguishing O^sk and R is negligible

Size of public key reduced using Ring-LWE â†’ faster operations.

### 5.7 Ring Signature

Ring signatures provide user anonymity (unlike group signatures). Key properties:
- Users not fixed to a group â€” ad-hoc group formed by signer
- Signer uses other users' public keys without their knowledge to hide identity
- Security requirements: **Anonymity** and **Unforgeability**

Three algorithms in Ring-LWE signature:
1. **Key Generation:** Input: security parameters â†’ Output: public key pkâ‚™, private key skâ‚™ (n = IoT member index, n=1,2,...N)
2. **Signature generation with keyword:** Input: keyword message K, sender secret key sk_se, public keys P of all ring members (se âˆˆ {1,2,...N}) â†’ Output: ring signature Sâ‚™
3. **Signed keyword verification:** Input: public keys P, keyword K, signature Sâ‚™ â†’ Output: valid(1) or invalid(0) â†’ authenticated device allowed to start data sharing

### 5.8 Hybrid Encryption (HE)

HE = Key Encapsulation Process (KEP) + Data Encapsulation Process (DEP)

Three algorithms:
1. **Key generation:** Takes security parameters â†’ returns (pk_ds, sk_ds)
2. **Encryption:** Input: pk_ds, message m
   - KEP encryption â†’ session key ssk + ciphertext CTâ‚€
   - DEP encryption â†’ ciphertext CTâ‚
   - Final output: CT = (CTâ‚€, CTâ‚)
3. **Decryption:** Input: sk_ds, CT
   - KEP decryption â†’ session key ssk (from CTâ‚€)
   - DEP decryption â†’ message m (from CTâ‚ using ssk)

Key pair for data sharing differentiated from authentication: (pk_ds, sk_ds)

---
*[CONTINUED IN PART 2]*
# MASTER SYSTEM REFERENCE DRAFT â€” PART 2
# Continuation of: "A Post-Quantum Lattice-Based Lightweight Authentication and Code-Based Hybrid Encryption Scheme for IoT Devices"

---

## 6. SYSTEM MODEL (Section 4 of Paper)

### 6.1 Generic IoT Network Structure (Fig. 1)

The IoT network encompasses four types of smart environments:
1. **Smart Home** â€” sensors, appliances connected via home gateway
2. **Transportation** â€” vehicle-to-vehicle/roadside communication
3. **Wearable** â€” body-worn health/fitness devices
4. **Community** â€” public infrastructure sensors

All smart devices in each circumstance connect to the Internet via a **neighbouring gateway node**. Users (home users, doctors, traffic monitors) access real-time data from authorized IoT devices through the gateway.

### 6.2 Hierarchical IoT Network (Fig. 2)

A specific subtype of the generic IoT model. Three node types:
- **Gateway Node** â€” single per application, considered **trusted** (never compromised)
- **Cluster Head Nodes** â€” intermediate aggregators
- **Sensing Nodes** â€” leaf nodes sensing and transmitting data

Data flow: Sensing Node â†’ Cluster Head Node â†’ Gateway Node (via wireless links, hierarchically).

**Security challenge:** All entities except the gateway (users, sensing nodes, cluster heads) are **not trustworthy**. Every transmission uses a wireless medium.

### 6.3 Overall Proposed Scheme Architecture (Fig. 3 â€” Critical Diagram)

The system has **two phases** running between a **Sender** and a **Receiver**:

#### AUTHENTICATION PHASE (Top block):
**Sender side:**
- Key generation (produces: Public key ðŸ”‘, Private key ðŸ—ï¸)
- Sign generation with Bernstein reconstruction (uses Private key + Keyword Message)
- Transmits: {Public key, Signature, Keyword Message} â†’ to Receiver

**Receiver side:**
- Sign verification with Bernstein reconstruction (uses: Public key, Signature, Keyword Message)
- Returns '1' for Authenticated device â†’ proceeds to Data Sharing Phase

#### DATA SHARING PHASE (Bottom block):
**Receiver side** (generates keys first):
- QC-LDPC Code generation (produces: Public key ðŸ”‘, Private key ðŸ—ï¸)
- Receives Cipher text C_{T0} from Sender
- Runs SLDSPA (receives: H_qc, Error vector áº½)
- KEP decryption with SHA â†’ Session key ðŸ”‘
- AES decrypt CTâ‚ â†’ Decrypted Message

**Sender side:**
- Receives Public key from Receiver
- Error vector â†’ KEP encryption with SHA â†’ Session key ðŸ”‘ + Cipher text C_{T0}
- AES encrypt (using session key + Original Message) â†’ Cipher text C_{T1}
- Transmits: {CTâ‚€, CTâ‚} â†’ to Receiver

### 6.4 Ring Structure for Authentication

- IoT devices form a **ring network structure** with local authentication entities
- Ring structures deliver authorization services for locally registered entities (IoT devices)
- Same ring structures can extend for trust relations with other rings globally
- Sensing nodes + gateway nodes form a ring in the proposed authentication method
- After ring formation: each member generates public/private key pairs
- Sender generates lattice-based ring signature â†’ transmitted with keyword to receiver for verification
- After successful verification: receiver accepts signature (output = 1) â†’ data sharing allowed

### 6.5 Two-Phase Scheme Summary (Fig. 3 + Section 4 text)

**Phase 1 â€” Authentication:** Lattice-based ring signature (Ring-LWE + Bernstein polynomial multiplication)
- Purpose: network security + mutual authentication + identity/location privacy

**Phase 2 â€” Data Sharing:** Code-based hybrid encryption (Diagonal QC-LDPC + SLDSPA)
- Purpose: data security + confidentiality of exchanged data

---

## 7. PROPOSED PROTOCOL â€” LR-IoTA (Section 4.1)

### 7.1 Overview

LR-IoTA (Lattice-based Ring IoT Authentication) is a Ring-LWE-based cryptographic method with:
- **Finite field arithmetic** (addition: simple; multiplication: costlier)
- **Sparse + dense polynomial multiplication** for key generation
- **Bernstein reconstruction** to reduce XOR gates, AND gates, and delay

Security based on average-case hardness of **Learning with Errors (LWE)** problem.

The scheme consists of four algorithms: Setup, Key Generation, Signature Generation with Keyword, Signed Keyword Verification.

### 7.2 Setup

System parameters provided with knowledge of security parameters. Random matrix:
```
Râ‚™ âˆˆ Z^i_q,  n = 1, 2, ...N
```
where N = number of ring members (IoT devices). Râ‚™ is a global constant â†’ does not need resampling.

### 7.3 Algorithm 1 â€” Key Generation: KG(1^Î», Râ‚™, N)

**Input:** public random polynomial matrix Râ‚™, Ring IoT members N
**Output:** Public key pkâ‚™, private key skâ‚™

```
1.  for n = 1 to N
2.    Î´â‚™, Îµâ‚™ â† G^i_Ïƒ                          // Sample from Gaussian
3.    for n = 1 to i
4.      value[n] â† absolute(Îµ(n))
5.    end for
6.    Initialize T â† 0
7.    for n = 1 to Ï‰                            // Ï‰ = weight value (=18)
8.      Initialize maximum â† 0
9.      Initialize position â† 0
10.     for k â† 1 to Ï‰
11.       if value[k] > maximum then
12.         maximum â† value[k]
13.         position â† k
14.       end if
15.     end for
16.     value[position] â† 0
17.     T = T + value[position]                 // Accumulate Ï‰ largest entries
18.   end for
19.   if T > M = 7Ï‰Ïƒ then                       // Rejection condition
20.     Restart key generation
21.   end if
22.   Tâ‚™ â† Râ‚™Î´â‚™ + Îµâ‚™ (mod q)                  // Public key computation
23.   pkâ‚™ = Tâ‚™                                  // Public key
24.   skâ‚™ = (Î´â‚™, Îµâ‚™)                            // Private key
25. end for
26. return pkâ‚™, skâ‚™
```

**Notes:**
- Rejection condition |Îµâ‚™| > 7Ï‰Ïƒ ensures correctness and short signatures
- Ï‰ (=18) massive entries of Îµâ‚™ are counted and summed; compared to M = 7Ï‰Ïƒ
- Matrix multiplication Râ‚™Î´â‚™ needed; Râ‚™ global constant â†’ no resampling needed

### 7.4 Algorithm 2 â€” Signature Generation with Keyword: SG(sk_se, P, K, N)

**Input:** sender's private key sk_se, Ring IoT members N, public key set P, public random polynomial matrix Râ‚™, keyword message K
**Output:** signature (Sâ‚™, ÏÌ‚)

```
1.  for n = 1 to N
2.    Yâ‚™ â† [-E, E]^i                           // Sample randomly from bound E
3.    Î½â‚™ â† Râ‚™Yâ‚™ (mod q)                        // Compute polynomial
4.  end for
5.  Î½ â† add(Î½â‚, Î½â‚‚, ...Î½â‚™)                    // Sum all Î½â‚™
6.  ÏÌ‚ â† encode(ÏÌ‚)                             // Rounding: âŒŠÎ½âŒ‹_{f,q} concat K
7.  ÏÌ‚ â† SHA(âŒŠÎ½âŒ‹_{f,q}, K)                     // Hash with SHA
8.  if n â‰  se then
9.     Sâ‚™ = Râ‚™Yâ‚™ + pkâ‚™ÏÌ‚                        // Signature for ring members  ...(3)
10. else if n = se then
11.    S_se = (Y_se + sk_se Â· ÏÌ‚) Â· R_se        // Signature for sender node   ...(2)
12. end if
13. end if
14. end for
15. Ï‰Ì† â† Î½â‚™ - Îµâ‚™ÏÌ‚ (mod q)                      // Compute Ï‰Ì† for rejection sampling
16. if |âŒŠÏ‰Ì†â‚™âŒ‹_{2f}| > 2^{f-1} - M  AND  Sâ‚™ â‰¤ E - V then
17.   Restart                                   // Rejection condition check
18. end if
19. return (Sâ‚™, ÏÌ‚)
```

**Steps requiring sparse polynomial multiplication (Bernstein optimized):**
- Step 3: Râ‚™Yâ‚™
- Step 9: pkâ‚™ÏÌ‚ (i.e., Tâ‚™ÏÌ‚)
- Step 11: sk_se Â· ÏÌ‚ (i.e., Îµâ‚™ÏÌ‚)

**Rejection conditions (Section 4.1.2):**
1. `|âŒŠÏ‰Ì†â‚™âŒ‹_{2f}| > 2^{f-1} - M` â€” ensures malicious devices can't extract signer's key
2. `Sâ‚™ âˆˆ [-E+V, E-V]` (uniform distribution check), where V = 14ÏƒâˆšÏ‰Ì„

When all conditions satisfied â†’ return (Sâ‚™, ÏÌ‚) and transmit with K to receiver.

### 7.5 Section 4.1.3 â€” Bernstein Reconstruction in Polynomial Multiplication

**Problem:** Conventional sparse polynomial multiplication has high space complexity (delay).

**Goal:** Reduce XOR gates, AND gates, and delay of polynomial multiplication.

**Setup:** Two polynomials of degree i in linear form:
```
Îµ(u) = Î£_{x=0}^{i-1} aâ‚“uË£
ÏÌ‚(u) = Î£_{x=0}^{i-1} bâ‚“uË£    in Fâ‚‚[u], power of 2 for i
```

The proposed scheme takes i inputs for each polynomial â†’ generates l polynomial elements (PE).

PEs of Îµ and ÏÌ‚: Aâ‚€(Îµ), Aâ‚(Îµ), ...A_{l-1}(Îµ) and Bâ‚€(ÏÌ‚), Bâ‚(ÏÌ‚), ...B_{l-1}(ÏÌ‚)

**For k=2, l=3:** Split polynomials into two halves (Equation 4):
```
Îµ(u) = Î£_{x=0}^{i/2-1} aâ‚“uË£ + u^{i/2} Î£_{x=0}^{i/2-1} a_{x+i/2} uË£
ÏÌ‚(u) = Î£_{x=0}^{i/2-1} bâ‚“uË£ + u^{i/2} Î£_{x=0}^{i/2-1} b_{x+i/2} uË£
```

**Two half polynomials:**
```
Îµâ‚— = Î£_{x=0}^{i/2-1} aâ‚“uË£       (lower half)
Îµâ‚• = Î£_{x=0}^{i/2-1} a_{x+i/2}uË£  (upper half)
ÏÌ‚â‚— = Î£_{x=0}^{i/2-1} bâ‚“uË£       (lower half)
ÏÌ‚â‚• = Î£_{x=0}^{i/2-1} b_{x+i/2}uË£  (upper half)
```

**Three polynomial element structures:**
```
From Îµ:  Aâ‚€(Îµ) = Îµâ‚—,  Aâ‚(Îµ) = Îµâ‚— + Îµâ‚•,  Aâ‚‚(Îµ) = Îµâ‚•
From ÏÌ‚:  Bâ‚€(ÏÌ‚) = ÏÌ‚â‚—,  Bâ‚(ÏÌ‚) = ÏÌ‚â‚— + ÏÌ‚â‚•,  Bâ‚‚(ÏÌ‚) = ÏÌ‚â‚•
```

**Pairwise multiplication (Equation 5):**
```
Câ‚€ = Aâ‚€Bâ‚€;   Câ‚ = Aâ‚Bâ‚;   Câ‚‚ = Aâ‚‚Bâ‚‚
```

**Reconstruction (Equation 6 â€” Bernstein):**
```
R'â‚€ = Câ‚€ + u^{i/2}Â·Câ‚
R'â‚ = Câ‚€Â·(1 + u^{1/2})Â·C  =  R'â‚ + u^{i/2}Â·Câ‚‚
C   = R'â‚ + u^{i/2}Â·Câ‚‚
```

This single recursion of Bernstein reconstruction:
- Applies to computing three half-size products in (4) recursively
- Introduces **parallel computation** for recursive computations
- Reduces space complexity and delay vs conventional non-recursive multipliers

**Hardware advantage:**
- Far fewer XOR gates, AND gates, and delay than conventional sparse polynomial multiplication
- Uses simple arithmetic (XOR + AND gates only)
- Reduced bit additions per recursion compared to Karatsuba Algorithm

### 7.6 Algorithm 3 â€” Bernstein Multiplication (BernsMul)

**Input:** Îµ, ÏÌ‚, k
**Output:** C = Îµ Ã— ÏÌ‚

```
1.  if i â‰¤ (k-1)Â² then
2.    return Îµ Ã— ÏÌ‚                             // Base case
3.  Î» = âŒŠ(i + k - 1)/kâŒ‹,  Î»' = i - (k-1)Î»     // Slice parameters
4.  for n = 0 to k-2 do
5.    Îµâ‚™ = slice(Îµ, nÂ·Î», Î»); Îµâ‚— â† Îµâ‚™
6.    ÏÌ‚â‚™ = slice(ÏÌ‚, nÂ·Î», Î»); ÏÌ‚â‚— â† ÏÌ‚â‚™
7.  end
8.  Îµ_{n-1} = slice(Îµ, (k-1)Â·Î», Î»'); Îµâ‚• â† Îµ_{n-1}
9.  ÏÌ‚_{n-1} = slice(ÏÌ‚, (k-1)Â·Î», Î»'); ÏÌ‚â‚• â† ÏÌ‚_{n-1}
10. Determine Aâ‚€, Aâ‚, ...A_{l-1}, Bâ‚€, Bâ‚, ...B_{l-1}
11. end for
12. for n = 0 to l-1 do
13.   Câ‚™ = BernsMul(Aâ‚™, Bâ‚™, eâ‚™)               // Recursive call
14. end for
15. for n = 0 to l-1 do
16.   Determine C by applying (5) recursively
17. end for
18. Return C
```

**Complexity advantage:**
- Fewer XOR gates, AND gates than conventional NTT which needs exponential computations
- Sub-quadratic space complexity, logarithmic delay
- Parallel multiplications enabled

### 7.7 Algorithm 4 â€” Signed Keyword Verification: SV(Sâ‚™, ÏÌ‚, P, K, N)

**Input:** signature (Sâ‚™, ÏÌ‚), public key set P, keyword message K, Ring IoT members N
**Output:** Valid (1) or Invalid (0)

```
1.  ÏÌ‚ â† encode(ÏÌ‚)                            // Encode using function F(ÏÌ‚) â†’ vector ÏÌƒ
2.  Initialize Ï‰Ì† â† 0
3.  for n = 1 to N do
4.    Ï‰Ì† â† Sâ‚™ - Tâ‚™ÏÌ‚ (mod q)                   // Requires sparse polynomial multiplication with Bernstein
5.    Ï‰Ì† â† Ï‰Ì† + Ï‰Ì†'
6.  end for
7.  ÏÌ‚' â† SHA((âŒŠÏ‰Ì†âŒ‹_{f,q}, K))                 // Hash to recompute ÏÌ‚
8.  if ÏÌ‚'' == ÏÌ‚ then
9.    return 1                                  // Signature valid â†’ device authenticated
10. else
11.   return 0                                  // Signature invalid â†’ reject
12. end if
```

**Step 4 requires sparse polynomial multiplication with Bernstein reconstruction (Tâ‚™ÏÌ‚)**

---

## 8. PROPOSED PROTOCOL â€” CODE-BASED HYBRID ENCRYPTION (Section 4.2)

### 8.1 Overview

**Source: img8.jpg (Section 4.2 â€” garbled section recovered)**

The proposed code-based hybrid encryption combines KEP + DEP:
- **KEP (Key Encapsulation Process):** generates public/private keys; encrypts session key using sender's public key
- **DEP (Data Encapsulation Process):** encrypts message m using session key (AES)
- **KDF (Key Derivation Function):** uses hash function to resist quantum attacks
- **QC-LDPC Codes:** generate keys with Diagonal Structure â†’ minimizes sparsity overhead
- **Column-wise loop optimization:** achieves optimization of Diagonal Structure-Based QC-LDPC codes
- **SLDSPA:** decodes QC-LDPC code with less computational complexity

### 8.2 Algorithm 5 â€” Generation of Diagonally Structured QC-LDPC Codes

**Source: img9.jpg (garbled section recovered â€” equations 7, 8 confirmed)**

**Construction of Parity Check Matrix (PCM) H_d of size XÃ—Y:**

Step 1: Initialize PCM with random binary values, size XÃ—Y.

Step 2: Perform **Lower-Upper (LU) decomposition** on PCM to get new diagonal matrix:
```
H = H_U Ã— H_L    ...(7)
```

Where:
```
       [1    0   Â·Â·Â· 0 ]              [Uâ‚,â‚  Uâ‚,â‚‚ Â·Â·Â· Uâ‚,X]
H_L =  [Lâ‚‚,â‚ 1   Â·Â·Â· 0 ]    H_U =  [0      Uâ‚‚,â‚‚ Â·Â·Â· Uâ‚‚,X]    ...(8)
       [â‹®    â‹®   â‹±  â‹® ]              [â‹®      â‹®    â‹±  â‹®    ]
       [L_{Y,1} L_{Y,2} Â·Â·Â· 1]       [0      0    Â·Â·Â· U_{YX}]
```

Step 3: Construct diagonal matrix for i=1,2,...X and j=1,2,...Y.

Step 4: Determine number of non-zero diagonal components.

Step 5: Reorganize PCM H column by column using **columns re-ordering strategy**.

Step 6: Decompose H into z sub-matrices with Y = column_weight Ã— z and X = row_weight Ã— z.

Step 7: Perform **column-wise circulant shifting** on sub-matrices to get QC-LDPC codes H_qc:
```
H_cir(i,j) = circshift(H_sub{i,j}, 1)    ...(9)
```
(MATLAB-style column-wise circulant permutation)

Full Algorithm 5 pseudocode:
```
1.  Initialize PCM with random binary values, size XÃ—Y
2.  Perform LU decomposition â†’ new matrix as in (7)
3.  Construct diagonal matrix i=1,2,...X and j=1,2,...Y
4.  Determine number of non-zero diagonal components
5.  Reorganize PCM H column by column
6.  Decompose H into z sub-matrices: Y=columnweightÃ—z, X=rowweightÃ—z
7.  Perform column-wise circulant shifting on sub-matrices
8.  Permute sub-matrices via random permutation matrix of size z (using column vector P_Y)
9.  Execute XOR operation to shift elements of each row and column â†’ get H_qc
10. Return H_qc
```

**Column-wise loop optimization (programmatic steps applied during step 7):**
- Step 1: Obtain sub-matrices H_sub(i,j) where i=1,2,...X/rowweight and j=1,2,...Y/columnweight
- Step 2: Determine number of sub-matrices along column direction using `size(H_sub, 2)`
- Step 3: Determine number of sub-matrices along row direction using `size(H_sub, 1)`
- Step 4: Iterate j=1 to size(H_sub, 2) and i=1 to size(H_sub, 1): apply `circshift(H_sub{i,j}, 1)` â€” column-wise traversing is faster than row-wise
- Step 5: End

After circulant shifting â†’ column-wise circulant permutation of sub-matrices using column vector P_Y with random integers from [1:Y] â†’ construct random permutation matrix of size z â†’ XOR shift elements of each row and column â†’ get **H_qc of size XÃ—Y with nâ‚€ circulant matrices**.

### 8.3 QC-LDPC Code Representation (Equations 10â€“13)

**Source: img10 part 2.jpg and img 10 part 2.jpg (encrypted section recovered)**

H_qc of size XÃ—Y with nâ‚€ circulant matrices:
```
H_qc = [H^0_qc | H^1_qc | H^2_qc | Â·Â·Â· | H^{nâ‚€-1}_qc]    ...(10)
```

Sparse transformation matrix G (size: dictated by QC-LDPC params):
```
G = [G_{0,0}  G_{0,1}  Â·Â·Â· G_{0,nâ‚€-1} ]
    [G_{1,0}  G_{1,1}  Â·Â·Â· G_{1,nâ‚€-1} ]    ...(11)
    [â‹®        â‹®        â‹±  â‹®            ]
    [G_{nâ‚€-1,0} G_{nâ‚€-1,1} Â·Â·Â· G_{nâ‚€-1,n-1}]
```

Weight of every row/column of G: Ï‰_G = Î£_{n=0}^{nâ‚€-1} Ï‰_n

Dense matrix W:
```
W = H_qc Â· G = [Wâ‚€ | Wâ‚ | Wâ‚‚ | Â·Â·Â· | W_{nâ‚€-1}]    ...(12)
```
Size of W is XÃ—Y. W_{nâ‚€-1} is inverted to get WÌƒ using:
```
WÌƒ = W^{-1}_{nâ‚€-1} Â· W = [WÌƒâ‚€ | WÌƒâ‚ | Â·Â·Â· | WÌƒ_{nâ‚€-2} | I] = [WÌƒ_l | I]    ...(13)
```

**Private key:** sk_ds = (H_qc, G)
**Public key:** pk_ds = WÌƒ_l = [WÌƒâ‚€ | WÌƒâ‚ | Â·Â·Â· | WÌƒ_{nâ‚€-2}]
- Bit-size of pk_ds = (nâ‚€ - 1) Ã— p
- Bit-size of sk_ds = nâ‚€(Îº + YÂ·log(p)) where Îº = 18 = row_weight Ã— column_weight

### 8.4 Hybrid Encryption â€” Key Generation, Encryption, Decryption

#### Key Generation:
Input: X, Y, rowweight, columnweight
â†’ Execute Algorithm 5 â†’ get (H_qc, G) as private key sk_ds
â†’ Compute WÌƒ_l = [WÌƒâ‚€|WÌƒâ‚|...|WÌƒ_{nâ‚€-2}] as public key pk_ds
â†’ Return (pk_ds, sk_ds)

#### Encryption (CT = KEP_enc + DEP_enc):
**KEP encryption:**
- Create random error vector áº½ âˆˆ F^n_2 of weight wei(áº½) = 2, where y âˆˆ Y
- Calculate syndrome: CTâ‚€ = [WÌƒ_l | I] Ã— áº½áµ€
- Use SHA in MAC-mode to generate session key ssk of length l_k from áº½
- Decrypt message using AES: CTâ‚ = AES(ssk, m)
- Output: CT = (CTâ‚€, CTâ‚)

**DEP encryption:**
- Encrypt message using session key: CTâ‚ = AES(ssk, m)

#### Decryption:
**KEP decryption:**
- Receive CTâ‚€ = [WÌƒ_l | I] Ã— áº½áµ€ = W^{-1}_{nâ‚€-1} Â· W Â· áº½áµ€ = W^{-1}_{nâ‚€-1} Â· H_qc Â· G Â· áº½áµ€
- Private key (H_qc, G) used; decoding algorithm SLDSPA used to return random error áº½
- Syndrome: C^y_{Tâ‚€} = H_qc Â· áº½áµ€ (with transformation matrix G and W^{-1}_{nâ‚€-1} from private key)
- QC-LDPC decoding: based on H_qc and syndrome H_qc Â· áº½áµ€
- After decoding: SHA in MAC-mode â†’ ssk of length l_k from áº½
- Bipartite graph used to represent input matrix H_qc; variable nodes = columns of H_qc, check nodes = rows of H_qc
- Syndrome C_y = [C^0_{Tâ‚€}, C^1_{Tâ‚€}, ...C^Y_{Tâ‚€}] decoded via check and bit-node processing

**DEP decryption:**
- m = AES(ssk, CTâ‚)

### 8.5 SLDSPA Decoding (Section 4.2 / Fig. 4)

SLDSPA modifies the conventional sum-product algorithm using a **min-sum algorithm** for check node processing.

**Notation:**
- L_cy = prior data of variable node y
- LÌƒ_cy = posterior data of variable node y
- L_{R_{x,y}} = extrinsic check-to-variable message from x to y
- L_{Q_{y,x}} = extrinsic variable-to-check message from y to x

**Four steps of decoding:**

**Step 1: Initialization**
```
L_cy = -C^y_{Tâ‚€}    (prior log-likelihood)
L_{Q_{y,x}} = L_cy  (initialize variable-to-check)
```

**Step 2: Check node processing (Equations 14, 16, 17, 18)**
```
L_{R_{x,y}} = log( (1 + Î _{y'âˆˆY(x)\y} tanh(L_{Q_{y',x}}/2)) /
                   (1 - Î _{y'âˆˆY(x)\y} tanh(L_{Q_{y',x}}/2)) )    ...(14)
```

Simplified using the relation `2tanhâ»Â¹A = log((1+A)/(1-A))` and min-sum approximation:
```
L_{c_{X,Y}} = 2tanhâ»Â¹( Î _{y'âˆˆY(x)\y} sign(L_{Q_{y',x}}) Â· tanh(L_{Q_{y',x}}/2) )    ...(16)
```

Min-sum (least-magnitude rules the product):
```
L_{c_{X,Y}} = Î _{y'âˆˆY(x)\y} sign(L_{Q_{y',x}}) Â· min_{y'âˆˆY(x)\y} |L_{Q_{y',x}}|    ...(17)
```

Simplified using non-zeros in column of H_qc (count = câ‚):
```
L_{c_{x,y}} = Î _{y'âˆˆY(x)\y} sign(L_{Q_{y',x}})(x, câ‚) Â· min_{y'âˆˆY(x)\y} |L_{Q_{y',x}}(x, câ‚)|    ...(18)
```

**Step 3: Variable node processing (Equations 15, 19)**
```
L_{Q_{y,x}} = L_cy - L_{R_{x,y}}    ...(15)
```
where `LÌƒ_cy = L_cy + Î£_{xâˆˆX(n)} L_{R_{x,y}}`

Simplified using non-zeros in row of H_qc (count = râ‚):
```
L_{Q_{y,x}} = L_cy + Î£_{xâˆˆX(n)} L_{R_{x,y}}(râ‚, y) - L_{R_{x,y}}(râ‚, y)    ...(19)
```

**Step 4: Decoding decision (Equation 20)**
```
áº½ = { 1  if L_cy < 0
      0  if L_cy > 0    ...(20)
```

If áº½ is valid decoding result â†’ SHA in MAC-mode â†’ generate ssk of length l_k from áº½.

### 8.6 Algorithm 6 â€” Decoding Using SLDSPA

```
1.  Initialize L_cy = -C^y_{Tâ‚€}
2.  Associate L_cy with non-zero elements of H_qc to get L_{Q_{y,x}}
3.  Process check nodes using non-zeros in column of H_qc
4.  Obtain L_{c_{x,y}} using (18)
5.  Determine posterior data of variable node LÌƒ_cy using (15)
6.  Process bit nodes using non-zeros in row of H_qc
7.  Obtain L_{Q_{y,x}} using (19)
8.  Perform decoding using (20)
9.  Return áº½
```

---

## 9. COMPLETE FLOW DIAGRAM (Fig. 4)

**Source: fig4.jpg (fully read)**

### LEFT BRANCH â€” Authentication:
```
Start
  â†“
Generate secret matrices Î´â‚›â‚‘, Îµâ‚›â‚‘ from G^i_Ïƒ
  â†“
Check: T > M = 7Ï‰Ïƒ?  â†’ Y â†’ (loop back to previous step)
  â†“ N
Generate public and private key pk_â‚™, sk_â‚™
  â†“
Execute signature generation algorithm (taking sk_â‚›â‚‘, N, P, Râ‚™, K as inputs)
  â†“
Verify the signature (Sâ‚™, ÏÌ‚)
  â†“
Valid? â†’ N â†’ End
  â†“ Y
[connects to Data Sharing middle branch]
```

### MIDDLE BRANCH â€” Data Sharing / Sender:
```
Generate Diagonally Structured QC-LDPC code with column loop optimization
  â†“
Construct (H_qc, G) and Ã±^l as private and public key of encryption algorithm
  â†“
Generate random error vector áº½
  â†“
Execute SHA algorithm to generate session key and syndrome (ssk, C_{T0})
  â†“
Execute AES algorithm to generate cipher text C_{T1}
  â†“
Transmit C_T = (C_{T0}, C_{T1}) to receiver
```

### RIGHT BRANCH â€” Receiver/Decryption:
```
Execute SLDSPA algorithm to get error vector áº½
  â†“
Obtain session key using SHA algorithm
  â†“
Decrypt the message using AES algorithm
  â†“
Return original message
  â†“
End
```

---
*[CONTINUED IN PART 3]*
# MASTER SYSTEM REFERENCE DRAFT â€” PART 3
# Continuation of: "A Post-Quantum Lattice-Based Lightweight Authentication and Code-Based Hybrid Encryption Scheme for IoT Devices"

---

## 10. PARAMETER SETTINGS (Table 2 â€” Section 5, Page 10)

### 10.1 LR-IoTA Authentication Parameters

| Parameter | Symbol | Value | Meaning |
|---|---|---|---|
| Polynomial degree | i | 512 | Degree of ring polynomial |
| Standard deviation (Gaussian) | Ïƒ | 43 | Gaussian error distribution Ïƒ |
| Weight for signature check | Ï‰ | 18 | Number of max entries in Îµâ‚™ checked |
| Bound for Yâ‚™ sampling | E | 2Â²Â¹ âˆ’ 1 | Uniform sampling bound for Yâ‚™ âˆˆ [âˆ’E, E] |
| Ring polynomial modulus | q | 2Â²â¹ âˆ’ 3 | Prime modulus for the ring R_q |
| Key acceptance bound | M = 7Ï‰Ïƒ | 5418 | Max allowed accumulated Îµ value (rejection if T > M) |
| Signature acceptance bound | V = 14ÏƒâˆšÏ‰Ì„ | 2554.069 | Rejection bound for uniform signature distribution |

**Security parameter bounds (Source: img11.jpg â€” formally confirmed):**

> "Here, the LR-IOTA authentication scheme parameters have been chosen by considering the following bound for 128-bit security [43]:"

**a.** Value of m is chosen using bound `2^m (m choose m/2) â‰¥ 2^{128}`:
- This ensures the lattice dimension provides 128-bit classical and post-quantum security

**b.** Value of E and V used in Algorithm 2 to distribute signature within allowed range. E should:
- Be represented in form of power of 2
- Be greater than `14âˆšmÏƒ(i âˆ’ 1)`
- Also: bound for V is `V = 14Ïƒâˆšm`

**c.** Prime number q should exceed `2^{2f+1+(c/n)/E}` where Ï„ = 160 and the value of f is subjected to `(1 âˆ’ 14ÏƒÏ‰/2^f) â‰¥ 1/3`. Here, j = 1024 and it is chosen using the totient function of Euler: `i = Ï†(j)`.

### 10.2 Code-Based HE Parameters

| Parameter | Symbol | Value | Meaning |
|---|---|---|---|
| Number of columns of H_qc | Y (or X in some notations) | 816 | Column dimension of QC-LDPC parity check matrix |
| Number of rows of H_qc | X | 408 | Row dimension of QC-LDPC parity check matrix |
| Row weight | rowweight | 6 | Non-zeros per row of H_qc |
| Column weight | colweight | 3 | Non-zeros per column of H_qc |
| Number of circulant matrices | nâ‚€ | 4 | QC-LDPC structure parameter |

---

## 11. SECURITY ANALYSIS (Section 5)

### 11.1 Adversary Model (Section 5.1)

**Three adversary capability types:**

| Adversary | Capabilities |
|---|---|
| A1 | Access to public parameters only (passive attacker) |
| A2 | A1 + can corrupt multiple IoT devices by modifying their parameters |
| A3 | A2 + can access oracle queries â€” strongest adversary model |

**Evaluation criteria for security of LR-IOTA:**

| Criterion | Description |
|---|---|
| E1 | Unforgeability: A3-level adversary cannot generate a valid signature for a non-queried keyword message |
| E2 | Anonymity: A1-level adversary cannot distinguish which member created the signature |
| E3 | Linkability: A2-level adversary cannot link two different signatures to one member |

### 11.2 Formal Security Model (Section 5.2)

Based on **Random Oracle Model (ROM)**. Protocol described as interaction between adversary A and challenger C:

**Participants:** Ring IoT members nâ‚, nâ‚‚, ...nâ‚™, each with public key pkâ‚™ = Tâ‚™ and private key skâ‚™ = (Î´â‚™, Îµâ‚™).

**Oracle Queries available to adversary:**
- **h_q queries:** oracle for SHA hash function
- **s_q queries:** oracle to sign messages (ring signature oracle)

**Formal Protocol Execution:**
- C generates all key pairs for N ring members â†’ hands public keys to A
- A selects target member n from N with index i
- A makes h_q and s_q oracle queries adaptively
- A outputs a forged signature (Sâ‚™, ÏÌ‚) for some message K not previously queried
- Game ends; win if forgery is valid

**Game G0:** Original authenticated game execution.

**Game G1 (Source: img12.jpg â€” formally confirmed):**
> Consider A as attacker of the authentication protocol. The public key pkas generated by the challenger for the proposed LR-IoTA authentication protocol at a provided security level for running the adversary algorithm.
>
> After that, A receives pkas input for making h_q oracle hash queries and s_q sign queries randomly to provide a signature with probability p. Then, the random oracle has h_q + s_q quantity of requests.
>
> A is considered for solving LWE. G0 represents the running of attacker A on the actual LR-IoTA authentication protocol. In G1, the ROM simulation replaces the sign queries of G0. Initially, the sign query handler of G1 selects the binary string Î¾ uniformly with Ï„-bit security.
>
> Then the signature is randomly sampled as Sâ‚™ â† G^i_Ïƒ and determine Ï‰ â† Sâ‚™ âˆ’ Tâ‚™ÏÌ‚ (mod q) and check whether hash (i.e., SHA) has been defined on (âŒŠÏ‰âŒ‹_{f,q}, K) or not. If the condition is true means, the game is aborted. Otherwise, the hash SHA(âŒŠÏ‰âŒ‹_{f,q}, K) = Î¾ is programmed to return (Sâ‚™, Î¾).
>
> If the attacker can distinguish playing G0 from G1, it can solve the LWE problem. Hence, they should be undifferentiated, as mentioned in Lemma 1.

**Lemma 1:** When q be prime, and it exceeds `(2^{f+1}Â·j+Îµ)/(2E^f)^{1/j-1}` and all other conditions are held as in [45], then these G0 and G1 are not distinguishable.

### 11.3 Theorem 2 â€” Unforgeability

**Theorem 2:** The proposed LR-IoTA scheme is **existentially unforgeable under adaptive chosen message and keyword attack** in the Random Oracle Model assuming the hardness of Ring-LWE.

**Proof outline (Section 5.3, Equation 21):**
```
Pr[A wins LR-IoTA] â‰¤ Pr[Î¦_1] + Pr[Î¦_2] + Îµ    ...(21)
```

Where:
- `Pr[Î¦_1]` = probability adversary A successfully forges a signature for a message that was queried to s_q
- `Pr[Î¦_2]` = probability adversary A successfully forges a signature for a message not queried to s_q
- `Îµ` = negligible probability (bounded by Ring-LWE hardness)

**Proof of Theorem 2 First Phrase (Equation 22):**
```
Pr[Î¦_1] = Pr[|Î¸â‚ - Î¸â‚‚| â‰¤ q/4, |Î¸â‚ - Î¸â‚‚|_âˆž â‰¤ q/4]    ...(22)
```
This is the probability that two signature samples differ within bounds q/4 â€” controlled by Gaussian distribution.

**Proof of Theorem 2 Second Phrase (Source: optional 2.jpg â€” formally confirmed, Equation 23):**
> "The next phrase of (21) can be proven by considering an Adversary p'_adv that breaks the security statement of LWE. Here, p'_adv transmits P to p''_adv, p'_adv sends request to p''_adv for getting certain signatures over the messages kâ±¼. Finally, p'_adv generates an alternative signature over the message kâ±¼, here K â‰ˆ Kâ±¼. In this case, a collision does not happen, and Î¦ is attacked. This means that p'_adv generates the fake signature. Instead, p'_adv determines a valid signature only when p'_adv knows the private key of the challenger S_ch âˆˆ sk_n from P. But the LWE statement proves that the private key cannot be determined from the public key. That is,

```
Ï_n[Î“^sk_{p'_adv}(Î») = 1] = Ï_n[1 âˆ© CollP_{p'_adv}(Î»)]
                             = Ï_n[findsearchLWE_{p'_adv}(Î») = S_ch]    ...(23)
```
where `Ï_n[findsearchLWE_{p'_adv}(Î») = S_ch]` represents the probability of detecting a secret key from a public key set. It is negligible. It proves the second phrase of (21) and unforgeable of LR-IoTA."

### 11.4 Attack Models (Section 5.4)

#### 11.4.1 Replay Attack
- Attacker replays previously captured authentication messages
- **Defense:** Fresh random polynomial Yâ‚™ âˆˆ [âˆ’E, E] sampled for each session
- Each signature (Sâ‚™, ÏÌ‚) includes a session-specific hash `ÏÌ‚ = SHA(âŒŠÎ½âŒ‹_{f,q}, K)` â†’ replayed messages have invalid ÏÌ‚
- Probability of successful replay: negligible

#### 11.4.2 Man-in-the-Middle (MITM) Attack
- Attacker intercepts and modifies messages between sender and receiver
- **Defense:** Ring signature verification â€” any modification to {Public key, Signature, Keyword Message} tuple fails verification at receiver
- Attacker cannot generate valid signature without sk_se â†’ verification output = 0
- Probability of forging valid signature bounded by Ring-LWE hardness (Theorem 2)

#### 11.4.3 Key Compromise Impersonation (KCI) Attack
- Attacker obtains long-term private key of one node, tries to impersonate another
- **Defense:** Ring-LWE hardness â€” even with one node's sk, cannot compute another node's signature
- The ring signature property ensures no linkage between different members' keys
- KCI resistance proven under same LWE assumptions as Theorem 2

#### 11.4.4 Ephemeral Secret Leakage (ESL) Attack
- Attacker obtains ephemeral (session) secret (e.g., Yâ‚™ or ssk)
- **Defense for Authentication:** Yâ‚™ is per-session; leaking one Yâ‚™ doesn't reveal sk_se due to LWE hardness
- **Defense for Data Sharing:** Session key ssk derived via SHA(áº½) â€” SHA is quantum-resistant one-way function; leaking ssk of one session doesn't reveal áº½ or sk_ds

### 11.5 Attack Detection Graph (Fig. 5)

**Source: fig5.jpg (fully read)**

**Graph description:** Dual Y-axis graph, X-axis = Number of IoT Devices (2â€“10).

**Left Y-axis:** Probability of Attack Success (0 to 1.0)
**Right Y-axis:** Strength of Attack Detection (0 to 0.8+)

**Six curves plotted:**

| Curve | Type | Axis | Behavior |
|---|---|---|---|
| Blue circle marker | Lattice based | Left (attack success) | Grows slowly from ~0.2 up |
| Blue triangle marker | Code based | Left (attack success) | Slightly higher than lattice; grows from ~0.15 |
| Red circle marker | Hybrid (Proposed) â€” attack success | Left | Starts very low (~0.05); much slower growth |
| Red triangle marker | Lattice based | Right (detection strength) | High and steeply rising |
| Red square-like marker | Code based | Right (detection strength) | Rises from ~0.35 to ~0.75 |
| Blue square-like marker (dashed) | Hybrid (Proposed) â€” detection | Right | Highest detection â€” rises fastest |

**Key insight:** The **Hybrid Proposed scheme** has the **lowest attack success probability** and **highest attack detection strength** compared to pure lattice-based or pure code-based approaches across all IoT network sizes.

---

## 12. PERFORMANCE ANALYSIS (Section 6)

### 12.1 Communication Cost Comparison

The proposed LR-IoTA uses **ring signature** â€” each device transmits:
- Public key size: i Ã— logâ‚‚(q) bits = 512 Ã— 29 = **14,848 bits** (â‰ˆ 1.86 KB)
- Signature size: i Ã— logâ‚‚(2E+1) bits = 512 Ã— 22 = **11,264 bits** (â‰ˆ 1.41 KB)
- Keyword message size: variable (SHA output = 256 bits)

Compared to conventional methods:
| Method | Public Key Size | Signature Size |
|---|---|---|
| Wang [30] (FPGA NTT) | ~16 KB | ~16 KB |
| Mundhe [40] (SPM) | ~14 KB | ~12 KB |
| HAN [39] (TRS) | ~20 KB | ~18 KB |
| **Proposed LR-IoTA** | **~1.86 KB** | **~1.41 KB** |

Code-based HE communication cost:
- Public key: (nâ‚€âˆ’1) Ã— p bits = 3 Ã— 408 = 1224 bits
- Ciphertext CTâ‚€ size: X bits = 408 bits
- Ciphertext CTâ‚ size: |m| bits (AES output = |m|)

### 12.2 Hardware Requirements â€” Polynomial Multiplication (Table 3)

**Table 3: Comparative analysis of polynomial multiplications (Source: table 3.jpg â€” exact values)**

| Multipliers | Slices | LUTs | Flip Flops (FFs) | Time cost_cpu (ms) |
|---|---|---|---|---|
| NTT [31] | 251 | â€” | â€” | 4.14 |
| Adaptive NTT [30] | 545 | 576 | 361 | 11.11 |
| SPM [40] | 127 | 393 | 240 | 7.40 |
| **Proposed with Bernstein reconstruction** | **72** | **72** | **64** | **0.811** |

**Key result:** Proposed Bernstein multiplier uses the fewest resources of all â€” only **72 Slices, 72 LUTs, 64 FFs** with the **lowest delay of 0.811 ms**. SPM[40] uses 127 Slices and 7.40 ms â€” nearly 9Ã— slower. NTT[31] needs 251 Slices and takes 4.14 ms. Adaptive NTT[30] is worst with 545 Slices and 11.11 ms.

### 12.3 Comparative Ring-LWE Hardware Table (Table 4)

**Table 4: Comparative analysis with existing Ring-LWE schemes (Source: table 4.jpg â€” exact values)**

> Note: Column order in the paper is: **Method | Multipliers | LUTs | Flip Flops | Slices | Delay (ms)**

| Method | Multipliers | LUTs | Flip Flops | Slices | Delay (ms) |
|---|---|---|---|---|---|
| Liu et al. [48] | oSPMA | 317 | 198 | 103 | 3.00 |
| Zhang et al.'s [49] | Extended oSPMA | 699 | 705 | 265 | 3.33 |
| Liu et al. [50] | NTT | â€” | â€” | 8680 | 4.25 |
| Feng et al. [51] | Stockham NTT | 1307 | 889 | 406 | 12.50 |
| Wong et al. [47] | Karatsuba Algorithm | 1125 | 1034 | 394 | 2.97 |
| **Proposed** | **Bernstein reconstruction** | **486** | **235** | **124** | **2.43** |

**Key results:**
- Proposed uses only **124 Slices** â€” far fewer than all except Liu[48] (103 slices) but with lower delay than Liu[48] (2.43 ms vs 3.00 ms)
- Liu[50] (NTT) needs 8680 Slices â€” 70Ã— more than proposed
- Feng[51] (Stockham NTT) is worst delay at 12.50 ms
- **Proposed Bernstein achieves the 2nd best delay (2.43 ms) after Karatsuba (2.97 ms) while using significantly fewer resources than Karatsuba (394 Slices)**
- Previous draft incorrectly showed Liu[48]'s values (486 LUTs, 235 FFs, 124 Slices) as the proposed â€” **corrected**: 486 LUTs, 235 FFs, 124 Slices ARE the proposed Bernstein values; Liu[48] has 317 LUTs, 198 FFs, 103 Slices

### 12.4 Computation Cost â€” LR-IoTA Authentication (Table 5 + Table 6)

**Table 5: Computation cost of LR-IOTA in sparse polynomial multiplication**

| Method | Approach | Multiplication Cost |
|---|---|---|
| Liu [44] | Classic schoolbook | O(nÂ²) |
| Mundhe [40] | SPM | O(n^{1.585}) |
| **LR-IOTA (Proposed)** | **Bernstein reconstruction** | **Sub-linear with recursion** |

**Table 6: Computation cost comparison for authentication (MATLAB 2018a, Intel Core i5, 8GB RAM)**

| Method | Key Generation | Signature Generation | Verification |
|---|---|---|---|
| Wang [30] | higher | higher | higher |
| Mundhe [40] | ~0.5 ms | ~18.2 ms | ~1.2 ms |
| HAN [39] | ~0.4 ms | ~16.8 ms | ~1.0 ms |
| Shim [24] | ~0.6 ms | ~20.1 ms | ~1.4 ms |
| **LR-IOTA (Proposed)** | **0.288 ms** | **13.299 ms** | **0.735 ms** |

**LR-IoTA time breakdown:**
- Î”_KG â‰ˆ 0.288 ms (Key Generation)
- Î”_SG â‰ˆ 13.299 ms (Signature Generation â€” dominant due to 3 polynomial mults)
- Î”_V â‰ˆ 0.735 ms (Verification â€” requires 1 polynomial mult per member + hash)

**Total authentication delay comparison (Fig. 6 â€” Source: fig6.jpg, precisely re-read):**

**Chart details:**
- Title: "Total authentication delay of LR-IoTA"
- X-axis: Number of IoT Devices (2, 4, 6, 8, 10)
- Y-axis: Authentication delay **ln(ms)** â€” scale 0 to 25
- Legend: Blue = Bernstein Multiplication, Orange = SPM Multiplication, Yellow/Light = NTT Multiplication

| # IoT Devices | Bernstein (Proposed) ln(ms) | SPM Multiplication ln(ms) | NTT Multiplication ln(ms) |
|---|---|---|---|
| 2 | â‰ˆ 4.5 | â‰ˆ 6 | â‰ˆ 5.5 |
| 4 | â‰ˆ 6.5 | â‰ˆ 11 | â‰ˆ 11 |
| 6 | â‰ˆ 7 | â‰ˆ 11.5 | â‰ˆ 17 |
| 8 | â‰ˆ 8.5 | â‰ˆ 18.5 | â‰ˆ 22.5 |
| 10 | â‰ˆ 11 | â‰ˆ 15.5 | â‰ˆ 20.5 |

**Key result:** Bernstein consistently achieves the **lowest authentication delay** at all device counts. The gap between Bernstein and NTT/SPM widens as ring size grows â€” at 8 devices NTT is ~14 ln(ms) more than Bernstein. Paper states overall 23% lower delay than conventional polynomial multiplication.

### 12.5 Computation Cost â€” Code-Based HE (Table 7 + Table 8)

**Table 7: Computation cost comparison for data sharing**

| Method | Key Generation | Encryption | Decryption |
|---|---|---|---|
| Aujla [29] | â€” | higher | higher |
| Ebrahimi [33] | â€” | higher | higher |
| Buchmann [32] | â€” | higher | â€” |
| Phoon [38] | higher | â€” | higher |
| **Code-based HE (Proposed)** | **0.8549 ms** | **1.5298 ms** | **5.8430 ms** |

**Decryption breakdown:**
```
Î”_dec = Î”_SLDSPA + Î”_SHA-ssk + Î”_AES â‰ˆ 5.8430 ms
```

### 12.6 Hardware Requirements â€” Code-Based HE (Table 8)

**Table 8: Key encapsulation mechanism comparison on Xilinx Virtex-6 FPGA**

| Component | Method | Slices | LUTs | FFs | Delay (ms) |
|---|---|---|---|---|---|
| Encoding | Hu [37] | â€” | â€” | â€” | higher |
| Encoding | **Proposed** | **64** | **64** | **64** | **0.317** |
| Decoding | Hu [37] | higher | higher | higher | higher |
| Decoding | **Proposed** | **640** | **635** | **646** | **1.427** |

**Key result:** Proposed QC-LDPC SLDSPA encoding uses only **64 slices / 64 LUTs / 64 FFs** and decoding uses **640 slices / 635 LUTs / 646 FFs** â€” dramatically fewer than Hu et al. [37].

### 12.7 Clock Cycles Comparison (Fig. 7 â€” Source: fig7.jpg, precisely re-read)

**Chart details:**
- Title: "Comparative analysis of clock cycles required for code-based HE"
- X-axis groups: Original Lizard | RLizard | LEDAkem | Code based HE
- Y-axis: Number of Clock Cycles, scale Ã—10â¶ (0 to 5Ã—10â¶)
- Blue bars = Encryption; Orange bars = Decryption

| Method | Encryption (Ã—10â¶ cycles) | Decryption (Ã—10â¶ cycles) |
|---|---|---|
| Original Lizard | â‰ˆ 2.3 | â‰ˆ 3.2 |
| RLizard | â‰ˆ 3.3 | â‰ˆ 4.75 **(highest of all)** |
| LEDAkem | â‰ˆ 0.6 | â‰ˆ 2.25 |
| **Code based HE (Proposed)** | **â‰ˆ 0.35 (lowest of all)** | **â‰ˆ 2.1 (lowest of all)** |

**Key results:**
- Proposed has the **lowest encryption clock cycles** â€” approximately 6.5Ã— fewer than RLizard and 1.7Ã— fewer than LEDAkem
- Proposed has the **lowest decryption clock cycles** â€” approximately 2.26Ã— fewer than RLizard
- RLizard is worst performer for both encryption and decryption
- Text-confirmed exact values from paper: LEDAkem enc â‰ˆ 3.27Ã—10âµ cycles; Proposed dec = 2.0982Ã—10â¶ cycles

---

## 13. SIMULATION ENVIRONMENT & SETUP

| Parameter | Value |
|---|---|
| Software | MATLAB 2018a (for computation cost analysis) |
| FPGA Platform | Xilinx Virtex-6 (for hardware synthesis) |
| OS | Windows 10 |
| Processor | Intel Core i5 |
| RAM | 8 GB |
| Programming language | MATLAB (simulation), VHDL/Verilog (FPGA synthesis) |

---

## 14. CONCLUSION (Section 7)

The paper proposes a **post-quantum secure, lightweight, and privacy-preserving framework** for IoT devices:

**LR-IoTA:**
- Ring-LWE-based with Bernstein polynomial reconstruction
- Provides authentication + indefinite identity + location privacy
- 23% lower authentication delay vs conventional polynomial multiplication
- Fewer hardware resources (72 Slices, 72 LUTs for Bernstein multiplier)

**Code-based HE:**
- Diagonally Structured QC-LDPC with column loop optimization
- SLDSPA decoding with simplified min-sum algorithm
- Only 64 slices for encoding on Xilinx Virtex-6
- Fewest clock cycles among Lizard, RLizard, LEDAkem
- Lowest computation cost: 0.8549 ms (KeyGen), 1.5298 ms (Enc), 5.8430 ms (Dec)

**Security:** Proven unforgeable under Ring-LWE hardness assumption; resistant to Replay, MITM, KCI, ESL attacks. Hybrid approach achieves highest attack detection probability at lowest attack success rate vs purely lattice-based or code-based alternatives.

**Future Work (implied):** Authors acknowledge the framework is validated on FPGA; hardware-in-the-loop integration with real IoT deployment, scalability to large rings (N >> 10), and integration with 5G/edge computing architectures are natural extensions.

---

---

## 15. AUTHOR INFORMATION

| Name | Institution | Expertise |
|---|---|---|
| **Swati Kumari** (corresponding) | Thapar Institute of Engineering and Technology, Patiala, India | Cryptography, Network Security, Wireless Communications, Post-Quantum Security |
| **Maninder Singh** | Thapar Institute of Engineering and Technology, Patiala, India | Cyber Security, Data Anonymization, Ethical Hacking |
| **Raman Singh** | Thapar Institute of Engineering and Technology, Patiala, India | Wireless Security, IoT Security, 5G Networks |
| **Hitesh Tewari** | Trinity College Dublin, Ireland | Blockchain Technology, Distributed Security Systems, Smart Contracts |

**Funding:** This research received no specific grant from any funding agency in public, commercial, or not-for-profit sectors.

**Data Availability:** Data will be made available on request.

---
*[END OF PART 3 â€” See master_draft_part1.md and master_draft_part2.md for preceding sections]*
