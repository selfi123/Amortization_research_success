Abstract—Resource-constrained Internet of Things (IoT) devices
experience an inherent tradeoff between post-quantum security
and energy feasibility. Ring-Learning-With-Errors lattice-based
authentication and Quasi-Cyclic Low-Density Parity-Check code-
based hybrid encryption offer post-quantum security but incur
high computational, bandwidth, and energy costs when used per-
packet on Class-1 devices with only 8 KB RAM and an 8 MHz
CPU.
This paper introduces SAKE-IoT (Session Amortization for
Key Establishment in IoT), a four-phase protocol where the
expensive post-quantum epoch initiation is amortizedd over an
entire session of lightweight data packets. It is an extension
of the lightweight authentication protocol using Ring-LWE
authentication and QC-LDPC key encapsulation by Kumari et
al. [1] with: (1) a two-tier epoch state machine consisting of a
heavy post-quantum handshake in Tier 1 and a lightweight per-
packet AEAD in Tier 2; (2) HKDF-SHA256 per-packet session
key derivation (RFC 5869 [2]); (3) AES-256-GCM authenticated
encryption (NIST SP 800-38D [7]); and (4) epoch renewal with
Epoch Bounded Forward Secrecy (EB-FS) using secure memory
zeroization.
We offer formal security proofs for IND-CCA2 (Theorem 1),
Strict Replay Resistance with Pr = 0 (Theorem 2), and Epoch
Bounded Forward Secrecy (Theorem 3), which are validated
through both MATLAB theoretical simulation and Contiki-NG/
Cooja network emulations over the IEEE 802.15.4 protocol stack
with 6LoWPAN
Key Results: ≈99.1% reduction in per-packet computation
latency (7.37 ms → 0.068 ms); 45.1% reduction in per-packet
bandwidth overhead (408 bits → 224 bits); and 33.1× times
reduction in clock cycles per packet. Cooja network simulation:
99.7% end-to-end latency reduction in the data phase, 94.7%
bandwidth saving at the session level with N =20 packets, and
100% packet delivery ratio. Security Results: ε = 0.0037 < 0.02
(IND-CCA2); Pr[replay accepted] = 0; and 0/100 cross-epoch key
recovery (EB-FS), with two verified epoch renewal cycles.
Index Terms—Post-Quantum Cryptography, Ring-LWE, IoT Se-
curity, Session Amortization, QC-LDPC, AES-256-GCM, Forward
Secrecy, Contiki-NG, 6LoWPAN
I. INTRODUCTION
The Internet of Things (IoT) has facilitated ubiquitous
connectivity among smart devices deployed across homes,
transportation systems, healthcare facilities, and industrial
systems. However, the security landscape is threatened by
two factors: (1) the impending arrival of quantum computers
jeopardizes all current public-key-based systems relying on
RSA and ECC algorithms; and (2) the quantum computer
replacement solutions impose prohibitive per-packet costs on
Class-1 constrained devices [20].
A. Problem Context
A hybrid scheme with Ring LWE Ring Signature Authenti-
cation (LR-IoTA) and a Quantum-Code Low Density Parity-
Check (QC-LDPC) code Key Encapsulation Process (KEP)
was presented by Kumari et al. [1]. Though the scheme
offers quantum-secure mutual authentication, the entire key
encapsulation process with SLDSPA decoding for every data
packet is mandatory, consuming 7.37 ms for every packet
(base paper Table 7: ∆enc + ∆dec = 1.5298 + 5.8430 ms).
B. The Amortization Gap
We identify the Amortization Gap: the costly post-quantum
epoch initiation (≈22.55 ms, one-time) should occur once
per session, with low-latency AEAD handling all subsequent
packets (≈0.068 ms each). This is the main source of the
novelty of SAKE-IoT.
Session amortization poses a required security query: does
reusing the Master Secret (MS) in multiple packets violate IND-
CCA2, facilitate replay attacks, or weaken forward secrecy?
This paper proves all of the above in a formal manner.
C. Key Contributions
1) SAKE-IoT Protocol:: A comprehensive four-phase pro-
tocol that extends [1] with a two-tier session architecture,
strict epoch bounds (Tmax = 86,400 s, Nmax = 220),
and formal Phase 4 memory zeroization.
2) Three Formal Security Proofs: : IND-CCA2 (Theo-
rem 1), Strict Replay Resistance with Pr = 0 (Theo-
rem 2), and Epoch-Bounded Forward Secrecy via Ring-
LWE hardness (Theorem 3).
3) 99.1% Per-Packet Latency Reduction: from 7.37 ms
→ 0.068 ms, as empirically measured by MATLAB
tic/toc over 10,000 iterations.
4) 45.1% Per-Packet Bandwidth Reduction: from 408 bits
(QC-LDPC CT0) → 224 bits (AES-GCM nonce + tag).
5) 33.1× Clock Cycle Reduction: from ≈2.45M cycles
(QC-LDPC HE) → ≈74K cycles (AEAD).
6) Epoch-Bounded Forward Secrecy (EB-FS): A novel
security property formally proven here, not addressed
in [1].
II. RELATED WORK
A. Lattice-Based Authentication for IoT
The best computational characteristics are offered by ring
LWE-based schemes. Li et al. [15] proposed a lattice-based
PAKE scheme. Wang et al. [17] proposed a two-factor ring
LWE authentication scheme. RLizard [18] showed efficient
key encapsulation using ring LWE, although using classical
polynomial multiplication. What is more, none of the above
amortize post-quantum costs over a session; a full handshake
is needed per data exchange.
B. Code-Based Encryption for IoT
In the research by Hu et al. [19], the authors analyzed the
performance of QC-LDPC KEMs on FPGAs but not for the
IoT’s low-RAM requirements. Kumari et al. [1] is the most
relevant prior work to the presented research, with the authors’
primitives being reused for the data phase with amortized
AEAD.
C. Session Management and Amortization
TLS 1.3 session resumption [4] is the inspiration for
our work, though the focus is classical crypto for high-
end platforms. Prior IoT authentication schemes [21] use
symmetric keys for data, though derived from classical (ECC)
handshakes, offering no post-quantum basis. To the best of our
knowledge, SAKE-IoT is the first scheme to amortize Ring-
LWE + QC-LDPC epoch establishment over a lightweight
AES-256-GCM data session

II. PRELIMINARIES
A. Notation
B. Lattice and LWE Foundations

A lattice Λ is defined as the set of all integer combinations of the form a1β1 + … + aiβi, with the coefficients being in Z and the vectors being linearly independent in Rn. In Search-LWE [10], with the given (Rn, Tn = Rnδn+εn), the objective is to recover δn. For Decisional-LWE, the objective is to distinguish LWE samples from a uniform distribution. These are the two objectives for Theorem 3 (EB-FS).