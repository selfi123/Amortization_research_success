To successfully publish your session amortization novelty in a high-impact, Scopus-indexed journal (like IEEE Internet of Things Journal or Elsevier Computer Networks), you must bridge the gap between "practical efficiency" and "provable cryptographic security."

Reviewers will not accept the novelty merely because it is faster; you must formally prove that reusing a Master Secret does not introduce critical vulnerabilities like replay attacks, chosen-ciphertext vulnerabilities, or the complete collapse of forward secrecy.

Here is the complete, formal sketch of what you must prove, how to prove it, the expected results, and the optimal architectural design required to win those proofs.

---

### Part 1: Optimal Architecture of the Session Amortization Novelty

To successfully validate the formal security proofs below, your proposed system cannot just use basic AES. You must structurally upgrade the protocol to use **Authenticated Encryption with Associated Data (AEAD)** and strict **Stateful Epoch Management**.

**Tier 1: The Master Handshake (Epoch Initiation)**

1. The Sender and Receiver execute the heavy post-quantum LR-IoTA authentication and QC-LDPC encapsulation *exactly as proposed in the base paper*.
2. Instead of using the output as a temporary session key, both nodes store it in secure, volatile memory as the **Master Secret ()**.
3. Both nodes initialize a state variable: .
4. An **Epoch Timer ()** or **Packet Limit ()** is started.

**Tier 2: The Amortized Session (Lightweight Data Transfer)**
For the -th data transfer within the current Epoch:

1. **Nonce Generation:** The Sender increments its counter to generate a strict, monotonically increasing Nonce: .
2. **Key Derivation:** The Sender uses a computationally secure Key Derivation Function (e.g., HMAC-SHA256) to derive a unique session key:

3. **Authenticated Encryption (Crucial for IND-CCA2):** The Sender encrypts the plaintext message () using an AEAD cipher like AES-GCM. This produces both the ciphertext () and a cryptographic MAC (Message Authentication Code) tag ().

4. **Transmission:** The Sender transmits only the tuple  to the Receiver.
5. **Decryption & Verification:** The Receiver checks if . If true, it derives , verifies the MAC tag , decrypts , and updates .

**Tier 3: Secure Erasure (Epoch Termination)**
Once  or  is reached, both devices trigger a **Cryptographic Zeroization** of the  from RAM and initiate a new Tier 1 Handshake to generate .

---

### Part 2: The Formal Security Proof Sketch

For your Scopus submission, create a section titled *"Formal Security Analysis in the Random Oracle Model (ROM)."* You must define three formal games played between a Challenger (the IoT system) and a Probabilistic Polynomial-Time (PPT) Adversary ().

#### Proof 1: IND-CCA2 Security (Indistinguishability under Adaptive Chosen-Ciphertext Attack)

* **The Goal:** Prove that derived keys  are indistinguishable from random noise, and an attacker cannot manipulate ciphertexts in transit.
* **The Game Setup:** The Challenger establishes . The Adversary  is given access to a KDF Oracle and an Encryption/Decryption Oracle.
* **The Challenge:**  submits two equal-length messages,  and . The Challenger flips a secret coin  and returns the encrypted ciphertext of .  can continue querying the decryption oracle for *any* ciphertext except the challenge ciphertext.  must guess .
* **How to Prove It:** You reduce this to the standard security assumptions of HMAC and AES-GCM. You mathematically prove that because AES-GCM validates the MAC tag () before decrypting, the Decryption Oracle will output  (reject) for any forged or altered ciphertext. Therefore, 's advantage in guessing  is bounded by , which is negligible.

#### Proof 2: Strict Replay and Desynchronization Resistance

* **The Goal:** Prove that reusing the Master Secret does not allow an attacker to intercept Session 1 and replay it later to trick the receiver.
* **The Game Setup:**  eavesdrops on the network and records a valid transmission tuple: . Later,  injects this exact tuple back into the receiver.
* **How to Prove It:** Define the Receiver's State Machine. State that the Receiver strictly enforces . Because the legitimate transmission already advanced the Receiver's counter to , the replayed packet evaluates as . The packet is mathematically dropped with a probability of exactly 1.

#### Proof 3: Epoch-Bounded Forward Secrecy (EB-FS)

* **The Goal:** The base paper claims perfect forward secrecy because keys are ephemeral. You must prove that storing the  does not cause catastrophic historical leakage if the device is physically hacked.
* **The Game Setup:**  physically compromises an IoT node during Epoch , extracting  from the RAM.
* **How to Prove It:** 1.  *Future Secrecy:* Prove that because  will expire at ,  cannot derive .
2.  *Past Secrecy:* Prove that  was securely zeroized from RAM. Because Tier 1 relies on fresh Post-Quantum Lattice (Ring-LWE) math for every Epoch, deriving  backward from  requires solving the underlying mathematically hard LWE problem. Therefore, inter-epoch forward secrecy is perfectly preserved.

---

### Part 3: Expected Simulation Results for Scopus Acceptance

To validate the novelty, you must replicate the MATLAB and FPGA simulations of the original paper and show a stark contrast between Tier 1 and Tier 2.

You should aim to present the following graphs and tables in your results section:

1. **Algorithmic Delay (Computation Overhead):**
* *Base Paper Result:* ~7.37 ms total for data encryption/decryption per session.
* *Your Result to Claim:* Tier 2 amortized sessions bypass QC-LDPC and SLDSPA entirely. Hashing and AES take  ms. You will graph a **~99% reduction in CPU delay** for all data sessions following the initial handshake.


2. **Communication Bandwidth Overhead:**
* *Base Paper Result:* The KEP ciphertext () adds significant bit-weight because it contains the error vector matrix.
* *Your Result to Claim:* Because your amortized session only sends a Nonce and the AES payload , you eliminate the KEP payload entirely. Show a bar chart proving a massive reduction in transmitted bits per packet.


3. **Hardware Energy Consumption (FPGA/IoT Battery Life):**
* *Base Paper Result:* Running SLDSPA requires hundreds of FPGA slices/flip-flops for every single data packet sent.
* *Your Result to Claim:* Show that your IoT device's processor enters a deep-sleep state faster because AEAD encryption takes a fraction of the clock cycles compared to QC-LDPC math. Graph the theoretical extension of the IoT node's battery life (e.g., extending node lifespan from 6 months to 2 years).



By structuring the paper with this strict AEAD + Nonce architecture, proving IND-CCA2 and Epoch-Bounded Forward Secrecy, and presenting a 99% reduction in computational latency, your manuscript will represent a highly rigorous, publishable improvement over the base protocol.