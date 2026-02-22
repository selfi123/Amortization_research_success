/**
 * crypto_core.h
 * Ring-LWE Lattice-Based Cryptography for IoT Authentication
 * Optimized for Cooja Mote Simulation
 * 
 * Implements:
 * - Ring-LWE with polynomial degree 512
 * - Ring signatures for anonymous authentication
 * - QC-LDPC encoding/decoding for hybrid encryption
 * - Session amortization with AEAD
 */

#ifndef CRYPTO_CORE_H_
#define CRYPTO_CORE_H_

#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* ========== RING-LWE PARAMETERS ========== */

#define POLY_DEGREE 128                    // n: Polynomial degree (minimal for Cooja testing)
#define MODULUS_Q 536870909L               // q: Prime modulus (2^29 - 3)
#define STD_DEVIATION 43                   // σ: Gaussian standard deviation
#define BOUND_E 2097151L                   // E: 2^21 - 1 (signature bound)
#define RING_SIZE 3                        // N: Number of ring members
#define REJECT_M 20000                     // M: Rejection threshold for keygen
#define REJECT_V 10000                     // V: Uniformity bound

/* ========== LDPC PARAMETERS ========== */

#define LDPC_ROWS 102                      // Parity check matrix rows (minimal for Cooja)
#define LDPC_COLS 204                      // Codeword length (minimal for Cooja)
#define LDPC_ROW_WEIGHT 6                  // Row weight (non-zero per row)
#define LDPC_COL_WEIGHT 3                  // Column weight (non-zero per column)
#define LDPC_N0 4                          // Number of circulant blocks

/* ========== CRYPTOGRAPHIC PRIMITIVES ========== */

#define SHA256_DIGEST_SIZE 32
#define AES128_KEY_SIZE 16
#define AES128_BLOCK_SIZE 16
#define KEYWORD_SIZE 32
#define MESSAGE_MAX_SIZE 64

/* ========== KEM ONE-SHOT ENCRYPTION ========== */

#define MASTER_KEY_LEN 32                  // Master key length
#define AEAD_NONCE_LEN 12                  // AEAD nonce length
#define AEAD_TAG_LEN 16                    // AEAD tag length

/* ========== DATA STRUCTURES ========== */

/**
 * Polynomial in ring Z_q[x]/(x^n + 1)
 */
typedef struct {
    int32_t coeff[POLY_DEGREE];
} Poly512;

/**
 * Ring-LWE key pair
 */
typedef struct {
    Poly512 secret;      // Secret key sk
    Poly512 public;      // Public key pk
    Poly512 random;      // Random polynomial R
} RingLWEKeyPair;

/**
 * Ring signature for N members
 */
typedef struct {
    Poly512 S[RING_SIZE];                  // Signature components
    Poly512 w; /* Added w for LWE verification */
    uint8_t commitment[SHA256_DIGEST_SIZE]; // Fiat-Shamir commitment
    uint8_t keyword[KEYWORD_SIZE];         // Signed keyword
} RingSignature;

/**
 * QC-LDPC public key (compressed circulant representation)
 */
typedef struct {
    uint8_t seed[32];                      // Seed for deterministic generation
    uint16_t shift_indices[LDPC_N0];       // Circulant shift values
} LDPCPublicKey;

/**
 * Full LDPC key pair
 */
typedef struct {
    LDPCPublicKey public_part;
    uint8_t private_info[64];              // Decoder auxiliary data
} LDPCKeyPair;

/**
 * Error vector for LDPC
 */
typedef struct {
    uint8_t bits[LDPC_COLS / 8];           // Packed bit representation
    uint16_t hamming_weight;               // Number of 1s
} ErrorVector;

/**
 * Authentication fragment (for reliable transmission)
 */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint16_t session_id;
    uint16_t fragment_id;
    uint16_t total_frags;
    uint16_t payload_len;
    uint8_t payload[64];
} AuthFragment;

/**
 * Fragment acknowledgment
 */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint16_t fragment_id;
} FragmentAck;

/* ========== POLYNOMIAL OPERATIONS ========== */

/**
 * NTT-based polynomial multiplication
 * result = a * b mod (x^n + 1) in Z_q
 */
void poly_mul_ntt(Poly512 *result, const Poly512 *a, const Poly512 *b);

/**
 * Modular reduction: result = a mod q
 */
void poly_mod_q(Poly512 *result, const Poly512 *a);

/**
 * Polynomial addition: result = a + b mod q
 */
void poly_add(Poly512 *result, const Poly512 *a, const Poly512 *b);

/**
 * Polynomial subtraction: result = a - b mod q
 */
void poly_sub(Poly512 *result, const Poly512 *a, const Poly512 *b);

/**
 * Scalar multiplication: result = scalar * a mod q
 */
void poly_scalar_mul(Poly512 *result, int32_t scalar, const Poly512 *a);

/**
 * L2 norm of polynomial
 */
uint32_t poly_norm(const Poly512 *a);

/**
 * Copy polynomial
 */
void poly_copy(Poly512 *dest, const Poly512 *src);

/* ========== RANDOM NUMBER GENERATION ========== */

/**
 * Initialize PRNG with seed
 */
void crypto_prng_init(uint32_t seed);

/**
 * Generate random 32-bit integer
 */
uint32_t crypto_random_uint32(void);

/**
 * Cryptographically secure random (for nonces, keys)
 */
void crypto_secure_random(uint8_t *output, size_t len);

/**
 * Discrete Gaussian sampling
 */
int32_t gaussian_sample(int sigma);

/* ========== RING-LWE OPERATIONS ========== */

/**
 * Ring-LWE key generation with rejection sampling
 */
int ring_lwe_keygen(RingLWEKeyPair *keypair);

/**
 * Generate deterministic ring member public key
 */
void generate_ring_member_key(Poly512 *public_key, int member_index);

/**
 * Generate ring signature
 * @param sig: Output signature
 * @param keyword: Message to sign
 * @param signer_keypair: Signer's key pair
 * @param ring_pubkeys: All N public keys in ring
 * @param signer_index: Index of signer (0 to N-1)
 */
int ring_sign(RingSignature *sig, const uint8_t *keyword,
              const RingLWEKeyPair *signer_keypair,
              const Poly512 ring_pubkeys[RING_SIZE],
              int signer_index);

/**
 * Verify ring signature
 * @returns 1 if valid, 0 if invalid
 */
int ring_verify(const RingSignature *sig, const Poly512 public_keys[RING_SIZE]);

/* ========== QC-LDPC OPERATIONS ========== */

/**
 * Generate QC-LDPC key pair
 */
int ldpc_keygen(LDPCKeyPair *keypair);

/**
 * Encode error vector to syndrome: s = H * e^T
 */
void ldpc_encode(uint8_t *syndrome, const ErrorVector *error, const LDPCPublicKey *pubkey);

/**
 * SLDSPA decoder
 * @returns 0 on success, -1 on failure
 */
int sldspa_decode(ErrorVector *error, const uint8_t *syndrome, const LDPCKeyPair *keypair);

/**
 * Generate random error vector
 */
void generate_error_vector(ErrorVector *error, uint16_t target_weight);

/* ========== CRYPTOGRAPHIC HASH ========== */

/**
 * SHA-256 hash
 */
void sha256_hash(uint8_t output[SHA256_DIGEST_SIZE], const uint8_t *input, uint32_t len);

/**
 * HMAC-SHA256
 */
void hmac_sha256(uint8_t *output, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len);

/**
 * HKDF-SHA256 key derivation
 */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

/* ========== AES ENCRYPTION ========== */

/**
 * AES-128 key expansion
 */
void aes128_key_expansion(uint8_t *roundkeys, const uint8_t *key);

/**
 * AES-128 block encryption
 */
void aes128_encrypt_block(uint8_t *output, const uint8_t *input, const uint8_t *roundkeys);

/**
 * AES-128 CTR mode
 */
void aes128_ctr_crypt(uint8_t *output, const uint8_t *input, uint32_t len,
                      const uint8_t *key, const uint8_t *iv);

/* ========== AEAD OPERATIONS ========== */

/**
 * AEAD encryption (AES-CTR + HMAC)
 */
int aead_encrypt(uint8_t *output, size_t *output_len,
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce);

/**
 * AEAD decryption (verify then decrypt)
 */
int aead_decrypt(uint8_t *output, size_t *output_len,
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce);

/* ========== KEY ENCAPSULATION MECHANISM ========== */

/**
 * Derive session key from Error Vector (Baseline implementation)
 */
void derive_kem_key(uint8_t *K_session, const uint8_t *error, size_t err_len);

/**
 * KEM decrypt (Baseline implementation)
 */
int aead_kem_decrypt(const ErrorVector *error,
                    const uint8_t *ct, size_t ct_len,
                    uint8_t *out, size_t *out_len);

/**
 * KEM encrypt (Baseline implementation)
 */
int aead_kem_encrypt(const ErrorVector *error,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *out, size_t *out_len);

/* ========== UTILITY FUNCTIONS ========== */

/**
 * Secure memory zeroization
 */
void secure_zero(void *ptr, size_t len);

/**
 * Constant-time comparison
 */
int constant_time_compare(const uint8_t *a, const uint8_t *b, uint32_t len);

/**
 * Print polynomial (debugging)
 */
void poly_print(const char *label, const Poly512 *p, int num_coeffs);

/* ========== UTILITIES ========== */
void poly_print(const char *label, const Poly512 *p, int num_coeffs);
void secure_zero(void *s, size_t n);
int constant_time_compare(const uint8_t *a, const uint8_t *b, uint32_t len);

/* ========== SERIALIZATION ========== */
void serialize_poly512(uint8_t *out, const Poly512 *p);
void deserialize_poly512(Poly512 *p, const uint8_t *in);

#endif /* CRYPTO_CORE_H_ */
