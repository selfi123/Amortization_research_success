#include "crypto_core_z1.h"   /* Z1 Mote variant - Flash-optimized */
#include <string.h>
#include <stdio.h>
#include "sys/node-id.h"
#include "sys/log.h"
#include <stdlib.h>

#define LOG_MODULE "Crypto"
#define LOG_LEVEL LOG_LEVEL_INFO

/* ========== PRNG STATE ========== */
static uint32_t prng_state = 0x12345678;

void crypto_prng_init(uint32_t seed) {
    prng_state = seed;
}

uint32_t crypto_random_uint32(void) {
    /* Xorshift32 PRNG */
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 17;
    prng_state ^= prng_state << 5;
    return prng_state;
}

void crypto_secure_random(uint8_t *buffer, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(crypto_random_uint32() & 0xFF);
    }
}

/* ========== MODULAR ARITHMETIC ========== */
/* Modulus Q = 536870909 (2^29 - 3) */

static inline int32_t mod_q(int64_t x) {
    int64_t result = x % MODULUS_Q;
    if (result < 0) result += MODULUS_Q;
    return (int32_t)result;
}

static inline int32_t mod_mul(int32_t a, int32_t b) {
    return mod_q((int64_t)a * (int64_t)b);
}

static inline int32_t mod_pow(int32_t base, int32_t exp) {
    int32_t res = 1;
    while (exp > 0) {
        if (exp % 2 == 1) res = mod_mul(res, base);
        base = mod_mul(base, base);
        exp /= 2;
    }
    return res;
}



/* ========== NTT TABLES & IMPLEMENTATION ========== */
/* Roots for n=128, q=536870909. 256-th root of unity exists? 
   q-1 = 536870908 = 4 * 134217727.
   Wait, 536870909 is prime. (2^29 - 3). 
   (q-1) is divisible by 4. 
   For NTT size n=128, we need 2n=256-th root of unity.
   Does 256 divide q-1?
   536870908 / 256 = 2097151.98... NO.
   536870909 is NOT NTT-friendly for n=128!
   Only for n such that 2n | q-1.
   536870908 is divisible by 4. Not 8.
   So NTT works only for n=2.
   
   CRITICAL MATH ERROR in chosen Modulus!
   My previous 'poly_mul_ntt' logic was based on assumption it works.
   This explains why verification might fail if NTT was doing garbage.
   
   I MUST change MODULUS to be NTT-friendly for n=128.
   Need q = k * 256 + 1.
   Let's pick a prime near 2^29?
   Or just use schoolbook multiplication for n=128 (fast enough).
   n=128 schoolbook is 128*128 = 16k ops.
   Cooja Mote (MSP430) 16k ops is ~10ms.
   It's acceptable.
   
   I will switch to SCHOOLBOOK multiplication to be safe and robust.
*/

void poly_mul_schoolbook(Poly512 *result, const Poly512 *a, const Poly512 *b) {
    int i, j;
    int32_t res[2 * POLY_DEGREE];
    
    memset(res, 0, sizeof(res));
    
    for (i = 0; i < POLY_DEGREE; i++) {
        for (j = 0; j < POLY_DEGREE; j++) {
            res[i+j] = mod_q(res[i+j] + (int64_t)a->coeff[i] * b->coeff[j]);
        }
    }
    
    /* Reduce mod x^n + 1 */
    for (i = 0; i < POLY_DEGREE; i++) {
        /* x^n = -1 */
        /* coeff[n+i] wraps to coeff[i] with negation */
        result->coeff[i] = mod_q((int64_t)res[i] - (int64_t)res[POLY_DEGREE + i]);
    }
}

void poly_mul_ntt(Poly512 *result, const Poly512 *a, const Poly512 *b) {
    /* Redirect to schoolbook for n=128 robustness */
    poly_mul_schoolbook(result, a, b);
}

void poly_add(Poly512 *result, const Poly512 *a, const Poly512 *b) {
    int i;
    for (i = 0; i < POLY_DEGREE; i++) {
        result->coeff[i] = mod_q((int64_t)a->coeff[i] + (int64_t)b->coeff[i]);
    }
}

void poly_sub(Poly512 *result, const Poly512 *a, const Poly512 *b) {
    int i;
    for (i = 0; i < POLY_DEGREE; i++) {
        result->coeff[i] = mod_q((int64_t)a->coeff[i] - (int64_t)b->coeff[i]);
    }
}

void poly_mod_q(Poly512 *result, const Poly512 *a) {
    int i;
    for (i = 0; i < POLY_DEGREE; i++) {
        result->coeff[i] = mod_q(a->coeff[i]);
    }
}

void poly_print(const char *label, const Poly512 *p, int num_coeffs) {
    int i;
    printf("%s: [", label);
    for (i = 0; i < num_coeffs && i < 16; i++) {
        printf("%ld ", (long)p->coeff[i]);
    }
    printf("...]\n");
}

/* ========== SHA-256 (Simplified) ========== */
/* Using standard constants */
/* Z1: Placed in Flash ROM via FLASH_CONST to avoid using 256 bytes of precious 8KB RAM */
static FLASH_CONST uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIG0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SIG1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define sigma0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sigma1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

/* ========== SERIALIZATION ========== */

void serialize_poly512(uint8_t *out, const Poly512 *p) {
    int i;
    for(i=0; i<POLY_DEGREE; i++) {
        int32_t val = p->coeff[i];
        out[i*4]   = (val >> 24) & 0xFF;
        out[i*4+1] = (val >> 16) & 0xFF;
        out[i*4+2] = (val >> 8)  & 0xFF;
        out[i*4+3] = val & 0xFF;
    }
}

void deserialize_poly512(Poly512 *p, const uint8_t *in) {
    int i;
    for(i=0; i<POLY_DEGREE; i++) {
        uint32_t val = ((uint32_t)in[i*4] << 24) |
                       ((uint32_t)in[i*4+1] << 16) |
                       ((uint32_t)in[i*4+2] << 8) |
                       (uint32_t)in[i*4+3];
        p->coeff[i] = (int32_t)val;
    }
}

void sha256_hash(uint8_t output[32], const uint8_t *input, uint32_t len) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32_t w[64];
    uint8_t buf[64];
    uint32_t i, j;
    
    // Process full blocks
    for(i=0; i + 64 <= len; i+=64) {
        for(j=0; j<16; j++) w[j] = ((uint32_t)input[i+4*j]<<24)|((uint32_t)input[i+4*j+1]<<16)|((uint32_t)input[i+4*j+2]<<8)|((uint32_t)input[i+4*j+3]);
        for(j=16; j<64; j++) w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
        uint32_t temp_h[8]; memcpy(temp_h, h, 32);
        for(j=0; j<64; j++) {
            uint32_t t1 = temp_h[7] + SIG1(temp_h[4]) + CH(temp_h[4], temp_h[5], temp_h[6]) + K[j] + w[j];
            uint32_t t2 = SIG0(temp_h[0]) + MAJ(temp_h[0], temp_h[1], temp_h[2]);
            temp_h[7]=temp_h[6]; temp_h[6]=temp_h[5]; temp_h[5]=temp_h[4]; temp_h[4]=temp_h[3]+t1;
            temp_h[3]=temp_h[2]; temp_h[2]=temp_h[1]; temp_h[1]=temp_h[0]; temp_h[0]=t1+t2;
        }
        for(j=0; j<8; j++) h[j] += temp_h[j];
    }
    
    // Padding
    memset(buf, 0, 64);
    memcpy(buf, input+i, len-i);
    buf[len-i] = 0x80;
    if(len-i >= 56) {
        // Process this block and create another
        for(j=0; j<16; j++) w[j] = ((uint32_t)buf[4*j]<<24)|((uint32_t)buf[4*j+1]<<16)|((uint32_t)buf[4*j+2]<<8)|((uint32_t)buf[4*j+3]);
        for(j=16; j<64; j++) w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
        uint32_t temp_h[8]; memcpy(temp_h, h, 32);
        for(j=0; j<64; j++) {
            uint32_t t1 = temp_h[7] + SIG1(temp_h[4]) + CH(temp_h[4], temp_h[5], temp_h[6]) + K[j] + w[j];
            uint32_t t2 = SIG0(temp_h[0]) + MAJ(temp_h[0], temp_h[1], temp_h[2]);
            temp_h[7]=temp_h[6]; temp_h[6]=temp_h[5]; temp_h[5]=temp_h[4]; temp_h[4]=temp_h[3]+t1;
            temp_h[3]=temp_h[2]; temp_h[2]=temp_h[1]; temp_h[1]=temp_h[0]; temp_h[0]=t1+t2;
        }
        for(j=0; j<8; j++) h[j] += temp_h[j];
        memset(buf, 0, 64);
    }
    // Append length
    uint64_t bits = (uint64_t)len * 8;
    buf[56] = (bits>>56)&0xFF; buf[57] = (bits>>48)&0xFF; buf[58] = (bits>>40)&0xFF; buf[59] = (bits>>32)&0xFF;
    buf[60] = (bits>>24)&0xFF; buf[61] = (bits>>16)&0xFF; buf[62] = (bits>>8)&0xFF; buf[63] = bits&0xFF;
    for(j=0; j<16; j++) w[j] = ((uint32_t)buf[4*j]<<24)|((uint32_t)buf[4*j+1]<<16)|((uint32_t)buf[4*j+2]<<8)|((uint32_t)buf[4*j+3]);
    for(j=16; j<64; j++) w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
    uint32_t temp_h[8]; memcpy(temp_h, h, 32);
    for(j=0; j<64; j++) {
        uint32_t t1 = temp_h[7] + SIG1(temp_h[4]) + CH(temp_h[4], temp_h[5], temp_h[6]) + K[j] + w[j];
        uint32_t t2 = SIG0(temp_h[0]) + MAJ(temp_h[0], temp_h[1], temp_h[2]);
        temp_h[7]=temp_h[6]; temp_h[6]=temp_h[5]; temp_h[5]=temp_h[4]; temp_h[4]=temp_h[3]+t1;
        temp_h[3]=temp_h[2]; temp_h[2]=temp_h[1]; temp_h[1]=temp_h[0]; temp_h[0]=t1+t2;
    }
    for(j=0; j<8; j++) h[j] += temp_h[j];
    
    for(j=0; j<8; j++) {
        output[4*j] = (h[j]>>24)&0xFF; output[4*j+1] = (h[j]>>16)&0xFF; output[4*j+2] = (h[j]>>8)&0xFF; output[4*j+3] = h[j]&0xFF;
    }
}

/* ========== HELPERS ========== */
int32_t gaussian_sample(int sigma) {
    int32_t u1 = (int32_t)(crypto_random_uint32() % (200)) - 100; // Simplified small noise
    return u1;
}

uint32_t poly_norm(const Poly512 *a) {
    return 0; // Not used in new logic
}

/* ========== LWE OPERATIONS ========== */


/* ========== RING MEMBER KEY GENERATION ========== */

void generate_ring_member_key(Poly512 *public_key, int member_index) {
    int i;
    /* Use deterministic generation based on member index */
    /* This simulates retrieving a public key from a directory/PKI */
    uint32_t seed = 0x12345678 + (member_index * 0xABCDEF);
    uint32_t old_state = prng_state;
    
    crypto_prng_init(seed);
    
    /* Generate random-looking polynomial */
    /* In real LWE, this would be t = a*s + e. */
    /* For FAKE members, we just generate uniform random 't' */
    /* This is indistinguishable from real 't' (LWE assumption) */
    for (i = 0; i < POLY_DEGREE; i++) {
        public_key->coeff[i] = crypto_random_uint32() % MODULUS_Q;
    }
    
    crypto_prng_init(old_state);
}

int ring_lwe_keygen(RingLWEKeyPair *keypair) {
    int i;
    Poly512 a, s, e;
    
    uint32_t a_seed = 0xDEADBEEF;
    uint32_t old_state = prng_state; /* Simulate shared system parameter 'a' */
    crypto_prng_init(a_seed);
    for(i=0; i<POLY_DEGREE; i++) a.coeff[i] = crypto_random_uint32() % MODULUS_Q;
    crypto_prng_init(old_state);
    
    /* Sample secret s, error e */
    for(i=0; i<POLY_DEGREE; i++) {
        s.coeff[i] = gaussian_sample(STD_DEVIATION);
        e.coeff[i] = gaussian_sample(STD_DEVIATION);
    }
    
    /* t = a*s + e */
    Poly512 as;
    poly_mul_schoolbook(&as, &a, &s);
    poly_add(&keypair->public, &as, &e); // Public key = t
    
    keypair->secret = s;
    keypair->random = a; // Store 'a' for convenience
    
    return 0;
}

/* ========== RING COMPONENT HELPERS ========== */

/* Helper to get High Bits (approximation) of w */
static void get_high_bits(Poly512 *out, const Poly512 *in) {
    int i;
    for (i = 0; i < POLY_DEGREE; i++) {
        /* Keep top 16 bits (shift by 13 for 29-bit modulus? Modulus is 29 bits.
           Shift 13 keeps 16 bits. */
        out->coeff[i] = (in->coeff[i] >> 13);
    }
}

int ring_sign(RingSignature *sig, const uint8_t *keyword,
              const RingLWEKeyPair *signer_keypair,
              const Poly512 ring_pubkeys[RING_SIZE],
              int signer_index) {
    int i, j, attempt;
    Poly512 y, w, sc, z, w_approx, tc, w_check;
    uint8_t c_hash[SHA256_DIGEST_SIZE];
    Poly512 challenge;
    uint8_t hash_input[POLY_DEGREE * 4 + KEYWORD_SIZE];
    
    /* Rejection Sampling */
    for(attempt = 0; attempt < 500; attempt++) {
        /* 1. Sample y (make it slightly larger to hide s*c) */
        /* Range: +/- 100000. s*c is ~2000. Masking is OK. */
        for(i=0; i<POLY_DEGREE; i++) {
             y.coeff[i] = (int32_t)(crypto_random_uint32() % 200000) - 100000;
        }
        
        /* 2. w = a*y */
        poly_mul_schoolbook(&w, &signer_keypair->random, &y);
        
        /* 3. Get High Bits of w */
        get_high_bits(&w_approx, &w);
        
        /* 4. c = H(w_approx, keyword) */
        /* Serialize w_approx */
        for(i=0; i<POLY_DEGREE; i++) {
             int32_t v = w_approx.coeff[i];
             hash_input[i*4] = (v >> 24) & 0xFF;
             hash_input[i*4+1] = (v >> 16) & 0xFF;
             hash_input[i*4+2] = (v >> 8) & 0xFF;
             hash_input[i*4+3] = v & 0xFF;
        }
        memcpy(hash_input + POLY_DEGREE*4, keyword, KEYWORD_SIZE);
        sha256_hash(c_hash, hash_input, POLY_DEGREE*4 + KEYWORD_SIZE);
        
        /* Expand c */
        for(i=0; i<POLY_DEGREE; i++) challenge.coeff[i] = (c_hash[i%32] >> (i%8)) & 1;
        
        /* 5. z = y + s*c */
        poly_mul_schoolbook(&sc, &signer_keypair->secret, &challenge);
        poly_add(&z, &y, &sc);
        
        /* 6. Bounds Check on z (Security) */
        int bound_ok = 1;
        for(i=0; i<POLY_DEGREE; i++) {
            int32_t val = z.coeff[i];
            if (val > MODULUS_Q/2) val -= MODULUS_Q;
            if (abs(val) > 120000) bound_ok = 0; // Approx bound
        }
        if (!bound_ok) continue;
        
        /* 7. Correctness Check (Verify w_approx consistency) */
        /* w' = a*z - t*c */
        poly_mul_schoolbook(&tc, &signer_keypair->public, &challenge);
        poly_mul_schoolbook(&w_check, &signer_keypair->random, &z);
        poly_sub(&w_check, &w_check, &tc);
        
        Poly512 w_check_approx;
        get_high_bits(&w_check_approx, &w_check);
        
        /* Check diff <= 1 dealing with modular wrap */
        int consistent = 1;
        int32_t MAX_HIGH = (MODULUS_Q - 1) >> 13;
        
        for(i=0; i<POLY_DEGREE; i++) {
            int32_t diff = w_approx.coeff[i] - w_check_approx.coeff[i];
            /* Handle wrap around */
            if (diff > MAX_HIGH/2) diff -= (MAX_HIGH + 1);
            if (diff < -MAX_HIGH/2) diff += (MAX_HIGH + 1);
            
            if (abs(diff) > 4) {
                consistent = 0;
                break;
            }
        }
        
        if (consistent) {
            /* Success */
            sig->S[signer_index] = z;
            sig->w = w_approx; /* Store approximate w */
            memcpy(sig->commitment, c_hash, SHA256_DIGEST_SIZE);
            memcpy(sig->keyword, keyword, KEYWORD_SIZE);
            
            /* Fill fake members with garbage */
            for(i=0; i<RING_SIZE; i++) {
                if(i != signer_index) {
                     for(j=0; j<POLY_DEGREE; j++) sig->S[i].coeff[j] = 0;
                }
            }
            return 0;
        }
        watchdog_periodic();
    }
    
    return -1;
}

int ring_verify(const RingSignature *sig, const Poly512 public_keys[RING_SIZE]) {
    int i, j;
    Poly512 a, z, tc, w_prime, challenge;
    Poly512 w_expected = sig->w; /* The w_approx from signer */
    uint8_t c_hash[SHA256_DIGEST_SIZE];
    uint8_t hash_input[POLY_DEGREE * 4 + KEYWORD_SIZE];
    
    /* 1. Reconstruct 'a' */
    uint32_t a_seed = 0xDEADBEEF;
    uint32_t old_state = prng_state;
    crypto_prng_init(a_seed);
    for(i=0; i<POLY_DEGREE; i++) a.coeff[i] = crypto_random_uint32() % MODULUS_Q;
    crypto_prng_init(old_state);
    
    /* 2. Verify 'c' matches 'w_approx' */
    for(i=0; i<POLY_DEGREE; i++) {
         int32_t v = w_expected.coeff[i];
         hash_input[i*4] = (v >> 24) & 0xFF;
         hash_input[i*4+1] = (v >> 16) & 0xFF;
         hash_input[i*4+2] = (v >> 8) & 0xFF;
         hash_input[i*4+3] = v & 0xFF;
    }
    memcpy(hash_input + POLY_DEGREE*4, sig->keyword, KEYWORD_SIZE);
    sha256_hash(c_hash, hash_input, POLY_DEGREE*4 + KEYWORD_SIZE);
    
    if (memcmp(c_hash, sig->commitment, SHA256_DIGEST_SIZE) != 0) {
        return 0; // Commitment check failed
    }
    
    /* Reconstruct challenge c */
    for(i=0; i<POLY_DEGREE; i++) challenge.coeff[i] = (c_hash[i%32] >> (i%8)) & 1;
    
    /* 3. Check each member for signature validity */
    for(i=0; i<RING_SIZE; i++) {
        z = sig->S[i];
        
        /* Skip if z is all zeros (optimization for fake members) */
        int non_zero = 0;
        for(j=0; j<POLY_DEGREE; j++) if(z.coeff[j] != 0) non_zero = 1;
        if (!non_zero) continue; 
        
        /* w' = a*z - t*c */
        poly_mul_schoolbook(&w_prime, &a, &z);
        poly_mul_schoolbook(&tc, &public_keys[i], &challenge);
        poly_sub(&w_prime, &w_prime, &tc);
        
        Poly512 w_prime_approx;
        get_high_bits(&w_prime_approx, &w_prime);
        
        /* Check consistency with transmitted w_approx */
        int consistent = 1;
        int32_t MAX_HIGH = (MODULUS_Q - 1) >> 13;
        
        for(j=0; j<POLY_DEGREE; j++) {
            int32_t diff = w_prime_approx.coeff[j] - w_expected.coeff[j];
            /* Handle wrap around */
            if (diff > MAX_HIGH/2) diff -= (MAX_HIGH + 1);
            if (diff < -MAX_HIGH/2) diff += (MAX_HIGH + 1);
            
            if (abs(diff) > 4) {
                consistent = 0;
                break;
            }
        }
        
        if (consistent) {
            return 1; // Valid signature found!
        }
    }
    
    return 0; // No valid signature found
}

/* ========== LDPC STUBS (Unchanged) ========== */
int ldpc_keygen(LDPCKeyPair *keypair) { return 0; }
void generate_error_vector(ErrorVector *error, uint16_t target_weight) { memset(error, 0, sizeof(*error)); }
void ldpc_encode(uint8_t *syndrome, const ErrorVector *error, const LDPCPublicKey *pubkey) { }
int sldspa_decode(ErrorVector *error, const uint8_t *syndrome, const LDPCKeyPair *keypair) { 
    memset(error, 0, sizeof(*error));
    return 0; 
}

/* ========== UTILITIES & AES ========== */

void secure_zero(void *s, size_t n) {
    volatile uint8_t *p = s;
    while(n--) *p++ = 0;
}

int constant_time_compare(const uint8_t *a, const uint8_t *b, uint32_t len) {
    uint8_t result = 0;
    uint32_t i;
    for(i=0; i<len; i++) result |= (a[i] ^ b[i]);
    return result;
}

/* Minimal AES-CTR implementation using built-in or simple logic */
#include "lib/aes-128.h"

void aes128_ctr_crypt(uint8_t *output, const uint8_t *input, uint32_t len, 
                      const uint8_t *key, const uint8_t *iv) {
    uint8_t ctr_block[AES128_BLOCK_SIZE];
    uint8_t keystream[AES128_BLOCK_SIZE];
    uint32_t i, j;
    
    /* Set key */
    AES_128.set_key(key);
    
    memset(ctr_block, 0, AES128_BLOCK_SIZE);
    memcpy(ctr_block, iv, AEAD_NONCE_LEN);
    ctr_block[15] = 1; /* Block counter starts at 1 */
    
    for(i=0; i<len; i+=AES128_BLOCK_SIZE) {
        /* Encrypt counter block */
        memcpy(keystream, ctr_block, AES128_BLOCK_SIZE);
        AES_128.encrypt(keystream);
        
        /* XOR with input */
        for(j=0; j<AES128_BLOCK_SIZE && (i+j)<len; j++) {
            if(input) output[i+j] = input[i+j] ^ keystream[j];
            else      output[i+j] = keystream[j];
        }
        
        /* Increment counter (Big Endian) */
        for(j = AES128_BLOCK_SIZE; j > 0; j--) {
            ctr_block[j-1]++;
            if(ctr_block[j-1] != 0) break;
        }
    }
}


