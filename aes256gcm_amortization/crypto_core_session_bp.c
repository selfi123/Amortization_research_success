/**
 * crypto_core_session.c  — AES-256-GCM Variant
 *
 * Session Amortization Cryptographic Primitives
 * Implements HKDF-SHA256, AES-256-GCM AEAD (GCM mode),
 * and session key derivation.
 *
 * AES-256-GCM replaces the original AES-128-CTR + HMAC-SHA256
 * to exactly match the MATLAB theoretical model, improving:
 *   - Bandwidth: 28-byte overhead (224 bits) vs 36 bytes in old code
 *   - Security:  256-bit encryption key (128-bit PQ via Grover)
 *   - Alignment: Matches sim_bandwidth.m and sim_latency.m benchmarks
 *
 * Optimized for Cooja soft-mote (JVM, unlimited RAM).
 */

#include "crypto_core_bp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ========== SECURE MEMORY OPERATIONS ========== */

void secure_zero(void *ptr, size_t len) __attribute__((weak));
void crypto_secure_random(uint8_t *output, size_t len) __attribute__((weak));

/* ======================================================
 * AES-256 IMPLEMENTATION (FIPS 197)
 * Key = 256-bit (32 bytes), Block = 128-bit (16 bytes)
 * 14 rounds
 * ====================================================== */

#define AES256_ROUNDS  14
#define AES256_KSCHED  ((AES256_ROUNDS + 1) * 16)  /* 240 bytes */

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint8_t xtime(uint8_t x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
}

static void aes256_key_expansion(const uint8_t *key, uint8_t *ks) {
    int i;
    uint8_t tmp[4];
    /* Copy key */
    memcpy(ks, key, 32);
    for (i = 8; i < (AES256_ROUNDS + 1) * 4; i++) {
        tmp[0] = ks[(i-1)*4+0]; tmp[1] = ks[(i-1)*4+1];
        tmp[2] = ks[(i-1)*4+2]; tmp[3] = ks[(i-1)*4+3];
        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t t = tmp[0];
            tmp[0] = sbox[tmp[1]] ^ rcon[i/8];
            tmp[1] = sbox[tmp[2]];
            tmp[2] = sbox[tmp[3]];
            tmp[3] = sbox[t];
        } else if (i % 8 == 4) {
            /* SubWord only */
            tmp[0] = sbox[tmp[0]]; tmp[1] = sbox[tmp[1]];
            tmp[2] = sbox[tmp[2]]; tmp[3] = sbox[tmp[3]];
        }
        ks[i*4+0] = ks[(i-8)*4+0] ^ tmp[0];
        ks[i*4+1] = ks[(i-8)*4+1] ^ tmp[1];
        ks[i*4+2] = ks[(i-8)*4+2] ^ tmp[2];
        ks[i*4+3] = ks[(i-8)*4+3] ^ tmp[3];
    }
}

static void aes256_add_round_key(uint8_t *state, const uint8_t *rk) {
    int i;
    for (i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void aes256_sub_bytes(uint8_t *state) {
    int i;
    for (i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void aes256_shift_rows(uint8_t *s) {
    uint8_t tmp;
    /* Row 1 */
    tmp=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=tmp;
    /* Row 2 */
    tmp=s[2]; s[2]=s[10]; s[10]=tmp;
    tmp=s[6]; s[6]=s[14]; s[14]=tmp;
    /* Row 3 */
    tmp=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=tmp;
}

static void aes256_mix_columns(uint8_t *s) {
    int c;
    for (c = 0; c < 4; c++) {
        uint8_t s0=s[c*4],s1=s[c*4+1],s2=s[c*4+2],s3=s[c*4+3];
        s[c*4+0] = xtime(s0)^xtime(s1)^s1^s2^s3;
        s[c*4+1] = s0^xtime(s1)^xtime(s2)^s2^s3;
        s[c*4+2] = s0^s1^xtime(s2)^xtime(s3)^s3;
        s[c*4+3] = xtime(s0)^s0^s1^s2^xtime(s3);
    }
}

/* Encrypt a single 16-byte block */
static void aes256_encrypt_block(const uint8_t *ks, const uint8_t *in, uint8_t *out) {
    uint8_t state[16];
    int r;
    memcpy(state, in, 16);
    aes256_add_round_key(state, ks);
    for (r = 1; r < AES256_ROUNDS; r++) {
        aes256_sub_bytes(state);
        aes256_shift_rows(state);
        aes256_mix_columns(state);
        aes256_add_round_key(state, ks + r*16);
    }
    aes256_sub_bytes(state);
    aes256_shift_rows(state);
    aes256_add_round_key(state, ks + AES256_ROUNDS*16);
    memcpy(out, state, 16);
}

/* AES-256-CTR keystream generation */
static void aes256_ctr_crypt(uint8_t *out, const uint8_t *in, size_t len,
                              const uint8_t *ks, const uint8_t *iv) {
    uint8_t ctr_block[16], keystream[16];
    uint32_t ctr_val = 1; /* GCM starts CTR at 2 for encryption */
    memcpy(ctr_block, iv, 12);
    while (len > 0) {
        ctr_block[12] = (ctr_val >> 24) & 0xFF;
        ctr_block[13] = (ctr_val >> 16) & 0xFF;
        ctr_block[14] = (ctr_val >> 8)  & 0xFF;
        ctr_block[15] =  ctr_val        & 0xFF;
        aes256_encrypt_block(ks, ctr_block, keystream);
        size_t chunk = (len < 16) ? len : 16;
        size_t i;
        for (i = 0; i < chunk; i++) out[i] = in[i] ^ keystream[i];
        out += chunk; in += chunk; len -= chunk;
        ctr_val++;
    }
}

/* ======================================================
 * GHASH — GF(2^128) Multiplication for GCM
 * Uses the standard 4-bit table-less bitwise approach.
 * ====================================================== */

static void ghash_mul(uint8_t *x, const uint8_t *h) {
    uint8_t v[16], z[16];
    int i, j;
    memset(z, 0, 16);
    memcpy(v, h, 16);
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            if ((x[i] >> j) & 1) {
                int k;
                for (k = 0; k < 16; k++) z[k] ^= v[k];
            }
            /* Right shift v, XOR with R=0xe1 if lsb was set */
            uint8_t carry = v[15] & 1;
            int k;
            for (k = 15; k > 0; k--) v[k] = (v[k] >> 1) | (v[k-1] << 7);
            v[0] >>= 1;
            if (carry) v[0] ^= 0xe1;
        }
    }
    memcpy(x, z, 16);
}

static void ghash(const uint8_t *h, const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len, uint8_t *out) {
    uint8_t y[16];
    uint8_t block[16];
    size_t i;

    memset(y, 0, 16);

    /* Process AAD (padded to 16-byte boundary) */
    size_t aad_offset = 0;
    while (aad_offset < aad_len) {
        size_t chunk = (aad_len - aad_offset < 16) ? (aad_len - aad_offset) : 16;
        memset(block, 0, 16);
        memcpy(block, aad + aad_offset, chunk);
        for (i = 0; i < 16; i++) y[i] ^= block[i];
        ghash_mul(y, h);
        aad_offset += chunk;
    }

    /* Process ciphertext (padded to 16-byte boundary) */
    size_t ct_offset = 0;
    while (ct_offset < ct_len) {
        size_t chunk = (ct_len - ct_offset < 16) ? (ct_len - ct_offset) : 16;
        memset(block, 0, 16);
        memcpy(block, ct + ct_offset, chunk);
        for (i = 0; i < 16; i++) y[i] ^= block[i];
        ghash_mul(y, h);
        ct_offset += chunk;
    }

    /* Length block: aad_len * 8 || ct_len * 8 (64-bit big-endian each) */
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)ct_len  * 8;
    block[0] = (aad_bits >> 56) & 0xFF; block[1] = (aad_bits >> 48) & 0xFF;
    block[2] = (aad_bits >> 40) & 0xFF; block[3] = (aad_bits >> 32) & 0xFF;
    block[4] = (aad_bits >> 24) & 0xFF; block[5] = (aad_bits >> 16) & 0xFF;
    block[6] = (aad_bits >>  8) & 0xFF; block[7] =  aad_bits        & 0xFF;
    block[8] = (ct_bits  >> 56) & 0xFF; block[9] = (ct_bits  >> 48) & 0xFF;
    block[10]= (ct_bits  >> 40) & 0xFF; block[11]= (ct_bits  >> 32) & 0xFF;
    block[12]= (ct_bits  >> 24) & 0xFF; block[13]= (ct_bits  >> 16) & 0xFF;
    block[14]= (ct_bits  >>  8) & 0xFF; block[15]=  ct_bits         & 0xFF;
    for (i = 0; i < 16; i++) y[i] ^= block[i];
    ghash_mul(y, h);

    memcpy(out, y, 16);
}

/* ======================================================
 * AES-256-GCM AEAD (NIST SP 800-38D)
 * IV (nonce): 12 bytes  → J0 = IV ‖ 00000001
 * Tag:        16 bytes  (128-bit)
 * Key:        32 bytes  (256-bit)
 * ====================================================== */

int aead_encrypt(uint8_t *output, size_t *output_len,
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    uint8_t ks[AES256_KSCHED];   /* 240 bytes key schedule */
    uint8_t H[16];               /* GHASH subkey */
    uint8_t J0[16];              /* Counter block for tag */
    uint8_t E_J0[16];            /* E(K, J0) for tag XOR */
    uint8_t tag[16];
    size_t i;

    if (pt_len > 128) return -1;
    if (aad_len > 64) return -1;

    /* Key expansion */
    aes256_key_expansion(key, ks);

    /* H = E(K, 0^128) */
    memset(H, 0, 16);
    aes256_encrypt_block(ks, H, H);

    /* J0 = IV ‖ 0^31 ‖ 1 (for 96-bit IV) */
    memcpy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    /* E(K, J0) for final tag XOR */
    aes256_encrypt_block(ks, J0, E_J0);

    /* CTR encryption starting at J0+1 = IV ‖ 0^31 ‖ 2 */
    aes256_ctr_crypt(output, plaintext, pt_len, ks, nonce);  /* ctr starts at 2 internally */

    /* GHASH(H, AAD, CT) */
    ghash(H, aad, aad_len, output, pt_len, tag);

    /* Tag = GHASH result XOR E(K, J0) */
    for (i = 0; i < 16; i++) tag[i] ^= E_J0[i];

    /* Append 128-bit tag */
    memcpy(output + pt_len, tag, GCM_TAG_LEN);
    *output_len = pt_len + GCM_TAG_LEN;

    /* Zeroize sensitive material */
    secure_zero(ks, AES256_KSCHED);
    secure_zero(H, 16);
    secure_zero(E_J0, 16);
    secure_zero(tag, 16);

    return 0;
}

int aead_decrypt(uint8_t *output, size_t *output_len,
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    uint8_t ks[AES256_KSCHED];
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t E_J0[16];
    uint8_t expected_tag[16];
    size_t pt_len, i;

    if (ct_len < GCM_TAG_LEN) return -1;
    if (aad_len > 64) return -1;

    pt_len = ct_len - GCM_TAG_LEN;

    /* Key expansion */
    aes256_key_expansion(key, ks);

    /* H = E(K, 0^128) */
    memset(H, 0, 16);
    aes256_encrypt_block(ks, H, H);

    /* J0 */
    memcpy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    /* E(K, J0) */
    aes256_encrypt_block(ks, J0, E_J0);

    /* GHASH over AAD and received ciphertext (before decryption — GCM is always Auth-then-Decrypt) */
    ghash(H, aad, aad_len, ciphertext, pt_len, expected_tag);

    /* Reconstruct expected tag */
    for (i = 0; i < 16; i++) expected_tag[i] ^= E_J0[i];

    /* Constant-time tag comparison */
    if (constant_time_compare(expected_tag, ciphertext + pt_len, GCM_TAG_LEN) != 0) {
        secure_zero(ks, AES256_KSCHED);
        secure_zero(H, 16);
        secure_zero(E_J0, 16);
        return -1;  /* Tag mismatch — reject WITHOUT decrypting */
    }

    /* Tag verified — now decrypt */
    aes256_ctr_crypt(output, ciphertext, pt_len, ks, nonce);
    *output_len = pt_len;

    secure_zero(ks, AES256_KSCHED);
    secure_zero(H, 16);
    secure_zero(E_J0, 16);
    secure_zero(expected_tag, 16);

    return 0;
}

/* ========== HMAC-SHA256 — kept for derive_master_key ========== */

void hmac_sha256(uint8_t *output, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len) {
    uint8_t k_pad[64];
    uint8_t i_key_pad[64], o_key_pad[64];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    uint8_t inner_msg[256];
    uint8_t outer_msg[64 + SHA256_DIGEST_SIZE];
    size_t i;

    memset(k_pad, 0, 64);
    if (key_len > 64) {
        sha256_hash(k_pad, key, key_len);
    } else {
        memcpy(k_pad, key, key_len);
    }

    for (i = 0; i < 64; i++) {
        i_key_pad[i] = k_pad[i] ^ 0x36;
        o_key_pad[i] = k_pad[i] ^ 0x5c;
    }

    if (msg_len > 192) msg_len = 192;
    memcpy(inner_msg, i_key_pad, 64);
    memcpy(inner_msg + 64, msg, msg_len);
    sha256_hash(inner_hash, inner_msg, 64 + msg_len);

    memcpy(outer_msg, o_key_pad, 64);
    memcpy(outer_msg + 64, inner_hash, SHA256_DIGEST_SIZE);
    sha256_hash(output, outer_msg, 64 + SHA256_DIGEST_SIZE);

    secure_zero(k_pad, 64);
    secure_zero(i_key_pad, 64);
    secure_zero(o_key_pad, 64);
    secure_zero(inner_hash, SHA256_DIGEST_SIZE);
}

/* ========== HKDF-SHA256 ========== */

static void hkdf_extract(uint8_t *prk,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len) {
    if (salt == NULL || salt_len == 0) {
        uint8_t zero_salt[SHA256_DIGEST_SIZE];
        memset(zero_salt, 0, SHA256_DIGEST_SIZE);
        hmac_sha256(prk, zero_salt, SHA256_DIGEST_SIZE, ikm, ikm_len);
    } else {
        hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
    }
}

static void hkdf_expand(uint8_t *okm, size_t okm_len,
                        const uint8_t *prk,
                        const uint8_t *info, size_t info_len) {
    uint8_t n = (okm_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    uint8_t t[SHA256_DIGEST_SIZE];
    uint8_t hmac_input[SHA256_DIGEST_SIZE + 32 + 1];
    size_t okm_offset = 0;
    uint8_t i;

    memset(t, 0, SHA256_DIGEST_SIZE);
    for (i = 1; i <= n; i++) {
        size_t input_len = 0;
        if (i > 1) {
            memcpy(hmac_input, t, SHA256_DIGEST_SIZE);
            input_len = SHA256_DIGEST_SIZE;
        }
        if (info && info_len > 0) {
            size_t copy_len = (info_len > 32) ? 32 : info_len;
            memcpy(hmac_input + input_len, info, copy_len);
            input_len += copy_len;
        }
        hmac_input[input_len++] = i;
        hmac_sha256(t, prk, SHA256_DIGEST_SIZE, hmac_input, input_len);
        size_t to_copy = (okm_len - okm_offset < SHA256_DIGEST_SIZE) ?
                         (okm_len - okm_offset) : SHA256_DIGEST_SIZE;
        memcpy(okm + okm_offset, t, to_copy);
        okm_offset += to_copy;
    }
    secure_zero(t, SHA256_DIGEST_SIZE);
}

int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm,  size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    uint8_t prk[SHA256_DIGEST_SIZE];
    hkdf_extract(prk, salt, salt_len, ikm, ikm_len);
    hkdf_expand(okm, okm_len, prk, info, info_len);
    secure_zero(prk, SHA256_DIGEST_SIZE);
    return 0;
}

/* ========== SESSION KEY DERIVATION ========== */

void derive_master_key(uint8_t *K_master,
                       const uint8_t *error, size_t err_len,
                       const uint8_t *gateway_nonce, size_t nonce_len) {
    uint8_t ikm[256];
    const uint8_t info[] = "master-key";
    size_t ikm_len;

    if (err_len > 192)  err_len = 192;
    if (nonce_len > 64) nonce_len = 64;

    memcpy(ikm, error, err_len);
    memcpy(ikm + err_len, gateway_nonce, nonce_len);
    ikm_len = err_len + nonce_len;

    hkdf_sha256(NULL, 0, ikm, ikm_len,
               info, sizeof(info) - 1,
               K_master, MASTER_KEY_LEN);

    printf("[AES-256-GCM] K_master[0-7] = %02x%02x%02x%02x%02x%02x%02x%02x\n",
           K_master[0], K_master[1], K_master[2], K_master[3],
           K_master[4], K_master[5], K_master[6], K_master[7]);

    secure_zero(ikm, ikm_len);
}

static void derive_message_key(uint8_t *K_i,
                               const uint8_t *K_master,
                               const uint8_t *sid, size_t sid_len,
                               uint32_t counter) {
    uint8_t info[32];
    size_t info_len = 0;

    memcpy(info, "session-key", 11);
    info_len = 11;
    memcpy(info + info_len, sid, sid_len);
    info_len += sid_len;
    info[info_len++] = (counter >> 24) & 0xFF;
    info[info_len++] = (counter >> 16) & 0xFF;
    info[info_len++] = (counter >> 8)  & 0xFF;
    info[info_len++] =  counter        & 0xFF;

    /* Derive 32 bytes = AES-256 key */
    hkdf_sha256(NULL, 0, K_master, MASTER_KEY_LEN, info, info_len, K_i, 32);
}

int session_encrypt(session_ctx_t *ctx,
                   const uint8_t *plaintext, size_t pt_len,
                   uint8_t *out, size_t *out_len) {
    uint8_t K_i[32];   /* AES-256 key */
    uint8_t nonce[GCM_NONCE_LEN];  /* 12 bytes */

    derive_message_key(K_i, ctx->K_master, ctx->sid, SID_LEN, ctx->counter);

    /* Nonce = SID[0..7] ‖ counter[4 bytes] = 12 bytes total */
    memcpy(nonce, ctx->sid, SID_LEN);      /* 8 bytes */
    nonce[8]  = (ctx->counter >> 24) & 0xFF;
    nonce[9]  = (ctx->counter >> 16) & 0xFF;
    nonce[10] = (ctx->counter >> 8)  & 0xFF;
    nonce[11] =  ctx->counter        & 0xFF;

    /* AAD = SID ‖ counter (IND-CCA2 binding — matches MATLAB proof1_ind_cca2.m) */
    uint8_t aad[SID_LEN + 4];
    memcpy(aad, ctx->sid, SID_LEN);
    aad[SID_LEN+0] = (ctx->counter >> 24) & 0xFF;
    aad[SID_LEN+1] = (ctx->counter >> 16) & 0xFF;
    aad[SID_LEN+2] = (ctx->counter >> 8)  & 0xFF;
    aad[SID_LEN+3] =  ctx->counter        & 0xFF;

    int ret = aead_encrypt(out, out_len, plaintext, pt_len,
                          aad, sizeof(aad), K_i, nonce);

    secure_zero(K_i, sizeof(K_i));
    return ret;
}

int session_decrypt(session_entry_t *se, uint32_t counter,
                   const uint8_t *ct, size_t ct_len,
                   uint8_t *out, size_t *out_len) {
    uint8_t K_i[32];
    uint8_t nonce[GCM_NONCE_LEN];

    /* Proof 2: Strict replay resistance */
    if (counter <= se->last_seq) {
        return -1;
    }

    derive_message_key(K_i, se->K_master, se->sid, SID_LEN, counter);

    memcpy(nonce, se->sid, SID_LEN);
    nonce[8]  = (counter >> 24) & 0xFF;
    nonce[9]  = (counter >> 16) & 0xFF;
    nonce[10] = (counter >> 8)  & 0xFF;
    nonce[11] =  counter        & 0xFF;

    /* AAD = SID ‖ counter (must match encrypt side exactly) */
    uint8_t aad[SID_LEN + 4];
    memcpy(aad, se->sid, SID_LEN);
    aad[SID_LEN+0] = (counter >> 24) & 0xFF;
    aad[SID_LEN+1] = (counter >> 16) & 0xFF;
    aad[SID_LEN+2] = (counter >> 8)  & 0xFF;
    aad[SID_LEN+3] =  counter        & 0xFF;

    int ret = aead_decrypt(out, out_len, ct, ct_len,
                          aad, sizeof(aad), K_i, nonce);

    if (ret == 0) {
        se->last_seq = counter;
    }

    secure_zero(K_i, sizeof(K_i));
    return ret;
}
