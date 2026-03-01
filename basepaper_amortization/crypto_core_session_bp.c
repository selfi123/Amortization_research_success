/**
 * crypto_core_session.c
 * Session Amortization Cryptographic Primitives
 * Implements HMAC-SHA256, HKDF, AEAD, and session key derivation
 * Optimized for Cooja Mote
 */

#include "crypto_core_bp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ========== SECURE MEMORY OPERATIONS ========== */

void secure_zero(void *ptr, size_t len) __attribute__((weak));
void crypto_secure_random(uint8_t *output, size_t len) __attribute__((weak));

/* ========== HMAC-SHA256 IMPLEMENTATION ========== */

void hmac_sha256(uint8_t *output, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len) {
    uint8_t k_pad[64];
    uint8_t i_key_pad[64], o_key_pad[64];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    uint8_t inner_msg[256]; // Fixed size buffer for embedded systems
    uint8_t outer_msg[64 + SHA256_DIGEST_SIZE];
    size_t i;
    
    /* Prepare key */
    memset(k_pad, 0, 64);
    if (key_len > 64) {
        sha256_hash(k_pad, key, key_len);
    } else {
        memcpy(k_pad, key, key_len);
    }
    
    /* Inner and outer pads */
    for (i = 0; i < 64; i++) {
        i_key_pad[i] = k_pad[i] ^ 0x36;
        o_key_pad[i] = k_pad[i] ^ 0x5c;
    }
    
    /* Inner hash: H(K ⊕ ipad || message) */
    if (msg_len > 192) msg_len = 192; // Limit for embedded
    
    memcpy(inner_msg, i_key_pad, 64);
    memcpy(inner_msg + 64, msg, msg_len);
    sha256_hash(inner_hash, inner_msg, 64 + msg_len);
    
    /* Outer hash: H(K ⊕ opad || inner_hash) */
    memcpy(outer_msg, o_key_pad, 64);
    memcpy(outer_msg + 64, inner_hash, SHA256_DIGEST_SIZE);
    sha256_hash(output, outer_msg, 64 + SHA256_DIGEST_SIZE);
    
    /* Zeroize sensitive data */
    secure_zero(k_pad, 64);
    secure_zero(i_key_pad, 64);
    secure_zero(o_key_pad, 64);
    secure_zero(inner_hash, SHA256_DIGEST_SIZE);
}

/* ========== HKDF-SHA256 IMPLEMENTATION ========== */

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
    uint8_t hmac_input[SHA256_DIGEST_SIZE + 32 + 1]; // Limited size for embedded
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
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    uint8_t prk[SHA256_DIGEST_SIZE];
    
    hkdf_extract(prk, salt, salt_len, ikm, ikm_len);
    hkdf_expand(okm, okm_len, prk, info, info_len);
    secure_zero(prk, SHA256_DIGEST_SIZE);
    
    return 0;
}

/* ========== AEAD IMPLEMENTATION ========== */

int aead_encrypt(uint8_t *output, size_t *output_len,
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    uint8_t enc_key[16], mac_key[32];
    uint8_t kdf_input[33];
    uint8_t mac_input[256];
    uint8_t tag[SHA256_DIGEST_SIZE];
    uint8_t temp_hash[SHA256_DIGEST_SIZE];
    
    /* limit sizes for embedded */
    if (pt_len > 128) return -1;
    if (aad_len > 64) return -1;
    
    /* Derive encryption key */
    memcpy(kdf_input, key, 32);
    kdf_input[32] = 0x01;
    sha256_hash(temp_hash, kdf_input, 33);
    memcpy(enc_key, temp_hash, 16);
    
    /* Derive MAC key */
    kdf_input[32] = 0x02;
    sha256_hash(mac_key, kdf_input, 33);
    
    /* Encrypt */
    aes128_ctr_crypt(output, plaintext, pt_len, enc_key, nonce);
    
    /* Compute MAC over AAD || C */
    if (aad_len > 0) {
        memcpy(mac_input, aad, aad_len);
    }
    memcpy(mac_input + aad_len, output, pt_len);
    
    hmac_sha256(tag, mac_key, 32, mac_input, aad_len + pt_len);
    
    /* Append tag */
    memcpy(output + pt_len, tag, AEAD_TAG_LEN);
    *output_len = pt_len + AEAD_TAG_LEN;
    
    /* Cleanup */
    secure_zero(enc_key, 16);
    secure_zero(mac_key, 32);
    secure_zero(tag, SHA256_DIGEST_SIZE);
    
    return 0;
}

int aead_decrypt(uint8_t *output, size_t *output_len,
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    uint8_t enc_key[16], mac_key[32];
    uint8_t kdf_input[33];
    uint8_t mac_input[256];
    uint8_t expected_tag[SHA256_DIGEST_SIZE];
   uint8_t temp_hash[SHA256_DIGEST_SIZE];
    size_t pt_len;
    
    if (ct_len < AEAD_TAG_LEN) return -1;
    if (aad_len > 64) return -1;
    
    pt_len = ct_len - AEAD_TAG_LEN;
    
    /* Derive keys */
    memcpy(kdf_input, key, 32);
    kdf_input[32] = 0x01;
    sha256_hash(temp_hash, kdf_input, 33);
    memcpy(enc_key, temp_hash, 16);
    kdf_input[32] = 0x02;
    sha256_hash(mac_key, kdf_input, 33);
    
    /* Verify MAC */
    if (aad_len > 0) {
        memcpy(mac_input, aad, aad_len);
    }
    memcpy(mac_input + aad_len, ciphertext, pt_len);
    
    hmac_sha256(expected_tag, mac_key, 32, mac_input, aad_len + pt_len);
    
    if (constant_time_compare(expected_tag, ciphertext + pt_len, AEAD_TAG_LEN) != 0) {
        secure_zero(enc_key, 16);
        secure_zero(mac_key, 32);
        return -1;
    }
    
    /* Decrypt */
    aes128_ctr_crypt(output, ciphertext, pt_len, enc_key, nonce);
    *output_len = pt_len;
    
    secure_zero(enc_key, 16);
    secure_zero(mac_key, 32);
    
    return 0;
}

/* ========== SESSION KEY DERIVATION ========== */

void derive_master_key(uint8_t *K_master,
                      const uint8_t *error, size_t err_len,
                      const uint8_t *gateway_nonce, size_t nonce_len) {
    uint8_t ikm[256];
    const uint8_t info[] = "master-key";
    size_t ikm_len;
    
    /* Limit sizes */
    if (err_len > 192) err_len = 192;
    if (nonce_len > 64) nonce_len = 64;
    
    memcpy(ikm, error, err_len);
    memcpy(ikm + err_len, gateway_nonce, nonce_len);
    ikm_len = err_len + nonce_len;
    
    hkdf_sha256(NULL, 0, ikm, ikm_len,
               info, sizeof(info) - 1,
               K_master, MASTER_KEY_LEN);
               
    printf("[Crypto Core] K_master[0-7] = %02x%02x%02x%02x%02x%02x%02x%02x\n",
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
    info[info_len++] = (counter >> 8) & 0xFF;
    info[info_len++] = counter & 0xFF;
    
    hkdf_sha256(NULL, 0, K_master, MASTER_KEY_LEN,
               info, info_len, K_i, 32);
}

int session_encrypt(session_ctx_t *ctx,
                   const uint8_t *plaintext, size_t pt_len,
                   uint8_t *out, size_t *out_len) {
    uint8_t K_i[32];
    uint8_t nonce[AEAD_NONCE_LEN];
    
    derive_message_key(K_i, ctx->K_master, ctx->sid, SID_LEN, ctx->counter);
    
    memcpy(nonce, ctx->sid, SID_LEN);
    nonce[8] = (ctx->counter >> 24) & 0xFF;
    nonce[9] = (ctx->counter >> 16) & 0xFF;
    nonce[10] = (ctx->counter >> 8) & 0xFF;
    nonce[11] = ctx->counter & 0xFF;
    
    uint8_t aad[SID_LEN + 4];
    memcpy(aad, ctx->sid, SID_LEN);
    aad[SID_LEN] = (ctx->counter >> 24) & 0xFF;
    aad[SID_LEN + 1] = (ctx->counter >> 16) & 0xFF;
    aad[SID_LEN + 2] = (ctx->counter >> 8) & 0xFF;
    aad[SID_LEN + 3] = ctx->counter & 0xFF;
    
    int ret = aead_encrypt(out, out_len, plaintext, pt_len,
                          aad, sizeof(aad), K_i, nonce);
    
    secure_zero(K_i, sizeof(K_i));
    return ret;
}

int session_decrypt(session_entry_t *se, uint32_t counter,
                   const uint8_t *ct, size_t ct_len,
                   uint8_t *out, size_t *out_len) {
    uint8_t K_i[32];
    uint8_t nonce[AEAD_NONCE_LEN];
    
    if (counter <= se->last_seq) {
        return -1; // Replay attack
    }
    
    derive_message_key(K_i, se->K_master, se->sid, SID_LEN, counter);
    
    memcpy(nonce, se->sid, SID_LEN);
    nonce[8] = (counter >> 24) & 0xFF;
    nonce[9] = (counter >> 16) & 0xFF;
    nonce[10] = (counter >> 8) & 0xFF;
    nonce[11] = counter & 0xFF;
    
    uint8_t aad[SID_LEN + 4];
    memcpy(aad, se->sid, SID_LEN);
    aad[SID_LEN] = (counter >> 24) & 0xFF;
    aad[SID_LEN + 1] = (counter >> 16) & 0xFF;
    aad[SID_LEN + 2] = (counter >> 8) & 0xFF;
    aad[SID_LEN + 3] = counter & 0xFF;
    
    int ret = aead_decrypt(out, out_len, ct, ct_len,
                          aad, sizeof(aad), K_i, nonce);
    
    if (ret == 0) {
        se->last_seq = counter;
    }
    
    secure_zero(K_i, sizeof(K_i));
    return ret;
}
