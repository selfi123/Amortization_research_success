#include "contiki.h"
#include "crypto_core.h"
#include "sys/log.h"
#include <stdio.h>
#include <string.h>

#define LOG_MODULE "Test"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Helper to print failure and exit */
void assert_true(int condition, const char *msg) {
    if (!condition) {
        printf("FAIL: %s\n", msg);
        // exit(1); // In Cooja we can't exit, just log
    } else {
        printf("PASS: %s\n", msg);
    }
}

/* Stubs for linker dependencies (AES not used in this test) */
/* Stubs for linker dependencies (AES not used in this test) */
/* AES functions now provided by crypto_core.c */


PROCESS(test_process, "Verification Test Process");
AUTOSTART_PROCESSES(&test_process);

PROCESS_THREAD(test_process, ev, data)
{
    PROCESS_BEGIN();

    printf("=== Starting Standalone Verification Test ===\n");
    
    /* 1. Init PRNG */
    crypto_prng_init(0x12345678);
    printf("PRNG Initialized\n");

    /* 2. Keygen */
    static RingLWEKeyPair keypair;
    int ret = ring_lwe_keygen(&keypair);
    assert_true(ret == 0, "Key Generation");
    
    poly_print("Secret Key", &keypair.secret, 8);
    poly_print("Public Key", &keypair.public, 8);

    /* 3. Ring Setup */
    static Poly512 ring_keys[RING_SIZE];
    ring_keys[0] = keypair.public;
    int i;
    for (i = 1; i < RING_SIZE; i++) {
        generate_ring_member_key(&ring_keys[i], i);
    }
    printf("Ring initialized with %d members\n", RING_SIZE);

    /* 4. Sign */
    static RingSignature sig;
    uint8_t keyword[KEYWORD_SIZE] = "AUTH_REQUEST";
    // Dummy syndrome
    uint8_t syndrome[LDPC_ROWS/8];
    memset(syndrome, 0xAA, sizeof(syndrome));
    
    /* Signature logic needs a message structure or hash binding */
    /* The ring_sign function takes explicit inputs. */
    /* Wait, ring_sign signature: 
       int ring_sign(RingSignature *sig, const uint8_t *keyword,
              const RingLWEKeyPair *signer_keypair,
              const Poly512 ring_pubkeys[RING_SIZE],
              int signer_index);
    */
    
    printf("Signing...\n");
    ret = ring_sign(&sig, keyword, &keypair, ring_keys, 0);
    assert_true(ret == 0, "Signature Generation");

    /* 5. Verify */
    printf("Verifying...\n");
    int verify_ret = ring_verify(&sig, ring_keys);
    assert_true(verify_ret == 1, "Signature Verification");

    if (verify_ret == 1) {
        printf("=== TEST PASSED: Logic is correct ===\n");
    } else {
        printf("=== TEST FAILED: Math issue or Bounds ===\n");
    }

    PROCESS_END();
}
