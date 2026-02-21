#include "contiki.h"
#include <stdio.h>
#include <string.h>
#include "crypto_core.h"

PROCESS(test_crypto_process, "Test Crypto Process");
AUTOSTART_PROCESSES(&test_crypto_process);

PROCESS_THREAD(test_crypto_process, ev, data)
{
    PROCESS_BEGIN();

    printf("Starting Crypto Isolation Test...\n");

    /* Dummy master key and SID */
    uint8_t K_master[MASTER_KEY_LEN];
    uint8_t SID[SID_LEN];
    memset(K_master, 0xAA, MASTER_KEY_LEN);
    memset(SID, 0xBB, SID_LEN);

    /* Sender session state */
    session_ctx_t sender_ctx;
    memcpy(sender_ctx.K_master, K_master, MASTER_KEY_LEN);
    memcpy(sender_ctx.sid, SID, SID_LEN);
    sender_ctx.counter = 1;

    /* Gateway session state */
    session_entry_t gateway_session;
    memcpy(gateway_session.K_master, K_master, MASTER_KEY_LEN);
    memcpy(gateway_session.sid, SID, SID_LEN);
    gateway_session.last_seq = 0;

    /* Message to encrypt */
    char secret_message[] = "Hello IoT #1";
    uint8_t ciphertext[128];
    size_t cipher_len = 0;

    printf("Original message: %s\n", secret_message);

    /* Encrypt */
    int ret = session_encrypt(&sender_ctx, (uint8_t *)secret_message, strlen(secret_message) + 1, ciphertext, &cipher_len);
    if (ret != 0) {
        printf("Encryption failed!\n");
    } else {
        printf("Encryption success! Cipher length: %u\n", (unsigned)cipher_len);
        printf("Ciphertext hex: ");
        for (size_t i = 0; i < cipher_len; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");
    }

    /* Decrypt */
    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    /* Decrypt using Gateway state */
    ret = session_decrypt(&gateway_session, 1, ciphertext, cipher_len, decrypted, &decrypted_len);
    
    if (ret != 0) {
        printf("Decryption failed!\n");
    } else {
        printf("Decryption success! Length: %u\n", (unsigned)decrypted_len);
        printf("Decrypted text: %s\n", (char *)decrypted);
    }

    PROCESS_END();
}
