/**
 * node-gateway.c
 * Gateway Node for Ring-LWE Based IoT Authentication
 * Optimized for Cooja Mote Simulation
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include "crypto_core.h"

#include <string.h>
#include <stdio.h>
#include "sys/rtimer.h"

#define LOG_MODULE "Gateway"
#define LOG_LEVEL LOG_LEVEL_INFO

/* UDP connection */
static struct simple_udp_connection udp_conn;

/* Message types */
#define MSG_TYPE_BASELINE 0x10
#define MSG_TYPE_AUTH_FRAG 0x04
#define MSG_TYPE_FRAG_ACK 0x05

/* Reassembly buffer */
static uint8_t reassembly_buf[3000];

/* ========== MESSAGE STRUCTURES ========== */

typedef struct {
    uint8_t type;
    uint8_t syndrome[LDPC_ROWS / 8];
    Poly512 public_key;
    RingSignature signature;
    uint32_t counter;
    uint16_t cipher_len;
    uint8_t ciphertext[MESSAGE_MAX_SIZE + AEAD_TAG_LEN];
} BaselineMessage;

/* ========== CRYPTOGRAPHIC STATE ========== */

static RingLWEKeyPair gateway_keypair;
static LDPCKeyPair gateway_ldpc_keypair;
static Poly512 ring_public_keys[RING_SIZE];

PROCESS(gateway_process, "Ring-LWE Gateway Process");
AUTOSTART_PROCESSES(&gateway_process);

/* ========== UDP RECEIVE CALLBACK ========== */

static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
    uint8_t msg_type = data[0];
    
    /* Copy sender address because simple_udp_sendto overwrites the shared uip_buf */
    uip_ipaddr_t sender_ip_copy;
    uip_ipaddr_copy(&sender_ip_copy, sender_addr);
    
    LOG_INFO("Received message type 0x%02x\n", msg_type);
    
    if (msg_type == MSG_TYPE_AUTH_FRAG) {
        AuthFragment *frag = (AuthFragment *)data;
        
        uint16_t fragment_id = uip_ntohs(frag->fragment_id);
        uint16_t total_frags = uip_ntohs(frag->total_frags);
        uint16_t payload_len = uip_ntohs(frag->payload_len);
        
        LOG_INFO("Received Fragment %d/%d (%d bytes)\n",
                 fragment_id + 1, total_frags, payload_len);
        
        /* Store payload */
        size_t offset = fragment_id * 64;
        if (offset + payload_len <= sizeof(reassembly_buf)) {
            memcpy(reassembly_buf + offset, frag->payload, payload_len);
        }
        
        /* Send ACK */
        uint8_t ack_buf[3];
        ack_buf[0] = MSG_TYPE_FRAG_ACK;
        ack_buf[1] = data[3]; /* MSB of fragment_id in AuthFragment */
        ack_buf[2] = data[4]; /* LSB of fragment_id in AuthFragment */
        simple_udp_sendto(&udp_conn, ack_buf, sizeof(ack_buf), &sender_ip_copy);
        
        /* Check if last fragment */
        if (fragment_id == total_frags - 1) {
            LOG_INFO("Reassembly complete. Verifying baseline payload...\n");
            
            static BaselineMessage bmsg_store;
            BaselineMessage *bmsg = &bmsg_store;
            size_t offset = 0;
            
            bmsg->type = reassembly_buf[offset++];
            
            /* Counter */
            bmsg->counter = ((uint32_t)reassembly_buf[offset] << 24) |
                            ((uint32_t)reassembly_buf[offset+1] << 16) |
                            ((uint32_t)reassembly_buf[offset+2] << 8) |
                             (uint32_t)reassembly_buf[offset+3];
            offset += 4;
            
            /* Cipher length and text */
            bmsg->cipher_len = ((uint16_t)reassembly_buf[offset] << 8) |
                                (uint16_t)reassembly_buf[offset+1];
            offset += 2;
            
            if (bmsg->cipher_len <= sizeof(bmsg->ciphertext)) {
                memcpy(bmsg->ciphertext, reassembly_buf + offset, bmsg->cipher_len);
            }
            offset += bmsg->cipher_len;
            
            /* Syndrome and Public Key */
            memcpy(bmsg->syndrome, reassembly_buf + offset, LDPC_ROWS / 8);
            offset += LDPC_ROWS / 8;
            
            deserialize_poly512(&bmsg->public_key, reassembly_buf + offset);
            offset += POLY_DEGREE * 4;
            
            /* Signature */
            int i;
            for(i=0; i<RING_SIZE; i++) {
                deserialize_poly512(&bmsg->signature.S[i], reassembly_buf + offset);
                offset += POLY_DEGREE * 4;
            }
            deserialize_poly512(&bmsg->signature.w, reassembly_buf + offset);
            offset += POLY_DEGREE * 4;
            
            memcpy(bmsg->signature.commitment, reassembly_buf + offset, SHA256_DIGEST_SIZE);
            offset += SHA256_DIGEST_SIZE;
            
            memcpy(bmsg->signature.keyword, reassembly_buf + offset, KEYWORD_SIZE);
            offset += KEYWORD_SIZE;
            
            LOG_INFO("Payload Parsed. Counter: %u, Cipher Len: %u\n", (unsigned)bmsg->counter, bmsg->cipher_len);
            
            /* Phase 1: Verify Identity (Ring-LWE) */
            ring_public_keys[0] = bmsg->public_key;
            
            LOG_INFO("Verifying Ring-LWE Signature...\n");
            int verify_result = ring_verify(&bmsg->signature, ring_public_keys);
            
            if (verify_result != 1) {
                LOG_ERR("Ring signature verification FAILED! Rejecting baseline packet.\n");
                return;
            }
            LOG_INFO("Ring signature verified: SUCCESS\n");
            
            /* Phase 2: Decapsulate LDPC KEM */
            LOG_INFO("Decoding LDPC syndrome to recover session error vector...\n");
            ErrorVector recovered_error;
            int decode_ret = sldspa_decode(&recovered_error, bmsg->syndrome, &gateway_ldpc_keypair);
            
            if (decode_ret != 0) {
                LOG_ERR("LDPC decoding failed!\n");
                return;
            }
            LOG_INFO("LDPC decoding successful (weight=%u)\n", recovered_error.hamming_weight);
            
            /* Phase 3: AEAD Decrypt using Error Vector */
            LOG_INFO("Running KEM AES-128-CTR Decryption...\n");
            uint8_t plaintext[MESSAGE_MAX_SIZE];
            size_t plain_len;
            
            int ret = aead_kem_decrypt(&recovered_error, bmsg->ciphertext, bmsg->cipher_len, plaintext, &plain_len);
            
            if (ret != 0) {
                LOG_ERR("KEM AEAD decryption failed (invalid MAC or Key)!\n");
                secure_zero(&recovered_error, sizeof(ErrorVector));
                return;
            }
            
            plaintext[plain_len] = '\0';
            
            printf("========================================================================\n");
            printf("*** BASELINE NOT AMORTIZED DECRYPTED DATA: %s ***\n", plaintext);
            printf("========================================================================\n");
            
            /* Zeroize sensitive data for Baseline */
            secure_zero(&recovered_error, sizeof(ErrorVector));
        }
    }
}

/* ========== GATEWAY PROCESS ========== */

PROCESS_THREAD(gateway_process, ev, data)
{
    static struct etimer periodic_timer;
    int i;
    
    PROCESS_BEGIN();
    
    LOG_INFO("=== Ring-LWE Gateway Node Starting ===\n");
    
    /* Initialize PRNG */
    crypto_prng_init(0xCAFEBABE);
    
    /* ===== KEY GENERATION ===== */
    LOG_INFO("[Initialization] Generating cryptographic keys...\n");
    
    LOG_INFO("1. Generating Ring-LWE keys...\n");
    if (ring_lwe_keygen(&gateway_keypair) != 0) {
        LOG_ERR("Failed to generate Ring-LWE key pair!\n");
        PROCESS_EXIT();
    }
    LOG_INFO("   Ring-LWE key generation: SUCCESS\n");
    
    LOG_INFO("2. Generating QC-LDPC keys...\n");
    if (ldpc_keygen(&gateway_ldpc_keypair) != 0) {
        LOG_ERR("Failed to generate LDPC key pair!\n");
        PROCESS_EXIT();
    }
    LOG_INFO("   LDPC matrix generation: SUCCESS\n");
    
    /* Initialize ring public keys */
    LOG_INFO("3. Initializing ring member public keys...\n");
    
    /* Ring member 0 (Sender) key is received in AuthMessage */
    /* We initialize it to zero here to be safe */
    memset(&ring_public_keys[0], 0, sizeof(Poly512));
    
    /* Generate fake ring members */
    for (i = 1; i < RING_SIZE; i++) {
        generate_ring_member_key(&ring_public_keys[i], i);
        LOG_INFO("   - Ring member %d public key generated\n", i + 1);
    }
    LOG_INFO("   Ring setup complete\n");
    
    LOG_INFO("\n=== Gateway Ready ===\n");
    LOG_INFO("Configuration:\n");
    LOG_INFO("  - Polynomial degree (n): %d\n", POLY_DEGREE);
    LOG_INFO("  - Modulus (q): %ld\n", (long)MODULUS_Q);
    LOG_INFO("  - Ring size (N): %d\n", RING_SIZE);
    LOG_INFO("  - LDPC dimensions: %dx%d\n", LDPC_ROWS, LDPC_COLS);
    LOG_INFO("\nListening on UDP port %d...\n\n", UDP_PORT);
    
    /* Initialize UDP */
    simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_rx_callback);
    
    /* Become RPL DAG root */
    NETSTACK_ROUTING.root_start();
    
    /* Main event loop */
    while(1) {
        etimer_set(&periodic_timer, 60 * CLOCK_SECOND);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
        LOG_INFO("[Status] Gateway operational\n");
    }
    
    PROCESS_END();
}
