/**
 * node-sender.c
 * Sender Node for Ring-LWE Based IoT Authentication
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
#include "sys/energest.h"

#define LOG_MODULE "Sender"
#define LOG_LEVEL LOG_LEVEL_INFO

/* UDP connection */
static struct simple_udp_connection udp_conn;

/* Message types */
#define MSG_TYPE_BASELINE 0x10
#define MSG_TYPE_AUTH_FRAG 0x04
#define MSG_TYPE_FRAG_ACK 0x05

/* Fragmentation state */
static volatile int last_ack_received = -1;

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

static RingLWEKeyPair sender_keypair;
static LDPCPublicKey shared_ldpc_pubkey;
static ErrorVector auth_error_vector;
static uint8_t syndrome[LDPC_ROWS / 8];

/* Message to encrypt */
static const char *secret_message = "Hello Baseline IoT";
#define RENEW_THRESHOLD 20   /* Renew session after 20 messages */
#define DATA_INTERVAL 5      /* Send 1 message every 5 seconds */

PROCESS(sender_process, "Ring-LWE Sender Process");
AUTOSTART_PROCESSES(&sender_process);

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
    
    if (msg_type == MSG_TYPE_FRAG_ACK) {
        FragmentAck *ack = (FragmentAck *)data;
        uint16_t ack_frag_id = uip_ntohs(ack->fragment_id);
        last_ack_received = ack_frag_id;
        process_poll(&sender_process);
        return;
    }
}

/* ========== SENDER PROCESS ========== */

PROCESS_THREAD(sender_process, ev, data)
{
    static struct etimer periodic_timer;
    static uip_ipaddr_t dest_ipaddr;
    int i;
    
    PROCESS_BEGIN();
    
    LOG_INFO("=== Ring-LWE Sender Node Starting ===\n");
    
    /* Initialize PRNG */
    uint32_t sender_seed = 0x12345678;
    crypto_prng_init(sender_seed);
    
    /* ===== KEY GENERATION ===== */
    LOG_INFO("[Phase 1] Generating Ring-LWE keys...\n");
    
    if (ring_lwe_keygen(&sender_keypair) != 0) {
        LOG_ERR("Failed to generate Ring-LWE key pair!\n");
        PROCESS_EXIT();
    }
    
    LOG_INFO("Ring-LWE key generation successful\n");
    poly_print("Sender PubKey", &sender_keypair.public, 8);
    
    /* Generate ring public keys */
    LOG_INFO("Generating ring public keys...\n");
    static Poly512 ring_public_keys[RING_SIZE];
    
    ring_public_keys[0] = sender_keypair.public;
    LOG_INFO("  - Ring member 1 (Sender): Real key\n");
    
    for (i = 1; i < RING_SIZE; i++) {
        generate_ring_member_key(&ring_public_keys[i], i);
        LOG_INFO("  - Ring member %d: Fake key\n", i + 1);
    }
    
    /* Initialize UDP */
    simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_rx_callback);
    
    /* Wait for network */
    LOG_INFO("Waiting for network initialization...\n");
    etimer_set(&periodic_timer, 5 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    
    /* Get gateway address */
    if(NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
        LOG_INFO("Gateway address obtained\n");
    } else {
        uip_create_linklocal_allnodes_mcast(&dest_ipaddr);
        LOG_INFO("Using multicast for gateway discovery\n");
    }
    
    /* Allow routing to stabilize */
    LOG_INFO("Allowing network routing to stabilize (10s)...\n");
    etimer_set(&periodic_timer, 10 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    
    static uint32_t baseline_seq_no = 1;
    
    // BASELINE LOOP: Authenticate and Send Data every interval
    while(1) {
        printf("\n======================================================\n");
        printf("*** [BASELINE] GENERATING NEW CONSTANT-TIME HANDSHAKE #%u ***\n", (unsigned)baseline_seq_no);
        printf("======================================================\n");
    
        /* Generate new LDPC public key for every single transmission (baseline is heavy) */
        LOG_INFO("Initializing LDPC public key...\n");
        if (ldpc_keygen((LDPCKeyPair *)&shared_ldpc_pubkey) != 0) {
            LOG_ERR("Failed to generate LDPC key!\n");
            PROCESS_EXIT();
        }
    
        /* Generate ephemeral error vector */
        LOG_INFO("Generating LDPC error vector...\n");
        generate_error_vector(&auth_error_vector, 50);
        
        /* Encode syndrome */
        LOG_INFO("Encoding syndrome...\n");
        ldpc_encode(syndrome, &auth_error_vector, &shared_ldpc_pubkey);
    
        /* Prepare keyword */
        uint8_t keyword[KEYWORD_SIZE];
        memset(keyword, 0, KEYWORD_SIZE);
        snprintf((char *)keyword, KEYWORD_SIZE, "BASELINE_AUTH_%u", (unsigned)baseline_seq_no);
    
        /* Generate heavy ring signature for THIS specific message */
        LOG_INFO("Generating ring signature (N=%d members)...\n", RING_SIZE);
        static BaselineMessage bmsg;
        bmsg.type = MSG_TYPE_BASELINE;
        memcpy(bmsg.syndrome, syndrome, LDPC_ROWS / 8);
        bmsg.public_key = sender_keypair.public;
        
        int sign_result = ring_sign(&bmsg.signature, keyword, &sender_keypair, ring_public_keys, 0);
        
        if (sign_result != 0) {
            LOG_ERR("Ring signature generation failed!\n");
            PROCESS_EXIT();
        }
        
        /* Prepare Data Payload */
        char msg_buf[64];
        snprintf(msg_buf, sizeof(msg_buf), "%s #%u", secret_message, (unsigned)baseline_seq_no);
        bmsg.counter = baseline_seq_no;
        
        LOG_INFO("Executing KEM AES-128-CTR Encrytion...\n");
        size_t cipher_len;
        int kem_ret = aead_kem_encrypt(&auth_error_vector, (uint8_t*)msg_buf, strlen(msg_buf) + 1, bmsg.ciphertext, &cipher_len);
        
        if (kem_ret != 0) {
            LOG_ERR("KEM Encryption failed!\n");
            break;
        }
        bmsg.cipher_len = cipher_len;
    
        /* Serialize Monolithic Payload */
        static uint8_t serialized_buffer[3000]; // Max size
        size_t offset = 0;
        
        serialized_buffer[offset++] = bmsg.type;
        
        /* Counter */
        serialized_buffer[offset++] = (bmsg.counter >> 24) & 0xFF;
        serialized_buffer[offset++] = (bmsg.counter >> 16) & 0xFF;
        serialized_buffer[offset++] = (bmsg.counter >> 8) & 0xFF;
        serialized_buffer[offset++] = bmsg.counter & 0xFF;
        
        /* Ciphertext metadata */
        serialized_buffer[offset++] = (bmsg.cipher_len >> 8) & 0xFF;
        serialized_buffer[offset++] = bmsg.cipher_len & 0xFF;
        memcpy(serialized_buffer + offset, bmsg.ciphertext, bmsg.cipher_len);
        offset += bmsg.cipher_len;
        
        /* Syndrome & Public Key */
        memcpy(serialized_buffer + offset, bmsg.syndrome, LDPC_ROWS / 8);
        offset += LDPC_ROWS / 8;
        serialize_poly512(serialized_buffer + offset, &bmsg.public_key);
        offset += POLY_DEGREE * 4;
        
        /* Heavy Signature: S[0..2], w, commitment, keyword */
        int i;
        for(i=0; i<RING_SIZE; i++) {
            serialize_poly512(serialized_buffer + offset, &bmsg.signature.S[i]);
            offset += POLY_DEGREE * 4;
        }
        serialize_poly512(serialized_buffer + offset, &bmsg.signature.w);
        offset += POLY_DEGREE * 4;
        
        memcpy(serialized_buffer + offset, bmsg.signature.commitment, SHA256_DIGEST_SIZE);
        offset += SHA256_DIGEST_SIZE;
        memcpy(serialized_buffer + offset, bmsg.signature.keyword, KEYWORD_SIZE);
        offset += KEYWORD_SIZE;
        
        static uint8_t *serialized_auth;
        serialized_auth = serialized_buffer;
        static size_t serialized_len;
        serialized_len = offset;
        
        static uint16_t total_frags;
        total_frags = (serialized_len + 63) / 64;
        printf("Total Baseline Payload: %u bytes (%u fragments)\n", (unsigned)serialized_len, total_frags);
        
        /* Fragment Blast Loop */
        static int frag_idx;
        static int attempts;
        static int acked;
        for (frag_idx = 0; frag_idx < total_frags; frag_idx++) {
            attempts = 0;
            acked = 0;
            last_ack_received = -1;
            
            while(attempts < 20 && !acked) {
                AuthFragment frag;
                frag.type = MSG_TYPE_AUTH_FRAG;
                frag.session_id = uip_htons(0xAB12);
                frag.fragment_id = uip_htons(frag_idx);
                frag.total_frags = uip_htons(total_frags);
                
                size_t offset = frag_idx * 64;
                size_t len = 64;
                if (offset + len > serialized_len) {
                    len = serialized_len - offset;
                }
                frag.payload_len = uip_htons(len);
                memcpy(frag.payload, serialized_auth + offset, len);
                
                simple_udp_sendto(&udp_conn, &frag, sizeof(AuthFragment), &dest_ipaddr);
                
                etimer_set(&periodic_timer, CLOCK_SECOND * 2);
                while(1) {
                    /* Check immediately in case ACK arrived via callback before we yielded */
                    if (last_ack_received == frag_idx) {
                        acked = 1;
                        etimer_stop(&periodic_timer);
                        break;
                    }
                    
                    PROCESS_YIELD();
                    
                    if (last_ack_received == frag_idx) {
                        acked = 1;
                        etimer_stop(&periodic_timer);
                        break;
                    }
                    if (etimer_expired(&periodic_timer)) {
                        break;
                    }
                }
                
                if (acked) {
                    /* Throttle to prevent overwhelming the Cooja radio/routing layer */
                    etimer_set(&periodic_timer, CLOCK_SECOND / 8);
                    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
                }
                
                attempts++;
            }
            if (!acked) {
                LOG_ERR("Failed to send fragment %d after 20 attempts\n", frBaseline protocol transaction (#%u) sent successfully!\nag_idx);
                break;
            }
        }
        
        if (acked) {
            LOG_INFO("", (unsigned)baseline_seq_no);
            baseline_seq_no++;
        }
        
        /* Zeroize ephemeral keys */
        secure_zero(&auth_error_vector, sizeof(ErrorVector));
        secure_zero(&bmsg.signature, sizeof(RingSignature));
        
        /* Wait for periodic interval before the next massive payload */
        etimer_set(&periodic_timer, DATA_INTERVAL * CLOCK_SECOND);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    }
  
  PROCESS_END();
}

