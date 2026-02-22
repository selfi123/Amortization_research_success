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
#define MSG_TYPE_AUTH 0x01
#define MSG_TYPE_AUTH_ACK 0x02
#define MSG_TYPE_DATA 0x03
#define MSG_TYPE_AUTH_FRAG 0x04
#define MSG_TYPE_FRAG_ACK 0x05

/* Fragmentation state */
static volatile int last_ack_received = -1;

/* ========== MESSAGE STRUCTURES ========== */

typedef struct {
    uint8_t type;
    uint8_t syndrome[LDPC_ROWS / 8];
    Poly512 public_key; /* Added Public Key for robust verification */
    RingSignature signature;
} AuthMessage;

typedef struct {
    uint8_t type;
    uint8_t N_G[32];
    uint8_t SID[SID_LEN];
} AuthAckMessage;

typedef struct {
    uint8_t type;
    uint8_t SID[SID_LEN];
    uint32_t counter;
    uint8_t ciphertext[MESSAGE_MAX_SIZE + AEAD_TAG_LEN];
    uint16_t cipher_len;
} DataMessage;

/* ========== CRYPTOGRAPHIC STATE ========== */

static RingLWEKeyPair sender_keypair;
static LDPCPublicKey shared_ldpc_pubkey;
static session_ctx_t session_ctx;
static ErrorVector auth_error_vector;
static uint8_t syndrome[LDPC_ROWS / 8];

/* Message to encrypt */
static const char *secret_message = "Hello IoT";
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
    
    LOG_INFO("Received message type 0x%02x\n", msg_type);
    
    if (msg_type == MSG_TYPE_FRAG_ACK) {
        FragmentAck *ack = (FragmentAck *)data;
        uint16_t ack_frag_id = uip_ntohs(ack->fragment_id);
        LOG_INFO("Received ACK for fragment %d\n", ack_frag_id);
        last_ack_received = ack_frag_id;
        process_poll(&sender_process);
        return;
    }
    
    if (msg_type == MSG_TYPE_AUTH_ACK && !session_ctx.active) {
        AuthAckMessage *ack = (AuthAckMessage *)data;
        
        LOG_INFO("Authentication ACK received!\n");
        
        /* Extract N_G and SID */
        uint8_t N_G[32];
        memcpy(N_G, ack->N_G, 32);
        memcpy(session_ctx.sid, ack->SID, SID_LEN);
        
        LOG_INFO("SID: [%02x%02x%02x%02x...]\n",
                 session_ctx.sid[0], session_ctx.sid[1],
                 session_ctx.sid[2], session_ctx.sid[3]);
        
        /* Derive master session key */
        LOG_INFO("Deriving master session key...\n");
        derive_master_key(session_ctx.K_master,
                         auth_error_vector.bits, sizeof(auth_error_vector.bits),
                         N_G, 32);
        
        /* Initialize session */
        session_ctx.counter = 1;
        session_ctx.active = 1;
        session_ctx.expiry_ts = 0;
        
        /* Zeroize error vector */
        secure_zero(&auth_error_vector, sizeof(ErrorVector));
        
        LOG_INFO("Session initialized! Entering sequence data phase...\n");
        process_poll(&sender_process);
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
    
    // RENEW LOOP: Continuously authenticate and send data
    while(1) {
        /* ===== AUTHENTICATION PHASE ===== */
        LOG_INFO("\n[Phase 2] Starting Ring Signature Authentication...\n");
    
    /* Generate LDPC public key */
    LOG_INFO("Initializing LDPC public key...\n");
    if (ldpc_keygen((LDPCKeyPair *)&shared_ldpc_pubkey) != 0) {
        LOG_ERR("Failed to generate LDPC key!\n");
        PROCESS_EXIT();
    }
    
    /* Generate error vector */
    LOG_INFO("Generating LDPC error vector...\n");
    generate_error_vector(&auth_error_vector, 50);
    LOG_INFO("Error vector generated (weight=%u)\n", auth_error_vector.hamming_weight);
    
    /* Encode syndrome */
    LOG_INFO("Encoding syndrome...\n");
    ldpc_encode(syndrome, &auth_error_vector, &shared_ldpc_pubkey);
    
    /* Prepare keyword */
    uint8_t keyword[KEYWORD_SIZE];
    memset(keyword, 0, KEYWORD_SIZE);
    strcpy((char *)keyword, "AUTH_REQUEST");
    
    /* Generate ring signature */
    LOG_INFO("Generating ring signature (N=%d members)...\n", RING_SIZE);
    
    static AuthMessage auth_msg;
    auth_msg.type = MSG_TYPE_AUTH;
    memcpy(auth_msg.syndrome, syndrome, LDPC_ROWS / 8);
    auth_msg.public_key = sender_keypair.public; /* Send PK */
    
    int sign_result = ring_sign(&auth_msg.signature,
                                keyword,
                                &sender_keypair,
                                ring_public_keys,
                                0); // Sender is index 0
    
    if (sign_result != 0) {
        LOG_ERR("Ring signature generation failed!\n");
        PROCESS_EXIT();
    }
    
    LOG_INFO("Ring signature generated successfully\n");
    
    /* DEBUG: Print Key and Sig to compare with Gateway */
    LOG_INFO("DEBUG: Sender Public Key sent:\n");
    poly_print("PubKey", &auth_msg.public_key, 8);
    LOG_INFO("DEBUG: Signature w sent (first 8 coeffs):\n");
    poly_print("Sig.w", &auth_msg.signature.w, 8);
    LOG_INFO("DEBUG: Signature Commitment (first 4 bytes): %02x%02x%02x%02x\n",
             auth_msg.signature.commitment[0], auth_msg.signature.commitment[1],
             auth_msg.signature.commitment[2], auth_msg.signature.commitment[3]);
    
    /* ===== SEND AUTHENTICATION MESSAGE ===== */
    LOG_INFO("Sending authentication message via fragmentation...\n");
    
    /* Serialize AuthMessage manually to avoid padding issues */
    static uint8_t serialized_buffer[3000]; // Max size
    size_t offset = 0;
    
    serialized_buffer[offset++] = auth_msg.type;
    memcpy(serialized_buffer + offset, auth_msg.syndrome, LDPC_ROWS / 8);
    offset += LDPC_ROWS / 8;
    
    serialize_poly512(serialized_buffer + offset, &auth_msg.public_key);
    offset += POLY_DEGREE * 4;
    
    /* Signature: S[0..2], w, commitment, keyword */
    int i;
    for(i=0; i<RING_SIZE; i++) {
        serialize_poly512(serialized_buffer + offset, &auth_msg.signature.S[i]);
        offset += POLY_DEGREE * 4;
    }
    serialize_poly512(serialized_buffer + offset, &auth_msg.signature.w);
    offset += POLY_DEGREE * 4;
    
    memcpy(serialized_buffer + offset, auth_msg.signature.commitment, SHA256_DIGEST_SIZE);
    offset += SHA256_DIGEST_SIZE;
    
    memcpy(serialized_buffer + offset, auth_msg.signature.keyword, KEYWORD_SIZE);
    offset += KEYWORD_SIZE;
    
    static uint8_t *serialized_auth;
    serialized_auth = serialized_buffer;
    static size_t serialized_len;
    serialized_len = offset;
    
    static uint16_t total_frags;
    total_frags = (serialized_len + 63) / 64;
    
    LOG_INFO("Total payload: %u bytes (%u fragments)\n",
             (unsigned)serialized_len, total_frags);
    
    static int frag_idx;
    for (frag_idx = 0; frag_idx < total_frags; frag_idx++) {
        int attempts = 0;
        int acked = 0;
        
        last_ack_received = -1;
        
        while(attempts < 5 && !acked) {
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
            
            LOG_INFO("Sending Fragment %d/%d (%u bytes)...\n",
                     frag_idx + 1, total_frags, (unsigned)len);
            simple_udp_sendto(&udp_conn, &frag, sizeof(AuthFragment), &dest_ipaddr);
            
            etimer_set(&periodic_timer, CLOCK_SECOND * 2);
            
            while(1) {
                PROCESS_YIELD();
                
                if (ev == PROCESS_EVENT_POLL && last_ack_received == frag_idx) {
                    acked = 1;
                    etimer_stop(&periodic_timer);
                    LOG_INFO("ACK received for fragment %d\n", frag_idx);
                    break;
                }
                
                if (etimer_expired(&periodic_timer)) {
                    LOG_INFO("Timeout for fragment %d, retrying...\n", frag_idx);
                    break;
                }
            }
            attempts++;
        }
        
        if (!acked) {
            LOG_ERR("Failed to send fragment %d after %d attempts\n", frag_idx, attempts);
            PROCESS_EXIT();
        }
    }
    
    LOG_INFO("Authentication payload sent successfully!\n");
    
    /* Wait for authentication response */
    if (!session_ctx.active) {
        etimer_set(&periodic_timer, 60 * CLOCK_SECOND);
    
        PROCESS_YIELD_UNTIL((ev == PROCESS_EVENT_POLL && session_ctx.active) ||
                            etimer_expired(&periodic_timer));
    
        if (etimer_expired(&periodic_timer)) {
            LOG_ERR("Authentication timeout! Retrying...\n");
            continue; // Loop back and try authenticating again
        }
    }
    
    LOG_INFO("\n=== AUTHENTICATION COMPLETE ===\n");
    
    /* ===== DATA TRANSMISSION PHASE ===== */
    LOG_INFO("[Phase 3] Starting Amortized Periodic Data Transmission...\n");
    
    while(session_ctx.active && session_ctx.counter <= RENEW_THRESHOLD) {
        char msg_buf[64];
        snprintf(msg_buf, sizeof(msg_buf), "%s #%u", secret_message, (unsigned)session_ctx.counter);
        
        /* Session encrypt */
        uint8_t ciphertext[MESSAGE_MAX_SIZE + AEAD_TAG_LEN];
        size_t cipher_len;
        
        int ret = session_encrypt(&session_ctx,
                                 (uint8_t *)msg_buf, strlen(msg_buf) + 1,
                                 ciphertext, &cipher_len);
        
        if (ret != 0) {
            LOG_ERR("Encryption failed for message %u!\n", (unsigned)session_ctx.counter);
            break;
        }
        
        LOG_INFO("Message %u encrypted (%u bytes)\n", (unsigned)session_ctx.counter, (unsigned)cipher_len);
        
        /* Pack wire format */
        uint8_t wire_buf[256];
        size_t wire_offset = 0;
        
        wire_buf[wire_offset++] = MSG_TYPE_DATA;
        memcpy(wire_buf + wire_offset, session_ctx.sid, SID_LEN);
        wire_offset += SID_LEN;
        
        wire_buf[wire_offset++] = (session_ctx.counter >> 24) & 0xFF;
        wire_buf[wire_offset++] = (session_ctx.counter >> 16) & 0xFF;
        wire_buf[wire_offset++] = (session_ctx.counter >> 8) & 0xFF;
        wire_buf[wire_offset++] = session_ctx.counter & 0xFF;
        
        wire_buf[wire_offset++] = (cipher_len >> 8) & 0xFF;
        wire_buf[wire_offset++] = cipher_len & 0xFF;
        
        memcpy(wire_buf + wire_offset, ciphertext, cipher_len);
        wire_offset += cipher_len;
        
        /* Send to gateway */
        simple_udp_sendto(&udp_conn, wire_buf, wire_offset, &dest_ipaddr);
        LOG_INFO("  -> UDP Packet Sent with counter=%u\n", (unsigned)session_ctx.counter);
        
        session_ctx.counter++;
        
        /* Wait for periodic interval (e.g., 5 seconds) */
        etimer_set(&periodic_timer, DATA_INTERVAL * CLOCK_SECOND);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    }
    
    if (session_ctx.counter > RENEW_THRESHOLD) {
        LOG_INFO("\n**************************************************\n");
        LOG_INFO("* AMORTIZATION THRESHOLD REACHED (%d msgs)      *\n", RENEW_THRESHOLD);
        LOG_INFO("* SECURE SESSION RENEWAL TRIGGERED               *\n");
        LOG_INFO("**************************************************\n");
        /* Zeroize old master key and deactivate session to force new handshake */
        secure_zero(&session_ctx, sizeof(session_ctx));
        session_ctx.active = 0;
    }
  } /* End of while(1) renew loop */
  
  PROCESS_END();
}

