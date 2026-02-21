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
#define MSG_TYPE_AUTH 0x01
#define MSG_TYPE_AUTH_ACK 0x02
#define MSG_TYPE_DATA 0x03
#define MSG_TYPE_AUTH_FRAG 0x04
#define MSG_TYPE_FRAG_ACK 0x05

/* Reassembly buffer */
static uint8_t reassembly_buf[3000];

/* ========== MESSAGE STRUCTURES ========== */

typedef struct {
    uint8_t type;
    uint8_t syndrome[LDPC_ROWS / 8];
    Poly512 public_key; /* Added Public Key */
    RingSignature signature;
} AuthMessage;

typedef struct {
    uint8_t type;
    uint8_t N_G[32];
    uint8_t SID[SID_LEN];
} AuthAckMessage;

/* ========== CRYPTOGRAPHIC STATE ========== */

static RingLWEKeyPair gateway_keypair;
static LDPCKeyPair gateway_ldpc_keypair;
static Poly512 ring_public_keys[RING_SIZE];

/* ========== SESSION MANAGEMENT ========== */

static session_entry_t session_table[MAX_SESSIONS];

PROCESS(gateway_process, "Ring-LWE Gateway Process");
AUTOSTART_PROCESSES(&gateway_process);

/* ========== SESSION FUNCTIONS ========== */

static session_entry_t* find_session(const uint8_t *sid) {
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (session_table[i].in_use &&
            memcmp(session_table[i].sid, sid, SID_LEN) == 0) {
            return &session_table[i];
        }
    }
    return NULL;
}

static session_entry_t* create_session(const uint8_t *sid,
                                      const uint8_t *K_master,
                                      const uip_ipaddr_t *peer) {
    session_entry_t *se = NULL;
    int i;
    
    /* Find free slot */
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!session_table[i].in_use) {
            se = &session_table[i];
            break;
        }
    }
    
    /* If no free slot, evict oldest */
    if (se == NULL) {
        se = &session_table[0];
        for (i = 1; i < MAX_SESSIONS; i++) {
            if (session_table[i].expiry_ts < se->expiry_ts) {
                se = &session_table[i];
            }
        }
        LOG_INFO("Evicting old session\n");
        secure_zero(se->K_master, MASTER_KEY_LEN);
    }
    
    /* Initialize session */
    memcpy(se->sid, sid, SID_LEN);
    memcpy(se->K_master, K_master, MASTER_KEY_LEN);
    memcpy(se->peer_addr, peer, 16);
    se->last_seq = 0;
    se->expiry_ts = 3600; // Placeholder
    se->in_use = 1;
    
    return se;
}

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
        FragmentAck ack;
        ack.type = MSG_TYPE_FRAG_ACK;
        ack.fragment_id = frag->fragment_id;
        simple_udp_sendto(&udp_conn, &ack, sizeof(FragmentAck), &sender_ip_copy);
        
        /* Check if last fragment */
        if (fragment_id == total_frags - 1) {
            LOG_INFO("Reassembly complete. Verifying signature...\n");
            
            static AuthMessage auth_msg_store;
            AuthMessage *auth_msg = &auth_msg_store;
            size_t offset = 0;
            
            auth_msg->type = reassembly_buf[offset++];
            memcpy(auth_msg->syndrome, reassembly_buf + offset, LDPC_ROWS / 8);
            offset += LDPC_ROWS / 8;
            
            deserialize_poly512(&auth_msg->public_key, reassembly_buf + offset);
            offset += POLY_DEGREE * 4;
            
            int i;
            for(i=0; i<RING_SIZE; i++) {
                deserialize_poly512(&auth_msg->signature.S[i], reassembly_buf + offset);
                offset += POLY_DEGREE * 4;
            }
            deserialize_poly512(&auth_msg->signature.w, reassembly_buf + offset);
            offset += POLY_DEGREE * 4;
            
            memcpy(auth_msg->signature.commitment, reassembly_buf + offset, SHA256_DIGEST_SIZE);
            offset += SHA256_DIGEST_SIZE;
            
            memcpy(auth_msg->signature.keyword, reassembly_buf + offset, KEYWORD_SIZE);
            offset += KEYWORD_SIZE;
            
            /* Use received public key for verification (Index 0) */
            ring_public_keys[0] = auth_msg->public_key;
            
            /* Verify signature */
            LOG_INFO("Verifying with key[0]:\n");
            poly_print("Verify Key", &ring_public_keys[0], 8);
            
            /* DEBUG: Check Signature integrity */
            LOG_INFO("DEBUG: Received Signature w (first 8 coeffs):\n");
            poly_print("Recv Sig.w", &auth_msg->signature.w, 8);
            LOG_INFO("DEBUG: Received Commitment (first 4 bytes): %02x%02x%02x%02x\n",
                     auth_msg->signature.commitment[0], auth_msg->signature.commitment[1],
                     auth_msg->signature.commitment[2], auth_msg->signature.commitment[3]);
            int verify_result = ring_verify(&auth_msg->signature, ring_public_keys);
            
            if (verify_result != 1) {
                LOG_ERR("Ring signature verification FAILED!\n");
                return;
            }
            
            LOG_INFO("Ring signature verified: SUCCESS\n");
            
            /* Extract syndrome */
            uint8_t received_syndrome[LDPC_ROWS / 8];
            memcpy(received_syndrome, auth_msg->syndrome, LDPC_ROWS / 8);
            
            /* LDPC decode */
            LOG_INFO("Decoding LDPC syndrome...\n");
            ErrorVector recovered_error;
            int decode_ret = sldspa_decode(&recovered_error, received_syndrome,
                                          &gateway_ldpc_keypair);
            
            if (decode_ret != 0) {
                LOG_ERR("LDPC decoding failed!\n");
                return;
            }
            
            LOG_INFO("LDPC decoding successful (weight=%u)\n",
                     recovered_error.hamming_weight);
            
            /* Generate session parameters */
            uint8_t N_G[32];
            uint8_t SID[SID_LEN];
            
            LOG_INFO("Generating session parameters...\n");
            crypto_secure_random(N_G, 32);
            crypto_secure_random(SID, SID_LEN);
            
            /* Derive master session key */
            LOG_INFO("Deriving master session key...\n");
            uint8_t K_master[MASTER_KEY_LEN];
            derive_master_key(K_master,
                             recovered_error.bits, sizeof(recovered_error.bits),
                             N_G, 32);
            
            /* Create session entry */
            LOG_INFO("Creating session entry...\n");
            session_entry_t *se = create_session(SID, K_master, sender_addr);
            
            if (se == NULL) {
                LOG_ERR("Failed to create session!\n");
                return;
            }
            
            LOG_INFO("Session created\n");
            
            /* Zeroize sensitive data */
            secure_zero(&recovered_error, sizeof(ErrorVector));
            secure_zero(K_master, MASTER_KEY_LEN);
            
            /* Send AUTH_ACK */
            AuthAckMessage ack_msg;
            ack_msg.type = MSG_TYPE_AUTH_ACK;
            memcpy(ack_msg.N_G, N_G, 32);
            memcpy(ack_msg.SID, SID, SID_LEN);
            
            simple_udp_sendto(&udp_conn, &ack_msg, sizeof(AuthAckMessage), &sender_ip_copy);
            LOG_INFO("ACK sent! Session established.\n");
        }
        return;
    }
    
    if (msg_type == MSG_TYPE_DATA) {
        /* ===== DATA PHASE ===== */
        
        /* Parse wire format */
        const uint8_t *ptr = data + 1;
        uint8_t sid[SID_LEN];
        uint32_t counter;
        uint16_t cipher_len;
        
        memcpy(sid, ptr, SID_LEN);
        ptr += SID_LEN;
        
        counter = ((uint32_t)ptr[0] << 24) |
                  ((uint32_t)ptr[1] << 16) |
                  ((uint32_t)ptr[2] << 8) |
                   (uint32_t)ptr[3];
        ptr += 4;
        
        cipher_len = ((uint16_t)ptr[0] << 8) | (uint16_t)ptr[1];
        ptr += 2;
        
        const uint8_t *ciphertext = ptr;
        
        LOG_INFO("\n[Data Phase] Received encrypted message\n");
        LOG_INFO("SID: [%02x%02x%02x%02x...]\n",
                 sid[0], sid[1], sid[2], sid[3]);
        LOG_INFO("Counter: %u\n", (unsigned)counter);
        
        /* Lookup session */
        session_entry_t *se = find_session(sid);
        
        if (se == NULL) {
            LOG_ERR("Session not found!\n");
            return;
        }
        
        LOG_INFO("Session found. Decrypting...\n");
        
        /* Decrypt */
        uint8_t plaintext[MESSAGE_MAX_SIZE];
        size_t plain_len;
        
        int ret = session_decrypt(se, counter, ciphertext, cipher_len,
                                 plaintext, &plain_len);
        
        if (ret != 0) {
            if (counter <= se->last_seq) {
                LOG_ERR("Replay attack detected! counter=%u, last_seq=%u\n",
                        (unsigned)counter, (unsigned)se->last_seq);
            } else {
                LOG_ERR("AEAD decryption failed!\n");
            }
            return;
        }
        
        plaintext[plain_len] = '\0';
        
        LOG_INFO("Session decryption successful!\n");
        LOG_INFO("========================================\n");
        LOG_INFO("*** DECRYPTED MESSAGE: %s ***\n", plaintext);
        LOG_INFO("========================================\n");
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
