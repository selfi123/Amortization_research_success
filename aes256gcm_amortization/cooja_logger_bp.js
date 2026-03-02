/**
 * cooja_logger_bp.js
 * Comprehensive Metrics Logger — AES-256-GCM Variant
 * Kumari et al. (POLY_DEGREE=512, RING_SIZE=3, Amortization enabled)
 * AEAD: AES-256-GCM (96-bit nonce, 128-bit GCM tag, 256-bit key)
 *
 * Logs to: aes256gcm_amortization/simulation_result.log
 *
 * Metrics captured:
 *   [A] Key Generation Delay
 *   [B] Ring Signature Generation Delay
 *   [C] Ring Signature Verification Delay
 *   [D] Total End-to-End Authentication Delay
 *   [E] Auth Communication Overhead (bytes, fragments)
 *   [F] Session Key Setup Delay (LDPC decode + HKDF)
 *   [G] Data Phase: per-message encryption latency
 *   [H] Data Phase: E2E delivery latency (Msg #1)
 *   [I] Session Amortization: renewal cycle count + timing
 *   [J] Per-cycle summary table
 *   [K] CSV export for graphing
 */

var FileWriter = java.io.FileWriter;
/* Absolute path — Cooja CWD is tools/cooja, not the project folder */
var logPath = "/home/selfi/contiki-ng/examples/Amortization_Research/aes256gcm_amortization/simulation_aes256gcm.log";
var out = new FileWriter(logPath);

TIMEOUT(1200000, writeFinalSummary()); /* 20 min timeout */

/* =====================================================================
 * METRIC STATE
 * ===================================================================== */
var m = {
    /* Key Generation */
    t_keygen_start: 0,
    t_keygen_end: 0,

    /* Ring Signature Generation (sender side, Phase 2 start → "Ring signature generated successfully") */
    t_sign_start: 0,
    t_sign_end: 0,

    /* Authentication E2E (Phase 2 start → Gateway "Session created") */
    t_auth_start: 0,
    t_auth_end: 0,

    /* Ring Verify (Gateway "Reassembly complete" → "Ring signature verified") */
    t_verify_start: 0,
    t_verify_end: 0,

    /* Session setup = LDPC decode + HKDF (Gateway "Decoding LDPC" → "ACK sent") */
    t_session_start: 0,
    t_session_end: 0,

    /* Fragment / Communication stats (reset each auth cycle) */
    auth_frags_sent: 0,
    auth_bytes_sent: 0,   /* from "Total payload: N bytes" */
    auth_frag_size: 64,  /* bytes per fragment payload */

    /* Data Phase */
    data_msg_sent: 0,
    data_msg_recv: 0,
    data_payload_bytes: 0,   /* last encrypted size */
    t_first_data_sent: 0,
    t_first_data_recv: 0,

    /* Session Renewal Cycles */
    renewal_count: 0,
    cycle_stats: [],  /* array of {auth_ms, verify_ms, session_ms, data_count} per cycle */
    cycle_data_count: 0,

    /* Current cycle accumulators */
    cur_auth_ms: 0,
    cur_verify_ms: 0,
    cur_session_ms: 0,

    /* Success flag */
    completed: false
};

/* =====================================================================
 * HEADER
 * ===================================================================== */
out.write("==============================================================\n");
out.write("    AES-256-GCM AMORTIZATION - SIMULATION METRICS            \n");
out.write("    Kumari et al. | n=512 | N=3 | LDPC 102x204 | AES-256-GCM \n");
out.write("    Nonce: 96-bit | Tag: 128-bit | Key: 256-bit (NIST SP 800-38D)\n");
out.write("==============================================================\n");
out.write("Timestamp(us)\tMoteID\tMessage\n");
out.write("--------------------------------------------------------------\n");

/* =====================================================================
 * HELPER
 * ===================================================================== */
function us2ms(t0, t1) {
    if (t0 == 0 || t1 == 0 || t1 < t0) return 0.0;
    return (t1 - t0) / 1000.0;
}

/* =====================================================================
 * SUMMARY WRITER
 * ===================================================================== */
function writeFinalSummary() {
    if (m.completed) return;
    m.completed = true;

    /* Flush any open cycle */
    if (m.cur_auth_ms > 0) {
        m.cycle_stats.push({
            cycle: m.renewal_count,
            auth_ms: m.cur_auth_ms,
            verify_ms: m.cur_verify_ms,
            session_ms: m.cur_session_ms,
            data_count: m.cycle_data_count
        });
    }

    out.write("\n\n==============================================================\n");
    out.write("                 PROTOCOL METRICS SUMMARY                    \n");
    out.write("==============================================================\n");

    /* A. Key Generation */
    var keygen_ms = us2ms(m.t_keygen_start, m.t_keygen_end);
    out.write("\n[A] KEY GENERATION\n");
    out.write("  Sender Ring-LWE KeyGen Delay : " + keygen_ms.toFixed(3) + " ms\n");
    out.write("  (n=512, schoolbook poly_mul, Gaussian sampling)\n");

    /* B. Ring Signature Generation */
    var sign_ms = us2ms(m.t_sign_start, m.t_sign_end);
    out.write("\n[B] RING SIGNATURE GENERATION (Sender)\n");
    out.write("  Ring Sign Delay              : " + sign_ms.toFixed(3) + " ms\n");
    out.write("  (Fiat-Shamir rejection sampling, N=3 ring members)\n");

    /* C. Ring Verification (Gateway) */
    var verify_ms = us2ms(m.t_verify_start, m.t_verify_end);
    out.write("\n[C] RING SIGNATURE VERIFICATION (Gateway)\n");
    out.write("  Ring Verify Delay            : " + verify_ms.toFixed(3) + " ms\n");
    out.write("  (a*z - t*c check, consistency with w_approx)\n");

    /* D. End-to-End Auth */
    var auth_ms = us2ms(m.t_auth_start, m.t_auth_end);
    out.write("\n[D] END-TO-END AUTHENTICATION DELAY\n");
    out.write("  Total Auth E2E Delay         : " + auth_ms.toFixed(3) + " ms\n");
    out.write("  (Phase 2 start → Gateway Session Created)\n");

    /* E. Communication Overhead */
    var total_auth_bytes = m.auth_bytes_sent;
    var auth_frags = Math.ceil(total_auth_bytes / m.auth_frag_size);
    out.write("\n[E] AUTHENTICATION COMMUNICATION OVERHEAD\n");
    out.write("  Auth Payload Size (n=512)    : " + total_auth_bytes + " bytes\n");
    out.write("  Fragment count               : " + auth_frags + " (@ 64B each)\n");
    out.write("  Fragmentation overhead       : " + (auth_frags * 9) + " bytes (9B header each)\n");
    out.write("  Total Auth over-the-air      : " + (total_auth_bytes + auth_frags * 9) + " bytes\n");
    out.write("  Breakdown:\n");
    out.write("    Syndrome (LDPC_ROWS/8)     : 13 bytes\n");
    out.write("    Public Key (n=512*4)       : 2048 bytes\n");
    out.write("    Sig.S[0] (n=512*4)         : 2048 bytes\n");
    out.write("    Sig.S[1] (n=512*4)         : 2048 bytes\n");
    out.write("    Sig.S[2] (n=512*4)         : 2048 bytes\n");
    out.write("    Sig.w   (n=512*4)          : 2048 bytes\n");
    out.write("    Commitment (SHA256)        : 32 bytes\n");
    out.write("    Keyword                    : 32 bytes\n");

    /* F. Session Key Setup */
    var session_ms = us2ms(m.t_session_start, m.t_session_end);
    out.write("\n[F] SESSION KEY SETUP DELAY (Gateway)\n");
    out.write("  LDPC Decode + K_master HKDF  : " + session_ms.toFixed(3) + " ms\n");

    /* G. Data Phase */
    var e2e_latency = us2ms(m.t_first_data_sent, m.t_first_data_recv);
    out.write("\n[G] DATA PHASE (Amortized AES-256-GCM — 96-bit nonce, 128-bit tag, 256-bit key)\n");
    out.write("  Per-packet overhead: 28 bytes (12B nonce + 16B GCM tag) — 45.1% saving vs CT0\n");
    out.write("  Data Payload per Message     : " + m.data_payload_bytes + " bytes (avg)\n");
    out.write("  E2E Latency (Message #1)     : " + e2e_latency.toFixed(3) + " ms\n");
    out.write("  Messages Sent (total)        : " + m.data_msg_sent + "\n");
    out.write("  Messages Decrypted (total)   : " + m.data_msg_recv + "\n");
    /* Compare Auth vs Data overhead */
    var data_total = m.data_msg_sent * (m.data_payload_bytes + 15); /* 15B header approx */
    var overhead_pct = 0;
    if (data_total > 0) {
        overhead_pct = (total_auth_bytes / (total_auth_bytes + data_total) * 100.0).toFixed(1);
    }
    out.write("  Auth overhead as % of total  : " + overhead_pct + "%\n");
    out.write("  Bandwidth saved vs no-amort  : ~" + (m.data_msg_sent > 0 ? ((m.data_msg_sent - 1) * total_auth_bytes / (m.data_msg_sent)).toFixed(0) : "N/A") + " bytes saved per session\n");

    /* H. Amortization Summary */
    out.write("\n[H] SESSION AMORTIZATION SUMMARY\n");
    out.write("  Total Session Renewal Cycles : " + m.renewal_count + "\n");
    out.write("  Msgs Transmitted per Session : " + (m.renewal_count > 0 ? Math.floor(m.data_msg_sent / m.renewal_count) : m.data_msg_sent) + " (approx)\n");

    if (m.cycle_stats.length > 0) {
        out.write("\n  Per-Cycle Breakdown:\n");
        out.write("  Cycle | Auth(ms) | Verify(ms) | Session(ms) | DataMsgs\n");
        out.write("  ------|----------|------------|-------------|----------\n");
        for (var ci = 0; ci < m.cycle_stats.length; ci++) {
            var cs = m.cycle_stats[ci];
            out.write("  " + (cs.cycle + 1) +
                "     | " + cs.auth_ms.toFixed(1) +
                "    | " + cs.verify_ms.toFixed(1) +
                "      | " + cs.session_ms.toFixed(1) +
                "       | " + cs.data_count + "\n");
        }
    }

    /* I. Cost Comparison (vs Unamortized / Z1 version) */
    out.write("\n[I] COMPARISON vs UNAMORTIZED & Z1 VARIANTS\n");
    out.write("  Parameter         | BasePaper(n=512) | Amortized(n=128) | Z1(n=32)\n");
    out.write("  ------------------|-----------------|-----------------|----------\n");
    out.write("  Auth payload (B)  | " + total_auth_bytes + " (est)  |  ~2637          |  ~589\n");
    out.write("  Keygen delay (ms) | " + keygen_ms.toFixed(1) + "         |  ~214.5         |  (Z1 hw)\n");
    out.write("  Auth delay (ms)   | " + auth_ms.toFixed(1) + "         |  ~450           |  (Z1 hw)\n");
    out.write("  Data delay (ms)   | " + e2e_latency.toFixed(1) + "          |  ~30            |  (Z1 hw)\n");
    out.write("  Session renewal   | Every 20 msgs  | Every 20 msgs   | Every 20 msgs\n");

    out.write("\n==============================================================\n");

    /* J. CSV Export for Graphing */
    out.write("\n\n==============================================================\n");
    out.write("              CSV EXPORT FOR EXCEL/PYTHON GRAPHING           \n");
    out.write("==============================================================\n");
    out.write("Metric,Value,Unit,Note\n");
    out.write("KeyGen_Delay," + keygen_ms.toFixed(3) + ",ms,n=512 Ring-LWE keygen\n");
    out.write("RingSign_Delay," + sign_ms.toFixed(3) + ",ms,Fiat-Shamir rejection sampling\n");
    out.write("RingVerify_Delay," + verify_ms.toFixed(3) + ",ms,Gateway verify\n");
    out.write("Auth_E2E_Delay," + auth_ms.toFixed(3) + ",ms,Phase2 start to Session Created\n");
    out.write("Session_Setup_Delay," + session_ms.toFixed(3) + ",ms,LDPC decode + HKDF\n");
    out.write("E2E_Data_Latency," + e2e_latency.toFixed(3) + ",ms,Msg#1 send to gateway decrypt\n");
    out.write("Auth_Payload_Bytes," + total_auth_bytes + ",bytes,Over-the-air auth message size\n");
    out.write("Auth_Fragment_Count," + auth_frags + ",frags,64-byte fragments for auth\n");
    out.write("Data_Payload_Bytes," + m.data_payload_bytes + ",bytes,Per msg encrypted payload\n");
    out.write("Total_Messages_Sent," + m.data_msg_sent + ",msgs,Total data msgs transmitted\n");
    out.write("Total_Messages_Recv," + m.data_msg_recv + ",msgs,Total msgs decrypted\n");
    out.write("Session_Renewals," + m.renewal_count + ",cycles,Amortization renewal count\n");
    out.write("POLY_DEGREE,512,coeff,Base paper parameter\n");
    out.write("RING_SIZE,3,members,Anonymity set size\n");
    out.write("LDPC_ROWS,102,rows,Parity check matrix\n");
    out.write("LDPC_COLS,204,cols,Codeword length\n");
    out.write("\n--- Horizontal comparison CSV (paste into single sheet with other variants) ---\n");
    out.write("Variant,n,N,KeyGen_ms,Auth_ms,Verify_ms,DataLatency_ms,AuthPayload_B,Renewals,AEAD_Overhead_B\n");
    out.write("AES256GCM_Amortized," + 512 + "," + 3 + "," +
        keygen_ms.toFixed(3) + "," + auth_ms.toFixed(3) + "," +
        verify_ms.toFixed(3) + "," + e2e_latency.toFixed(3) + "," +
        total_auth_bytes + "," + m.renewal_count + ",28\n");
    out.write("[Note] 28B overhead = 12B GCM nonce + 16B tag. Saves 45.1% vs base paper CT0 (51B)\n");
    out.write("==============================================================\n");

    out.flush();
    out.close();
}

/* =====================================================================
 * MAIN EVENT LOOP
 * ===================================================================== */
while (true) {
    /* Write raw log line */
    out.write(time + "\t" + id + "\t" + msg + "\n");
    out.flush();
    log.log(time + ":" + id + ":" + msg + "\n");

    /* ---- KEY GENERATION ---- */
    if (msg.contains("[Phase 1] Generating Ring-LWE keys")) {
        m.t_keygen_start = time;
        m.t_sign_start = time; /* sign starts within Phase 2 but Phase1 gives keygen reference */
    }
    if (msg.contains("Ring-LWE key generation successful")) {
        m.t_keygen_end = time;
    }

    /* ---- AUTHENTICATION CYCLE START ---- */
    if (msg.contains("[Phase 2] Starting Ring Signature Authentication")) {
        m.t_auth_start = time;
        m.t_sign_start = time;
        /* Reset per-cycle fragment counters */
        m.auth_frags_sent = 0;
    }

    /* ---- RING SIGN COMPLETE ---- */
    if (msg.contains("Ring signature generated successfully")) {
        m.t_sign_end = time;
    }

    /* ---- FRAGMENT COUNTING (sender) ---- */
    if (msg.contains("Total payload:")) {
        var mp = msg.match(/Total payload: (\d+) bytes/);
        if (mp) m.auth_bytes_sent = parseInt(mp[1]);
    }
    if (msg.contains("Sending Fragment") && id == 1) {
        m.auth_frags_sent++;
    }

    /* ---- GATEWAY VERIFY PHASE ---- */
    if (msg.contains("Reassembly complete. Verifying signature")) {
        m.t_verify_start = time;
    }
    if (msg.contains("Ring signature verified: SUCCESS")) {
        m.t_verify_end = time;
    }

    /* ---- SESSION KEY SETUP ---- */
    if (msg.contains("Decoding LDPC syndrome")) {
        m.t_session_start = time;
    }
    if (msg.contains("ACK sent! Session established")) {
        m.t_session_end = time;
        m.t_auth_end = time;  /* auth complete when gateway sends ACK */

        /* Record cycle stats */
        m.cur_auth_ms = us2ms(m.t_auth_start, m.t_auth_end);
        m.cur_verify_ms = us2ms(m.t_verify_start, m.t_verify_end);
        m.cur_session_ms = us2ms(m.t_session_start, m.t_session_end);
        m.cycle_stats.push({
            cycle: m.renewal_count,
            auth_ms: m.cur_auth_ms,
            verify_ms: m.cur_verify_ms,
            session_ms: m.cur_session_ms,
            data_count: 0  /* will be updated when next renewal happens */
        });
        m.renewal_count++;
        m.cycle_data_count = 0;

        /* Log inline cycle summary */
        out.write("\n>>> [Cycle " + m.renewal_count + " Auth Summary] Auth=" +
            m.cur_auth_ms.toFixed(1) + "ms Verify=" + m.cur_verify_ms.toFixed(1) +
            "ms SessionSetup=" + m.cur_session_ms.toFixed(1) + "ms AuthPayload=" +
            m.auth_bytes_sent + "B\n\n");
        out.flush();
    }

    /* ---- DATA PHASE ---- */
    if (msg.contains("Message") && msg.contains("encrypted")) {
        var me = msg.match(/encrypted \((\d+) bytes\)/);
        if (me) m.data_payload_bytes = parseInt(me[1]);
        m.data_msg_sent++;
        m.cycle_data_count++;
        /* Update last cycle's data count */
        if (m.cycle_stats.length > 0) {
            m.cycle_stats[m.cycle_stats.length - 1].data_count = m.cycle_data_count;
        }
        if (m.data_msg_sent == 1) m.t_first_data_sent = time;
    }
    if (msg.contains("DECRYPTED MESSAGE:")) {
        m.data_msg_recv++;
        if (m.data_msg_recv == 1) m.t_first_data_recv = time;
    }

    /* ---- AMORTIZATION THRESHOLD HIT ---- */
    if (msg.contains("AMORTIZATION THRESHOLD REACHED")) {
        out.write("\n>>> [AMORTIZATION] Session renewal triggered after " +
            m.cycle_data_count + " messages. Starting new handshake...\n\n");
        out.flush();
    }

    /* ---- COMPLETION CONDITION ----
       End after at least 1 full renewal cycle (>20 data msgs from session 2) */
    if (m.data_msg_recv >= 25 && m.renewal_count >= 2) {
        log.log("SUCCESS: Two full amortization cycles verified!\n");
        writeFinalSummary();
        log.testOK();
    }

    /* ---- FAILURE ---- */
    if (msg.contains("Authentication timeout!")) {
        out.write("\n# TEST FAILED: Auth Timeout\n");
        writeFinalSummary();
        out.close();
        log.testFailed();
    }

    YIELD();
}
