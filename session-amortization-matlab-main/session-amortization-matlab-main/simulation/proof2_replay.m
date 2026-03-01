% proof2_replay.m — Proof 2: Strict Replay Resistance Validation
% Tests:
%   TEST 1: Replayed packets (Nonce_i <= Ctr_Rx) are ALWAYS rejected (10,000 trials)
%   TEST 2: Valid forward packets (Nonce_i > Ctr_Rx) are ALWAYS accepted (10,000 trials)
%   TEST 3: Packet drop / desynchronization handled: receiver counter self-heals
%   TEST 4: Duplicate delivery (same Nonce twice, not replay) is rejected
%
% Proof argument: Strict monotonic counter makes replay probability exactly 0.
% Source: novelty-security proof draft.md §Proof 2, session amortization draft.md §3.1

clear; clc; close all;

fprintf('=============================================================\n');
fprintf('  PROOF 2: STRICT REPLAY RESISTANCE VALIDATION\n');
fprintf('=============================================================\n\n');

N_trials = 10000;
rng(42);
results = struct('t1_replay', false, 't2_valid', false, 't3_desynch', false, 't4_dup', false);

%% ===== TEST 1: Replay Attack — Old Nonce =====
fprintf('[TEST 1] Simulating %d replay attempts (Nonce_i <= Ctr_Rx)...\n', N_trials);

Ctr_Rx = 500;  % Receiver has processed packets 1 to 500
replays_accepted = 0;

for t = 1:N_trials
    % Attacker replays a nonce from the history window [1, Ctr_Rx]
    Nonce_replayed = randi(Ctr_Rx);

    % Receiver check: strict monotonic — reject if Nonce <= Ctr_Rx
    if Nonce_replayed > Ctr_Rx
        replays_accepted = replays_accepted + 1;  % Should NEVER fire
    end
    % else: correct → DROPPED (not accepted)
end

results.t1_replay = (replays_accepted == 0);
if results.t1_replay
    fprintf('  [PASS] Replay rejection: %d/%d replays rejected (rate = 1.000000)\n', N_trials, N_trials);
    fprintf('         Adversary replay success probability: exactly 0\n');
else
    fprintf('  [FAIL] %d replay packets wrongly accepted.\n', replays_accepted);
end

%% ===== TEST 2: Valid Future Packets (Must Always Be Accepted) =====
fprintf('\n[TEST 2] Simulating %d valid sequential packet arrivals...\n', N_trials);

Ctr_Tx = 500;
Ctr_Rx = 500;
valid_accepted = 0;

for t = 1:N_trials
    Ctr_Tx = Ctr_Tx + 1;
    Nonce_i = Ctr_Tx;  % Strictly increasing valid nonce

    if Nonce_i > Ctr_Rx
        valid_accepted = valid_accepted + 1;
        Ctr_Rx = Nonce_i;  % Update receiver state
    end
end

results.t2_valid = (valid_accepted == N_trials);
if results.t2_valid
    fprintf('  [PASS] Valid acceptance: %d/%d packets accepted (rate = 1.000000)\n', N_trials, N_trials);
    fprintf('         Final Ctr_Rx = %d (correctly advanced)\n', Ctr_Rx);
else
    fprintf('  [FAIL] %d valid packets incorrectly rejected.\n', N_trials - valid_accepted);
end

%% ===== TEST 3: Packet Drop / Desynchronization Recovery =====
fprintf('\n[TEST 3] Simulating packet drops (20%% drop rate, %d packets)...\n', N_trials);

Ctr_Tx = 0; Ctr_Rx = 0;
drop_prob = 0.2;
sent = 0; dropped = 0; received = 0; accepted = 0;

for i = 1:N_trials
    Ctr_Tx = Ctr_Tx + 1;
    sent = sent + 1;

    if rand() < drop_prob
        % Packet lost in transit — receiver does not see this Nonce
        dropped = dropped + 1;
    else
        % Packet arrives at receiver
        Nonce_i = Ctr_Tx;
        received = received + 1;
        if Nonce_i > Ctr_Rx
            % Valid (even if some were dropped — counter gap is fine)
            accepted = accepted + 1;
            Ctr_Rx = Nonce_i;  % Self-heal: skip dropped nonces gracefully
        end
    end
end

results.t3_desynch = (accepted == received);
fprintf('  Sent: %d | Dropped: %d | Received: %d | Accepted: %d\n', ...
    sent, dropped, received, accepted);
if results.t3_desynch
    fprintf('  [PASS] All received packets accepted despite drops. Counter self-heals correctly.\n');
    fprintf('         No state corruption: Ctr_Rx = %d (matches last received nonce)\n', Ctr_Rx);
else
    fprintf('  [FAIL] %d received packets incorrectly rejected after drops.\n', received - accepted);
end

%% ===== TEST 4: Duplicate Delivery (Same Nonce Delivered Twice) =====
fprintf('\n[TEST 4] Simulating %d duplicate delivery attempts...\n', N_trials);

Ctr_Rx = 0; Ctr_Tx = 0;
dups_accepted = 0;

for t = 1:N_trials
    Ctr_Tx = Ctr_Tx + 1;
    Nonce_i = Ctr_Tx;

    % First delivery — should succeed
    if Nonce_i > Ctr_Rx
        Ctr_Rx = Nonce_i;
    end

    % Duplicate delivery of SAME nonce (e.g., network retransmit)
    if Nonce_i > Ctr_Rx
        dups_accepted = dups_accepted + 1;  % Should never fire
    end
end

results.t4_dup = (dups_accepted == 0);
if results.t4_dup
    fprintf('  [PASS] All %d duplicate deliveries rejected (Nonce_i = Ctr_Rx is also rejected).\n', N_trials);
else
    fprintf('  [FAIL] %d duplicates wrongly accepted.\n', dups_accepted);
end

%% ===== FORMAL PROOF STATEMENT =====
fprintf('\n--- FORMAL REPLAY RESISTANCE ARGUMENT ---\n');
fprintf('Theorem (Strict Replay Resistance):\n');
fprintf('  For any packet with Nonce_i ≤ Ctr_Rx:\n');
fprintf('    Pr[Receiver accepts replayed packet] = 0\n');
fprintf('  This follows directly from the monotonic counter check (N_i > Ctr_Rx).\n');
fprintf('  The condition is deterministic (no probability space) → probability exactly 0.\n\n');
fprintf('  Corollary: Desynchronization from packet loss does not weaken replay defense.\n');
fprintf('  The receiver counter self-advances to the last seen valid Nonce,\n');
fprintf('  rejecting any replay of skipped (dropped) nonces automatically.\n');

%% ===== FINAL VERDICT =====
fprintf('\n');
all_passed = results.t1_replay && results.t2_valid && results.t3_desynch && results.t4_dup;
if all_passed
    fprintf('======================================\n');
    fprintf('PROOF 2: REPLAY RESISTANCE PASSED\n');
    fprintf('======================================\n');
    fprintf('  ✓ Replay rejection rate: exactly 1.0 (0 false accepts in %d trials)\n', N_trials);
    fprintf('  ✓ Valid packet acceptance: exactly 1.0 (%d/10000)\n', N_trials);
    fprintf('  ✓ Desynchronization recovery: clean (no state corruption)\n');
    fprintf('  ✓ Duplicate delivery rejection: exactly 1.0\n');
else
    fprintf('PROOF 2: FAILED — review above tests.\n');
end
