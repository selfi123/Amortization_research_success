% sim_bandwidth.m — Communication Bandwidth Overhead Comparison
% Base Paper (CT0 per packet) vs Session Amortization Novelty (Nonce + GCM tag)
% Platform: MATLAB R2018a+ (same as base paper)
% Source: master_draft_COMPLETE.md §12.1, §10.2
%
% Run: sim_bandwidth.m
% Output: sim_bandwidth.png + console results

clear; clc; close all;

fprintf('=============================================================\n');
fprintf('  SIMULATION 2: Bandwidth Overhead Comparison\n');
fprintf('  Base Paper vs Session Amortization Novelty\n');
fprintf('=============================================================\n\n');

%% ===== PARAMETERS (exact from master_draft_COMPLETE.md) =====

% --- Base paper data packet overhead (beyond payload |m|) ---
% CT0 = syndrome = X bits, where X = row dimension of H_qc = 408 (Table 2, §10.2)
CT0_bits = 408;   % bits — KEP ciphertext (syndrome)

% --- Authentication phase overhead (Phase 1 — per session/epoch, UNCHANGED) ---
% From master_draft §12.1
pk_bits  = 14848;  % Public key: i × log2(q) = 512 × 29 = 14848 bits
sig_bits = 11264;  % Signature:  i × log2(2E+1) = 512 × 22 = 11264 bits
kwd_bits = 256;    % Keyword message (SHA-256 output)
auth_overhead_bits = pk_bits + sig_bits + kwd_bits;   % 26368 bits (one-time per epoch)

% --- Code-based HE public key (sent once per epoch during KEP) ---
% pk_ds = (n0-1) × p bits = 3 × 408 = 1224 bits (§12.1)
pk_HE_bits = 1224;  % bits — QC-LDPC public key (one-time per epoch)

% --- Proposed Tier 2 per-packet overhead ---
nonce_bits   = 96;   % bits — AES-GCM standard 96-bit nonce
gcm_tag_bits = 128;  % bits — AES-256-GCM authentication tag
tier2_overhead = nonce_bits + gcm_tag_bits;  % 224 bits

% --- Net saving per data packet ---
net_saving_bits = CT0_bits - tier2_overhead;       % 184 bits
saving_percent  = (net_saving_bits / CT0_bits) * 100;  % 45.1%

%% ===== CUMULATIVE OVERHEAD OVER N PACKETS =====
N_packets = 1:50;

% Base paper: auth overhead ONCE, then CT0 per every data packet
% In base paper, each data "session" triggers full auth + HE
overhead_base_cumulative = auth_overhead_bits + pk_HE_bits + N_packets .* CT0_bits;

% Proposed: auth overhead ONCE per epoch, then only Nonce+TAG per packet
overhead_novel_cumulative = auth_overhead_bits + pk_HE_bits + N_packets .* tier2_overhead;

%% ===== CONSOLE OUTPUT =====
fprintf('--- Per-Packet Data Overhead (beyond payload |m|) ---\n');
fprintf('  Base paper CT0 (syndrome):      %d bits\n', CT0_bits);
fprintf('  Proposed Tier 2 overhead:       %d bits\n', tier2_overhead);
fprintf('    - Nonce (96-bit AES-GCM):     %d bits\n', nonce_bits);
fprintf('    - GCM auth tag (128-bit):     %d bits\n', gcm_tag_bits);
fprintf('  Net saving per data packet:     %d bits (%.1f%% reduction in per-packet OH)\n', ...
    net_saving_bits, saving_percent);

fprintf('\n--- Epoch-Level Overhead (sent once, unchanged for both) ---\n');
fprintf('  LR-IoTA authentication:         %d bits\n', auth_overhead_bits);
fprintf('    - Public key:                 %d bits\n', pk_bits);
fprintf('    - Signature:                  %d bits\n', sig_bits);
fprintf('    - Keyword message:            %d bits\n', kwd_bits);
fprintf('  QC-LDPC public key (pk_ds):     %d bits\n', pk_HE_bits);
fprintf('  [This authentication overhead is IDENTICAL in base and proposed — unchanged]\n');

fprintf('\n--- Cumulative Overhead Savings ---\n');
for n = [5 10 25 50]
    base_total = auth_overhead_bits + pk_HE_bits + n * CT0_bits;
    novel_total = auth_overhead_bits + pk_HE_bits + n * tier2_overhead;
    fprintf('  At N=%2d packets: Base=%d bits | Proposed=%d bits | Saving=%d bits\n', ...
        n, base_total, novel_total, base_total - novel_total);
end

%% ===== PLOT 1: Per-Packet Overhead Bar Chart =====
figure('Name', 'Bandwidth Per-Packet', 'Position', [100 100 700 480]);
bar_data = [CT0_bits; tier2_overhead];
b = bar([1 2], bar_data, 0.5);
b.FaceColor = 'flat';
b.CData = [0.85 0.33 0.10; 0.00 0.45 0.74];

hold on;
text(1, CT0_bits + 8, sprintf('%d bits', CT0_bits), ...
    'HorizontalAlignment', 'center', 'FontWeight', 'bold', 'FontSize', 12);
text(2, tier2_overhead + 8, sprintf('%d bits', tier2_overhead), ...
    'HorizontalAlignment', 'center', 'FontWeight', 'bold', 'FontSize', 12);

xticks([1 2]);
xticklabels({'Base Paper (CT_0 per packet)', 'Proposed Tier 2 (Nonce_{96} + GCM Tag_{128})'});
ylabel('Overhead Bits Per Data Packet (excluding payload)', 'FontSize', 12);
title(sprintf('Per-Packet Bandwidth Overhead Comparison\nNet saving: %d bits/packet (%.1f%% reduction)', ...
    net_saving_bits, saving_percent), 'FontSize', 13);
ylim([0 500]); grid on; hold off;
saveas(gcf, 'results/sim_bandwidth_bar.png');

%% ===== PLOT 2: Cumulative Overhead vs N Packets =====
figure('Name', 'Bandwidth Cumulative', 'Position', [820 100 700 480]);
plot(N_packets, overhead_base_cumulative/1000, 'r-o', 'LineWidth', 2, 'MarkerSize', 4, ...
    'DisplayName', 'Base Paper');
hold on;
plot(N_packets, overhead_novel_cumulative/1000, 'b-s', 'LineWidth', 2, 'MarkerSize', 4, ...
    'DisplayName', 'Proposed Novelty');
xlabel('Number of Data Packets in Epoch', 'FontSize', 12);
ylabel('Cumulative Protocol Overhead (Kbits)', 'FontSize', 12);
title({'Cumulative Bandwidth Overhead vs Number of Packets'; ...
    sprintf('Proposed saves %d bits/packet beyond epoch handshake', net_saving_bits)}, 'FontSize', 13);
legend('Location', 'northwest', 'FontSize', 11);
grid on; hold off;
saveas(gcf, 'results/sim_bandwidth_cumulative.png');

fprintf('\nFigures saved: sim_bandwidth_bar.png, sim_bandwidth_cumulative.png\n');
fprintf('[SIMULATION 2 COMPLETE]\n');
