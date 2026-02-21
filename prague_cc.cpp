#include <chrono>
#include "prague_cc.h"

// --- Fixed-point helpers ---
uint64_t mul_64_64_shift(uint64_t left, uint64_t right, uint32_t shift = 0) {
    uint64_t a0 = left & ((1ULL << 32)-1);
    uint64_t a1 = left >> 32;
    uint64_t b0 = right & ((1ULL << 32)-1);
    uint64_t b1 = right >> 32;
    uint64_t m0 = a0 * b0;
    uint64_t m1 = a0 * b1;
    uint64_t m2 = a1 * b0;
    uint64_t m3 = a1 * b1;
    uint64_t result_low;
    uint64_t result_high;

    m2 += (m0 >> 32);
    m2 += m1;
    /* Overflow */
    if (m2 < m1)
        m3 += (1ULL << 32);

    result_low = (m0 & ((1ULL << 32)-1)) | (m2 << 32);
    result_high = m3 + (m2 >> 32);
    if (shift && 64 >= shift) {
        result_low = (result_low >> shift) | (result_high << (64 - shift));
        result_high = (result_high >> shift);
    }
    return (result_high) ? 0xffffffffffffffffULL : result_low;
}

uint64_t div_64_64_round(uint64_t a, uint64_t divisor) {
    uint64_t dividend = a + (divisor >> 1);
    uint64_t overflow = (dividend < a) ? 1 : 0;
    uint64_t quotient1 = 0;
    uint64_t quotient2 = 0;
    uint64_t quotient3 = 0;
    uint64_t remainder = 0;

    if (!divisor)
        return 0xffffffffffffffffULL;

    if (!overflow)
        return dividend / divisor;

    quotient1 = overflow / divisor;
    /* Overflow */
    if (quotient1)
        return 0xffffffffffffffffULL;

    remainder = overflow % divisor;
    quotient2 = ((remainder << 32) | (dividend >> 32)) / divisor;

    remainder = ((remainder << 32) | (dividend >> 32)) % divisor;
    quotient3 = ((remainder << 32) | (dividend & 0xffffffff)) / divisor;
    return (quotient2 << 32) + quotient3;
}

// --- Prague constants ---
const rate_tp MIN_STEP = 7;                // [vRTT] minimum wait before allowing faster growth.
const rate_tp RATE_STEP = 1920000;         // per 1920kB/s = 15360kbps pacing rate wait one RTT longer
const time_tp QUEUE_GROWTH = 1000;         // [µs] growth targets ~1ms additional queue after the growth wait
const time_tp BURST_TIME = 250;            // [µs] burst budget (packet_burst is sized to fit roughly this time)
const time_tp REF_RTT = 25000;             // [µs] reference RTT floor for vRTT (25ms)
const uint8_t PROB_SHIFT = 20;             // Fixed-point shift for probability/alpha math. Enough as max value that can control up to 100Gbps with r [Mbps] = 1/p - 1, p = 1/(r + 1) = 1/100001
const prob_tp MAX_PROB = 1 << PROB_SHIFT;  // Alpha upper bound (represents "1.0" in fixed-point). with r [Mbps] = 1/p - 1 = 2^20 Mbps = 1Tbps
const uint8_t ALPHA_SHIFT = 4;             // Alpha EWMA shift (divide by 16).
const count_tp MIN_PKT_BURST = 1;          // [Packets]
const count_tp MIN_PKT_WIN = 2;            // [Packets]
const uint8_t RATE_OFFSET = 3;             // [%] Dither pacing rate by +/-RATE_OFFSET% per half-vRTT to probe for extra bandwidth via ECN feedback (non-RT mode)
const count_tp MIN_FRAME_WIN = 2;          // [Frames] minimum window in frame-mode.

// --- Prague methods ---
time_tp PragueCC::Now() {
    if (m_start_ref == 0) { // => Uninitialized
        m_start_ref = time_tp(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());

        // If we happened to read 0, set to -1 so that subsequent (now - start_ref) is positive
        if (m_start_ref == 0)
            m_start_ref = -1;

        return 1;
    }

    time_tp now = time_tp(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()) - m_start_ref;

    // Avoid returning 0 (sentinel)
    return (now) ? now : 1;
}

time_tp PragueCC::get_ref_rtt() {
  return (m_frame_interval) ? m_frame_interval : REF_RTT;
}

count_tp PragueCC::get_alpha_shift() {
  return (m_frame_interval) ? (1 << ALPHA_SHIFT) * (REF_RTT) / (m_frame_interval) 
                            : 1 << ALPHA_SHIFT;
}

PragueCC::PragueCC(size_tp max_packet_size, fps_tp fps, time_tp frame_budget, rate_tp init_rate, count_tp init_window, rate_tp min_rate, rate_tp max_rate) {
    m_start_ref = 0; // Uninitialized
    time_tp ts_now = Now(); // NOTE: Initializes m_start_ref

    // --- Parameters ---
    m_init_rate = init_rate;
    m_init_window = window_tp(init_window) * max_packet_size * 1000000;
    m_min_rate = min_rate;
    m_max_rate = max_rate;
    m_max_packet_size = max_packet_size;

    // Frame mode config (fps==0 => bulk)
    m_frame_interval = fps ? 1000000 / fps : 0;
    m_frame_budget = frame_budget;
    if (m_frame_budget > m_frame_interval)
        m_frame_budget = m_frame_interval;

    // Both end variables
    m_ts_remote = 0;  // no peer timestamp known yet
    m_rtt = 0;
    m_srtt = 0;
    m_vrtt = 0;

    // Receiver-side state (to be echoed to sender)
    m_r_prev_ts = 0;
    m_r_packets_received = 0;
    m_r_packets_CE = 0;
    m_r_packets_lost = 0;
    m_r_error_L4S = false;

    // --- Sender-side state ---
    m_cc_ts = ts_now;
    m_packets_received = 0;
    m_packets_CE = 0;
    m_packets_lost = 0;
    m_packets_sent = 0;
    m_error_L4S = false;

    // --- Alpha estimation ---
    m_alpha_ts = ts_now;
    m_alpha_packets_received = 0;
    m_alpha_packets_CE = 0;
    m_alpha_packets_lost = 0;
    m_alpha_packets_sent = 0;

    // --- Loss bookkeeping ---
    m_loss_ts = 0;
    m_loss_cca = cca_prague_win;
    m_lost_window = 0;
    m_lost_rate = 0;
    m_loss_packets_lost = 0;
    m_loss_packets_sent = 0;
    m_lost_rtts_to_growth = 0;

    // --- CWR bookkeeping ---
    m_cwr_ts = 0;
    m_cwr_packets_sent = 0;

    // --- Initial CC outputs ---
    m_cc_state = cs_init;
    m_cca_mode = cca_prague_win;

    // Growth delay: higher initial rate => longer delay before aggressive growth
    m_rtts_to_growth= init_rate / RATE_STEP + MIN_STEP;

    m_alpha = 0;
    m_pacing_rate = init_rate;
    m_fractional_window = m_init_window;

    // Choose initial packet size from rate and RTT scale; clamp into [PRAGUE_MINMTU, m_max_packet_size]
    m_packet_size = m_pacing_rate * get_ref_rtt() / 1000000 / MIN_PKT_WIN;            // B/p = B/s * 25ms/burst / 2p/window
    if (m_packet_size < PRAGUE_MINMTU)
        m_packet_size = PRAGUE_MINMTU;
    if (m_packet_size > m_max_packet_size)
        m_packet_size = m_max_packet_size;

    // Compute packet burst such that burst covers roughly BURST_TIME at the current rate
    m_packet_burst = count_tp(m_pacing_rate * BURST_TIME / 1000000 / m_packet_size);  // p = B/s * 250µs / B/p
    if (m_packet_burst < MIN_PKT_BURST)
        m_packet_burst = MIN_PKT_BURST;

    // Packet window derived from fractional window and packet_size; enforce minimum
    m_packet_window = count_tp((m_fractional_window / 1000000 + m_packet_size - 1) / m_packet_size);
    if (m_packet_window < MIN_PKT_WIN)
        m_packet_window = MIN_PKT_WIN;
}

PragueCC::~PragueCC() { }

bool PragueCC::RFC8888Received(size_t num_rtt, time_tp *pkts_rtt) {
    // Consume RTT samples and update smoothed RTT and vRTT
    for (size_t i = 0; i < num_rtt; i++) {
        m_rtt = pkts_rtt[i];

        // EWMA SRTT with 1/8 smoothing; initialize on first sample
        m_srtt = (m_cc_state != cs_init) ?  m_srtt + ((m_rtt - m_srtt) >> 3) : m_rtt;

        // vRTT is floored by reference RTT
        m_vrtt = (m_srtt > get_ref_rtt()) ? m_srtt : get_ref_rtt();
    }

    return true;
}

bool PragueCC::PacketReceived(const time_tp timestamp, const time_tp echoed_timestamp) {
    // Ignore older or invalid ACKs (these counters can't go down in new ACKs)
    if ((m_cc_state != cs_init) && (m_r_prev_ts - timestamp > 0))
        return false;

    time_tp ts = Now();
    m_ts_remote = ts - timestamp;  // Freeze the remote timestamp
    m_rtt = ts - echoed_timestamp; // Calculate the new rtt sample

    // EWMA SRTT with 1/8 smoothing; initialize on first sample
    m_srtt = (m_cc_state != cs_init) ?  m_srtt + ((m_rtt - m_srtt) >> 3) : m_rtt;

    // vRTT is floored by reference RTT
    m_vrtt = (m_srtt > get_ref_rtt()) ? m_srtt : get_ref_rtt();

    m_r_prev_ts = timestamp;

    return true;
}

bool PragueCC::ACKReceived(count_tp packets_received, count_tp packets_CE, count_tp packets_lost, count_tp packets_sent, bool error_L4S, count_tp &inflight) {
    // Ignore older or invalid ACKs (these counters can't go down in new ACKs)
    if ((m_packets_received - packets_received > 0) || (m_packets_CE - packets_CE > 0))
        return false;

    time_tp pacing_interval = m_packet_size * 1000000 / m_pacing_rate; // Max expected RTT from pacing [µs]
    time_tp srtt = (m_srtt);

    // Initial transition: initialize fractional window using current pacing rate * RTT
    if (m_cc_state == cs_init) {
        m_fractional_window = srtt * m_pacing_rate;
        m_cc_state = cs_cong_avoid;
    }

    // --- Mode selection ---
    if ((srtt <= 2000) || (srtt <= pacing_interval)) {
        // Prefer rate-based mode when RTT is too small/noisy to infer queue growth reliably
        m_cca_mode = cca_prague_rate;
    }
    else {
        // Prefer window-based mode when RTT is sufficiently above pacing interval.
        // On mode switch, keep rate stable by re-deriving window from srtt * pacing_rate
        if (m_cca_mode == cca_prague_rate)
            m_fractional_window = srtt * m_pacing_rate;
        m_cca_mode = cca_prague_win;
    }

    time_tp ts = Now();

    // --- Alpha update ---
    // Update alpha only if a real and virtual rtt have passed
    if ((packets_received + packets_lost - m_alpha_packets_sent > 0) && (ts - m_alpha_ts - m_vrtt >= 0)) {
        // Fixed-point marking probability over the window:
        // prob = (ΔCE / Δreceived) in PROB_SHIFT fixed-point
        prob_tp prob = (prob_tp(packets_CE - m_alpha_packets_CE) << PROB_SHIFT) /
                        (packets_received - m_alpha_packets_received);

        // EWMA update for alpha
        m_alpha += ((prob - m_alpha) / get_alpha_shift());
        m_alpha = (m_alpha > MAX_PROB) ? MAX_PROB : m_alpha;

        m_alpha_packets_sent = packets_sent;
        m_alpha_packets_CE = packets_CE;
        m_alpha_packets_received = packets_received;
        m_alpha_ts = ts;

        // Each alpha epoch also counts down the growth-wait
        if (m_rtts_to_growth > 0)
            m_rtts_to_growth--;
    }

    // --- Undo loss reduction on reordering correction ---
    // If we previously reduced due to an increase in packets_lost, and the receiver later "walks back"
    // packets_lost to the value that triggered the reduction, treat it as reordering and undo once.
    if ((m_lost_window > 0 || m_lost_rate > 0) && (m_loss_packets_lost - packets_lost >= 0)) {
        m_cca_mode = m_loss_cca;

        if (m_cca_mode == cca_prague_rate) {
            m_pacing_rate += m_lost_rate;
            m_lost_rate = 0; // undo only once
        } else {
            m_fractional_window += m_lost_window;
            m_lost_window = 0; // undo only once
        }

        m_rtts_to_growth -= m_lost_rtts_to_growth;
        if (m_rtts_to_growth < 0)
            m_rtts_to_growth = 0;

        m_lost_rtts_to_growth = 0; // undo only once
        m_cc_state = cs_cong_avoid;
    }

    // --- End loss epoch after one vRTT ---
    // Prevent multiple loss reductions per vRTT
    if ((m_cc_state == cs_in_loss) &&
        (packets_received + packets_lost - m_loss_packets_sent > 0) && 
        (ts - m_loss_ts - m_vrtt >= 0)) {
        m_cc_state = cs_cong_avoid;
    }

    // --- Loss-triggered reduction ---
    if ((m_cc_state != cs_in_loss) && (m_packets_lost - packets_lost < 0)) {
        // vRTTs needed to get to the time where a REF_RTT flow would hit the same bottleneck again. after that do 1ms growth
        count_tp rtts_to_growth = m_pacing_rate / 2 / m_max_packet_size * REF_RTT / m_vrtt * REF_RTT / 1000000; // rescale twice

        // Record how much we changed growth-wait so we can undo on reordering correction
        m_lost_rtts_to_growth += rtts_to_growth - m_rtts_to_growth;
        if (m_lost_rtts_to_growth > rtts_to_growth)
            m_lost_rtts_to_growth = rtts_to_growth;

        m_rtts_to_growth = rtts_to_growth;

        // Apply reduction (rate or window), and remember it for one-time undo
        if (m_cca_mode == cca_prague_win) {
            m_lost_window = m_fractional_window / 2;
            m_fractional_window -= m_lost_window;
        } else { // (m_cca_mode == cca_prague_rate)
            m_lost_rate = m_pacing_rate / 2;
            m_pacing_rate -= m_lost_rate;
        }

        m_cc_state = cs_in_loss;
        m_loss_cca = m_cca_mode;
        m_loss_packets_sent = packets_sent;
        m_loss_ts = ts;
        m_loss_packets_lost = m_packets_lost;
    }

    // --- Growth (on non-CE ACKs, when not in loss epoch) ---
    // acks = Δreceived - ΔCE (only credit for ACKs that did not report CE)
    count_tp acks = (packets_received - m_packets_received) - (packets_CE - m_packets_CE);
    if ((m_cc_state != cs_in_loss) && (acks > 0)) {
        // Growth step size: either 1ms of queue (rate * 1ms) or at least 1 MTU,
        // depending on growth-wait status
        size_tp increment = mul_64_64_shift(m_pacing_rate, QUEUE_GROWTH) / 1000000;  // incr = B/s * 1ms
        if ((increment < m_max_packet_size) || m_rtts_to_growth)
            increment = m_max_packet_size;

        // W[p] = W + acks / W * (srrt/vrtt)², but in the right order to not lose precision
        // W[µB] = W + acks * mtu² * 1000000² / W * (srrt/vrtt)²
        // correct order to prevent loss of precision
        if (m_cca_mode == cca_prague_win) {
            // Window growth formula scaled for fixed-point math
            uint64_t divisor  = mul_64_64_shift(m_vrtt, m_vrtt);     // Use mul_64_64 to implicitely convert to uint64_t
            uint64_t scaler   = div_64_64_round((uint64_t) srtt * 1000000 * srtt, divisor);
            uint64_t increase = div_64_64_round(acks * m_packet_size * scaler * 1000000, m_fractional_window);
            uint64_t scaled_increase = mul_64_64_shift(increase, increment);
            m_fractional_window += scaled_increase;
        } else {
            // Rate-mode growth
            uint64_t divisor = mul_64_64_shift(m_packet_size, 1000000);
            uint64_t invscaler = div_64_64_round(mul_64_64_shift(m_pacing_rate, m_vrtt), divisor);
            uint64_t increase = div_64_64_round(mul_64_64_shift((uint64_t) acks * increment, 1000000), m_vrtt);
            uint64_t scaled_increase = div_64_64_round(increase, invscaler);
            m_pacing_rate += scaled_increase;
        }
    }

    // --- End CWR epoch after one window and vRTT ---
    if ((m_cc_state == cs_in_cwr) &&
        (packets_received + packets_lost - m_cwr_packets_sent > 0) && 
        (ts - m_cwr_ts - m_vrtt >= 0)) {
        m_cc_state = cs_cong_avoid;
    }


    // --- CE-triggered reduction (CWR) ---
    // Reduce once per vRTT when CE counter increases and we are in normal avoidance
    if ((m_cc_state == cs_cong_avoid) && (m_packets_CE - packets_CE < 0)) {
        // Reset growth-wait on CE
        m_rtts_to_growth = m_pacing_rate / RATE_STEP + MIN_STEP;

        // Reduce by alpha/2 factor
        if (m_cca_mode == cca_prague_win)
            m_fractional_window -= m_fractional_window * m_alpha >> (PROB_SHIFT + 1);
        else
            m_pacing_rate -= m_pacing_rate * m_alpha >> (PROB_SHIFT + 1);

        m_cc_state = cs_in_cwr;
        m_cwr_packets_sent = packets_sent;
        m_cwr_ts = ts;
    }

    // --- Derive dependent parameters and clamp ---

    // Align window and rate depending on active controller.
    if (m_cca_mode != cca_prague_rate)
        m_pacing_rate = m_fractional_window / srtt;   // [B/s]
    if (m_pacing_rate < m_min_rate)
        m_pacing_rate = m_min_rate;
    if (m_pacing_rate > m_max_rate)
        m_pacing_rate = m_max_rate;

    m_fractional_window = m_pacing_rate * srtt; // [µB]
    if (m_fractional_window == 0)
        m_fractional_window = 1;

    // Packet size selection: based on rate and vRTT, with minimum and MTU cap.
    m_packet_size = m_pacing_rate * m_vrtt / 1000000 / MIN_PKT_WIN; // B/p = B/s * 25ms/burst / 2p/burst
    if (m_packet_size < PRAGUE_MINMTU)
        m_packet_size = PRAGUE_MINMTU;
    if (m_packet_size > m_max_packet_size)
        m_packet_size = m_max_packet_size;

    // Packet burst: sized to fit approximately BURST_TIME.
    m_packet_burst = count_tp(m_pacing_rate * BURST_TIME / 1000000 / m_packet_size);  // p = B/s * 250µs / B/p
    if (m_packet_burst < MIN_PKT_BURST)
        m_packet_burst = MIN_PKT_BURST;

    // Packet window: allow a small headroom so cwnd doesn't block pacing due to short freezes/hiccups.
    m_packet_window = count_tp((m_fractional_window * (100 + RATE_OFFSET) / 100000000) / m_packet_size + 1);
    if (m_packet_window < MIN_PKT_WIN)
        m_packet_window = MIN_PKT_WIN;

    // --- Commit ACK as "previous" for next delta computations ---
    m_cc_ts = ts;
    m_packets_received = packets_received;  // can NOT go down
    m_packets_CE = packets_CE;              // can NOT go down
    m_packets_lost = packets_lost;          // CAN go down
    m_packets_sent = packets_sent;          // can NOT go down
    m_error_L4S |= error_L4S;               // can NOT reset

    inflight = packets_sent - m_packets_received - m_packets_lost;

    return true;
}

void PragueCC::DataReceivedSequence(ecn_tp ip_ecn, count_tp packet_seq_nr) {
    ip_ecn = ecn_tp(ip_ecn & ecn_ce);

    // NOTE: Assumes no duplicates are delivered by the network/application.
    m_r_packets_received++;

    count_tp skipped = packet_seq_nr - m_r_packets_received - m_r_packets_lost;
    if (skipped >= 0)
        m_r_packets_lost += skipped;  // Possible loss
    else if (m_r_packets_lost > 0)
        m_r_packets_lost--; // Reordered packet

    if (ip_ecn == ecn_ce)
        m_r_packets_CE++;
    else if (ip_ecn != ecn_l4s_id)
        m_r_error_L4S = true;
}

void PragueCC::DataReceived(ecn_tp ip_ecn, count_tp packets_lost) {
    ip_ecn = ecn_tp(ip_ecn & ecn_ce);

    m_r_packets_received++;
    m_r_packets_lost += packets_lost; // May be -1 to undo previous loss attribution

    if (ip_ecn == ecn_ce)
        m_r_packets_CE++;
    else if (ip_ecn != ecn_l4s_id)
        m_r_error_L4S = true;
}

void PragueCC::ResetCCInfo() {
    // Reset algorithmic state to initial conditions
    m_cc_ts = Now();
    m_cc_state = cs_init;
    m_cca_mode = cca_prague_win;

    // Reset alpha estimation
    m_alpha_ts = m_cc_ts;
    m_alpha = 0;

    // Reset rate/window outputs
    m_pacing_rate = m_init_rate;
    m_fractional_window = m_max_packet_size * 1000000; // Reset to 1 packet

    // Reset packet-level outputs
    m_packet_burst = MIN_PKT_BURST;
    m_packet_size = m_max_packet_size;
    m_packet_window = MIN_PKT_WIN;

    // Reset growth-wait bookkeeping and undo bookkeeping
    m_rtts_to_growth = m_pacing_rate / RATE_STEP + MIN_STEP;
    m_lost_rtts_to_growth = 0;
}

void PragueCC::GetTimeInfo(time_tp &timestamp, time_tp &echoed_timestamp, ecn_tp &ip_ecn) {
    timestamp = Now();
    echoed_timestamp = (m_ts_remote) ? timestamp - m_ts_remote : 0;
    ip_ecn =  (m_error_L4S) ? ecn_not_ect : ecn_l4s_id;
}

void PragueCC::GetCCInfo(rate_tp &pacing_rate, count_tp &packet_window, count_tp &packet_burst, size_tp &packet_size) {
  // Alternate pacing rate by ±RATE_OFFSET% around m_pacing_rate every ~vRTT/2.
  // The higher phase probes for spare capacity; CE feedback (alpha) determines further growth.
    if (Now() - m_alpha_ts - (m_vrtt >> 1) >= 0)
        pacing_rate = m_pacing_rate * 100 / (100 + RATE_OFFSET);
    else
        pacing_rate = m_pacing_rate * (100 + RATE_OFFSET) / 100;

    packet_window = m_packet_window;
    packet_burst = m_packet_burst;
    packet_size = m_packet_size;
}

void PragueCC::GetCCInfoVideo(rate_tp &pacing_rate, size_tp &frame_size, count_tp &frame_window, count_tp &packet_burst, size_tp &packet_size) {
    pacing_rate = m_pacing_rate;
    packet_burst = m_packet_burst;
    packet_size = m_packet_size;

    // Frame size is at least one packet and at most what fits in (rate * frame_budget).
    frame_size = m_pacing_rate * m_frame_budget / 1000000;
    if (frame_size < m_packet_size)
      frame_size = m_packet_size;

    // Frame window derived from packet window scaled by bytes/frame.
    frame_window = m_packet_window * m_packet_size / frame_size;
    if (frame_window < MIN_FRAME_WIN)
       frame_window = MIN_FRAME_WIN;
}

void PragueCC::GetACKInfo(count_tp &packets_received, count_tp &packets_CE, count_tp &packets_lost, bool &error_L4S) {
    // Export receiver-side cumulative counters and L4S error flag for ACK generation
    packets_received = m_r_packets_received;
    packets_CE = m_r_packets_CE;
    packets_lost = m_r_packets_lost;
    error_L4S = m_r_error_L4S;
}
