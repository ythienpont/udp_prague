#include "prague_cc.h"
#include <chrono>

uint64_t mul_64_64_shift(uint64_t left, uint64_t right, uint32_t shift = 0) {
  uint64_t a0 = left & ((1ULL << 32) - 1);
  uint64_t a1 = left >> 32;
  uint64_t b0 = right & ((1ULL << 32) - 1);
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

  result_low = (m0 & ((1ULL << 32) - 1)) | (m2 << 32);
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

// Prague constants

// Minimally wait for 7 RTTs to try to increase faster
const rate_tp MIN_STEP = 7;

// Per 1920kB/s = 15360kbps pacing rate wait one RTT longer
const rate_tp RATE_STEP = 1920000;
// Target a queue growth of 1000us = 1ms
// after waiting pacing_rate / RATE_STEP + MIN_STEP
const time_tp QUEUE_GROWTH = 1000;
const time_tp BURST_TIME = 250; // 250us
const time_tp REF_RTT = 25000;  // 25ms
// enough as max value that can control up to 100Gbps
// with r [Mbps] = 1/p - 1, p = 1/(r + 1) = 1/100001
const uint8_t PROB_SHIFT = 20;
// With r [Mbps] = 1/p - 1 = 2^20 Mbps = 1Tbps
const prob_tp MAX_PROB = 1 << PROB_SHIFT;
const uint8_t ALPHA_SHIFT = 4;    // >> 4 is divide by 16
const count_tp MIN_PKT_BURST = 1; // 1 packet
const count_tp MIN_PKT_WIN = 2;   // 2 packets
// +3% and -3% for non-RTmode transfer during 1st and 2nd halve vrtt
const uint8_t RATE_OFFSET = 3;
const count_tp MIN_FRAME_WIN = 2; // 2 frames

time_tp PragueCC::Now() // Returns number of µs since first call
{
  // Checks if now==0; skip this value used to check uninitialized timepstamp
  if (m_start_ref == 0) {
    m_start_ref =
        time_tp(std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count());

    // Init m_start_ref with -1 to avoid next now to be less than this value
    m_start_ref = (m_start_ref != 0) ? m_start_ref : -1;

    return 1; // make sure we don't return less than or equal to 0
  }

  time_tp now = time_tp(std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count()) -
                m_start_ref;

  return (now != 0) ? now : 1;
}

time_tp PragueCC::get_ref_rtt() {
  return (m_frame_interval != 0) ? m_frame_interval : REF_RTT;
}

count_tp PragueCC::get_alpha_shift() {
  return (m_frame_interval != 0)
             ? (1 << ALPHA_SHIFT) * (REF_RTT) / (m_frame_interval)
             : 1 << ALPHA_SHIFT;
}

PragueCC::PragueCC(size_tp max_packet_size, fps_tp fps, time_tp frame_budget,
                   rate_tp init_rate, count_tp init_window, rate_tp min_rate,
                   rate_tp max_rate) {
  m_start_ref = 0;
  time_tp ts_now = Now();

  m_init_rate = init_rate;
  m_init_window = window_tp(init_window) * max_packet_size * 1000000;
  m_min_rate = min_rate;
  m_max_rate = max_rate;
  m_max_packet_size = max_packet_size;
  m_frame_interval = fps ? 1000000 / fps : 0;
  m_frame_budget = frame_budget;
  if (m_frame_budget > m_frame_interval)
    m_frame_budget = m_frame_interval;

  m_ts_remote = 0;

  m_rtt = 0;
  m_srtt = 0;
  m_vrtt = 0;

  m_r_prev_ts = 0;
  m_r_packets_received = 0;
  m_r_packets_CE = 0;
  m_r_packets_lost = 0;
  m_r_error_L4S = false;

  m_cc_ts = ts_now;
  m_packets_received = 0;
  m_packets_CE = 0;
  m_packets_lost = 0;
  m_packets_sent = 0;
  m_error_L4S = false;

  m_alpha_ts = ts_now; // Start recording alpha from now on (every vrtt)
  m_alpha_packets_received = 0;
  m_alpha_packets_CE = 0;
  m_alpha_packets_lost = 0;
  m_alpha_packets_sent = 0;

  m_loss_ts = 0;
  m_loss_cca = cca_prague_win;
  m_lost_window = 0;
  m_lost_rate = 0;
  m_loss_packets_lost = 0;
  m_loss_packets_sent = 0;
  m_lost_rtts_to_growth = 0;

  m_cwr_ts = 0;
  m_cwr_packets_sent = 0;

  m_cc_state = cs_init;
  m_cca_mode = cca_prague_win;
  m_rtts_to_growth = init_rate / RATE_STEP + MIN_STEP;
  m_alpha = 0;
  m_pacing_rate = init_rate;
  m_fractional_window = m_init_window;

  // B/p = B/s * 25ms/burst / 2p/window
  m_packet_size = m_pacing_rate * get_ref_rtt() / 1000000 / MIN_PKT_WIN;
  if (m_packet_size < PRAGUE_MINMTU)
    m_packet_size = PRAGUE_MINMTU;
  if (m_packet_size > m_max_packet_size)
    m_packet_size = m_max_packet_size;

  // p = B/s * 250µs / B/p
  m_packet_burst =
      count_tp(m_pacing_rate * BURST_TIME / 1000000 / m_packet_size);
  if (m_packet_burst < MIN_PKT_BURST)
    m_packet_burst = MIN_PKT_BURST;

  m_packet_window = count_tp(
      (m_fractional_window / 1000000 + m_packet_size - 1) / m_packet_size);
  if (m_packet_window < MIN_PKT_WIN)
    m_packet_window = MIN_PKT_WIN;
}

PragueCC::~PragueCC() {}

bool PragueCC::RFC8888Received(size_t num_rtt, time_tp *pkts_rtt) {
  for (size_t i = 0; i < num_rtt; i++) {
    m_rtt = pkts_rtt[i];
    if (m_cc_state != cs_init)
      m_srtt += (m_rtt - m_srtt) >> 3;
    else
      m_srtt = m_rtt;
    m_vrtt = (m_srtt > get_ref_rtt()) ? m_srtt : get_ref_rtt();
  }
  return true;
}

bool PragueCC::PacketReceived(const time_tp timestamp,
                              const time_tp echoed_timestamp) {
  // Ignore older or invalid ACKs (these counters can't go down in new ACKs)
  if ((m_cc_state != cs_init) && (m_r_prev_ts - timestamp > 0))
    return false;

  time_tp ts = Now();
  m_ts_remote = ts - timestamp;  // freeze the remote timestamp
  m_rtt = ts - echoed_timestamp; // calculate the new rtt sample

  if (m_cc_state != cs_init)
    m_srtt += (m_rtt - m_srtt) >> 3; // smooth with EWMA of 1/8th
  else
    m_srtt = m_rtt;

  // Calculate the virtual RTT (if srtt < 25ms reference RTT)
  m_vrtt = (m_srtt > get_ref_rtt()) ? m_srtt : get_ref_rtt();

  m_r_prev_ts = timestamp;

  return true;
}

bool PragueCC::ACKReceived(count_tp packets_received, count_tp packets_CE,
                           count_tp packets_lost, count_tp packets_sent,
                           bool error_L4S, count_tp &inflight) {
  // Ignore older or invalid ACKs (these counters can't go down in new ACKs)
  if ((m_packets_received - packets_received > 0) ||
      (m_packets_CE - packets_CE > 0))
    return false;

  // Calculate the max expected rtt from pacing
  time_tp pacing_interval = m_packet_size * 1000000 / m_pacing_rate;

  time_tp srtt = (m_srtt);

  // Initialize the window with the initial pacing rate
  if (m_cc_state == cs_init) {
    m_fractional_window = srtt * m_pacing_rate;
    m_cc_state = cs_cong_avoid;
  }

  // Select the rate- or window-based update, but keep the rate stable on
  // switching below the pacing interval or 2ms the RTT is too unstable to
  // calculate a rate. Also no queue can be identified reliably.
  if ((srtt <= 2000) || (srtt <= pacing_interval)) {
    // Keep rate stable when large dip in srtt
    m_cca_mode = cca_prague_rate;
  } else {
    // Keep rate stable when large jump in srtt
    if (m_cca_mode == cca_prague_rate)
      m_fractional_window = srtt * m_pacing_rate;
    m_cca_mode = cca_prague_win;
  }

  time_tp ts = Now();

  // Update alpha if both a window and a virtual rtt are passed
  if ((packets_received + packets_lost - m_alpha_packets_sent > 0) &&
      (ts - m_alpha_ts - m_vrtt >= 0)) {
    updateAlpha(ts, packets_sent, packets_received, packets_CE);
  }

  // Undo the window reduction if the lost count is again down to the one that
  // caused a reduction (reordered iso loss)
  if ((m_lost_window > 0 || m_lost_rate > 0) &&
      (m_loss_packets_lost - packets_lost >= 0))
    restoreReduction();

  // Clear the in_loss state if in_loss and a real and virtual rtt are passed
  if ((m_cc_state == cs_in_loss) &&
      (packets_received + packets_lost - m_loss_packets_sent > 0) &&
      (ts - m_loss_ts - m_vrtt >= 0))
    m_cc_state = cs_cong_avoid;

  // Reduce the window if the loss count is increased
  if ((m_cc_state != cs_in_loss) && (m_packets_lost - packets_lost < 0))
    reduceOnLoss(ts, packets_sent);

  // Increase the window if not in-loss for all the non-CE ACKs
  count_tp acks =
      (packets_received - m_packets_received) - (packets_CE - m_packets_CE);

  if ((m_cc_state != cs_in_loss) && (acks > 0))
    applyIncrease(srtt, acks);

  // Clear the in_cwr state if in_cwr and a real and virtual rtt are passed
  if ((m_cc_state == cs_in_cwr) &&
      (packets_received + packets_lost - m_cwr_packets_sent > 0) &&
      (ts - m_cwr_ts - m_vrtt >= 0)) {
    // Set the loss state to avoid multiple reductions per RTT
    m_cc_state = cs_cong_avoid;
  }

  // Reduce the window if the CE count is increased, and if not in-loss and not
  // in-cwr
  if ((m_cc_state == cs_cong_avoid) && (m_packets_CE - packets_CE < 0)) {
    // First reset the growth waiting time
    m_rtts_to_growth = m_pacing_rate / RATE_STEP + MIN_STEP;

    if (m_cca_mode == cca_prague_win) // Reduce the window by a factor alpha/2
      m_fractional_window -= m_fractional_window * m_alpha >> (PROB_SHIFT + 1);
    else // Reduce the rate by a factor alpha/2
      m_pacing_rate -= m_pacing_rate * m_alpha >> (PROB_SHIFT + 1);

    // Set the loss state to avoid multiple reductions per RTT
    m_cc_state = cs_in_cwr;
    m_cwr_packets_sent = packets_sent; // set when to end in_loss state
    m_cwr_ts = ts; // Set the cwr timestampt to check if a virtRtt is passed
  }

  // Updating dependant parameters
  // align and limit pacing rate and fractional window
  if (m_cca_mode != cca_prague_rate)
    m_pacing_rate = m_fractional_window / srtt; // in B/s
  if (m_pacing_rate < m_min_rate)
    m_pacing_rate = m_min_rate;
  if (m_pacing_rate > m_max_rate)
    m_pacing_rate = m_max_rate;
  m_fractional_window = m_pacing_rate * srtt; // in uB
  if (m_fractional_window == 0)
    m_fractional_window = 1;

  // Determine packet size
  m_packet_size = m_pacing_rate * m_vrtt / 1000000 /
                  MIN_PKT_WIN; // B/p = B/s * 25ms/burst / 2p/burst
  if (m_packet_size < PRAGUE_MINMTU)
    m_packet_size = PRAGUE_MINMTU;
  if (m_packet_size > m_max_packet_size)
    m_packet_size = m_max_packet_size;

  // Packet burst
  m_packet_burst = count_tp(m_pacing_rate * BURST_TIME / 1000000 /
                            m_packet_size); // p = B/s * 250µs / B/p
  if (m_packet_burst < MIN_PKT_BURST) {
    m_packet_burst = MIN_PKT_BURST;
  }

  // packet window: allow 3% higher pacing rate and round up (add one). Window
  // should not block pacing; block only when the network has a freeze or
  // hiccup.
  m_packet_window = count_tp(
      (m_fractional_window * (100 + RATE_OFFSET) / 100000000) / m_packet_size +
      1);
  if (m_packet_window < MIN_PKT_WIN) {
    m_packet_window = MIN_PKT_WIN;
  }

  // remember this previous ACK for the next ACK
  m_cc_ts = ts;
  m_packets_received = packets_received; // can NOT go down
  m_packets_CE = packets_CE;             // can NOT go down
  m_packets_lost = packets_lost;         // CAN go down
  m_packets_sent = packets_sent;         // can NOT go down
  m_error_L4S |= error_L4S;              // can NOT reset
  inflight = packets_sent - m_packets_received - m_packets_lost;
  return true;
}

void PragueCC::DataReceivedSequence(ecn_tp ip_ecn, count_tp packet_seq_nr) {
  ip_ecn = ecn_tp(ip_ecn & ecn_ce);
  m_r_packets_received++; // Assuming no duplicates (by for instance the NW)
  count_tp skipped = packet_seq_nr - m_r_packets_received - m_r_packets_lost;

  if (skipped >= 0)
    m_r_packets_lost += skipped; // 0 or more lost
  else if (m_r_packets_lost > 0)
    m_r_packets_lost--; // reordered packet

  if (ip_ecn == ecn_ce)
    m_r_packets_CE++;
  else if (ip_ecn != ecn_l4s_id)
    m_r_error_L4S = true;
}

void PragueCC::DataReceived(ecn_tp ip_ecn, count_tp packets_lost) {
  ip_ecn = ecn_tp(ip_ecn & ecn_ce);
  m_r_packets_received++;
  m_r_packets_lost += packets_lost;
  if (ip_ecn == ecn_ce)
    m_r_packets_CE++;
  else if (ip_ecn != ecn_l4s_id)
    m_r_error_L4S = true;
}

void PragueCC::ResetCCInfo() {
  m_cc_ts = Now();
  m_cc_state = cs_init;
  m_cca_mode = cca_prague_win;
  m_alpha_ts = m_cc_ts;
  m_alpha = 0;
  m_pacing_rate = m_init_rate;
  m_fractional_window = m_max_packet_size * 1000000; // Reset to 1 packet
  m_packet_burst = MIN_PKT_BURST;
  m_packet_size = m_max_packet_size;
  m_packet_window = MIN_PKT_WIN;
  m_rtts_to_growth = m_pacing_rate / RATE_STEP + MIN_STEP;
  m_lost_rtts_to_growth = 0;
}

void PragueCC::GetTimeInfo(time_tp &timestamp, time_tp &echoed_timestamp,
                           ecn_tp &ip_ecn) {
  timestamp = Now();

  echoed_timestamp = (m_ts_remote != 0) ? timestamp - m_ts_remote : 0;
  ip_ecn = (m_error_L4S) ? ecn_not_ect : ecn_l4s_id;
}

void PragueCC::GetCCInfo(rate_tp &pacing_rate, count_tp &packet_window,
                         count_tp &packet_burst, size_tp &packet_size) {
  if (Now() - m_alpha_ts - (m_vrtt >> 1) >= 0)
    pacing_rate = m_pacing_rate * 100 / (100 + RATE_OFFSET);
  else
    pacing_rate = m_pacing_rate * (100 + RATE_OFFSET) / 100;

  packet_window = m_packet_window;
  packet_burst = m_packet_burst;
  packet_size = m_packet_size;
}

void PragueCC::GetCCInfoVideo(rate_tp &pacing_rate, size_tp &frame_size,
                              count_tp &frame_window, count_tp &packet_burst,
                              size_tp &packet_size) {
  pacing_rate = m_pacing_rate;
  packet_burst = m_packet_burst;
  packet_size = m_packet_size;
  frame_size = (m_packet_size > m_pacing_rate * m_frame_budget / 1000000)
                   ? (m_packet_size)
                   : (m_pacing_rate * m_frame_budget / 1000000);
  frame_window = m_packet_window * m_packet_size / frame_size;
  if (frame_window < MIN_FRAME_WIN)
    frame_window = MIN_FRAME_WIN;
}

void PragueCC::GetACKInfo(count_tp &packets_received, count_tp &packets_CE,
                          count_tp &packets_lost, bool &error_L4S) {
  packets_received = m_r_packets_received;
  packets_CE = m_r_packets_CE;
  packets_lost = m_r_packets_lost;
  error_L4S = m_r_error_L4S;
}

void PragueCC::reduceOnLoss(time_tp now, count_tp packets_sent) {
  // vRTTs needed to get to the time where a REF_RTT flow would hit the same
  // bottleneck again. after that do 1ms growth
  count_tp rtts_to_growth = m_pacing_rate / 2 / m_max_packet_size * REF_RTT /
                            m_vrtt * REF_RTT / 1000000; // rescale twice
  // First reset the growth waiting time, but prepare to undo
  m_lost_rtts_to_growth +=
      rtts_to_growth - m_rtts_to_growth; // accumulate over different
                                         // reordering rtts if applicable

  // No need to undo more than what will be used next
  if (m_lost_rtts_to_growth > rtts_to_growth)
    m_lost_rtts_to_growth = rtts_to_growth;

  // also equivalent to m_rtts_to_growth += m_lost_rtts_to_growth; so can be
  // undone with -=
  m_rtts_to_growth = rtts_to_growth;

  if (m_cca_mode == cca_prague_win) {
    m_lost_window = m_fractional_window / 2; // remember the reduction
    m_fractional_window -= m_lost_window;    // reduce the window
  } else {                                   // (m_cca_mode == cca_prague_rate)
    m_lost_rate = m_pacing_rate / 2;         // remember the reduction
    m_pacing_rate -= m_lost_rate;            // reduce the rate
  }

  // set the loss state to avoid multiple reductions per RTT
  m_cc_state = cs_in_loss;
  m_loss_cca = m_cca_mode;
  m_loss_packets_sent = packets_sent; // Set when to end in_loss state
  m_loss_ts = now; // Set the loss timestampt to check if a virtRtt is passed

  // Remember the previous packets_lost for the undo if needed
  m_loss_packets_lost = m_packets_lost;
}

void PragueCC::restoreReduction() {
  m_cca_mode = m_loss_cca; // Restore the cca mode before recovery
  if (m_cca_mode == cca_prague_rate) {
    m_pacing_rate += m_lost_rate; // Add the reduction to the rate again
    m_lost_rate = 0;              // Can be done only once
  } else {
    // Add the reduction to the window again
    m_fractional_window += m_lost_window;
    m_lost_window = 0; // Can be done only once
  }

  m_rtts_to_growth -= m_lost_rtts_to_growth; // Restore the rtts to growth
  if (m_rtts_to_growth < 0)
    m_rtts_to_growth = 0;
  m_lost_rtts_to_growth = 0;  // Clear all lost growth rtts
  m_cc_state = cs_cong_avoid; // Restore the loss statea
}

void PragueCC::updateAlpha(time_tp now, count_tp packets_sent,
                           count_tp packets_received, count_tp packets_CE) {
  prob_tp prob = (prob_tp(packets_CE - m_alpha_packets_CE) << PROB_SHIFT) /
                 (packets_received - m_alpha_packets_received);
  m_alpha += ((prob - m_alpha) / get_alpha_shift());
  m_alpha = (m_alpha > MAX_PROB) ? MAX_PROB : m_alpha;
  m_alpha_packets_sent = packets_sent;
  m_alpha_packets_CE = packets_CE;
  m_alpha_packets_received = packets_received;
  m_alpha_ts = now;

  // Also reduce the rtts to growth if not already 0
  if (m_rtts_to_growth > 0)
    m_rtts_to_growth--;
}

void PragueCC::applyIncrease(time_tp srtt, count_tp acks) {
  // incr = B/s * 1ms
  size_tp increment = mul_64_64_shift(m_pacing_rate, QUEUE_GROWTH) / 1000000;

  // increment with 1ms queue delay if no more rtts to wait for growth and if
  // > than 1 max packet
  if ((increment < m_max_packet_size) || m_rtts_to_growth)
    increment = m_max_packet_size;

  // W[p] = W + acks / W * (srrt/vrtt)², but in the right order to not lose
  // precision W[µB] = W + acks * mtu² * 1000000² / W * (srrt/vrtt)² correct
  // order to prevent loss of precision
  if (m_cca_mode == cca_prague_win) {
    // Use mul_64_64 to implicitely convert to uint64_t
    uint64_t divisor = mul_64_64_shift(m_vrtt, m_vrtt);
    uint64_t scaler = div_64_64_round((uint64_t)srtt * 1000000 * srtt, divisor);
    uint64_t increase = div_64_64_round(acks * m_packet_size * scaler * 1000000,
                                        m_fractional_window);
    uint64_t scaled_increase = mul_64_64_shift(increase, increment);
    m_fractional_window += scaled_increase;
  } else {
    uint64_t divisor = mul_64_64_shift(m_packet_size, 1000000);
    uint64_t invscaler =
        div_64_64_round(mul_64_64_shift(m_pacing_rate, m_vrtt), divisor);
    uint64_t increase = div_64_64_round(
        mul_64_64_shift((uint64_t)acks * increment, 1000000), m_vrtt);
    uint64_t scaled_increase = div_64_64_round(increase, invscaler);
    m_pacing_rate += scaled_increase;
  }
}
