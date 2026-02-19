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
const RateBps MIN_STEP = 7;

// Per 1920kB/s = 15360kbps pacing rate wait one RTT longer
const RateBps RATE_STEP = 1920000;
// Target a queue growth of 1000us = 1ms
// after waiting pacing_rate / RATE_STEP + MIN_STEP
const TimeUs QUEUE_GROWTH = 1000;
const TimeUs BURST_TIME = 250; // 250us
const TimeUs REF_RTT = 25000;  // 25ms
// enough as max value that can control up to 100Gbps
// with r [Mbps] = 1/p - 1, p = 1/(r + 1) = 1/100001
const uint8_t PROB_SHIFT = 20;
// With r [Mbps] = 1/p - 1 = 2^20 Mbps = 1Tbps
const Probability MAX_PROB = 1 << PROB_SHIFT;
const uint8_t ALPHA_SHIFT = 4; // >> 4 is divide by 16
const Count MIN_PKT_BURST = 1; // 1 packet
const Count MIN_PKT_WIN = 2;   // 2 packets
// +3% and -3% for non-RTmode transfer during 1st and 2nd halve vrtt
const uint8_t RATE_OFFSET = 3;
const Count MIN_FRAME_WIN = 2; // 2 frames

TimeUs PragueCC::Now() // Returns number of µs since first call
{
  // Checks if now==0; skip this value used to check uninitialized timepstamp
  if (start_ref_ == 0) {
    start_ref_ = TimeUs(std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count());

    // Init m_start_ref with -1 to avoid next now to be less than this value
    start_ref_ = (start_ref_ != 0) ? start_ref_ : -1;

    return 1; // make sure we don't return less than or equal to 0
  }

  TimeUs now = TimeUs(std::chrono::duration_cast<std::chrono::microseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count()) -
               start_ref_;

  return (now != 0) ? now : 1;
}

TimeUs PragueCC::get_ref_rtt() {
  return (frame_interval_ != 0) ? frame_interval_ : REF_RTT;
}

Count PragueCC::get_alpha_shift() {
  return (frame_interval_ != 0)
             ? (1 << ALPHA_SHIFT) * (REF_RTT) / (frame_interval_)
             : 1 << ALPHA_SHIFT;
}

PragueCC::PragueCC(SizeB max_packet_size, Fps fps, TimeUs frame_budget,
                   RateBps init_rate, Count init_window, RateBps min_rate,
                   RateBps max_rate) {
  start_ref_ = 0;
  TimeUs ts_now = Now();

  init_rate_ = init_rate;
  init_window_ = FracWindowUB(init_window) * max_packet_size * 1000000;
  min_rate_ = min_rate;
  max_rate_ = max_rate;
  max_packet_size_ = max_packet_size;
  frame_interval_ = fps ? 1000000 / fps : 0;
  frame_budget_ = frame_budget;
  if (frame_budget_ > frame_interval_)
    frame_budget_ = frame_interval_;

  ts_remote_ = 0;

  rtt_ = 0;
  srtt_ = 0;
  vrtt_ = 0;

  r_prev_ts_ = 0;
  r_packets_received_ = 0;
  r_packets_marked_ = 0;
  r_packets_lost_ = 0;
  r_error_L4S_ = false;

  last_cc_update_ = ts_now;
  packets_received_ = 0;
  packets_marked_ = 0;
  packets_lost_ = 0;
  packets_sent_ = 0;
  error_L4S_ = false;

  last_alpha_update_ = ts_now;
  alpha_packets_received_ = 0;
  alpha_packets_marked_ = 0;
  alpha_packets_lost_ = 0;
  alpha_packets_sent_ = 0;

  last_loss_ = 0;
  cca_before_loss_ = cca_prague_win;
  lost_window_ = 0;
  lost_rate_ = 0;
  lost_rtts_to_growth_ = 0;
  loss_packets_lost_ = 0;
  loss_packets_sent_ = 0;

  last_cwnd_reduction_ = 0;
  cwr_packets_sent_ = 0;

  state_ = cs_init;
  mode_ = cca_prague_win;
  rtts_to_growth_ = init_rate / RATE_STEP + MIN_STEP;
  alpha_ = 0;
  pacing_rate_ = init_rate;
  fractional_window_ = init_window_;

  // B/p = B/s * 25ms/burst / 2p/window
  packet_size_ = pacing_rate_ * get_ref_rtt() / 1000000 / MIN_PKT_WIN;
  if (packet_size_ < PRAGUE_MINMTU)
    packet_size_ = PRAGUE_MINMTU;
  if (packet_size_ > max_packet_size_)
    packet_size_ = max_packet_size_;

  // p = B/s * 250µs / B/p
  packet_burst_ = Count(pacing_rate_ * BURST_TIME / 1000000 / packet_size_);
  if (packet_burst_ < MIN_PKT_BURST)
    packet_burst_ = MIN_PKT_BURST;

  packet_window_ =
      Count((fractional_window_ / 1000000 + packet_size_ - 1) / packet_size_);
  if (packet_window_ < MIN_PKT_WIN)
    packet_window_ = MIN_PKT_WIN;
}

PragueCC::~PragueCC() {}

bool PragueCC::RFC8888Received(size_t num_rtt, TimeUs *pkts_rtt) {
  for (size_t i = 0; i < num_rtt; i++) {
    rtt_ = pkts_rtt[i];
    if (state_ != cs_init)
      srtt_ += (rtt_ - srtt_) >> 3;
    else
      srtt_ = rtt_;
    vrtt_ = (srtt_ > get_ref_rtt()) ? srtt_ : get_ref_rtt();
  }
  return true;
}

bool PragueCC::PacketReceived(const TimeUs timestamp,
                              const TimeUs echoed_timestamp) {
  // Ignore older or invalid ACKs (these counters can't go down in new ACKs)
  if ((state_ != cs_init) && (r_prev_ts_ - timestamp > 0))
    return false;

  TimeUs ts = Now();
  ts_remote_ = ts - timestamp;  // freeze the remote timestamp
  rtt_ = ts - echoed_timestamp; // calculate the new rtt sample

  if (state_ != cs_init)
    srtt_ += (rtt_ - srtt_) >> 3; // smooth with EWMA of 1/8th
  else
    srtt_ = rtt_;

  // Calculate the virtual RTT (if srtt < 25ms reference RTT)
  vrtt_ = (srtt_ > get_ref_rtt()) ? srtt_ : get_ref_rtt();

  r_prev_ts_ = timestamp;

  return true;
}

bool PragueCC::ACKReceived(Count packets_received, Count packets_marked,
                           Count packets_lost, Count packets_sent,
                           bool error_L4S, Count &inflight) {
  // Ignore older or invalid ACKs (these counters can't go down in new ACKs)
  if ((packets_received_ - packets_received > 0) ||
      (packets_marked_ - packets_marked > 0))
    return false;

  // Calculate the max expected rtt from pacing
  TimeUs pacing_interval = packet_size_ * 1000000 / pacing_rate_;

  TimeUs srtt = (srtt_);

  // Initialize the window with the initial pacing rate
  if (state_ == cs_init) {
    fractional_window_ = srtt * pacing_rate_;
    state_ = cs_cong_avoid;
  }

  // Select the rate- or window-based update, but keep the rate stable on
  // switching below the pacing interval or 2ms the RTT is too unstable to
  // calculate a rate. Also no queue can be identified reliably.
  if ((srtt <= 2000) || (srtt <= pacing_interval)) {
    // Keep rate stable when large dip in srtt
    mode_ = cca_prague_rate;
  } else {
    // Keep rate stable when large jump in srtt
    if (mode_ == cca_prague_rate)
      fractional_window_ = srtt * pacing_rate_;
    mode_ = cca_prague_win;
  }

  TimeUs ts = Now();

  // Update alpha if both a window and a virtual rtt are passed
  if ((packets_received + packets_lost - alpha_packets_sent_ > 0) &&
      (ts - last_alpha_update_ - vrtt_ >= 0)) {
    updateAlpha(ts, packets_sent, packets_received, packets_marked);
  }

  // Undo the window reduction if the lost count is again down to the one that
  // caused a reduction (reordered iso loss)
  if ((lost_window_ > 0 || lost_rate_ > 0) &&
      (loss_packets_lost_ - packets_lost >= 0))
    restoreReduction();

  // Clear the in_loss state if in_loss and a real and virtual rtt are passed
  if ((state_ == cs_in_loss) &&
      (packets_received + packets_lost - loss_packets_sent_ > 0) &&
      (ts - last_loss_ - vrtt_ >= 0))
    state_ = cs_cong_avoid;

  // Reduce the window if the loss count is increased
  if ((state_ != cs_in_loss) && (packets_lost_ - packets_lost < 0))
    reduceOnLoss(ts, packets_sent);

  // Increase the window if not in-loss for all the non-CE ACKs
  Count acks = (packets_received - packets_received_) -
               (packets_marked - packets_marked_);

  if ((state_ != cs_in_loss) && (acks > 0))
    applyIncrease(srtt, acks);

  // Clear the in_cwr state if in_cwr and a real and virtual rtt are passed
  if ((state_ == cs_in_cwr) &&
      (packets_received + packets_lost - cwr_packets_sent_ > 0) &&
      (ts - last_cwnd_reduction_ - vrtt_ >= 0)) {
    // Set the loss state to avoid multiple reductions per RTT
    state_ = cs_cong_avoid;
  }

  // Reduce the window if the CE count is increased, and if not in-loss and not
  // in-cwr
  if ((state_ == cs_cong_avoid) && (packets_marked_ - packets_marked < 0)) {
    // First reset the growth waiting time
    rtts_to_growth_ = pacing_rate_ / RATE_STEP + MIN_STEP;

    if (mode_ == cca_prague_win) // Reduce the window by a factor alpha/2
      fractional_window_ -= fractional_window_ * alpha_ >> (PROB_SHIFT + 1);
    else // Reduce the rate by a factor alpha/2
      pacing_rate_ -= pacing_rate_ * alpha_ >> (PROB_SHIFT + 1);

    // Set the loss state to avoid multiple reductions per RTT
    state_ = cs_in_cwr;
    cwr_packets_sent_ = packets_sent; // set when to end in_loss state
    last_cwnd_reduction_ =
        ts; // Set the cwr timestampt to check if a virtRtt is passed
  }

  // Updating dependant parameters
  // align and limit pacing rate and fractional window
  if (mode_ != cca_prague_rate)
    pacing_rate_ = fractional_window_ / srtt; // in B/s
  if (pacing_rate_ < min_rate_)
    pacing_rate_ = min_rate_;
  if (pacing_rate_ > max_rate_)
    pacing_rate_ = max_rate_;
  fractional_window_ = pacing_rate_ * srtt; // in uB
  if (fractional_window_ == 0)
    fractional_window_ = 1;

  // Determine packet size
  packet_size_ = pacing_rate_ * vrtt_ / 1000000 /
                 MIN_PKT_WIN; // B/p = B/s * 25ms/burst / 2p/burst
  if (packet_size_ < PRAGUE_MINMTU)
    packet_size_ = PRAGUE_MINMTU;
  if (packet_size_ > max_packet_size_)
    packet_size_ = max_packet_size_;

  // Packet burst
  packet_burst_ = Count(pacing_rate_ * BURST_TIME / 1000000 /
                        packet_size_); // p = B/s * 250µs / B/p
  if (packet_burst_ < MIN_PKT_BURST) {
    packet_burst_ = MIN_PKT_BURST;
  }

  // packet window: allow 3% higher pacing rate and round up (add one). Window
  // should not block pacing; block only when the network has a freeze or
  // hiccup.
  packet_window_ = Count(
      (fractional_window_ * (100 + RATE_OFFSET) / 100000000) / packet_size_ +
      1);
  if (packet_window_ < MIN_PKT_WIN) {
    packet_window_ = MIN_PKT_WIN;
  }

  // remember this previous ACK for the next ACK
  last_cc_update_ = ts;
  packets_received_ = packets_received; // can NOT go down
  packets_marked_ = packets_marked;     // can NOT go down
  packets_lost_ = packets_lost;         // CAN go down
  packets_sent_ = packets_sent;         // can NOT go down
  error_L4S_ |= error_L4S;              // can NOT reset
  inflight = packets_sent - packets_received_ - packets_lost_;
  return true;
}

void PragueCC::DataReceivedSequence(Ecn ip_ecn, Count packet_seq_nr) {
  ip_ecn = Ecn(ip_ecn & ecn_ce);
  r_packets_received_++; // Assuming no duplicates (by for instance the NW)
  Count skipped = packet_seq_nr - r_packets_received_ - r_packets_lost_;

  if (skipped >= 0)
    r_packets_lost_ += skipped; // 0 or more lost
  else if (r_packets_lost_ > 0)
    r_packets_lost_--; // reordered packet

  if (ip_ecn == ecn_ce)
    r_packets_marked_++;
  else if (ip_ecn != ecn_l4s_id)
    r_error_L4S_ = true;
}

void PragueCC::DataReceived(Ecn ip_ecn, Count packets_lost) {
  ip_ecn = Ecn(ip_ecn & ecn_ce);
  r_packets_received_++;
  r_packets_lost_ += packets_lost;
  if (ip_ecn == ecn_ce)
    r_packets_marked_++;
  else if (ip_ecn != ecn_l4s_id)
    r_error_L4S_ = true;
}

void PragueCC::ResetCCInfo() {
  last_cc_update_ = Now();
  state_ = cs_init;
  mode_ = cca_prague_win;
  last_alpha_update_ = last_cc_update_;
  alpha_ = 0;
  pacing_rate_ = init_rate_;
  fractional_window_ = max_packet_size_ * 1000000; // Reset to 1 packet
  packet_burst_ = MIN_PKT_BURST;
  packet_size_ = max_packet_size_;
  packet_window_ = MIN_PKT_WIN;
  rtts_to_growth_ = pacing_rate_ / RATE_STEP + MIN_STEP;
  lost_rtts_to_growth_ = 0;
}

void PragueCC::GetTimeInfo(TimeUs &timestamp, TimeUs &echoed_timestamp,
                           Ecn &ip_ecn) {
  timestamp = Now();
  echoed_timestamp = (ts_remote_ != 0) ? timestamp - ts_remote_ : 0;
  ip_ecn = (error_L4S_) ? ecn_not_ect : ecn_l4s_id;
}

void PragueCC::GetCCInfo(RateBps &pacing_rate, Count &packet_window,
                         Count &packet_burst, SizeB &packet_size) {
  if (Now() - last_alpha_update_ - (vrtt_ >> 1) >= 0)
    pacing_rate = pacing_rate_ * 100 / (100 + RATE_OFFSET);
  else
    pacing_rate = pacing_rate_ * (100 + RATE_OFFSET) / 100;

  packet_window = packet_window_;
  packet_burst = packet_burst_;
  packet_size = packet_size_;
}

void PragueCC::GetCCInfoVideo(RateBps &pacing_rate, SizeB &frame_size,
                              Count &frame_window, Count &packet_burst,
                              SizeB &packet_size) {
  pacing_rate = pacing_rate_;
  packet_burst = packet_burst_;
  packet_size = packet_size_;
  frame_size = (packet_size_ > pacing_rate_ * frame_budget_ / 1000000)
                   ? (packet_size_)
                   : (pacing_rate_ * frame_budget_ / 1000000);
  frame_window = packet_window_ * packet_size_ / frame_size;
  if (frame_window < MIN_FRAME_WIN)
    frame_window = MIN_FRAME_WIN;
}

void PragueCC::GetACKInfo(Count &packets_received, Count &packets_marked,
                          Count &packets_lost, bool &error_L4S) {
  packets_received = r_packets_received_;
  packets_marked = r_packets_marked_;
  packets_lost = r_packets_lost_;
  error_L4S = r_error_L4S_;
}

void PragueCC::reduceOnLoss(TimeUs now, Count packets_sent) {
  // vRTTs needed to get to the time where a REF_RTT flow would hit the same
  // bottleneck again. after that do 1ms growth
  Count rtts_to_growth = pacing_rate_ / 2 / max_packet_size_ * REF_RTT / vrtt_ *
                         REF_RTT / 1000000; // rescale twice
  // First reset the growth waiting time, but prepare to undo
  lost_rtts_to_growth_ +=
      rtts_to_growth - rtts_to_growth_; // accumulate over different
                                        // reordering rtts if applicable

  // No need to undo more than what will be used next
  if (lost_rtts_to_growth_ > rtts_to_growth)
    lost_rtts_to_growth_ = rtts_to_growth;

  // also equivalent to rtts_to_growth_ += m_lost_rtts_to_growth; so can be
  // undone with -=
  rtts_to_growth_ = rtts_to_growth;

  if (mode_ == cca_prague_win) {
    lost_window_ = fractional_window_ / 2; // remember the reduction
    fractional_window_ -= lost_window_;    // reduce the window
  } else {                                 // (mode_ == cca_prague_rate)
    lost_rate_ = pacing_rate_ / 2;         // remember the reduction
    pacing_rate_ -= lost_rate_;            // reduce the rate
  }

  // set the loss state to avoid multiple reductions per RTT
  state_ = cs_in_loss;
  cca_before_loss_ = mode_;
  loss_packets_sent_ = packets_sent; // Set when to end in_loss state
  last_loss_ = now; // Set the loss timestamp to check if a virtRtt is passed

  // Remember the previous packets_lost for the undo if needed
  loss_packets_lost_ = packets_lost_;
}

void PragueCC::restoreReduction() {
  mode_ = cca_before_loss_; // Restore the cca mode before recovery
  if (mode_ == cca_prague_rate) {
    pacing_rate_ += lost_rate_; // Add the reduction to the rate again
    lost_rate_ = 0;             // Can be done only once
  } else {
    // Add the reduction to the window again
    fractional_window_ += lost_window_;
    lost_window_ = 0; // Can be done only once
  }

  rtts_to_growth_ -= lost_rtts_to_growth_; // Restore the rtts to growth
  if (rtts_to_growth_ < 0)
    rtts_to_growth_ = 0;
  lost_rtts_to_growth_ = 0; // Clear all lost growth rtts
  state_ = cs_cong_avoid;   // Restore the loss statea
}

void PragueCC::updateAlpha(TimeUs now, Count packets_sent,
                           Count packets_received, Count packets_marked) {
  Probability prob =
      (Probability(packets_marked - alpha_packets_marked_) << PROB_SHIFT) /
      (packets_received - alpha_packets_received_);
  alpha_ += ((prob - alpha_) / get_alpha_shift());
  alpha_ = (alpha_ > MAX_PROB) ? MAX_PROB : alpha_;
  alpha_packets_sent_ = packets_sent;
  alpha_packets_marked_ = packets_marked;
  alpha_packets_received_ = packets_received;
  last_alpha_update_ = now;

  // Also reduce the rtts to growth if not already 0
  if (rtts_to_growth_ > 0)
    rtts_to_growth_--;
}

void PragueCC::applyIncrease(TimeUs srtt, Count acks) {
  // incr = B/s * 1ms
  SizeB increment = mul_64_64_shift(pacing_rate_, QUEUE_GROWTH) / 1000000;

  // increment with 1ms queue delay if no more rtts to wait for growth and if
  // > than 1 max packet
  if ((increment < max_packet_size_) || rtts_to_growth_)
    increment = max_packet_size_;

  // W[p] = W + acks / W * (srrt/vrtt)², but in the right order to not lose
  // precision W[µB] = W + acks * mtu² * 1000000² / W * (srrt/vrtt)² correct
  // order to prevent loss of precision
  if (mode_ == cca_prague_win) {
    // Use mul_64_64 to implicitely convert to uint64_t
    uint64_t divisor = mul_64_64_shift(vrtt_, vrtt_);
    uint64_t scaler = div_64_64_round((uint64_t)srtt * 1000000 * srtt, divisor);
    uint64_t increase = div_64_64_round(acks * packet_size_ * scaler * 1000000,
                                        fractional_window_);
    uint64_t scaled_increase = mul_64_64_shift(increase, increment);
    fractional_window_ += scaled_increase;
  } else {
    uint64_t divisor = mul_64_64_shift(packet_size_, 1000000);
    uint64_t invscaler =
        div_64_64_round(mul_64_64_shift(pacing_rate_, vrtt_), divisor);
    uint64_t increase = div_64_64_round(
        mul_64_64_shift((uint64_t)acks * increment, 1000000), vrtt_);
    uint64_t scaled_increase = div_64_64_round(increase, invscaler);
    pacing_rate_ += scaled_increase;
  }
}
