#ifndef PRAGUE_CC_H
#define PRAGUE_CC_H

#include <stdint.h>

/*
 * - All time values are in microseconds (µs) unless stated otherwise.
 * - Many quantities intentionally use signed 32-bit types to allow wrap-safe
 *   comparisons using (a - b) > 0 / < 0 idioms.
 */

typedef uint64_t size_tp;    // Size in bytes [B]
typedef uint64_t window_tp;  // Fractional window in micro-bytes [µB] = bytes * 1e6.
                             // This keeps units aligned with time in µs so that:
                             //   rate [B/s] ≈ window_µB / RTT_µs.

typedef uint64_t rate_tp;    // Rate in bytes per second [B/s]
typedef int32_t time_tp;     // Time in µs (monotonic, wraps ~ every 4294.967s); use for deltas / wrap-safe ordering
typedef int32_t count_tp;    // Packet/frame counters, wrapping signed 32-bit.
typedef uint8_t fps_tp;      // Frames per second [1..255]. Use 0 for bulk (continuous streaming mode).
typedef int64_t prob_tp;     // Fixed-point probability accumulator (see PROB_SHIFT in .cpp).

// IP ECN field (2 bits). Valid values are 0..3.
// L4S uses ECT(1)=0b01 and CE=0b11; non-L4S endpoints may use ECT(0)=0b10.
enum ecn_tp : uint8_t {
    ecn_not_ect = 0,
    ecn_l4s_id  = 1,
    ecn_ect0    = 2,
    ecn_ce      = 3
};

enum cs_tp {cs_init, cs_cong_avoid, cs_in_loss, cs_in_cwr}; // CC state
enum cca_tp {cca_prague_win, cca_prague_rate};  // CC algorithm

static const count_tp PRAGUE_INITWIN  = 10;          // Initial window [Packets]
static const size_tp  PRAGUE_MINMTU   = 150;         // Minimal MTU size [Bytes]
static const size_tp  PRAGUE_INITMTU  = 1400;        // Initial MTU size [Bytes]
static const rate_tp  PRAGUE_INITRATE = 12500;       // Initial rate (~100kbps) [B/s]
static const rate_tp  PRAGUE_MINRATE  = 12500;       // Minimal rate (~100kbps) [B/s]
static const rate_tp  PRAGUE_MAXRATE  = 12500000000; // Maximal rate (~100Gbps) [B/s]

struct PragueState {
    time_tp   m_start_ref;  // Now() epoch offset [µs] (0 means "uninitialized")

    // --- Configuration / parameters ---
    rate_tp   m_init_rate;        // Initial pacing rate [B/s]
    window_tp m_init_window;      // Initial congestion window [µB]
    rate_tp   m_min_rate;         // Minimum allowed pacing rate [B/s]
    rate_tp   m_max_rate;         // Maximum allowed pacing rate [B/s]
    size_tp   m_max_packet_size;  // Packet size cap (MTU limit) [B]

    // Frame mode
    time_tp   m_frame_interval;   // Inter-frame interval [µs] (0 = bulk mode)
    time_tp   m_frame_budget;     // Pacing budget per frame [µs] (<= frame_interval)

    // --- Timestamp / RTT tracking (both ends) ---
    time_tp   m_ts_remote;     // Frozen peer timestamp offset (used to echo peer time back)
    time_tp   m_rtt;           // Latest RTT sample [µs] (for stats / debugging)
    time_tp   m_srtt;          // Smoothed RTT [µs] (EWMA, α=1/8)
    time_tp   m_vrtt;          // Virtual RTT [µs]= max(srtt, reference RTT)

    // --- Receiver-side counters (echoed back to sender) ---
    time_tp   m_r_prev_ts;            // Last accepted peer timestamp (reject older packets)
    count_tp  m_r_packets_received;   // Total received (monotonic, wrap-safe)
    count_tp  m_r_packets_CE;         // Total CE-marked received
    count_tp  m_r_packets_lost;       // Inferred loss count (may decrease due to reordering undo logic)
    bool      m_r_error_L4S;          // ECN invalid/bleached observed -> signal sender to stop using L4S-id

    // --- Sender-side view of receiver counters ---
    time_tp   m_cc_ts;                // Last CC update time [µs]
    count_tp  m_packets_received;     // Latest echoed received counter
    count_tp  m_packets_CE;           // Latest echoed CE counter
    count_tp  m_packets_lost;         // Latest echoed loss counter (may decrease due to reordering corrections).
    count_tp  m_packets_sent;         // Local sent counter
    bool      m_error_L4S;            // Receiver-end error state; sticky: once set, do not clear

    // --- Alpha estimator state (per vRTT) ---
    time_tp   m_alpha_ts;               // Last alpha update time [µs]
    count_tp  m_alpha_packets_received;
    count_tp  m_alpha_packets_CE;
    count_tp  m_alpha_packets_lost;
    count_tp  m_alpha_packets_sent;


    // --- Loss / recovery bookkeeping (supports undo on reordering) ---
    time_tp   m_loss_ts;               // Timestamp of last loss-triggered reduction [µs]
    cca_tp    m_loss_cca;              // CC algorithm at time of loss
    window_tp m_lost_window;           // Amount of window reduction remembered for possible undo [µB]
    rate_tp   m_lost_rate;             // Amount of rate reduction remembered for possible undo [B/s]
    count_tp  m_lost_rtts_to_growth;   // Growth-wait adjustment remembered for possible undo [vRTT units]
    count_tp  m_loss_packets_lost;     // Loss counter value that triggered the reduction (for undo check)
    count_tp  m_loss_packets_sent;     // Packets-sent snapshot used to determine when the loss epoch ends

    // --- CE / CWR bookkeeping ---
    time_tp   m_cwr_ts;             // Timestamp of last CE-triggered reduction [µs]
    count_tp  m_cwr_packets_sent;   // Packets-sent snapshot used to determine when the CWR epoch ends

    // --- Current CC outputs / state machine ---
    cs_tp     m_cc_state;
    cca_tp    m_cca_mode;         // Window-based vs rate-based
    count_tp  m_rtts_to_growth;   // Virtual RTTs before going into growth mode
    prob_tp   m_alpha;            // Marking probability estimate (fixed-point)
    rate_tp   m_pacing_rate;      // Current pacing rate [B/s]
    window_tp m_fractional_window;// Congestion window (cwnd) in [µB] (see window_tp)
    count_tp  m_packet_burst;     // Max packets to send in one burst (~<250µs)
    size_tp   m_packet_size;      // Packet size [Bytes]
    count_tp  m_packet_window;    // Cwnd in packets
};

class PragueCC: private PragueState {
public:
    PragueCC(
        size_tp max_packet_size = PRAGUE_INITMTU, // use MTU detection, or a low enough value. Can be updated on the fly (todo)
        fps_tp fps = 0,                           // only used for video; frames per second, 0 must be used for bulk transfer
        time_tp frame_budget = 0,                 // only used for video; over what time [µs] you want to pace the frame (max 1000000/fps [µs])
        rate_tp init_rate = PRAGUE_INITRATE,
        count_tp init_window = PRAGUE_INITWIN,
        rate_tp min_rate = PRAGUE_MINRATE,
        rate_tp max_rate = PRAGUE_MAXRATE);

    virtual ~PragueCC();

    // Returns monotonic time in µs. Never returns 0.
    // Override in simulators to provide a consistent time source with the same properties.
    virtual time_tp Now();

    time_tp get_ref_rtt();

    count_tp get_alpha_shift();

    bool RFC8888Received(size_t num_rtt, time_tp *pkts_rtt);

    // Called on receipt of a peer packet containing timestamps (datamessage or ackmessage)
    // - Rejects older timestamps (wrap-safe).
    // - Updates RTT/SRTT/vRTT using echoed_timestamp.
    // Returns false if ignored as older than last accepted timestamp.
    bool PacketReceived(time_tp timestamp, time_tp echoed_timestamp);

    bool ACKReceived(          // call this when an ACK is received from peer, returns false if the old ack is ignored
        count_tp packets_received, // echoed_packet counter
        count_tp packets_CE,       // echoed CE counter
        count_tp packets_lost,     // echoed lost counter
        count_tp packets_sent,     // local counter of packets sent up to now, an RTT is reached if remote ACK packets_received+packets_lost
        bool error_L4S,            // receiver found a bleached/error ECN; stop using L4S_id on the sending packets!
        count_tp &inflight);       // how many packets are in flight after the ACKed);

    // Receiver-side: update counters when the app can identify losses directly.
    // packets_lost may be -1 to undo a previous loss attribution (reordering correction).
    void DataReceived(ecn_tp ip_ecn, count_tp packets_lost);

    // Receiver-side: update counters using per-packet sequence numbers.
    // Infers loss/reordering from gaps in packet_seq_nr.
    void DataReceivedSequence(ecn_tp ip_ecn, count_tp packet_seq_nr);

    // Reset CC state after an RTO is detected.
    void ResetCCInfo();

    // Returns timestamp/echo/ECN info for the next outgoing packet.
    // - timestamp: local send timestamp to be echoed by peer
    // - echoed_timestamp: peer timestamp translated into our time domain (0 if unknown)
    // - ip_ecn: ECN value to set (L4S-id unless ECN invalid/bleached observed)
    void GetTimeInfo(time_tp &timestamp, time_tp &echoed_timestamp, ecn_tp &ip_ecn);

    // Returns current CC outputs for bulk packet sending.
    void GetCCInfo(rate_tp &pacing_rate, count_tp &packet_window, count_tp &packet_burst, size_tp &packet_size);

    // Returns current receiver counters to include in ACKs.
    void GetACKInfo(count_tp &packets_received, count_tp &packets_CE, count_tp &packets_lost, bool &error_L4S);

    // Returns current CC outputs for frame sending.
    void GetCCInfoVideo(rate_tp &pacing_rate, size_tp &frame_size, count_tp &frame_window, count_tp &packet_burst, size_tp &packet_size);

    void GetStats(PragueState &stats) { stats = *this; } // Snapshot copy of current state.
    const PragueState* GetStatePtr() { return this; } // Live read-only view (pointer).

};
#endif //PRAGUE_CC_H
