#ifndef PRAGUE_CC_H
#define PRAGUE_CC_H

#include <cstddef>
#include <stdint.h>

typedef uint64_t SizeB; // size in Bytes

// fractional window size in µBytes (to match time in µs, for easy Bytes/second
// rate calculations)
typedef uint64_t FracWindowUB;

typedef uint64_t RateBps; // rate in Bytes/second

// Timestamp or interval in microseconds, timestamps have a fixed
// but no meaningful reference, so use only for intervals beteen 2
// timestamps signed because it can wrap around, and we need to
// compare both ways (< 0 and > 0)
typedef int32_t TimeUs;

// Count in packets (or frames), signed because it can
// wrap around, and we need to compare both ways
typedef int32_t Count;

// 2 bits in the IP header, only values 0-3 are valid, and 1 (0b01) and 3 (0b11)
// are L4S valid
enum Ecn : uint8_t {
  ecn_not_ect = 0,
  ecn_l4s_id = 1,
  ecn_ect0 = 2,
  ecn_ce = 3
};

// Frames per second: any value from 1 to 255 can be used, 0 for bulk
typedef uint8_t Fps;
typedef int64_t Probability;

enum CCState { cs_init, cs_cong_avoid, cs_in_loss, cs_in_cwr };
enum CCAlgo { cca_prague_win, cca_prague_rate };

static const Count PRAGUE_INITWIN = 10;   // Prague initial window size
static const SizeB PRAGUE_MINMTU = 150;   // Prague minmum MTU size
static const SizeB PRAGUE_INITMTU = 1400; // Prague initial MTU size
// Prague initial rate 12500 Byte/s (equiv. 100kbps)
static const RateBps PRAGUE_INITRATE = 12500;
// Prague minimum rate 12500 Byte/s (equiv. 100kbps)
static const RateBps PRAGUE_MINRATE = 12500;
// Prague maximum rate 12500000000 Byte/s (equiv. 100Gbps)
static const RateBps PRAGUE_MAXRATE = 12500000000;

struct PragueState {
  // Parameters

  // Used to have a start time of 0
  TimeUs start_ref_;

  RateBps init_rate_;
  FracWindowUB init_window_;
  RateBps min_rate_;
  RateBps max_rate_;
  SizeB max_packet_size_;
  TimeUs frame_interval_;
  TimeUs frame_budget_;

  // Both-end variables
  TimeUs ts_remote_; // to keep the frozen timestamp from the peer, and echo
                     // it back defrosted
  TimeUs rtt_;       // last reported rtt (only for stats)
  TimeUs srtt_; // our own measured and smoothed RTT (smoothing factor = 1/8)
  TimeUs vrtt_; // our own virtual RTT = max(srtt, 25ms)

  // Receiver-end variables (to be echoed to sender)
  TimeUs r_prev_ts_; // used to see if an ack isn't older than the previous ack
  Count r_packets_received_; // as a receiver, keep counters to echo back
  Count r_packets_marked_;
  Count r_packets_lost_;
  bool r_error_L4S_; // as a receiver, check L4S-ECN validity to echo back an
                     // error
                     // sender-end variables
  TimeUs last_cc_update_;
  Count packets_received_; // latest known receiver end counters
  Count packets_marked_;
  Count packets_lost_;
  Count packets_sent_;
  bool error_L4S_; // latest known receiver-end error state

  // For alpha calculation, keep the previous alpha variables' state
  TimeUs last_alpha_update_;
  Count alpha_packets_received_;
  Count alpha_packets_marked_;
  Count alpha_packets_lost_;
  Count alpha_packets_sent_;

  // For loss and recovery calculation
  TimeUs last_loss_;
  CCAlgo cca_before_loss_;
  FracWindowUB lost_window_;
  RateBps lost_rate_;
  Count lost_rtts_to_growth_;
  Count loss_packets_lost_;
  Count loss_packets_sent_;

  // For congestion experienced and window reduction (cwr) calculation
  TimeUs last_cwnd_reduction_;
  Count cwr_packets_sent_;

  // State updated for the actual congestion control variables
  CCState state_;
  CCAlgo mode_;
  Count rtts_to_growth_; // virtual rtts before going into growth mode
  Probability alpha_;
  RateBps pacing_rate_;
  FracWindowUB fractional_window_;
  Count packet_burst_;
  SizeB packet_size_;
  Count packet_window_;
};

class PragueCC : private PragueState {
public:
  PragueCC(
      SizeB max_packet_size =
          PRAGUE_INITMTU, // use MTU detection, or a low enough value. Can be
                          // updated on the fly (todo)
      Fps fps = 0, // only used for video; frames per second, 0 must be used
                   // for bulk transfer
      TimeUs frame_budget = 0, // only used for video; over what time [µs] you
                               // want to pace the frame (max 1000000/fps [µs])
      RateBps init_rate = PRAGUE_INITRATE, Count init_window = PRAGUE_INITWIN,
      RateBps min_rate = PRAGUE_MINRATE, RateBps max_rate = PRAGUE_MAXRATE);

  virtual ~PragueCC();

  virtual TimeUs
  Now(); // Can be overwritten (e.g. for simulators),
         // needs a monotonic increasing signed int 32 which wraps around (after
         // exactly 4294.967296 seconds) and skips 0 as a special value, so
         // value 1 lasts 2 microseconds

  TimeUs get_ref_rtt();

  Count get_alpha_shift();

  bool RFC8888Received(size_t num_rtt, TimeUs *pkts_rtt);

  bool PacketReceived( // call this when a packet is received from peer, returns
                       // false if the old packet is ignored
      TimeUs timestamp, // timestamp from peer, freeze and keep this time
      TimeUs echoed_timestamp); // echoed_timestamp can be used to calculate
                                // the RTT

  bool ACKReceived( // call this when an ACK is received from peer, returns
                    // false if the old ack is ignored
      Count packets_received, // echoed_packet counter
      Count packets_marked,   // echoed CE counter
      Count packets_lost,     // echoed lost counter
      Count packets_sent, // local counter of packets sent up to now, an RTT is
                          // reached if remote ACK packets_received+packets_lost
      bool error_L4S, // receiver found a bleached/error ECN; stop using L4S_id
                      // on the sending packets!
      Count &inflight); // how many packets are in flight after the ACKed);

  void DataReceived( // call this when a data packet is received as a receiver
                     // and you can identify lost packets
      Ecn ip_ecn,    // IP.ECN field value
      Count packets_lost); // packets skipped; can be optionally -1 to
                           // potentially undo a previous cwindow reduction

  void DataReceivedSequence( // call this every time when a data packet with a
                             // sequence number is received as a receiver
      Ecn ip_ecn,            // IP.ECN field value
      Count packet_seq_nr);  // sequence number of the received packet

  void ResetCCInfo(); // call this when there is a RTO detected

  void GetTimeInfo(             // when the any-app needs to send a packet
      TimeUs &timestamp,        // Own timestamp to echo by peer
      TimeUs &echoed_timestamp, // defrosted timestamp echoed to peer
      Ecn &ip_ecn);             // ecn field to be set in the IP header

  void GetCCInfo(           // when the sending-app needs to send a packet
      RateBps &pacing_rate, // rate to pace the packets
      Count &packet_window, // the congestion window in number of packets
      Count
          &packet_burst, // number of packets that can be paced at once (<250µs)
      SizeB &packet_size); // the packet size to transmit

  void GetACKInfo(             // when the receiving-app needs to send a packet
      Count &packets_received, // packet counter to echo
      Count &packets_marked,   // CE counter to echo
      Count &packets_lost,     // lost counter to echo (if used)
      bool &error_L4S);        // bleached/error ECN status to echo

  void GetCCInfoVideo(      // when the sending app needs to send a frame
      RateBps &pacing_rate, // rate to pace the packets
      SizeB &frame_size,    // the size of a single frame in Bytes
      Count &frame_window,  // the congestion window in number of frames
      Count
          &packet_burst, // number of packets that can be paced at once (<250µs)
      SizeB &packet_size); // the packet size to transmit

  // Returns a copy of the internal state and parameters for logging purposes
  void GetStats(PragueState &stats) { stats = *this; }

  // Returns a const pointer for reading the live state for logging purposes
  const PragueState *GetStatePtr() { return this; }

private:
  inline void updateAlpha(TimeUs now, Count packets_sent,
                          Count packets_received, Count packets_marked);
  inline void reduceOnLoss(TimeUs now, Count packets_sent);
  inline void restoreReduction();
  inline void applyIncrease(TimeUs srtt, Count acks);
};
#endif // PRAGUE_CC_H
