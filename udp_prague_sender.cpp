// udp_prague_sender.cpp:
// An example of a (dummy data) UDP sender that needs to receive ACKs from a UDP
// receiver for congestion control
//

#include "udpsocket.h"
// #include "icmpsocket.h" TODO: optimize MTU detection
#include "app_stuff.h"
#include "pkt_format.h"

#define MAX_TIMEOUT 2 // Maximum number of timeouts before exiting

int main(int argc, char **argv) {
  AppStuff app(true, argc, argv); // initialize the app

  // Create a UDP socket
  UDPSocket us;
  if (app.connect)
    us.Connect(app.rcv_addr, (uint16_t)app.rcv_port);
  else
    us.Bind(app.rcv_addr, (uint16_t)app.rcv_port);

  char receivebuffer[BUFFER_SIZE];
  uint32_t sendbuffer[BUFFER_SIZE / 4];
  // init payload with dummy data
  for (int i = 0; i < BUFFER_SIZE / 4; i++)
    sendbuffer[i] = htonl(i);

  struct AckMessage &ack_msg =
      (struct AckMessage &)(receivebuffer); // overlaying the receive buffer
  struct DataMessage &data_msg =
      (struct DataMessage &)(sendbuffer); // overlaying the send buffer

  // Frame message
  struct FrameMessage &frame_msg =
      (struct FrameMessage &)(sendbuffer); // overlaying the send buffer

  // RFC8888 buffer
  struct Rfc8888Ack &rfc8888_ackmsg =
      (struct Rfc8888Ack &)(receivebuffer); // overlaying the receive buffer
  TimeUs sendtime[PKT_BUFFER_SIZE] = {0};
  pktsend_tp pkts_stat[PKT_BUFFER_SIZE] = {snd_init};
  TimeUs pkts_rtt[REPORT_SIZE] = {0};
  Count last_ackseq = 0;   // Last received ACK sequence
  Count pkts_received = 0; // Receivd packets counter for RFC8888 feedback
  Count pkts_CE = 0;       // CE packets counter for RFC8888 feedback
  Count pkts_lost = 0;     // Lost packets counter for RFC8888 feedback
  bool err_L4S = false;    // L4S error flag for RFC8888 feedback

  // create a PragueCC object. Using default parameters for the Prague CC in
  // line with TCP_Prague
  PragueCC pragueCC(app.max_pkt, app.rt_mode ? app.rt_fps : 0,
                    app.rt_mode ? app.rt_frameduration : 0, PRAGUE_INITRATE,
                    PRAGUE_INITWIN, PRAGUE_MINRATE, app.max_rate);

  // outside PragueCC CC-loop state
  TimeUs now = pragueCC.Now();
  TimeUs nextSend = now; // time to send the next burst
  Count seqnr = 0; // sequence number of last sent packet (first sequence number
                   // will be 1)
  Count inflight = 0;  // packets in-flight counter
  RateBps pacing_rate; // used for pacing the packets with the right interval
                       // (not taking into account the bursts)
  Count packet_window; // allowed maximum packets in-flight
  Count packet_burst;  // allowed number of packets to send back-to-back; pacing
                       // interval needs to be taken into account for the next
                       // burst only
  SizeB packet_size; // packet size is reduced when rates are low to preserve 2
                     // packets per 25ms pacing interval
  Ecn new_ecn;       // Sent IP-ECN codepoint
  Ecn rcv_ecn;       // Received  IP-ECN codepoint
  SizeB bytes_received = 0; // Received Bytes
  TimeUs compRecv = 0;      // send time compensation
  TimeUs waitTimeout = 0;   // time to wait for ACK receiving

  TimeUs frame_timer = 0; // frame timer for next frame
  Count frame_nr = 0;   // frame sequence number of last sent frame (first frame
                        // sequence number will be 1)
  SizeB frame_size;     // frame size in Bytes
  SizeB frame_sent = 0; // frame sent size in Bytes
  Count frame_window;   // frame window
  Count frame_inflight = 0; // frame inflight

  bool is_sending = false; // current frame is still sending
  Count sent_frame = 0;    // sent frame counter
  Count recv_frame = 0;    // received frame counter
  Count lost_frame = 0;    // lost frame counter
  Count frame_idx[PKT_BUFFER_SIZE] = {0};
  Count frame_pktlost[FRM_BUFFER_SIZE] = {0};
  Count frame_pktsent[FRM_BUFFER_SIZE] = {0};

  uint8_t num_timeout = 0;

  // wait for a trigger packet, otherwise just start sending
  if (!app.connect) {
    do {
      bytes_received =
          us.Receive(receivebuffer, sizeof(receivebuffer), rcv_ecn, 0);
    } while (bytes_received == 0);
    bytes_received = 0;
  }

  // Find maximum MTU can be used
  // ICMPSocket icmps(rcv_addr);
  // max_pkt = icmps.mtu_discovery(150, max_pkt, 1000000, 1);

  // get initial CC state
  pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst, packet_size);

  while (true) {
    Count inburst = 0;    // packets in-burst counter
    TimeUs startSend = 0; // next time to send
    now = pragueCC.Now();
    if (!app.rt_mode) {
      // if the window and pacing interval allows, send the next burst
      while ((inflight < packet_window) && (inburst < packet_burst) &&
             (nextSend - now <= 0)) {
        pragueCC.GetTimeInfo(data_msg.timestamp, data_msg.echoed_timestamp,
                             new_ecn);
        if (!startSend)
          startSend = now;
        data_msg.seq_nr = ++seqnr;
        app.LogSendData(now, data_msg.timestamp, data_msg.echoed_timestamp,
                        seqnr, packet_size, pacing_rate, packet_window,
                        packet_burst, inflight, inburst, nextSend);
        data_msg.hton();
        app.ExitIf(us.Send((char *)(&data_msg), packet_size, new_ecn) !=
                       packet_size,
                   "invalid data packet length sent");
        sendtime[seqnr % PKT_BUFFER_SIZE] = startSend;
        pkts_stat[seqnr % PKT_BUFFER_SIZE] = snd_sent;
        inburst++;
        inflight++;
      }
      if (startSend != 0) {
        if (compRecv + packet_size * inburst * 1000000 / pacing_rate <= 0)
          nextSend = TimeUs(startSend + 1);
        else
          nextSend = TimeUs(startSend + compRecv +
                            packet_size * inburst * 1000000 / pacing_rate);
        compRecv = 0;
      }
    } else {
      if (!frame_sent && nextSend - now <= 0) {
        // Update next frame start time (Could be external at frame sender)
        if (!frame_timer) {
          frame_nr++;
          frame_timer = now + 1000000 / app.rt_fps;
        } else {
          Count frame_adv = 1;
          if (frame_timer - now <= 0)
            frame_adv = 1 + (now - frame_timer) * app.rt_fps / 1000000;
          frame_nr += frame_adv;
          frame_timer += frame_adv * 1000000 / app.rt_fps;
        }
        compRecv = 0;

        // Get extra frame info from Prague CC and update frame sender info
        pragueCC.GetCCInfoVideo(pacing_rate, frame_size, frame_window,
                                packet_burst, packet_size);
        // printf("[FRAME %d] now: %d, inflight: %d(%d/%d/%d/%d), frame_size:
        // %ld, frame_window: %d, packet_size: %ld, pacing_rate: %ld\n",
        //     frame_nr, now, frame_inflight, is_sending, sent_frame,
        //     lost_frame, recv_frame, frame_size, frame_window, packet_size,
        //     pacing_rate);
      }
      while ((frame_inflight <= frame_window) && (frame_sent < frame_size) &&
             (inburst < packet_burst) && (nextSend - now <= 0)) {
        pragueCC.GetTimeInfo(frame_msg.timestamp, frame_msg.echoed_timestamp,
                             new_ecn);
        if (!frame_sent) {
          is_sending = true;
          frame_pktlost[frame_nr % FRM_BUFFER_SIZE] = 0;
          frame_pktsent[frame_nr % FRM_BUFFER_SIZE] = 0;
        }
        if (!startSend)
          startSend = now;
        frame_msg.seq_nr = ++seqnr;
        frame_msg.frame_nr = frame_nr;
        frame_msg.frame_sent = frame_sent;
        frame_msg.frame_size = frame_size;

        // Reduce packet size of the last packet
        if (frame_sent + packet_size > frame_size)
          packet_size = (frame_sent + PRAGUE_MINMTU > frame_size)
                            ? PRAGUE_MINMTU
                            : (frame_size - frame_sent);
        app.LogSendFrameData(
            now, frame_msg.timestamp, frame_msg.echoed_timestamp, seqnr,
            packet_size, pacing_rate, frame_window, frame_window, packet_burst,
            frame_inflight, frame_sent, inburst, nextSend);
        frame_msg.hton();
        app.ExitIf(us.Send((char *)(&frame_msg), packet_size, new_ecn) !=
                       packet_size,
                   "invalid frame packet length sent");
        sendtime[seqnr % PKT_BUFFER_SIZE] = startSend;
        pkts_stat[seqnr % PKT_BUFFER_SIZE] = snd_sent;
        frame_idx[seqnr % PKT_BUFFER_SIZE] = frame_nr;
        inburst++;
        inflight++;
        frame_sent += packet_size;
      }
      if (startSend != 0) {
        frame_pktsent[frame_nr % FRM_BUFFER_SIZE] += inburst;
        if (frame_sent >= frame_size) {
          nextSend = frame_timer;
          frame_sent = 0;

          is_sending = false;
          sent_frame++;
          if (frame_pktlost[frame_nr % FRM_BUFFER_SIZE])
            lost_frame++;
        } else {
          // frame_pktsize might be different from packet_size
          if (compRecv + packet_size * inburst * 1000000 / pacing_rate <= 0)
            nextSend = TimeUs(startSend + 1);
          else
            nextSend = TimeUs(startSend + compRecv +
                              packet_size * inburst * 1000000 / pacing_rate);
          compRecv = 0;
        }
        // Update frame_inflight
        frame_inflight = is_sending + sent_frame - recv_frame - lost_frame;
      }
    }

    waitTimeout = nextSend;
    now = pragueCC.Now();
    if (!app.rt_mode && inflight >= packet_window)
      waitTimeout = now + SND_TIMEOUT;
    else if (app.rt_mode && frame_inflight >= frame_window)
      waitTimeout = now + SND_TIMEOUT;
    do {
      bytes_received =
          us.Receive(receivebuffer, sizeof(receivebuffer), rcv_ecn,
                     (waitTimeout - now > 0) ? (waitTimeout - now) : 1);
      now = pragueCC.Now();
    } while ((bytes_received == 0) && (waitTimeout - now > 0));
    if (receivebuffer[0] == PKT_ACK_TYPE &&
        bytes_received >= ssize_t(sizeof(ack_msg))) {
      if (!app.rt_mode) {
        ack_msg.get_stat(pkts_stat, pkts_lost);
      } else {
        // Update frame_inflight
        ack_msg.get_frame_stat(pkts_stat, pkts_lost, is_sending, frame_nr,
                               recv_frame, lost_frame, frame_idx, frame_pktsent,
                               frame_pktlost);
        frame_inflight = is_sending + sent_frame - recv_frame - lost_frame;
      }
      pragueCC.PacketReceived(ack_msg.timestamp, ack_msg.echoed_timestamp);
      pragueCC.ACKReceived(ack_msg.packets_received, ack_msg.packets_CE,
                           ack_msg.packets_lost, seqnr, ack_msg.error_L4S,
                           inflight);
      if (!app.rt_mode) {
        pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst,
                           packet_size);
        app.LogRecvACK(now, ack_msg.timestamp, ack_msg.echoed_timestamp, seqnr,
                       bytes_received, ack_msg.packets_received,
                       ack_msg.packets_CE, ack_msg.packets_lost,
                       ack_msg.error_L4S, pacing_rate, packet_window,
                       packet_burst, inflight, inburst, nextSend);
      } else {
        app.LogRecvACK(
            now, ack_msg.timestamp, ack_msg.echoed_timestamp, seqnr,
            bytes_received, ack_msg.packets_received, ack_msg.packets_CE,
            ack_msg.packets_lost, ack_msg.error_L4S, pacing_rate, packet_window,
            packet_burst, inflight, inburst, nextSend, frame_window,
            frame_inflight, is_sending, sent_frame, lost_frame, recv_frame);
      }
    } else if (receivebuffer[0] == RFC8888_ACK_TYPE &&
               bytes_received >= rfc8888_ackmsg.get_size(0)) {
      uint16_t num_rtt = 0;
      if (!app.rt_mode) {
        num_rtt = rfc8888_ackmsg.get_stat(now, sendtime, pkts_rtt,
                                          pkts_received, pkts_lost, pkts_CE,
                                          err_L4S, pkts_stat, last_ackseq);
      } else {
        // Update frame_inflight
        num_rtt = rfc8888_ackmsg.get_frame_stat(
            now, sendtime, pkts_rtt, pkts_received, pkts_lost, pkts_CE, err_L4S,
            pkts_stat, last_ackseq, is_sending, frame_nr, recv_frame,
            lost_frame, frame_idx, frame_pktsent, frame_pktlost);
        frame_inflight = is_sending + sent_frame - recv_frame - lost_frame;
      }
      if (num_rtt) {
        pragueCC.RFC8888Received(num_rtt, pkts_rtt);
        pragueCC.ACKReceived(pkts_received, pkts_CE, pkts_lost, seqnr, err_L4S,
                             inflight);
        if (!app.rt_mode)
          pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst,
                             packet_size);
      }
      if (!app.rt_mode) {
        app.LogRecvRFC8888ACK(
            now, seqnr, bytes_received, rfc8888_ackmsg.begin_seq,
            rfc8888_ackmsg.num_reports, num_rtt, pkts_rtt, pkts_received,
            pkts_CE, pkts_lost, err_L4S, pacing_rate, packet_window,
            packet_burst, inflight, inburst, nextSend);
      } else {
        app.LogRecvRFC8888ACK(
            now, seqnr, bytes_received, rfc8888_ackmsg.begin_seq,
            rfc8888_ackmsg.num_reports, num_rtt, pkts_rtt, pkts_received,
            pkts_CE, pkts_lost, err_L4S, pacing_rate, packet_window,
            packet_burst, inflight, inburst, nextSend, frame_window,
            frame_inflight, is_sending, sent_frame, lost_frame, recv_frame);
      }
    } else {
      if (!app.rt_mode && inflight >= packet_window) {
        app.ExitIf(num_timeout > MAX_TIMEOUT,
                   "stop prague sender due to consecutive timeout");
        pragueCC.ResetCCInfo();
        inflight = 0;
        perror("Reset PragueCC\n");
        pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst,
                           packet_size);
        nextSend = now;
        num_timeout++;
      } else if (app.rt_mode && frame_inflight >= frame_window) {
        app.ExitIf(num_timeout > MAX_TIMEOUT,
                   "stop prague sender due to consecutive timeout");
        pragueCC.ResetCCInfo();
        frame_inflight = 0;
        perror("Reset Real-Time PragueCC\n");
        nextSend = now;
        frame_sent = 0;
        frame_timer = 0;
        num_timeout++;
      }
    }
    // Exceed time will be compensated (except reset)
    now = pragueCC.Now();
    if (waitTimeout - now <= 0) {
      if (!app.rt_mode && inflight > 0) {
        compRecv += (waitTimeout - now);
      } else if (app.rt_mode && frame_inflight > 0) {
        compRecv += (waitTimeout - now);
      }
    }
  }
}
