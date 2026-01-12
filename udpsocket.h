#ifndef UDPSOCKET_H
#define UDPSOCKET_H

#ifdef _WIN32
#include <winsock2.h>

#include <mstcpip.h>
#include <mswsock.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#elif __linux__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#elif __FreeBSD__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#elif __APPLE__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#ifdef __MUSL__
#include <pthread.h>
#include <sys/time.h>
#endif
#include "prague_cc.h"

#ifdef _WIN32
typedef int ssize_t;
#endif

// Holds a resolved socket address (IPv4 or IPv6) and its length.
struct Endpoint {
  sockaddr_storage sa{};
  socklen_t len{0};

  bool is_v4() const { return sa.ss_family == AF_INET; }
  bool is_v6() const { return sa.ss_family == AF_INET6; }
  int family() const { return sa.ss_family; }
};

// Platform-abstracted socket type (SOCKET on Windows, else int).
using SocketHandle =
#ifdef _WIN32
    SOCKET;
#else
    int;
#endif

// High-level UDP socket wrapper
class UDPSocket {
public:
  /**
   * Construct a UDPSocket, initializes platform state and attempt to raise
   * priority. On Windows, calls WSAStartup. The socket is not created until
   * Bind/Connect.
   */
  UDPSocket();

  /**
   * Destroy the UDPSocket, closing any open socket and cleaning up
   * platform state. On Windows, calls WSACleanup.
   */
  ~UDPSocket();

  // Bind the socket to a local address and port and enable ECN
  void Bind(const char *addr, uint16_t port);
  // Connect the socket to a remote peer and enable ECN
  void Connect(const char *addr, uint16_t port);

  // Receive data with optional timeout and extract ECN from the incoming packet
  size_tp Receive(char *buf, size_tp len, ecn_tp &ecn, time_tp timeout);
  // Send data to the connected peer (or to peer set by Bind/Connect) with ECN
  size_tp Send(char *buf, size_tp len, ecn_tp ecn);

private:
  /**
   * Initialize platform-specific I/O extensions
   * (Windows: load WSARecvMsg/WSASendMsg)
   */
  void init_io();

private:
#ifdef _WIN32
  WSADATA wsaData;                   // Winsock state data
  LPFN_WSARECVMSG WSARecvMsg = NULL; // Pointer to WSARecvMsg extension function
  LPFN_WSASENDMSG WSASendMsg = NULL; // Pointer to WSASendMsg extension function

  WSABUF dataBuf;

  CHAR sendControl[WSA_CMSG_SPACE(sizeof(INT))] = {0};
  WSABUF sendControlBuf;
  WSAMSG sendMsg;

  CHAR recvControl[WSA_CMSG_SPACE(sizeof(INT))] = {0};
  WSABUF recvControlBuf;
  WSAMSG recvMsg;
#else
  msghdr send_msg{};
  iovec send_iov{};
  alignas(cmsghdr) char send_ctrl[CMSG_SPACE(sizeof(int))];

  msghdr recv_msg{};
  iovec recv_iov{};
  alignas(cmsghdr) char recv_ctrl[CMSG_SPACE(sizeof(int))];
#endif
  SocketHandle sock;
  Endpoint peer{};

  // Whether the socket is connected to a specific peer
  bool connected;
};

#endif // UDPSOCKET_H
