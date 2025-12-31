#ifndef UDPSOCKET_H
#define UDPSOCKET_H

#ifdef _WIN32
// #define _WINSOCK_DEPRECATED_NO_WARNINGS

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
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#ifdef __MUSL__
#include <pthread.h>
#include <sys/time.h>
#endif
#include "prague_cc.h"

#define IS_DUALSTACK 1

struct Endpoint {
  sockaddr_storage sa{};
  socklen_t len{0};
  bool is_v4() const { return sa.ss_family == AF_INET; }
  bool is_v6() const { return sa.ss_family == AF_INET6; }
  int family() const { return sa.ss_family; }
};

using SocketHandle =
#ifdef _WIN32
    SOCKET;
#else
    int;
#endif

#ifdef _WIN32
typedef int ssize_t;
#else
constexpr int SOCKET_ERROR = -1;
#define ECN_MASK ecn_ce
#endif

void set_max_priority();

SocketHandle invalid_socket();
bool is_socket_valid(SocketHandle s);
void close_socket(SocketHandle s);

SocketHandle make_udp_socket(int family);

void enable_recv_ecn(SocketHandle s, int family);

void set_send_ecn(SocketHandle s, const Endpoint &ep, ecn_tp ecn);

Endpoint resolve_endpoint(const char *addr, uint16_t port);

#ifdef _WIN32
size_t recv_with_ecn_windows(LPFN_WSARECVMSG WSARecvMsg, SocketHandle s,
                             Endpoint &peer, char *buf, size_t len,
                             ecn_tp &ecn);
#else
size_t recv_with_ecn(SocketHandle s, Endpoint &peer, char *buf, size_t len,
                     ecn_tp &ecn);
#endif

size_t send_with_ecn(SocketHandle s, const Endpoint &ep, const char *buf,
                     size_t len, ecn_tp ecn, bool connected);

int last_error_code();

bool wait_for_readable(SocketHandle s, time_tp timeout);

class UDPSocket {

public:
  UDPSocket();
  ~UDPSocket();

  void Bind(const char *addr, uint16_t port);
  void Connect(const char *addr, uint16_t port);

  size_tp Receive(char *buf, size_tp len, ecn_tp &ecn, time_tp timeout);
  size_tp Send(char *buf, size_tp len, ecn_tp ecn);

private:
  void init_io();

private:
#ifdef _WIN32
  WSADATA wsaData;
  LPFN_WSARECVMSG WSARecvMsg = NULL;
  LPFN_WSASENDMSG WSASendMsg = NULL;
#endif
  SocketHandle sock;
  Endpoint peer{};
  bool connected;
  ecn_tp current_ecn;
};

#endif // UDPSOCKET_H
