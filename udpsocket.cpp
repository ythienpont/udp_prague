#include "udpsocket.h"
#include "prague_cc.h"
#include <cassert>
#include <cstring>
#include <system_error>
#include <winsock2.h>

SocketHandle invalid_socket() {
#ifdef _WIN32
  return INVALID_SOCKET;
#else
  return -1;
#endif
}

bool is_socket_valid(SocketHandle s) {
#ifdef _WIN32
  return s != INVALID_SOCKET;
#else
  return s >= 0;
#endif
}

void close_socket(SocketHandle s) {
  if (is_socket_valid(s)) {
#ifdef _WIN32
    ::closesocket(s);
#else
    ::close(s);
#endif
  }
}

int last_error_code() {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

void set_max_priority() {
// Set priority
#ifdef _WIN32
  DWORD dwPriClass;
  if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS))
    perror("SetPriorityClass failed.\n");
  dwPriClass = GetPriorityClass(GetCurrentProcess());
  DWORD dwThreadPri;
  if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL))
    perror("SetThreadPriority failed.\n");
  dwThreadPri = GetThreadPriority(GetCurrentThread());
  printf("Current priority class is 0x%x, thread priority is 0x%x\n",
         (uint32_t)dwPriClass, (uint32_t)dwThreadPri);
#elif defined(__MUSL__)
  if (geteuid() == 0) {
    struct sched_param sp;
    sp.sched_priority = sched_get_priority_max(SCHED_RR);
    // SCHED_OTHER, SCHED_FIFO, SCHED_RR
    if (pthread_setschedparam(pthread_self(), SCHED_RR, &sp) < 0) {
      perror("Client set scheduler");
    }
  }
#elif defined(__linux__) || defined(__FreeBSD__)
  if (geteuid() == 0) {
    struct sched_param sp;
    sp.sched_priority = sched_get_priority_max(SCHED_RR);
    // SCHED_OTHER, SCHED_FIFO, SCHED_RR
    if (sched_setscheduler(0, SCHED_RR, &sp) < 0) {
      perror("Client set scheduler");
    }
  }
#elif __APPLE__
  if (geteuid() == 0) {
    struct sched_param sp;
    sp.sched_priority = sched_get_priority_max(SCHED_RR);
    // SCHED_OTHER, SCHED_FIFO, SCHED_RR
    if (pthread_setschedparam(pthread_self(), SCHED_RR, &sp) < 0) {
      perror("Client set scheduler");
    }
  }
#endif
}

bool wait_for_readable(SocketHandle s, time_tp timeout) {
  assert(is_socket_valid(s));
  assert(timeout >= 0);

#ifdef _WIN32
  // For small timeouts on Windows, select has ~15ms granularity.
  // If <15ms, treat as non-blocking "poll".
  if (timeout > 0 && timeout < 15000)
    timeout = 0;
#endif

  fd_set recvsds;
  FD_ZERO(&recvsds);
  FD_SET(s, &recvsds);

  timeval tv{};
  tv.tv_sec = static_cast<long>(timeout / 1000000);
  tv.tv_usec = static_cast<long>(timeout % 1000000);

  int r = select((INT)s + 1, &recvsds, NULL, NULL, &tv);

  if (r == SOCKET_ERROR)
    throw std::system_error(last_error_code(), std::system_category(),
                            "select");

  return r > 0;
}

SocketHandle make_udp_socket(int family) {
  if (!(family == AF_INET || family == AF_INET6)) {
    throw std::system_error(EAFNOSUPPORT, std::system_category(),
                            "Unsupported address family");
  }

  SocketHandle s = ::socket(family, SOCK_DGRAM, 0);

  if (!is_socket_valid(s))
    throw std::system_error(last_error_code(), std::system_category(),
                            "socket");

  return s;
}

void enable_recv_ecn(SocketHandle s, int family) {
  assert(is_socket_valid(s));
  assert(family == AF_INET || family == AF_INET6);

#ifdef _WIN32
  (void)family; // unused

  if (WSASetRecvIPEcn(s, TRUE) != 0)
    throw std::system_error(last_error_code(), std::system_category(),
                            "WSASetRecvIPEcn");
#else
  int set = 1;

  switch (family) {
  case AF_INET:
    if (setsockopt(s, IPPROTO_IP, IP_RECVTOS, &set,
                   static_cast<socklen_t>(sizeof(set))) == -1)
      throw std::system_error(errno, std::system_category(),
                              "setsockopt(IP_RECVTOS)");
    break;
  case AF_INET6:
    if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVTCLASS, &set,
                   static_cast<socklen_t>(sizeof(set))) == -1)
      throw std::system_error(errno, std::system_category(),
                              "setsockopt(IPV6_RECVTCLASS)");
    break;
  default:
    throw std::system_error(EAFNOSUPPORT, std::system_category(),
                            "Unsupported socket family for ECN receive");
  }
#endif
}

Endpoint resolve_endpoint(const char *addr, uint16_t port) {
  Endpoint ep{};

  // Try IPv4
  {
    auto *v4 = reinterpret_cast<sockaddr_in *>(&ep.sa);
    std::memset(v4, 0, sizeof(*v4));
    v4->sin_family = AF_INET;
    v4->sin_port = htons(port);
    int rc = inet_pton(AF_INET, addr, &v4->sin_addr);
    if (rc == 1) {
      ep.len = static_cast<socklen_t>(sizeof(sockaddr_in));
      return ep;
    }
  }

  // Try IPv6
  {
    auto *v6 = reinterpret_cast<sockaddr_in6 *>(&ep.sa);
    std::memset(v6, 0, sizeof(*v6));
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(port);
    int rc = inet_pton(AF_INET6, addr, &v6->sin6_addr);
    if (rc == 1) {
      ep.len = static_cast<socklen_t>(sizeof(sockaddr_in6));
      return ep;
    }
  }

  throw std::system_error(EAFNOSUPPORT, std::system_category(),
                          "Unsupported address type");
}

#ifndef _WIN32
size_t recv_with_ecn(SocketHandle s, Endpoint &peer, char *buf, size_t len,
                     ecn_tp &ecn) {
  int r;
  char ctrl_msg[CMSG_SPACE(sizeof(ecn))];

  struct msghdr rcv_msg;
  struct iovec rcv_iov[1];
  rcv_iov[0].iov_len = len;
  rcv_iov[0].iov_base = buf;

  rcv_msg.msg_name = &peer.sa;
  rcv_msg.msg_namelen = peer.len;
  rcv_msg.msg_iov = rcv_iov;
  rcv_msg.msg_iovlen = 1;
  rcv_msg.msg_control = ctrl_msg;
  rcv_msg.msg_controllen = sizeof(ctrl_msg);

  if ((r = recvmsg(s, &rcv_msg, 0)) < 0) {
    perror("Fail to recv UDP message from socket\n");
    exit(1);
  }

  struct cmsghdr *cmptr = CMSG_FIRSTHDR(&rcv_msg); // TODO Loop instead
#ifdef __linux__
  if (!(cmptr->cmsg_level == IPPROTO_IP) && (cmptr->cmsg_type == IP_TOS) &&
      !(cmptr->cmsg_level == IPPROTO_IPV6) &&
      (cmptr->cmsg_type == IPV6_TCLASS)) {
#else
  if (!(cmptr->cmsg_level == IPPROTO_IP) && (cmptr->cmsg_type == IP_RECVTOS) &&
      !(cmptr->cmsg_level == IPPROTO_IPV6) &&
      (cmptr->cmsg_type == IPV6_RECVTCLASS)) {
#endif
    perror("Fail to recv IP.ECN field from packet\n");
    exit(1);
  }

  ecn = (ecn_tp)((unsigned char)(*(uint32_t *)CMSG_DATA(cmptr)) & ECN_MASK);
  return r;
}
#endif

#ifdef _WIN32
size_t recv_with_ecn_windows(LPFN_WSARECVMSG WSARecvMsg, SocketHandle s,
                             Endpoint &peer, char *buf, size_t len,
                             ecn_tp &ecn) {
  assert(ecn == ecn_not_ect || ecn == ecn_ect0 || ecn == ecn_l4s_id ||
         ecn == ecn_ce);

  DWORD numBytes;
  INT error;

  CHAR control[WSA_CMSG_SPACE(sizeof(INT))] = {0};
  WSABUF dataBuf;
  WSABUF controlBuf;
  WSAMSG wsaMsg;
  PCMSGHDR cmsg;

  dataBuf.buf = buf;
  dataBuf.len = ULONG(len);
  controlBuf.buf = control;
  controlBuf.len = sizeof(control);
  wsaMsg.name = (PSOCKADDR)(&peer.sa);
  wsaMsg.namelen = sizeof(peer.sa);
  wsaMsg.lpBuffers = &dataBuf;
  wsaMsg.dwBufferCount = 1;
  wsaMsg.Control = controlBuf;
  wsaMsg.dwFlags = 0;

  error = WSARecvMsg(s, &wsaMsg, &numBytes, NULL, NULL);

  if (error == SOCKET_ERROR)
    throw std::system_error(last_error_code(), std::system_category(),
                            "WSARecvMsg");

  peer.len = static_cast<socklen_t>(wsaMsg.namelen);

  cmsg = WSA_CMSG_FIRSTHDR(&wsaMsg);
  while (cmsg != NULL) {
    if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_ECN) ||
        (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_ECN)) {
      ecn = ecn_tp(*(PINT)WSA_CMSG_DATA(cmsg));
      break;
    }
    cmsg = WSA_CMSG_NXTHDR(&wsaMsg, cmsg);
  }

  return static_cast<size_t>(numBytes);
}
#endif

void UDPSocket::Bind(const char *addr, uint16_t port) {
  assert(addr != nullptr);

  Endpoint ep = resolve_endpoint(addr, port);
  sock = make_udp_socket(ep.sa.ss_family);
  init_io();
  enable_recv_ecn(sock, ep.sa.ss_family);

  if (::bind(sock, reinterpret_cast<const sockaddr *>(&ep.sa), ep.len) ==
      SOCKET_ERROR)
    throw std::system_error(last_error_code(), std::system_category(), "bind");
}

void UDPSocket::Connect(const char *addr, uint16_t port) {
  assert(addr != nullptr);

  peer = resolve_endpoint(addr, port);
  sock = make_udp_socket(peer.sa.ss_family);
  init_io();
  enable_recv_ecn(sock, peer.sa.ss_family);

  if (::connect(sock, reinterpret_cast<sockaddr *>(&peer.sa), peer.len) ==
      SOCKET_ERROR)
    throw std::system_error(last_error_code(), std::system_category(),
                            "connect");

  connected = true;
}

UDPSocket::UDPSocket()
    :
#ifdef _WIN32
      WSARecvMsg(NULL), WSASendMsg(NULL),
#endif
      sock(invalid_socket()), peer{}, connected(false),
      current_ecn(ecn_not_ect) {

  set_max_priority();

#ifdef _WIN32
  // Initialize Winsock
  WORD versionRequested = MAKEWORD(2, 2);
  if (WSAStartup(versionRequested, &wsaData) != 0) {
    perror("WSAStartup failed.\n");
    exit(1);
  }
#endif
}

UDPSocket::~UDPSocket() {
  close_socket(sock);
#ifdef _WIN32
  WSACleanup();
#endif
  sock = invalid_socket();
}

void UDPSocket::init_io() {
#ifdef _WIN32
  // Initialize recv and send functions
  GUID guidWSARecvMsg = WSAID_WSARECVMSG;
  GUID guidWSASendMsg = WSAID_WSASENDMSG;
  DWORD dwBytes = 0;
  if (SOCKET_ERROR == WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                               &guidWSARecvMsg, sizeof(guidWSARecvMsg),
                               &WSARecvMsg, sizeof(WSARecvMsg), &dwBytes, NULL,
                               NULL))
    throw std::system_error(WSAGetLastError(), std::system_category(),
                            "WSAIoctl(WSARecvMsg)");

  if (SOCKET_ERROR == WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                               &guidWSASendMsg, sizeof(guidWSASendMsg),
                               &WSASendMsg, sizeof(WSASendMsg), &dwBytes, NULL,
                               NULL))
    throw std::system_error(WSAGetLastError(), std::system_category(),
                            "WSAIoctl(WSASendMsg)");

  assert(WSARecvMsg != nullptr);
  assert(WSASendMsg != nullptr);
#endif
  // Not necessary on other platforms
}

size_tp UDPSocket::Receive(char *buf, size_tp len, ecn_tp &ecn,
                           time_tp timeout) {
  assert(buf != nullptr);
  assert(len > 0);
  assert(is_socket_valid(sock));

  if (timeout > 0 && !wait_for_readable(sock, timeout))
    return 0;

#ifdef _WIN32
  return recv_with_ecn_windows(WSARecvMsg, sock, peer, buf, len, ecn);
#else
  return recv_with_ecn(sock, peer, buf, len, ecn);
#endif
}

size_tp UDPSocket::Send(char *buf, size_tp len, ecn_tp ecn) {
  assert(buf != nullptr);
  assert(len > 0);
  assert(is_socket_valid(sock));
  assert(ecn == ecn_not_ect || ecn == ecn_ect0 || ecn == ecn_l4s_id ||
         ecn == ecn_ce);

#ifdef _WIN32
  DWORD numBytes;
  INT error;

  CHAR control[WSA_CMSG_SPACE(sizeof(INT))] = {0};
  WSABUF dataBuf;
  WSABUF controlBuf;
  WSAMSG wsaMsg;
  PCMSGHDR cmsg;

  dataBuf.buf = buf;
  dataBuf.len = ULONG(len);
  controlBuf.buf = control;
  controlBuf.len = sizeof(control);
  if (connected) { // Used only with unconnected sockets
    wsaMsg.name = nullptr;
    wsaMsg.namelen = 0;
  } else {
    wsaMsg.name = (PSOCKADDR)(&peer.sa);
    wsaMsg.namelen = peer.len;
  }
  wsaMsg.lpBuffers = &dataBuf;
  wsaMsg.dwBufferCount = 1;
  wsaMsg.Control = controlBuf;
  wsaMsg.dwFlags = 0;

  cmsg = WSA_CMSG_FIRSTHDR(&wsaMsg);
  cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
  cmsg->cmsg_level = (peer.sa.ss_family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
  cmsg->cmsg_type = (peer.sa.ss_family == AF_INET) ? IP_ECN : IPV6_ECN;
  *(PINT)WSA_CMSG_DATA(cmsg) = ecn;

  error = WSASendMsg(sock, &wsaMsg, 0, &numBytes, NULL, NULL);

  if (error == SOCKET_ERROR)
    throw std::system_error(last_error_code(), std::system_category(),
                            "WSASendMsg");

  return static_cast<size_t>(numBytes);
#else
  // TODO switch to per packet instead of sockopt
  if (current_ecn != ecn) {
    unsigned int ecn_set = ecn;

    if (peer.is_v4()) { // Check for IPv4
      if (setsockopt(sock, IPPROTO_IP, IP_TOS, &ecn_set, sizeof(ecn_set)) < 0) {
        printf("Could not apply ecn %d,\n", ecn);
        return -1;
      }
    } else {
      if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &ecn_set,
                     sizeof(ecn_set)) < 0) {
        printf("Could not apply ecn %d,\n", ecn);
        return -1;
      }
    }
    current_ecn = ecn;
  }

  if (connected)
    rc = send(sock, buf, len, 0);
  else
    rc = sendto(sock, buf, len, 0, (SOCKADDR *)&peer.sa, peer.len);
  if (rc < 0) {
    perror("Sent failed.");
    exit(1);
  }
  return size_tp(rc);
#endif
}
