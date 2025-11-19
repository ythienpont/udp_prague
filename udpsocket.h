#ifndef UDPSOCKET_H
#define UDPSOCKET_H

#ifdef WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#ifndef WIN32_LEAN_AND_MEAN
//#define WIN32_LEAN_AND_MEAN
//#endif
#include <iostream>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mswsock.h>
#elif __linux__
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netdb.h>
#elif __FreeBSD__
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#elif __APPLE__
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#ifdef __MUSL__
#include <sys/time.h>
#include <pthread.h>
#endif
#include "prague_cc.h"

#ifdef WIN32
typedef int socklen_t;
typedef int ssize_t;
#define S_ADDR S_un.S_addr
#else // Unix/Linux type of OSs
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
#define S_ADDR s_addr
#define ECN_MASK ecn_ce
#define SOCKET_ERROR SO_ERROR
#endif

#define IS_DUALSTACK 1

class UDPSocket {
#ifdef WIN32
    WSADATA wsaData;
    LPFN_WSARECVMSG WSARecvMsg;
    LPFN_WSASENDMSG WSASendMsg;
#endif
    ecn_tp current_ecn;
    sockaddr_storage peer_addr;
    socklen_t peer_len;
    SOCKET sockfd;
    bool connected;

    // Initialize the socket with provided family
    void init_socket(const int family) {
        sockfd = socket(family, SOCK_DGRAM, 0);

        if (sockfd < 0) {
            perror("Socket creation failed.\n");
            exit(EXIT_FAILURE);
        }

        unsigned int set = 1;

        if (family == AF_INET) {
          if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, &set, sizeof(set)) < 0) {
              perror("setsockopt for IP_RECVTOS failed.\n");
                  exit(EXIT_FAILURE);
          }
        } else {
          if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS, &set, sizeof(set)) < 0) {
              perror("setsockopt for IPV6_RECVTCLASS failed.\n");
                  exit(EXIT_FAILURE);
          }
#ifdef __linux__ 
          // On Apple hosts, the application only sets IPV6_RECVTCLASS; setting IP_RECVTOS will return an error.
          if (IS_DUALSTACK) {
            if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, &set, sizeof(set)) < 0) {
                perror("setsockopt for IP_RECVTOS failed.\n");
                    exit(EXIT_FAILURE);
            }
          }
#endif
        }

    }
public:
    UDPSocket() :
#ifdef WIN32
        WSARecvMsg(NULL), WSASendMsg(NULL),
#endif
        current_ecn(ecn_not_ect), peer_addr{}, peer_len(0), sockfd(-1), connected(false) {
#ifdef WIN32
        DWORD dwPriClass;
        if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS))
            perror("SetPriorityClass failed.\n");
        dwPriClass = GetPriorityClass(GetCurrentProcess());
        DWORD dwThreadPri;
        if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL))
            perror("SetThreadPriority failed.\n");
        dwThreadPri = GetThreadPriority(GetCurrentThread());
        printf("Current priority class is 0x%x, thread priority is 0x%x\n", dwPriClass, dwThreadPri);
        // Initialize Winsock
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            perror("WSAStartup failed.\n");
            exit(1);
        }
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
#ifdef WIN32
        // Initialize recv and send functions
        GUID guidWSARecvMsg = WSAID_WSARECVMSG;
        GUID guidWSASendMsg = WSAID_WSASENDMSG;
        DWORD dwBytes = 0;
        if (SOCKET_ERROR == WSAIoctl(sockfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guidWSARecvMsg, sizeof(guidWSARecvMsg), &WSARecvMsg, sizeof(WSARecvMsg), &dwBytes, NULL, NULL)) {
            perror("Get WSARecvMsg function pointer failed.\n");
            exit(1);
        }
        if (SOCKET_ERROR == WSAIoctl(sockfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guidWSASendMsg, sizeof(guidWSASendMsg), &WSASendMsg, sizeof(WSASendMsg), &dwBytes, NULL, NULL)) {
            perror("Get WSASendMsg function pointer failed.\n");
            exit(1);
        }
        // enable receiving ECN
        DWORD enabled = TRUE;
        if ((SOCKET_ERROR == setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, (char *)&enabled, sizeof(enabled))) &&
            (SOCKET_ERROR == setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS, (char *)&enabled, sizeof(enabled)))) {
            perror("setsockopt for IP_RECVTOS/IPV6_RECVTCLASS failed.\n");
            exit(1);
        }
#else
        // Can't set sock options yet
#endif
    }
    ~UDPSocket() {
#ifdef WIN32
        WSACleanup();
#else
        close(sockfd);
        sockfd = -1;
#endif
    }

    void Bind(const char* addr, uint32_t port) {
        struct addrinfo hints{}, *result = nullptr;

        hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */

        if (getaddrinfo(addr, nullptr, &hints, &result) != 0) {
          perror("getaddrinfo failed");
          exit(EXIT_FAILURE);
        }

        int family = result->ai_family;

        init_socket(family);

        freeaddrinfo(result);

        sockaddr_storage own_addr{};
        socklen_t own_len;

        if (family == AF_INET) {
          sockaddr_in* v4 = (sockaddr_in*)(&own_addr);

          v4->sin_family = AF_INET;
          v4->sin_port = htons(port);
          v4->sin_addr.s_addr = inet_addr(addr);
          own_len = sizeof(sockaddr_in);
        } else {
          sockaddr_in6* v6 = (sockaddr_in6*)(&own_addr);
          v6->sin6_family = AF_INET6;
          v6->sin6_port = htons(port);
          own_len = sizeof(sockaddr_in6);

          // Toggles dual-stack behaviour
          int v6only = !IS_DUALSTACK;
          setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        }

        peer_len = own_len;

        if (bind(sockfd, (sockaddr*)(&own_addr), own_len) < 0) {
          perror("Bind failed");
          exit(EXIT_FAILURE);
        }
    }

    void Connect(const char* addr, uint32_t port) {
        struct addrinfo hints{}, *result = nullptr;

        hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */

        // Convert port number to a string
        char portbuf[16];
        snprintf(portbuf, sizeof(portbuf), "%u", port);

        if (getaddrinfo(addr, portbuf, &hints, &result) != 0) {
          perror("getaddrinfo failed");
          exit(EXIT_FAILURE);
        }

        init_socket(result->ai_family);

        memcpy(&peer_addr, result->ai_addr, result->ai_addrlen);
        peer_len = result->ai_addrlen;

        freeaddrinfo(result);

        if (connect(sockfd, (sockaddr*)&peer_addr, peer_len) < 0) {
          perror("Connect failed");
          exit(EXIT_FAILURE);
        }

        connected = true;
    }

    size_tp Receive(char *buf, size_tp len, ecn_tp &ecn, time_tp timeout)
    {
#ifdef WIN32
        int r;
        if (timeout > 0) {
            if (timeout < 15000)
                 timeout = 0; // Spin for Windows. Select without blocking if the timeout is smaller than 15ms
            struct timeval tv_in;
            tv_in.tv_sec = ((uint32_t)timeout) / 1000000;
            tv_in.tv_usec = ((uint32_t)timeout) % 1000000;
            fd_set recvsds;
            FD_ZERO(&recvsds);
            FD_SET((unsigned int)sockfd, &recvsds);
            r = select(sockfd + 1, &recvsds, NULL, NULL, &tv_in);
            if (r < 0) {
                // select error
                perror("Select error.\n");
                exit(1);
            }
            else if (r == 0) {
                // Timeout
                return 0;
            }
        }
        DWORD numBytes;
        CHAR control[WSA_CMSG_SPACE(sizeof(INT))] = { 0 };
        WSABUF dataBuf;
        WSABUF controlBuf;
        WSAMSG wsaMsg;
        PCMSGHDR cmsg;
        dataBuf.buf = buf;
        dataBuf.len = ULONG(len);
        controlBuf.buf = control;
        controlBuf.len = sizeof(control);
        wsaMsg.name = LPSOCKADDR(&peer_addr);
        wsaMsg.namelen = sizeof(peer_addr);
        wsaMsg.lpBuffers = &dataBuf;
        wsaMsg.dwBufferCount = 1;
        wsaMsg.Control = controlBuf;
        wsaMsg.dwFlags = 0;
        r = WSARecvMsg(sockfd, &wsaMsg, &numBytes, NULL, NULL);
        if (r == SOCKET_ERROR) {
            perror("Fail to recv UDP message from socket.\n");
            exit(1);
        }
        cmsg = WSA_CMSG_FIRSTHDR(&wsaMsg);
        while (cmsg != NULL) { // FIXME Should be IP_ECN and IPV6_ECN
            if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) ||
                (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)) {
                ecn = ecn_tp(*(PINT)WSA_CMSG_DATA(cmsg));
                break;
            }
            cmsg = WSA_CMSG_NXTHDR(&wsaMsg, cmsg);
        }
        return numBytes;
#else
        ssize_t r;
        char ctrl_msg[CMSG_SPACE(sizeof(ecn))];

        struct msghdr rcv_msg;
        struct iovec rcv_iov[1];
        rcv_iov[0].iov_len = len;
        rcv_iov[0].iov_base = buf;

        rcv_msg.msg_name = &peer_addr;
        rcv_msg.msg_namelen = peer_len;
        rcv_msg.msg_iov = rcv_iov;
        rcv_msg.msg_iovlen = 1;
        rcv_msg.msg_control = ctrl_msg;
        rcv_msg.msg_controllen = sizeof(ctrl_msg);


        if (timeout > 0) {
            struct timeval tv_in;
            tv_in.tv_sec = ((uint32_t)timeout) / 1000000;
            tv_in.tv_usec = ((uint32_t)timeout) % 1000000;
            fd_set recvsds;
            FD_ZERO(&recvsds);
            FD_SET((unsigned int)sockfd, &recvsds);
            int r = select(sockfd + 1, &recvsds, NULL, NULL, &tv_in);
            if (r == SOCKET_ERROR) {
                // select error
                perror("Select error.\n");
                exit(1);
            }
            else if (r == 0) {
                // Timeout
                return 0;
            }
        }

        if ((r = recvmsg(sockfd, &rcv_msg, 0)) < 0) {
            perror("Fail to recv UDP message from socket\n");
            exit(1);
        }

        struct cmsghdr *cmptr = CMSG_FIRSTHDR(&rcv_msg);
#ifdef __linux__
        if (!(cmptr->cmsg_level == IPPROTO_IP) && (cmptr->cmsg_type == IP_TOS) &&
            !(cmptr->cmsg_level == IPPROTO_IPV6) && (cmptr->cmsg_type == IPV6_TCLASS)) {
#else  // other Unix

        if (!(cmptr->cmsg_level == IPPROTO_IP) && (cmptr->cmsg_type == IP_RECVTOS) &&
            !(cmptr->cmsg_level == IPPROTO_IPV6) && (cmptr->cmsg_type == IPV6_RECVTCLASS)) {
#endif
            perror("Fail to recv IP.ECN field from packet\n");
            exit(1);
        }

        ecn = (ecn_tp)((unsigned char)(*(uint32_t*)CMSG_DATA(cmptr)) & ECN_MASK);
        return r;
#endif
    }

    size_tp Send(char *buf, size_tp len, ecn_tp ecn)
    {
        ssize_t rc = -1;
#ifdef WIN32
        DWORD numBytes;
        CHAR control[WSA_CMSG_SPACE(sizeof(INT))] = { 0 };
        WSABUF dataBuf;
        WSABUF controlBuf;
        WSAMSG wsaMsg;
        PCMSGHDR cmsg;
        dataBuf.buf = buf;
        dataBuf.len = ULONG(len);
        controlBuf.buf = control;
        controlBuf.len = sizeof(control);
        wsaMsg.name = LPSOCKADDR(&peer_addr);
        wsaMsg.namelen = sizeof(peer_addr);
        wsaMsg.lpBuffers = &dataBuf;
        wsaMsg.dwBufferCount = 1;
        wsaMsg.Control = controlBuf;
        wsaMsg.dwFlags = 0;
        cmsg = WSA_CMSG_FIRSTHDR(&wsaMsg);
        cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
        cmsg->cmsg_level = (PSOCKADDR_STORAGE(&peer_addr)->ss_family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
        cmsg->cmsg_type = (PSOCKADDR_STORAGE(&peer_addr)->ss_family == AF_INET) ? IP_ECN : IPV6_ECN;
        *(PINT)WSA_CMSG_DATA(cmsg) = ecn;
        rc = WSASendMsg(sockfd, &wsaMsg, 0, &numBytes, NULL, NULL);
        if (rc == SOCKET_ERROR) {
            perror("Sent failed.");
            exit(1);
        }
        return numBytes;
#else
        if (current_ecn != ecn) {
            unsigned int ecn_set = ecn;

            if (peer_len == sizeof(sockaddr_in)) { // Check for IPv4
              if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &ecn_set, sizeof(ecn_set)) < 0) {
                  printf("Could not apply ecn %d,\n", ecn);
                  return -1;
              }
            } else {
              if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, &ecn_set, sizeof(ecn_set)) < 0) {
                  printf("Could not apply ecn %d,\n", ecn);
                  return -1;
              }

#ifdef __linux__ 
              // On Apple hosts, the application only sets IPV6_TCLASS;
              if (IS_DUALSTACK) {
                if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &ecn_set, sizeof(ecn_set)) < 0) {
                    perror("setsockopt for IP_RECVTOS failed.\n");
                        exit(EXIT_FAILURE);
                }
              }
#endif
            }
            current_ecn = ecn;
        }

        if (connected)
            rc = send(sockfd, buf, len, 0);
        else
            rc = sendto(sockfd, buf, len, 0, (SOCKADDR *) &peer_addr, peer_len);
        if (rc < 0) {
            perror("Sent failed.");
            exit(1);
        }
        return size_tp(rc);
#endif
    }
};
#endif //UDPSOCKET_H
