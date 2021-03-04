#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <openenclave/bits/edl/syscall_types.h>
#include <openenclave/bits/result.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "helloworld_t.h"

void enclave_helloworld()
{
    fprintf(stdout, "Hello world from the enclave\n");

    oe_result_t result = host_helloworld();
    if (result != OE_OK) {
        fprintf(stderr, "Call to host_helloworld failed: result=%u (%s)\n", result, oe_result_str(result));
    }
}

#define CHECK_RESULT(result)                                                                                     \
    do {                                                                                                         \
        if (result != OE_OK) {                                                                                   \
            fprintf(stderr, "Call to %s failed: result=%u (%s)\n", __FUNCTION__, result, oe_result_str(result)); \
        }                                                                                                        \
    } while (0)

oe_host_fd_t sa_socket(int domain, int type, int protocol = 0)
{
    oe_host_fd_t sockfd;
    oe_result_t result = oe_syscall_socket_ocall(&sockfd, domain, type, protocol);
    CHECK_RESULT(result);
    return sockfd;
}

int sa_close(oe_host_fd_t sockfd)
{
    int retval;
    oe_result_t result = oe_syscall_close_socket_ocall(&retval, sockfd);
    CHECK_RESULT(result);
    return retval;
}

int sa_connect(oe_host_fd_t sockfd, const struct oe_sockaddr* addr, oe_socklen_t addrlen)
{
    int retval;
    oe_result_t result = oe_syscall_connect_ocall(&retval, sockfd, addr, addrlen);
    CHECK_RESULT(result);
    return retval;
}

ssize_t sa_send(oe_host_fd_t sockfd, const void* buf, size_t len, int flags)
{
    ssize_t retval;
    oe_result_t result = oe_syscall_send_ocall(&retval, sockfd, buf, len, flags);
    CHECK_RESULT(result);
    return retval;
}

ssize_t sa_read(oe_host_fd_t fd, void* buf, size_t count)
{
    ssize_t retval;
    oe_result_t result = oe_syscall_read_ocall(&retval, fd, buf, count);
    CHECK_RESULT(result);
    return retval;
}

void enclave_socket()
{
    const char* http_host    = "httpbin.org";
    const char* http_ip      = "34.199.75.4";
    const uint16_t http_port = 80;
    const char* http_request = ("GET /get HTTP/1.1\r\n"
                                "Host: httpbin.org\r\n"
                                "\r\n");

    oe_host_fd_t sockfd = sa_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Socket creation error: socket returns %ld\n", sockfd);
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(http_port);

    if (inet_pton(AF_INET, http_ip, &serv_addr.sin_addr) < 0) {
        fprintf(stderr, "Address not supported %s:%u\n", http_ip, http_port);
    }

    if (sa_connect(sockfd, reinterpret_cast<oe_sockaddr*>(&serv_addr), sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Connection failed %s:%u\n", http_ip, http_port);
    }

    if (sa_send(sockfd, http_request, strlen(http_request), 0) < 0) {
        fprintf(stderr, "Send HTTP request failed\n");
    }

    char buf[BUFSIZ];

    if (sa_read(sockfd, buf, BUFSIZ) < 0) {
        fprintf(stderr, "Receive HTTP response failed\n");
    }

    puts(buf);

    sa_close(sockfd);
}
