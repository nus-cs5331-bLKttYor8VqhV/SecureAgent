#include <cstdio>
#include <openenclave/enclave.h>
#include <openenclave/bits/module.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "TLSStream.hpp"
#include "helloworld_t.h"

TLSClient* enclave_client;

/* void enclave_https()
{
    oe_load_module_host_socket_interface();
    oe_load_module_host_resolver();

    char buf[BUFSIZ];

    try {
        TLSClient tls_client(mbedtls_test_cas_pem);
        tls_client.connect(server_host, server_port);
        tls_client.send((const unsigned char*)http_request, strlen(http_request));
        tls_client.recv((unsigned char*)buf, BUFSIZ);

        puts(buf);
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
} */

void socket_test(uint16_t port)
{
    oe_load_module_host_socket_interface();
    oe_load_module_host_resolver();
    int listener;

    /* Create the listener socket. */
    if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        printf("socket() failed: errno=%d", errno);

    /* Reuse this server address. */
    {
        const int opt = 1;
        const socklen_t opt_len = sizeof(opt);

        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, opt_len) != 0)
            printf("setsockopt() failed: errno=%d", errno);
    }

    /* Listen on this address. */
    {
        struct sockaddr_in addr;
        const int backlog = 10;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0)
            printf("bind() failed: errno=%d", errno);

        if (listen(listener, backlog) != 0)
            printf("listen() failed: errno=%d", errno);
    }

    /* Accept-recv-send-close until a zero value is received. */
    for (;;)
    {
        int client;
        uint64_t value;
        char buffer[1024] = {0};

        if ((client = accept(listener, NULL, NULL)) < 0)
            printf("accept() failed: errno=%d\n", errno);

        if (read(client, buffer, sizeof(buffer)) != 0)
            printf("recv_n() failed: errno=%d\n", errno);

        if (send(client, buffer, sizeof(buffer), 0) != 0)
            printf("send_n() failed: errno=%d\n", errno);

        close(client);
        printf("Value : %c ; len = %lu\n", buffer[0], sizeof(buffer[0]));
        if (buffer[0] == 'e'){
            printf("Closing ...\n");
            break;
        }
    }

    close(listener);
}    


void initialize_enclave()
{
    oe_load_module_host_socket_interface();
    oe_load_module_host_resolver();

    try {
        enclave_client = new TLSClient(mbedtls_test_cas_pem);
        puts("[+] Enclave created");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void connect_enclave(const char* server_host, const char* server_port)
{
    try {
        if (enclave_client == NULL) {
            initialize_enclave();
        }
        enclave_client->connect(server_host, server_port);
        puts("[+] Enclave connected");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void request_enclave(const char* http_request)
{
    // Check if connected
    try {
        enclave_client->send((const unsigned char*)http_request, strlen(http_request));
        puts("[+] Request sent");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void receive_enclave(char* buf, int len)
{
    try {
        enclave_client->recv((unsigned char*)buf, len);
        puts("[+] Response printed");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void close_enclave()
{
    try {
        enclave_client = NULL;
        puts("[+] Closed");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}