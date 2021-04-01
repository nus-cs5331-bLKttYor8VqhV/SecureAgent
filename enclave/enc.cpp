#include <cstdio>

#include <openenclave/bits/module.h>

#include "TLSStream.hpp"
#include "helloworld_t.h"

TLSClient *enclave_client;

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

void connect_enclave(const char* server_host, const char* server_port){
    try {
        if(enclave_client == NULL){
            initialize_enclave();
        }
        enclave_client->connect(server_host, server_port);
        puts("[+] Enclave connected");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void request_enclave(const char* http_request){
    // Check if connected
    try {
        enclave_client->send((const unsigned char*)http_request, strlen(http_request));
        puts("[+] Request sent");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void receive_enclave(char* buf, int len){
    try {
        enclave_client->recv((unsigned char*)buf, len);
        puts(buf);
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