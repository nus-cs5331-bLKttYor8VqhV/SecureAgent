#include <cstdio>

#include <openenclave/bits/module.h>

#include "TLSStream.hpp"
#include "helloworld_t.h"

const char* server_host            = "httpbin.org";
const char* server_port            = "443";
constexpr const char* http_request = "GET /get HTTP/1.1\r\n"
                                     "Host: httpbin.org\r\n"
                                     "\r\n";
TLSClient *test_client;

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
        test_client = new TLSClient(mbedtls_test_cas_pem);
        puts("[+] Enclave created");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void call_test(){
    char buf[BUFSIZ];

    try {
        test_client->connect(server_host, server_port);
        test_client->send((const unsigned char*)http_request, strlen(http_request));
        test_client->recv((unsigned char*)buf, BUFSIZ);
        puts(buf);
        puts("[+] Response printed");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}


void call_test_2(){
    char buf[BUFSIZ];

    try {
        test_client->connect(server_host, server_port);
        test_client->send((const unsigned char*)http_request, strlen(http_request));
        test_client->recv((unsigned char*)buf, BUFSIZ);
        puts(buf);
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
    puts("[+] Response printed");
}