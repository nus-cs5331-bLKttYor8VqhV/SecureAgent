#include <cstdio>

#include <openenclave/bits/module.h>

#include "TLSStream.hpp"
#include "helloworld_t.h"

const char* server_host            = "httpbin.org";
const char* server_port            = "443";
constexpr const char* http_request = "GET /get HTTP/1.1\r\n"
                                     "Host: httpbin.org\r\n"
                                     "\r\n";

void enclave_https()
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
}
