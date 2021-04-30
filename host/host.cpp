// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>

// Include the untrusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the helloworld.edl file.
#include "helloworld_u.h"

#include "HTTP_Interface.hpp"

unsigned int microsecond           = 1000000;
const char* server_host            = "httpbin.org";
const char* server_port            = "443";
constexpr const char* http_request = "GET /get HTTP/1.1\r\n"
                                     "Host: httpbin.org\r\n"
                                     "\r\n";

int main(int argc, const char* argv[])
{
    /*     HTTP_Interface hi = HTTP_Interface(argv[1]);
        char buf[BUFSIZ];
        int len = BUFSIZ;

        hi.e_connect(server_host, server_port);
        hi.e_request(http_request);
        hi.e_get_response(buf, len);
        hi.e_close();

        puts(buf);
        puts("[+] Response printed");
    */
    // Create enclave and test
    oe_enclave_t* enclave = NULL;

    oe_result_t result;
    uint32_t flags                                             = OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE;
    oe_enclave_setting_context_switchless_t switchless_setting = { 2, // number of host worker threads
        2 };                                                          // number of enclave worker threads.
    oe_enclave_setting_t settings[]                            = { {
        .setting_type                 = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
        .u.context_switchless_setting = &switchless_setting,
    } };
    result
        = oe_create_helloworld_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, settings, OE_COUNTOF(settings), &enclave);
    if (result != OE_OK) {
        fprintf(stderr, "oe_create_helloworld_enclave(): result=%u (%s)\n", result, oe_result_str(result));
        throw std::runtime_error("Enclave creation failed");
    }

    // Run server
    enclave_main(enclave);

    return 0;
}
