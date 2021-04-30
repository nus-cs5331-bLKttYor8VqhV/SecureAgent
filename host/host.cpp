// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <cstdio>
#include <stdexcept>

#include <openenclave/host.h>

#include "helloworld_u.h"

int main(int argc, const char* argv[])
{
    // prepare enclave settings
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE;

    oe_enclave_setting_context_switchless_t switchless_setting = { 2, // number of host worker threads
        2 };                                                          // number of enclave worker threads.
    oe_enclave_setting_t settings[]                            = { {
        .setting_type                 = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
        .u.context_switchless_setting = &switchless_setting,
    } };

    // create enclave
    oe_enclave_t* enclave = nullptr;
    oe_result_t result
        = oe_create_helloworld_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, settings, OE_COUNTOF(settings), &enclave);
    if (result != OE_OK) {
        fprintf(stderr, "oe_create_helloworld_enclave(): result=%u (%s)\n", result, oe_result_str(result));
        throw std::runtime_error("Enclave creation failed");
    }

    // run server
    enclave_main(enclave);

    return 0;
}
