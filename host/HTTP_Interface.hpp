#include <stdexcept>

class HTTP_Interface {
public:
    HTTP_Interface(const char* enclave_sign)
    {
        puts("[+] Creating interface");
        create_enclave(enclave_sign);
        // ECALL to initialize the enclave socket
        initialize_tls_client(enclave);
    };

    HTTP_Interface(const char* enclave_sign, const char* hostname, const char* port)
    {
        puts("[+] Creating interface");
        create_enclave(enclave_sign);
        // ECALL to initialize the enclave socket
        initialize_tls_client(enclave);
        this->e_connect(hostname, port);
    }

    int e_request(const char* request)
    {
        oe_result_t result = request_enclave(this->enclave, request);
        if (result != OE_OK) {
            fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
            return -1;
        }
        return 0;
    }

    int e_get_response(char* buf, int len)
    {
        oe_result_t result = receive_enclave(this->enclave, buf, len);
        if (result != OE_OK) {
            fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
            return -1;
        }
        return 0;
    }

    int e_close()
    {
        oe_result_t result = close_enclave(this->enclave);
        if (result != OE_OK) {
            fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
            return -1;
        }
        return 0;
    }

    int e_connect(const char* server_host, const char* server_port)
    {
        oe_result_t result = connect_enclave(this->enclave, server_host, server_port);
        if (result != OE_OK) {
            fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
            return -1;
        }
        return 0;
    }

    ~HTTP_Interface()
    {
        puts("[-] Destroying object");
        if (enclave != NULL) {
            oe_terminate_enclave(this->enclave);
        }
    }

private:
    oe_enclave_t* enclave { NULL };

    void create_enclave(const char* enclave_sign)
    {
        oe_result_t result;
        uint32_t flags                                             = OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE;
        oe_enclave_setting_context_switchless_t switchless_setting = { 1, // number of host worker threads
            0 };                                                          // number of enclave worker threads.
        oe_enclave_setting_t settings[]                            = { {
            .setting_type                 = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
            .u.context_switchless_setting = &switchless_setting,
        } };
        result                                                     = oe_create_helloworld_enclave(
            enclave_sign, OE_ENCLAVE_TYPE_SGX, flags, settings, OE_COUNTOF(settings), &enclave);
        if (result != OE_OK) {
            fprintf(stderr, "oe_create_helloworld_enclave(): result=%u (%s)\n", result, oe_result_str(result));
            throw std::runtime_error("Enclave creation failed");
        }
    }
};