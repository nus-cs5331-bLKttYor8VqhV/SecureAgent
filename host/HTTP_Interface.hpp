class HTTP_Interface:
    public:
        HTTP_Interface(){
            oe_result_t result;
            int ret               = 1;
            oe_enclave_t* enclave = NULL;

            char buf[BUFSIZ];
            int len = BUFSIZ;

            uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
            if (check_simulate_opt(&argc, argv)) {
                flags |= OE_ENCLAVE_FLAG_SIMULATE;
            }

            if (argc != 2) {
                fprintf(stderr, "Usage: %s enclave_image_path [ --simulate  ]\n", argv[0]);
                return -1;
            }

            oe_enclave_setting_context_switchless_t switchless_setting = {
                1,  // number of host worker threads
                0}; // number of enclave worker threads.
            oe_enclave_setting_t settings[] = {{
                .setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
                .u.context_switchless_setting = &switchless_setting,
            }};

            // Create the enclave
            result = oe_create_helloworld_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, settings, OE_COUNTOF(settings), &enclave);
            if (result != OE_OK) {
                fprintf(stderr, "oe_create_helloworld_enclave(): result=%u (%s)\n", result, oe_result_str(result));
                goto exit;
            }

        };

        HTTP_Interface(const char* hostname, const char* port){

        }

        int e_request(oe_enclave_t* enclave, const char* request){
            oe_result_t result = request_enclave(enclave, request);
            if (result != OE_OK) {
                fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
                return -1;
            }
            return 0;
        }

        int e_get_response(oe_enclave_t* enclave, char* buf, int len){
            oe_result_t result = receive_enclave(enclave, buf, len);
            if (result != OE_OK) {
                fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
                return -1;
            }
            return 0;
        }

        int e_close(oe_enclave_t* enclave){
            oe_result_t result = close_enclave(enclave);
            if (result != OE_OK) {
                fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
                return -1;
            }
            return 0;}

        int e_connect(oe_enclave_t* enclave, const char* server_host, const char* server_port){
            oe_result_t result = connect_enclave(enclave, server_host, server_port);
            if (result != OE_OK) {
                fprintf(stderr, "calling into calltest2 failed: result=%u (%s)\n", result, oe_result_str(result));
                return -1;
            }
            return 0;
        }
    private:
        int secret{0};