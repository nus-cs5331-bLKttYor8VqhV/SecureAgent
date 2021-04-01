class HTTP_Interface:
    public:
        HTTP_Interface(){

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