#include "SocketStream.hpp"
#include "TLSStream.hpp"
#include "Encryption.hpp"

#include "helloworld_t.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <regex>
#include <string>
#include <stdlib.h>
#include <math.h>

TLSClient* tls_client;
SocketStream* socket_stream;

void parse_response(const char *data, long* data1, long* data2, long* data3);
void set_ke_response(char* buf, int len, int B);
void decrypt_request(char *data, char* buf, int len);

int hex_to_bytes(const char *src, int src_len, unsigned char* out, int out_len) {
    // https://stackoverflow.com/questions/1557400/hex-to-char-array-in-c
    unsigned char *dst = out;
    unsigned char *end = out + out_len * sizeof(char);
    unsigned int u;

    while (dst < end && sscanf(src, "%2x", &u) == 1)
    {
        *dst++ = u;
        src += 2;
    }

    for (dst = out; dst < end; dst++)
        printf("%d: %c (%d, 0x%02x)\n", dst - out,
               (isprint(*dst) ? *dst : '.'), *dst, *dst);

    return(0);
}

void socket_test(uint16_t port)
{
    socket_stream = new SocketStream(4567);
    socket_stream->test_echo_server();
}

void enclave_main()
{
    // AES Test
    Encryption* aa;
    char* key = "eeeeeeeeeeeeeeee";
    aa = new Encryption(key, strlen(key)*8);

    unsigned char input[17] = "aaaaaaaaaaaaaaaa";
    unsigned char output[16];
    aa->decrypt_block(input, output, 16);
    for(int i=0; i<16; i++){
        printf("%x ", output[i]);
    }


    // Key exchange part
    srand (time(NULL));
    long A, p, g, B, K;
    long b = rand() % 10 + 1;



    oe_load_module_host_socket_interface();
    oe_load_module_host_resolver();

    socket_stream = new SocketStream(4567);
    while (1) {
        puts("[+] Listening to clients\n");
        while (socket_stream->listen_for_client() != 0) { }
        puts("[+] Python library connected\n");

        // Initialize the rec buffers and receive
        char server_host[2*BUFSIZ]  = { 0 };
        char http_request[2*BUFSIZ] = { 0 };
        char server_port[2*BUFSIZ]  = { 0 };

        memset(server_host, '\0', 2*BUFSIZ);
        memset(server_port, '\0', 2*BUFSIZ);
        memset(http_request, '\0', 2*BUFSIZ);

        // Receive three fields from the web server
        int all_three_received = 0;
        int ret_val;
        while (all_three_received != 3) {
            puts("DEBUG: new loop\n");
            all_three_received = 0;

            // TODO: dirty code, need to redo
            ret_val = (socket_stream->receive_from_client(server_host, 2*BUFSIZ) );
            switch (ret_val) {
            case -1:
                break;
            case -2:
                continue;
            case 0:
                continue;
            default:
                all_three_received++;
            }
            ret_val = (socket_stream->receive_from_client(server_port, 2*BUFSIZ) );
            switch (ret_val) {
            case -1:
                break;
            case -2:
                continue;
            case 0:
                continue;
            default:
                all_three_received++;
            }
            ret_val = (socket_stream->receive_from_client(http_request, 2*BUFSIZ) );
            switch (ret_val) {
            case -1:
                break;
            case -2:
                continue;
            case 0:
                continue;
            default:
                all_three_received++;
            }
        }

        if (all_three_received != 3) {
            puts("[+] Error, breaking\n");
            break;
        }
        puts("[+] Host, port and request received\n");

        if(strcmp(server_host, "key_exchange")==0){ // Key exchange
            // Parse JSON
            parse_response(http_request, &A, &p, &g);
            printf("%d %d %d %d\n", A, p, g, b);
            // Calculate key)
            B = ((long)pow(g, b)+p) % p;
            K = ((long)pow(A, b)+p) % p;
            printf("Derived key: B=%d K=%d\n", B, K);
            char rec_buf[2*BUFSIZ] = { 0 };
            memset(rec_buf, '\0', 2*BUFSIZ);
            set_ke_response(rec_buf, 2*BUFSIZ, B);
            // Send back for ke
            socket_stream->send_to_client(rec_buf, strlen(rec_buf));
            int ret = socket_stream->close_client();
            
        }
        else{  // Request through enclave
            initialize_tls_client();
            char decrypted_http_request[2*BUFSIZ] = { 0 };
            decrypt_request(http_request, decrypted_http_request, 2*BUFSIZ);
            connect_enclave(server_host, server_port);
            request_enclave(decrypted_http_request);

            puts("[+] Request sent to host, waiting\n");

            char rec_buf[2*BUFSIZ] = { 0 };
            memset(rec_buf, '\0', 2*BUFSIZ);

            receive_enclave(rec_buf, 2*BUFSIZ);

            puts("[+] Response received from bank\n");

            socket_stream->send_to_client(rec_buf, strlen(rec_buf));
            int ret = socket_stream->close_client();
            puts("[+] Client close\n");
        }
    }
}

void initialize_tls_client()
{

    try {
        tls_client = new TLSClient(mbedtls_test_cas_pem);
        puts("  [+] TLS Client created\n");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void connect_enclave(const char* server_host, const char* server_port)
{
    try {
        if (tls_client == NULL) {
            initialize_tls_client();
        }
        tls_client->connect(server_host, server_port);
        puts("  [+] Connected to bank\n");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void request_enclave(const char* http_request)
{
    // Check if connected
    try {
        tls_client->send((const unsigned char*)http_request, strlen(http_request));
        puts("  [+] Request sent to bank\n");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void receive_enclave(char* buf, int len)
{
    try {
        tls_client->recv((unsigned char*)buf, len);
        puts("[+] Response received from bank\n");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void close_enclave()
{
    try {
        tls_client = NULL;
        puts("  [+] Closed\n");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void parse_response(const char *data, long* data1, long* data2, long* data3){
    // Parse DHKE request to get parameters
    char *str2, *saveptr2;
    char *del = "{";
    char *str = strdup(data);
    int i = 0;
    char *rest = NULL;
    char *token = strtok_r(str, "{", &rest);
    token = strtok_r(NULL, "}", &rest);
    // Token is the JSON Content
    // "public_key": 13, "q": 19, "a": 15
    //TODO: delete this part, useless with the next regex
    printf("%s\n", token);
    
    // Extraction of several sub-matches
    const std::regex pieces_regex("\"public_key\": ([0-9]+), \"q\": ([0-9]+), \"a\": ([0-9]+)");
    std::smatch pieces_match;
    std::string token_str(token);

    if (std::regex_search(token_str, pieces_match, pieces_regex)) {
        for (size_t i = 1; i < pieces_match.size(); ++i) {
            std::ssub_match sub_match = pieces_match[i];
            std::string piece = sub_match.str();
            char* chr_to_disp = const_cast<char*>(piece.c_str());
            int data_to_disp = atoi(chr_to_disp);
            switch (i)
            {
            case 1:
                printf("PubKey A = %d\n", data_to_disp);
                *data1 = data_to_disp;
                break;
            case 2:
                printf("qA = %d\n", data_to_disp);
                *data2 = data_to_disp;
                break;
            case 3:
                printf("aA = %d\n", data_to_disp);
                *data3 = data_to_disp;
                break;
            }
        }   
    }
    else{
        printf("No match\n");
    }
}

void set_ke_response(char* buf, int len, int B){
    // Create the answer of DHKE
    char str_begin[2*BUFSIZ] = "POST /post HTTP/1.1\r\nHost: /sgx/key_exchange\r\nContent-Type: application/json\r\nContent-Length: 89\r\n\r\n{\"B\":";
    char str_end[2] = "}";
    char str_data[12];
    sprintf(str_data, "%d\0", B);
	strcat(str_begin, str_data);
    strcat(str_begin, str_end);
    strncpy(buf, str_begin, len);
	printf("%s\n", str_begin);
}

void decrypt_request(char *data, char* buf, int len){
    // Decrypt each post parameter and generate the request for the bank
    // TODO: content len, host
    printf("%s\n", data);
    const std::regex json_regex("\"user_name\": \"([a-f0-9]+)\", \"card_number\": \"([a-f0-9]+)\", \"month\": \"([a-f0-9]+)\", \"year\": \"([a-f0-9]+)\", \"cvc_code\": \"([a-f0-9]+)\""); 
    std::smatch pieces_match;
    std::string token_str(data);
    char ch_arr[6][20] = {
                         "\"user_name\": \"",
                         "\", \"card_number\": \"",
                         "\", \"month\": \"",
                         "\", \"year\": \"",
                         "\", \"cvc_code\": \"",
                         "\"}"
                     };

    char str_begin[2*BUFSIZ] = "POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{";
    if (std::regex_search(token_str, pieces_match, json_regex)) {
        for (size_t i = 1; i < pieces_match.size(); ++i) {
            std::ssub_match sub_match = pieces_match[i];
            std::string piece = sub_match.str();
            char* chr_to_disp = const_cast<char*>(piece.c_str());
            printf("Cipher hex = %d %s\n", i, chr_to_disp);
            unsigned char cipher_char[17];
            hex_to_bytes(chr_to_disp, strlen(chr_to_disp), cipher_char, 16);

            Encryption* aa;
            char* key = "eeeeeeeeeeeeeeee";
            aa = new Encryption(key, strlen(key)*8);

            unsigned char output[17];
            aa->decrypt_block(cipher_char, output, 16);
            output[16] = '\0';
            strcat(str_begin, ch_arr[i-1]);
            strcat(str_begin, (char*) output);
        }   
        strcat(str_begin, ch_arr[5]);
        printf("%s\n", str_begin);
        strncpy(buf, str_begin, len);
    }
    else{
        printf("No match\n");
    }
}
