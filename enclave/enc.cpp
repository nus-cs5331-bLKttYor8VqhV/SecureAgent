#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <regex>
#include <string>
#include <unistd.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"

#include "helloworld_t.h"

#include "Encryption.hpp"
#include "SocketStream.hpp"
#include "TLSStream.hpp"

TLSClient* tls_client;
SocketStream* socket_stream;
char hexa_derived_secret[65];

void parse_ecdh_request(const char* data, char* data1, char* data2);
int DeriveCryptoKeyFromPassword(unsigned char* passwd, size_t pLen, const unsigned char* salt, const size_t saltLen,
    const size_t iterations, const size_t keyLen, unsigned char* derivedKey);
void decrypt_request_new(char* data, char* buf, int len, unsigned char* iv, int iv_len);
void set_ke_response(char* buf, int len, char* exported_key, int key_len);

void initialize_tls_client();
void connect_enclave(const char* server_host, const char* server_port);
void request_enclave(const char* http_request);
void receive_enclave(char* buf, int len);
void close_enclave();

int hex_to_bytes(const char* src, int src_len, unsigned char* out, int out_len)
{
    // https://stackoverflow.com/questions/1557400/hex-to-char-array-in-c
    unsigned char* dst = out;
    unsigned char* end = out + out_len * sizeof(char);
    unsigned int u;

    while (dst < end && sscanf(src, "%2x", &u) == 1) {
        *dst++ = u;
        src += 2;
    }

    /* for (dst = out; dst < end; dst++)
        printf("%d: %c (%d, 0x%02x)\n", dst - out,
               (isprint(*dst) ? *dst : '.'), *dst, *dst); */

    return (0);
}

void enclave_main()
{
    // Entropy
    int ret = 1;
    mbedtls_ecdh_context ctx_cli, ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char pers[] = "ecdh";

    mbedtls_ecdh_init(&ctx_cli);
    mbedtls_ecdh_init(&ctx_srv);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    if ((ret
            = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, sizeof pers))
        != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        exit(1);
    }
    ret = mbedtls_ecp_group_load(&ctx_srv.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n", ret);
        exit(1);
    }

    ret = mbedtls_ecdh_gen_public(&ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret);
        exit(1);
    }

    // AES Test
    // f7 41 1c b1 de 21 c6 b6 5c 71 4 97 1e f1 d0 34
    const char* key = "eeeeeeeeeeeeeeee";
    Encryption cipher(key, strlen(key) * 8);

    unsigned char input[17] = "aaaaaaaaaaaaaaaa";
    unsigned char output[16];
    unsigned char m_iv[IV_SIZE]
        = { 0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 0x5e, 0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75 };
    cipher.decrypt_block(input, output, 16, m_iv);
    for (int i = 0; i < 16; i++) {
        printf("%x ", output[i]);
    }

    // Key exchange part
    char x[BUFSIZ];
    char y[BUFSIZ];

    // Init socket
    oe_load_module_host_socket_interface();
    oe_load_module_host_resolver();

    socket_stream = new SocketStream(4567);
    while (1) {
        puts("[+] Listening to clients\n");
        while (socket_stream->listen_for_client() != 0) { }
        puts("[+] Python library connected\n");

        // Initialize the rec buffers and receive
        char server_host[2 * BUFSIZ]  = { 0 };
        char http_request[2 * BUFSIZ] = { 0 };
        char server_port[2 * BUFSIZ]  = { 0 };

        memset(server_host, '\0', 2 * BUFSIZ);
        memset(server_port, '\0', 2 * BUFSIZ);
        memset(http_request, '\0', 2 * BUFSIZ);

        // Receive three fields from the web server
        int all_three_received = 0;
        int ret_val;
        while (all_three_received != 3) {
            puts("DEBUG: new loop\n");
            all_three_received = 0;

            // TODO: dirty code, need to redo
            ret_val = (socket_stream->receive_from_client(server_host, 2 * BUFSIZ));
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
            ret_val = (socket_stream->receive_from_client(server_port, 2 * BUFSIZ));
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
            ret_val = (socket_stream->receive_from_client(http_request, 2 * BUFSIZ));
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

        if (strcmp(server_host, "key_exchange") == 0) { // Key exchange
            // See : https://github.com/ARMmbed/mbedtls/blob/development/programs/pkey/ecdh_curve25519.c
            // Very useful for the ECDH flow

            // Parse JSON browser public key
            parse_ecdh_request(http_request, x, y);

            // Create point from x & y with right format
            mbedtls_ecp_point browser_public_key;

            mbedtls_ecp_point_init(&browser_public_key);
            int ret = mbedtls_ecp_point_read_string(&browser_public_key, 16, x, y);
            if (ret != 0) {
                printf("failed\n  ! mbedtls_ecp_point_read_string ret=%d", ret);
            }
            // Check point
            ret = mbedtls_ecp_check_pubkey(&ctx_srv.grp, &browser_public_key);
            if (ret != 0) {
                printf("failed\n  ! mbedtls_ecp_check_pubkey returned %d\n", ret);
                exit(1);
            } else {
                puts(" Valid public key on the curve");
            }

            // Compute shared secret
            ret = mbedtls_ecdh_compute_shared(
                &ctx_srv.grp, &ctx_srv.z, &browser_public_key, &ctx_srv.d, mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0) {
                printf("[-] failed\n ! mbedtls_ecdh_compute_shared returned ret=%d\n", ret);
            }

            // Send x & y (server public key) to browser
            unsigned char export_pub_key[BUFSIZ];
            size_t oo;
            ret = mbedtls_ecp_point_write_binary(
                &ctx_srv.grp, &ctx_srv.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &oo, export_pub_key, BUFSIZ);
            if (ret != 0) {
                printf(" failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret);
                exit(1);
            }
            // printf("%s\n", export_pub_key);
            char rec_buf[2 * BUFSIZ] = { 0 };
            memset(rec_buf, '\0', 2 * BUFSIZ);

            // Convert binary to hex
            char hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

            char hexa_export_pub_key[2 * oo + 1];
            for (int i = 0; i < oo; ++i) {
                char byte                      = export_pub_key[i];
                hexa_export_pub_key[2 * i]     = hex_chars[(byte & 0xF0) >> 4];
                hexa_export_pub_key[2 * i + 1] = hex_chars[(byte & 0x0F) >> 0];
            }
            hexa_export_pub_key[2 * oo] = '\0';

            unsigned char shared_secret[512];
            size_t aa;
            ret = mbedtls_mpi_write_binary(&ctx_srv.z, (unsigned char*)shared_secret, 32);
            if (ret != 0) {
                printf(" failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret);
                exit(1);
            }

            char hexa_shared_secret[65];
            for (int i = 0; i < 32; ++i) {
                char byte                     = shared_secret[i];
                hexa_shared_secret[2 * i]     = hex_chars[(byte & 0xF0) >> 4];
                hexa_shared_secret[2 * i + 1] = hex_chars[(byte & 0x0F) >> 0];
            }
            hexa_shared_secret[64] = '\0';
            printf("Shared secret: %s \n", hexa_shared_secret);

            const unsigned char* salt = reinterpret_cast<const unsigned char*>("Websecurity");

            unsigned char derived[33];
            ret = DeriveCryptoKeyFromPassword(shared_secret, 32, salt, 11, 32, 32, (unsigned char*)derived);

            for (int i = 0; i < 32; ++i) {
                char byte                      = derived[i];
                hexa_derived_secret[2 * i]     = hex_chars[(byte & 0xF0) >> 4];
                hexa_derived_secret[2 * i + 1] = hex_chars[(byte & 0x0F) >> 0];
            }
            hexa_derived_secret[64] = '\0';
            printf("\nDerived secret %s \n", hexa_derived_secret);

            // See https://forums.mbed.com/t/unable-to-calculate-ecdh-shared-secret-from-x-and-y-coordinates/5606 for
            // details mbedtls_mpi_write_binary outputs (4 || x || y)
            set_ke_response(rec_buf, 2 * BUFSIZ, hexa_export_pub_key, strlen(hexa_export_pub_key));
            socket_stream->send_to_client(rec_buf, strlen(rec_buf));
            ret = socket_stream->close_client();
            puts("[+] Client close\n");

        } else { // Request through enclave
            initialize_tls_client();
            char decrypted_http_request[2 * BUFSIZ] = { 0 };
            unsigned char iv[20];
            decrypt_request_new(http_request, decrypted_http_request, 2 * BUFSIZ, (unsigned char*)iv, 20);

            // decrypt_request(http_request, decrypted_http_request, 2*BUFSIZ);
            connect_enclave(server_host, server_port);
            request_enclave(decrypted_http_request);

            puts("[+] Request sent to host, waiting\n");

            char rec_buf[2 * BUFSIZ] = { 0 };
            memset(rec_buf, '\0', 2 * BUFSIZ);

            receive_enclave(rec_buf, 2 * BUFSIZ);

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

void parse_ecdh_request(const char* data, char* data1, char* data2)
{
    char *str2, *saveptr2;
    const char* del = "{";
    char* str       = strdup(data);
    int i           = 0;
    char* rest      = NULL;
    char* token     = strtok_r(str, "{", &rest);
    token           = strtok_r(NULL, "}", &rest);
    // Token is the JSON Content
    // "public_key": 13, "q": 19, "a": 15
    // TODO: delete this part, useless with the next regex
    printf("%s\n", token);

    // Extraction of several sub-matches
    const std::regex pieces_regex("\"x\": \"([A-F0-9]+)\", \"y\": \"([A-F0-9]+)\"");
    std::smatch pieces_match;
    std::string token_str(token);

    if (std::regex_search(token_str, pieces_match, pieces_regex)) {
        for (size_t i = 1; i < pieces_match.size(); ++i) {
            std::ssub_match sub_match = pieces_match[i];
            std::string piece         = sub_match.str();
            char* chr_to_disp         = const_cast<char*>(piece.c_str());
            switch (i) {
            case 1:
                printf("x = %s\n", chr_to_disp);
                strncpy(data1, chr_to_disp, BUFSIZ);
                break;
            case 2:
                printf("y = %s\n", chr_to_disp);
                strncpy(data2, chr_to_disp, BUFSIZ);
                break;
            }
        }
    } else {
        printf("No match\n");
    }
}

int DeriveCryptoKeyFromPassword(unsigned char* passwd, size_t pLen, const unsigned char* salt, const size_t saltLen,
    const size_t iterations, const size_t keyLen, unsigned char* derivedKey)
{
    // https://github.com/Samsung/TizenRT/blob/master/external/iotivity/iotivity_1.2-rel/resource/csdk/security/src/pbkdf2.c
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t* info_sha;
    int ret = -1;

    mbedtls_md_init(&sha_ctx);

    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == NULL) {
        printf("Failed to get hash information");
        return ret;
    }

    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0) {
        printf("Failed to setup hash function ret=%d", ret);
        return ret;
    }

    ret = mbedtls_pkcs5_pbkdf2_hmac(&sha_ctx, passwd, pLen, salt, saltLen, iterations, keyLen, derivedKey);
    if (ret != 0) {
        printf("Call to mbedtls PBKDF2 function failed ret=%d", ret);
    }

    mbedtls_md_free(&sha_ctx);
    return ret;
}

void decrypt_request_new(char* data, char* buf, int len, unsigned char* iv, int iv_len)
{
    // Decrypt each post parameter and generate the request for the bank
    // TODO: content len, host
    const std::regex json_regex("\"enc\": \"([a-f0-9]+)\", \"iv\": \"([a-f0-9]+)\"");
    std::smatch pieces_match;
    std::string token_str(data);

    char str_begin[2 * BUFSIZ]
        = "POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Type: application/json\r\nContent-Length: ";
    char sep[] = "\r\n\r\n";
    if (std::regex_search(token_str, pieces_match, json_regex)) {
        assert(pieces_match.size() == 3);

        // Setup iv
        std::ssub_match sub_match = pieces_match[2];
        std::string iv            = sub_match.str();
        unsigned char* iv_uc      = (unsigned char*)(iv.c_str());
        char* iv_uc_2             = (char*)(iv.c_str());
        printf("IV : %s \n", iv_uc_2);

        // Hex string to byte array, https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
        const char* pos = iv_uc_2;
        unsigned char m_iv[IV_SIZE];

        /* WARNING: no sanitization or error-checking whatsoever */
        for (size_t count = 0; count < sizeof m_iv / sizeof *m_iv; count++) {
            sscanf(pos, "%2hhx", &m_iv[count]);
            pos += 2;
        }

        /* printf("0x");
        for(size_t count = 0; count < sizeof m_iv/sizeof *m_iv; count++){
            printf("%02x/", m_iv[count]);
            printf("%d ", m_iv[count]);
        }
        printf("\n"); */

        // Decypher enc
        std::ssub_match sub_match2 = pieces_match[1];
        std::string enc            = sub_match2.str();
        char* enc_str              = (char*)(enc.c_str());

        printf("Cipher hex = %s\n", enc_str);
        int enc_length = strlen(enc_str);
        printf("Length = %d\n", enc_length);
        unsigned char cipher_char[enc_length / 2 + 1];
        hex_to_bytes(enc_str, strlen(enc_str), cipher_char, enc_length / 2);
        cipher_char[enc_length / 2] = 0;

        hexa_derived_secret[32] = '\0';
        printf("Pass %s\n", hexa_derived_secret);

        Encryption* aa = new Encryption(hexa_derived_secret, strlen(hexa_derived_secret) * 8);
        unsigned char output[enc_length / 2 + 1];
        aa->decrypt_block(cipher_char, output, enc_length / 2, m_iv);
        output[enc_length / 2] = '\0';
        int out_len            = enc_length / 2;

        // Remove the padding by shortening the output
        // pkcs5/7
        for (int i = 0; i < enc_length / 2; i++) {
            if (output[i] < 17) {
                output[i] = '\0';
                printf("Stoped at i=%d", i);
                out_len = i;
                break;
            }
        }
        printf("%s\n", output);

        char str_len[10];
        sprintf(str_len, "%d", out_len);
        strcat(str_begin, (char*)str_len);
        strcat(str_begin, (char*)sep);
        strcat(str_begin, (char*)output);
        printf("%s\n", str_begin);
        strncpy(buf, str_begin, len);
    } else {
        printf("No match\n");
    }
}

void set_ke_response(char* buf, int len, char* exported_key, int key_len)
{
    // Create the answer of DHKE
    char str_begin[2 * BUFSIZ] = "POST /post HTTP/1.1\r\nHost: /sgx/key_exchange\r\nContent-Type: "
                                 "application/json\r\nContent-Length: 138\r\n\r\n{\"B\":\"";
    char str_end[3] = "\"}";
    strcat(str_begin, exported_key);
    strcat(str_begin, str_end);
    strncpy(buf, str_begin, len);
}
