#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <errno.h>
#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <netinet/in.h>
#include <openenclave/bits/module.h>
#include <openenclave/enclave.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

#define HASH_VALUE_SIZE_IN_BYTES     32  // sha256 hashing algorithm
#define ENCRYPTION_KEY_SIZE          256 // AES256-CBC encryption algorithm
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
#define IV_SIZE                      16 // determined by AES256-CBC
#define SALT_SIZE_IN_BYTES           IV_SIZE

using namespace std;

// Errors, see :
// https://os.mbed.com/teams/Arcola/code/mbedtls/docs/tip/bignum_8h_source.html
// https://tls.mbed.org/api/ecp_8h.html#a20464525ea74ab8fcca9f59a12f5dc4b

// Curves, see:
// https://tls.mbed.org/api/ecp_8h.html#ae069f80bc2f9cf2215c34430a9ccd924

class Encryption {
    // To decrypt the browser post request
    //FIXME: should be named decryption
public:
    Encryption(const char* password, size_t password_size)
    {
        puts("[+] Creating interface");
        mbedtls_aes_init(&m_aescontext);
        int ret = mbedtls_aes_setkey_dec(&m_aescontext, (const unsigned char*)password, password_size);
        if (ret != 0) {
            printf("mbedtls_aes_setkey_dec failed with %d", ret);
        }
    };

    int decrypt_block(unsigned char* input_buffer, unsigned char* output_buffer, size_t size, unsigned char* m_iv)
    {
        int ret = 0;

        ret = mbedtls_aes_crypt_cbc(&m_aescontext,
            // MBEDTLS_AES_ENCRYPT for encryption
            MBEDTLS_AES_DECRYPT,
            size, // input data length in bytes,
            m_iv, // Initialization vector (updated after use)
            input_buffer, output_buffer);
        if (ret != 0) {
            printf("mbedtls_aes_crypt_cbc failed with %d", ret);
        }

        return ret;
    };

private:
    mbedtls_aes_context m_aescontext;
};