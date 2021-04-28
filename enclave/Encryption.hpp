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

    int decrypt_block(unsigned char* input_buffer, unsigned char* output_buffer, size_t size)
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
    unsigned char m_iv[IV_SIZE]
        = { 0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 0x5e, 0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75 };
};