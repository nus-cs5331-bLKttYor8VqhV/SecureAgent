// https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client1.c
// https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client2.c

#pragma once

#include <cstring>
#include <exception>
#include <string>

#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

class MbedException : std::exception {
    std::string message;

public:
    MbedException(const char* msg, int code)
    {
        char buf[BUFSIZ] = { 0 };
        snprintf(buf, BUFSIZ, "%s: (%d)", msg, code);

        char* err = buf + strlen(buf);
        *(err++)  = ' ';
        mbedtls_strerror(code, err, BUFSIZ - strlen(buf));

        message = buf;
    }

    const char* what() const noexcept { return message.c_str(); }
};

class TLSClient {

    /**
     * Personalization data can be provided in addition to the more generic
     * entropy source, to make this instantiation as unique as possible.
     */
    const std::string personalization_data = "tls client for group 27 @ cs5331";

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

public:
    TLSClient() { initialize(); }
    TLSClient(const std::string& certificates)
    {
        initialize();
        set_certificate(certificates);
    }

    void set_certificate(const std::string& certificates)
    {
        int ret = mbedtls_x509_crt_parse(&cacert, (const uint8_t*)certificates.c_str(), certificates.size() + 1);
        if (ret < 0) {
            throw MbedException("mbedtls_x509_crt_parse", ret);
        }
    }

    void connect(const char* hostname, const char* port)
    {
        int ret = mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP);
        if (ret < 0) {
            throw MbedException("mbedtls_net_connect", ret);
        }

        setup_tls(hostname);
        handshake();
        verify_certificate();
    }

    void send(const unsigned char* buf, size_t len)
    {
        int ret;
        while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                throw MbedException("mbedtls_ssl_write", ret);
            }
        }
    }

    int recv(unsigned char* buf, size_t len)
    {
        memset(buf, 0, len);
        int ret;

        while ((ret = mbedtls_ssl_read(&ssl, buf, len)) < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                break;
            }

            if (ret < 0) {
                throw MbedException("mbedtls_ssl_read", ret);
            }
        }

        mbedtls_ssl_close_notify(&ssl);
        return ret;
    }

    ~TLSClient() { free(); }

private:
    void initialize()
    {
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);

        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            (const uint8_t*)personalization_data.c_str(), personalization_data.size());
        if (ret != 0) {
            throw MbedException("mbedtls_ctr_drbg_seed", ret);
        }
    }

    void setup_tls(const char* hostname)
    {
        int ret = mbedtls_ssl_config_defaults(
            &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            throw MbedException("mbedtls_ssl_config_defaults", ret);
        }

        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
            throw MbedException("mbedtls_ssl_setup", ret);
        }

        if ((ret = mbedtls_ssl_set_hostname(&ssl, hostname)) != 0) {
            throw MbedException("mbedtls_ssl_set_hostname", ret);
        }

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    }

    void handshake()
    {
        int ret;
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                throw MbedException("mbedtls_ssl_handshake", ret);
            }
        }
    }

    void verify_certificate()
    {
        uint32_t flags;
        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
            char vrfy_buf[512];
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "mbedtls_ssl_get_verify_result", flags);
            throw MbedException(vrfy_buf, 0);
        }
    }

    void free()
    {
        mbedtls_net_free(&server_fd);

        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }
};
