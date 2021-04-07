#include "SocketStream.hpp"
#include "TLSStream.hpp"

#include "helloworld_t.h"
#include <unistd.h>

TLSClient* tls_client;
SocketStream* socket_stream;

void socket_test(uint16_t port)
{
    socket_stream = new SocketStream(4567);
    socket_stream->test_echo_server();
}

void enclave_main()
{
    /* Logic : check if there is any request from Python interface lib
        if so, parse and get parameters to contact the bank server
        contact the bank server with TLS stream
        get response back
        send what is needed to Python interface lib
    */
    oe_load_module_host_socket_interface();
    oe_load_module_host_resolver();

    socket_stream = new SocketStream(4567);
    while (1) {
        puts("[+] Listening to clients\n");
        while (socket_stream->listen_for_client() != 0) { }
        puts("[+] Python library connected\n");

        // Initialize the rec buffers and receive
        char server_host[BUFSIZ]  = { 0 };
        char http_request[BUFSIZ] = { 0 };
        char server_port[BUFSIZ]  = { 0 };

        memset(server_host, '\0', BUFSIZ);
        memset(server_port, '\0', BUFSIZ);
        memset(http_request, '\0', BUFSIZ);

        // Receive three fields from the web server
        int all_three_received = 0;
        int ret_val;
        while (all_three_received != 3) {
            puts("DEBUG: new loop\n");
            all_three_received = 0;
            ret_val            = (socket_stream->receive_from_client(server_host, BUFSIZ) > 0);
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
            ret_val = (socket_stream->receive_from_client(server_port, BUFSIZ) > 0);
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
            ret_val = (socket_stream->receive_from_client(http_request, BUFSIZ) > 0);
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

        initialize_tls_client();
        connect_enclave(server_host, server_port);
        request_enclave(http_request);

        puts("[+] Request sent to host, waiting\n");

        char rec_buf[BUFSIZ] = { 0 };
        memset(rec_buf, '\0', BUFSIZ);

        receive_enclave(rec_buf, BUFSIZ);

        puts("[+] Response received from bank\n");

        socket_stream->send_to_client(rec_buf, strlen(rec_buf));
        int ret = socket_stream->close_client();
        puts("[+] Client close\n");
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