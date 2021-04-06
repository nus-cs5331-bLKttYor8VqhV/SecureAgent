#include "TLSStream.hpp"
#include "SocketStream.hpp"

#include "helloworld_t.h"
#include <unistd.h>

TLSClient* tls_client;
SocketStream* socket_stream;

/* void enclave_https()
{
    oe_load_module_host_socket_interface();
    oe_load_module_host_resolver();

    char buf[BUFSIZ];

    try {
        TLSClient tls_client(mbedtls_test_cas_pem);
        tls_client.connect(server_host, server_port);
        tls_client.send((const unsigned char*)http_request, strlen(http_request));
        tls_client.recv((unsigned char*)buf, BUFSIZ);

        puts(buf);
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
} */

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
    while(1){
        while(socket_stream->listen_for_client() != 0){
        }
        puts("[+] Python library connected\n");

        // Initialize the rec buffers and receive
        char server_host[BUFSIZ] = {0};
        char http_request[BUFSIZ] = {0};
        char server_port[BUFSIZ] = {0};
        
        memset (server_host,'\0',BUFSIZ);
        memset (server_port,'\0',BUFSIZ);
        memset (http_request,'\0',BUFSIZ);
        
        while(socket_stream->receive_from_client(server_host, BUFSIZ) <= 0){
        }
        while(socket_stream->receive_from_client(server_port, BUFSIZ) <= 0){
        }
        while(socket_stream->receive_from_client(http_request, BUFSIZ) <= 0){
        }

        puts("[+] Received\n");

        printf("%s\n%s\n%s\n%d\n", server_host, server_port, http_request, strlen(server_port));
        
        initialize_tls_client();
        connect_enclave(server_host, server_port);
        request_enclave(http_request);

        puts("[+] Request sent, waiting\n");

        char rec_buf[BUFSIZ] = {0};
        memset(rec_buf,'\0',BUFSIZ);

        receive_enclave(rec_buf, BUFSIZ);
        // TODO: get response back properly
        // TODO: parse it, format it and send it to socket
        puts("[+] Received again\n");


        socket_stream->send_to_client(rec_buf, strlen(rec_buf));
        int ret = socket_stream->close_client();
        printf("%s\n", rec_buf);
        puts("[+] Client close\n");
    }
}

void initialize_tls_client()
{

    try {
        tls_client = new TLSClient(mbedtls_test_cas_pem);
        puts("[+] Enclave created");
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
        puts("[+] Enclave connected");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void request_enclave(const char* http_request)
{
    // Check if connected
    try {
        tls_client->send((const unsigned char*)http_request, strlen(http_request));
        puts("[+] Request sent");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void receive_enclave(char* buf, int len)
{
    try {
        tls_client->recv((unsigned char*)buf, len);
        puts("[+] Response printed");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}

void close_enclave()
{
    try {
        tls_client = NULL;
        puts("[+] Closed");
    } catch (MbedException& err) {
        fprintf(stderr, "%s %s\n", __FUNCTION__, err.what());
    }
}