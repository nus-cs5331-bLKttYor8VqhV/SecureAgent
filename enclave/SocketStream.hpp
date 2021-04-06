#include <stdexcept>
#include <cstdio>
#include <openenclave/enclave.h>
#include <openenclave/bits/module.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

class SocketStream {
public:
    SocketStream(uint16_t port)
    {
        puts("[+] Creating interface");

        /* Create the listener socket. */
        if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            printf("socket() failed: errno=%d", errno);

        /* Reuse this server address. */
        {
            const int opt = 1;
            const socklen_t opt_len = sizeof(opt);

            if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, opt_len) != 0)
                printf("setsockopt() failed: errno=%d", errno);
        }

        /* Listen on this address. */
        {
            struct sockaddr_in addr;
            const int backlog = 10;

            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(port);

            if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0)
                printf("bind() failed: errno=%d", errno);

            if (listen(listener, backlog) != 0)
                printf("listen() failed: errno=%d", errno);
        }
    };

    void test_echo_server()
    {
        for (;;)
        {
            int client;
            uint64_t value;
            char buffer[4096] = {0};

            if ((client = accept(listener, NULL, NULL)) < 0)
                printf("accept() failed: errno=%d\n", errno);

            if (read(client, buffer, sizeof(buffer)) != 0)
                printf("recv_n() failed: errno=%d\n", errno);

            if (send(client, buffer, sizeof(buffer), 0) != 0)
                printf("send_n() failed: errno=%d\n", errno);

            close(client);
            printf("Value : %c ; len = %lu\n", buffer[0], sizeof(buffer[0]));
            if (buffer[0] == 'e'){
                printf("Closing ...\n");
                break;
            }
        }

        close(listener);

    }

    int listen_for_client()
    {
        if ((client = accept(listener, NULL, NULL)) < 0){
            printf("accept() failed: errno=%d\n", errno);
            return -1;
        }
        return 0;
    }

    int receive_from_client(char* buf, int len){
        assert(client != 0);
        struct pollfd fd;
        int ret;
        fd.fd = client;
        fd.events = POLLIN;
        ret = poll(&fd, 1, 1000); // 1 second for timeout
        switch (ret) {
            case -1:
                return -1;
            case 0:
                return -2;
            default:
                return read(client, buf, len); // get your data
        }
    }

    int close_client(){
        return close(client);
    }
private:
    int listener;
    int client{0};
};