#define _GNU_SOURCE
#include <arpa/inet.h>
//#include <ctype.h>
//#include <dirent.h>
//#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
//#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include "utl.h"

#define SERVER_IP           "127.0.0.1"
#define SERVER_PORT         4443
#define SERVER_CERT_PATH    "sslkeys/certs/pcloud_g1.com.crt"
#define SERVER_KEY_PATH     "sslkeys/private/pcloud_g1.com.key"
#define SERVER_PSK_PATH     "sslkeys/private/pcloud.com.private.psk-000"

SSL_CTX*  server_ctx;
EVP_PKEY* server_psk;
SSL*      server_ssl;
int       is_accepted = 0;

SSL_CTX *sssl_ctx_create(const char *crt, const char *key);
int http_read_request(int fd, SSL *ssl, void *data, int num);
int http_send_all(int fd, SSL *ssl, const void *data, int len);
int sssl_destroy(int fd, SSL *ssl);

EVP_PKEY* get_server_psk(unsigned char idx) {
  if (idx != 0)
    return NULL;
  return server_psk;
}


int main(int argc, char **argv) {
    struct sockaddr_in server_sockaddr;
    int sock = socket(PF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP);
    if (sock == -1) {
        fprintf(stderr, "unable to create socket\n");
        return 1;
    }
    int sock_opt=1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, sizeof(sock_opt));
    setsockopt(sock, SOL_TCP, TCP_NODELAY, (char*)&sock_opt, sizeof(sock_opt));
    sock_opt=10;
    setsockopt(sock, SOL_TCP, TCP_KEEPCNT, &sock_opt, sizeof(sock_opt));
    sock_opt=60;
    setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, &sock_opt, sizeof(sock_opt));
    sock_opt=30;
    setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, &sock_opt, sizeof(sock_opt));

    memset(&server_sockaddr, 0, sizeof(server_sockaddr));
    server_sockaddr.sin_family = AF_INET;
    inet_aton(SERVER_IP, &server_sockaddr.sin_addr);
    server_sockaddr.sin_port = htons(SERVER_PORT);

    if (bind(sock, (struct sockaddr *) &server_sockaddr, sizeof (server_sockaddr))==-1) {
        fprintf(stderr, "unable to bind to %s:%u\n", SERVER_IP, SERVER_PORT);
        return 1;
    }

    if (listen(sock, 4096)==-1) {
        fprintf(stderr, "unable to listen to %s:%u\n", SERVER_IP, SERVER_PORT);
        return 1;
    }
    printf("listening...\n");

    server_ctx = sssl_ctx_create(SERVER_CERT_PATH, SERVER_KEY_PATH);
    if (!server_ctx){
        fprintf(stderr, "unable to create ctx\n");
        return 1;
    }

    FILE *fp=fopen(SERVER_PSK_PATH, "r");
    if (!fp) {
        printf("error: cannot open '%s'", SERVER_PSK_PATH);
        return 1;
    }

    server_psk=PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!server_psk){
      printf("error: cannot read key from '%s'", SERVER_PSK_PATH);
    }


    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen = sizeof(remote_addr);
    int fd;

    if ((fd=accept4(sock, (struct sockaddr *)&remote_addr, &remote_addrlen, SOCK_CLOEXEC|SOCK_NONBLOCK))==-1){
        fprintf(stderr, "accept fail\n");
        return 1;
    }
    trace_init();
    trace("accepted");

    server_ssl = SSL_new(server_ctx);
    if (SSL_set_fd(server_ssl, fd) < 0){
        fprintf(stderr, "accept fail\n");
        return 1;
    }

    int ret;
    char buf[1024];

    while (http_read_request(fd, server_ssl, buf, sizeof(buf)) >= 0) {
        strcpy(buf, "server-response");
        ret = http_send_all(fd, server_ssl, buf, strlen(buf));
        if (ret < 0) {
            trace("send fail");
            return 1;
        }
    }

    sssl_destroy(fd, server_ssl);
    return 0;
}
