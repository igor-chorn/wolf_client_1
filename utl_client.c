#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/select.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "utl.h"

#define RX_TIMEOUT_S                2
#define TX_TIMEOUT_MS               (2 * 1000)
#define DEFAULT_CHUNK_SIZE          4096


///////////////////////////////////////////////////////////////////////////////////////
int connect_socket(const char *srv_ip, uint16_t srv_port) {
    struct sockaddr_in serv_addr;
    int fd, ret, sock_opt;

    trace("entry");

#if 1
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP);
#endif

    sock_opt = 1;
    ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&sock_opt, sizeof(sock_opt));
    if (ret) {
        terror("setsockopt failed");
        return -1;
    }
    ret = setsockopt(fd, IPPROTO_TCP, SO_KEEPALIVE, (char *)&sock_opt, sizeof(sock_opt));
    if (ret) {
        terror("setsockopt failed");
        return -1;
    }
    ret = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, (char *)&sock_opt, sizeof(sock_opt));
    if (ret) {
        terror("setsockopt failed");
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(srv_port);
    inet_pton(AF_INET, srv_ip, &serv_addr.sin_addr);
    errno = 0;
    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1 && errno != EINPROGRESS) {
        terror("connect failed");
        return -1;
    }

    while (1) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        trace("poll start timeout_ms:%d", TX_TIMEOUT_MS);
        errno = 0;
        ret = poll(&pfd, 1, TX_TIMEOUT_MS);
        trace("poll done, ret:%d errno:'%s' (%d)", ret, errno_str(errno), errno);

        if (ret == -1 && errno == EINTR)
            continue;
        if (ret != 1)
            fd = -1;
        break;
    }

    trace("exit fd:%d", fd);
    return fd;
}

int send_ssl_data(int fd, WOLFSSL *ssl, const void *data, size_t data_size) {
  struct pollfd pfd = {.fd = fd, .events = POLLOUT};
  int ret;

  while (1) {
    trace("poll start timeout_ms:%d", TX_TIMEOUT_MS);
    errno = 0;
    ret = poll(&pfd, 1, TX_TIMEOUT_MS);
    trace("poll done, ret:%d errno:'%s' (%d)", ret, errno_str(errno), errno);

    if (ret == -1 && errno == EINTR)
      continue;
    if (ret != 1)
      break;

    ret = wolfSSL_write(ssl, data, data_size);
    trace("Reg TX [%d] '%s'", ret, nformat(data, ret));
    if (ret > 0)
      set_time_point(&first_tx_time);

    if (ret <= 0) {
      int ssl_err = wolfSSL_get_error(ssl, ret);
      trace("wolfSSL_get_error: %d",  ssl_err);
      break;
    }

    if (ret != (int)data_size) {
      trace("wolfSSL_write - not all data are sent, ret:%d", ret);
    }
    break;
  }

  trace("exit. ret:%d", ret);
  return ret;
}

int send_early_data(int fd, WOLFSSL *ssl, const void *data, size_t data_size) {
  struct pollfd pfd = {.fd = fd, .events = POLLOUT};
  int ret;

  while (1) {
    trace("poll start timeout_ms:%d", TX_TIMEOUT_MS);
    errno = 0;
    ret = poll(&pfd, 1, TX_TIMEOUT_MS);
    trace("poll done, ret:%d errno:'%s' (%d)", ret, errno_str(errno), errno);

    if (ret == -1 && errno == EINTR)
      continue;
    if (ret != 1)
      break;

    int tx_actual = 0;
    ret = wolfSSL_write_early_data(ssl, data, data_size, &tx_actual);
    trace("Ed TX [%d - %d] '%s'", ret, tx_actual, nformat(data, ret));
    if (ret > 0)
      set_time_point(&first_tx_time);

    if (ret < 0) { // TODO: <= ???
        char buffer[80];
        int ssl_err = wolfSSL_get_error(ssl, ret);
        trace("wolfSSL_get_error: %d '%s'",  ssl_err, wolfSSL_ERR_error_string(ssl_err, buffer));
        break;
    }

    if (ret != (int)data_size) {
      trace("wolfSSL_write - not all data are sent, ret:%d", ret);
    }
    break;
  }

  trace("exit. ret:%d", ret);
  return ret;
}

//////////////////////////////////////////////////////////////////////////////
static int psync_wait_socket_writable_microsec(int sock, long sec, long usec){
    fd_set wfds;
    struct timeval tv;
    int res;

    tv.tv_sec=sec;
    tv.tv_usec=usec;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);

    res=select(sock+1, NULL, &wfds, NULL, &tv);
    if (res==1)
        return 0;

    trace("fail");
    return -1;
}

#define RX_CHUNK_SIZE   (4*1024)
size_t receive_ssl_data(int fd, WOLFSSL *ssl, void *data, size_t max_data_size) {
  int ret = 0;
  size_t total_rx_size = 0;
  void* data_ptr = data;

  do {
    trace("loop start");

    errno = 0;
    if ((size_t)(data_ptr + RX_CHUNK_SIZE - data) > max_data_size) {
      trace("buffer overflow, break");
      break;
    }

    if (psync_wait_socket_writable_microsec(fd, RX_TIMEOUT_S, 0) != 0){
        trace("error");
        return 0;
    }

    ret = wolfSSL_read(ssl, data_ptr, RX_CHUNK_SIZE);
    trace("Reg RX [%d] '%s'", ret, nformat(data_ptr, ret));

    if (ret > 0) {
      set_time_point(&first_rx_time);
      update_time_point(&last_rx_time);
      total_rx_size += ret;
      data_ptr += ret;
      continue;
    }

    int ssl_err = wolfSSL_get_error(ssl, ret);
    trace("err:%d", ssl_err);

    if (ssl_err == WOLFSSL_ERROR_WANT_READ || ssl_err == WOLFSSL_ERROR_WANT_WRITE)
      continue;

    trace("break");
    break;
  } while (1);

  trace("exit. ret:%lu", total_rx_size);
  return total_rx_size;
}

void save_rx_file(void* data, size_t data_len, const char* fname) {
  trace("entry");
  FILE *file = fopen(fname, "w");
  if (!file) {
    terror("cannot open '%s'", fname);
    return;
  }

  const char* last_header = "\r\n\r\n";
  void* body_ptr = data;
  size_t body_len = data_len;
  char* header_ptr = strstr(data, last_header);
  if (header_ptr) {
    body_ptr = header_ptr + strlen(last_header);
    body_len -= (body_ptr - data);
    trace("HTTP header found, ofs:%d", body_ptr - data);
  }

  size_t len = fwrite(body_ptr, 1, body_len, file);
  trace("fwrite len:%lu %s", len, len == body_len ? "ok" : "error");

  fclose(file);
}
