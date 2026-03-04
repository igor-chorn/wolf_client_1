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


#define DEFAULT_SERVER_IP           "74.120.8.220" // p-def1.pcloud.com
#define DEFAULT_SERVER_PORT         443
#define DEFAULT_CHUNK_SIZE          4096

char buff[RXTX_BUF_SIZE];
const char *server_ip = DEFAULT_SERVER_IP;
uint16_t server_port = DEFAULT_SERVER_PORT;
const char *keylog_file = NULL;
const char *sess_in = NULL;
const char *sess_out = NULL;
unsigned int psk_key_idx = 0;
const char *rx_edfile = NULL;
const char *rx_regfile = NULL;
const char *sni_name = NULL;
size_t chunk_size = DEFAULT_CHUNK_SIZE;
int ed_req_index_0 = 0;
int ed_req_index_1 = -1;
int reg_req_index_0 = -1;
int reg_req_index_1 = -1;
size_t delay_ms = 0;
time_point_t first_tx_time;
time_point_t first_rx_time;
time_point_t last_rx_time;

const char* http_req_arr[] = {
"GET "  "/crossdomain.xml"  " HTTP/1.1\r\n" "Connection: keep-alive\r\n"  "\r\n",
"GET "  "/"                 " HTTP/1.1\r\n" "Connection: close\r\n"  "\r\n",
};
size_t http_req_arr_size = ARRAY_LENGTH(http_req_arr);


const char *nformat(const void *data, int len) {
  const char *src = (const char *)data;
  static char buf[512];
  char *dst = buf;

  if (len < 0)
    len = 0;
  if ((size_t)len > sizeof(buf) - 1)
    len = sizeof(buf) - 1;
  for (; len; --len, ++src, ++dst) {
    char sym = *src;
    *dst = isprint(sym) ? sym : '.';
  }
  *dst = 0;
  return buf;
}

const char *bin2str(const void *data, size_t len) {
  const unsigned char *src = data;
  static char buf[1024];
  char *dst = buf;

  if (len > sizeof(buf) / 2 - 1)
    len = sizeof(buf) / 2 - 1;
  for (; len; --len, ++src, dst += 2) {
    sprintf(dst, "%02x", *src);
  }
  *dst = 0;
  return buf;
}

char bin2digit(unsigned char val) {
  return val <= 9 ? val + '0' : val + ('a' - 0xa);
}

int bin2hex(const void *bin, size_t bin_len, char *hex, size_t hex_len) {
  if (bin_len * 2 > hex_len)
    return 0;

  for (const unsigned char *src = bin; bin_len; --bin_len, ++src) {
    unsigned char val = *src;
    unsigned char hi = val >> 4 & 0x0f;
    unsigned char lo = val & 0x0f;
    *hex++ = bin2digit(hi);
    *hex++ = bin2digit(lo);
  }
  *hex = 0;
  return 1;
}

int digit2bin(char dig) {
  if ('0' <= dig &&  dig <= '9')
    return dig - '0';
  if ('a' <= dig &&  dig <= 'f')
    return dig - ('a' - 0xa);
  if ('A' <= dig &&  dig <= 'F')
    return dig - ('A' - 0xa);
  return -1;
}

int hex2bin(const char *hex, size_t hex_len, void *bin, size_t bin_len) {
  if (hex_len % 2 != 0 || hex_len / 2 > bin_len)
    return 0;

  for (unsigned char *dst = bin; hex_len; hex_len-=2, ++dst) {
    int hi = digit2bin(*hex++);
    int lo = digit2bin(*hex++);
    if (lo < 0 || hi < 0)
      return 0;
    int val = hi << 4 | lo;;
    *dst = (unsigned char)val;
  }
  return 1;
}

const char *early_data_status_str(int err) {
    switch (err) {
    case WOLFSSL_EARLY_DATA_NOT_SENT: return "WOLFSSL_EARLY_DATA_NOT_SENT";
    case WOLFSSL_EARLY_DATA_REJECTED: return "WOLFSSL_EARLY_DATA_REJECTED";
    case WOLFSSL_EARLY_DATA_ACCEPTED: return "WOLFSSL_EARLY_DATA_ACCEPTED";
    default: return "WOLFSSL_EARLY_DATA_xxx";
    }
}


struct timespec start_time;

void trace_init() {
  clock_gettime(CLOCK_MONOTONIC, &start_time);
}

void do_trace(const char *function, unsigned int line, const char *fmt, ...) {
  int errno_copy = errno;
  struct timespec end_time;
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  double tm = 1000.0 * (end_time.tv_sec - start_time.tv_sec) + (1.0 * end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;

  char fmt_buf[512];
  va_list ap;
  snprintf(fmt_buf, sizeof(fmt_buf), "%5.1f ms [%s:%u] %s\n", tm, function, line, fmt);
  fmt_buf[sizeof(fmt_buf) - 1] = 0;
  va_start(ap, fmt);
  vfprintf(stdout, fmt_buf, ap);
  va_end(ap);
  fflush(stdout);
  errno = errno_copy;
}

void parse_cmd_line(int argc, char **argv) {
  static struct option long_options[] = {
      {"ip",           required_argument, NULL, 1},
      {"port",         required_argument, NULL, 2},
      {"keylogfile",   required_argument, NULL, 3},
      {"sess_in",      required_argument, NULL, 4},
      {"sess_out",     required_argument, NULL, 5},
      {"psk_key_idx",  required_argument, NULL, 6},
      {"chunk_size",   required_argument, NULL, 7},

      {"ed_req_0",     required_argument, NULL, 8},
      {"ed_req_1",     required_argument, NULL, 9},
      {"reg_req_0",    required_argument, NULL, 10},
      {"req_req_1",    required_argument, NULL, 11},
      {"delay_ms",     required_argument, NULL, 12},

      {"rx_edfile",    required_argument, NULL, 13},
      {"rx_regfile",   required_argument, NULL, 14},
      {"sni_name",     required_argument, NULL, 15},
      // // {"early_data",   required_argument, NULL, 7},
      // // {"regular_data", required_argument, NULL, 8},
      {0, 0, NULL, 0}};
  int res = 0;
  while (res != -1) {
    res = getopt_long_only(argc, argv, "", long_options, NULL);
    switch (res) {
    case 1: server_ip = optarg;               break;
    case 2: server_port = atoi(optarg);       break;
    case 3: keylog_file = optarg;             break;
    case 4: sess_in = optarg;                 break;
    case 5: sess_out = optarg;                break;
    case 6: psk_key_idx = atoi(optarg);       break;
    case 7: chunk_size = atoi(optarg);        break;

    case 8:  ed_req_index_0 = atoi(optarg);   break;
    case 9:  ed_req_index_1 = atoi(optarg);   break;
    case 10: reg_req_index_0 = atoi(optarg);  break;
    case 11: reg_req_index_1 = atoi(optarg);  break;
    case 12: delay_ms    = atoi(optarg);      break;
    case 13: rx_edfile = optarg;              break;
    case 14: rx_regfile = optarg;             break;
    case 15: sni_name = optarg;               break;
    case -1: break;
    default:
      printf("Supported options:\n");
      for (size_t i = 0; i < ARRAY_LENGTH(long_options); ++i) {
        if (long_options[i].name)
          printf("  -%s\n", long_options[i].name);
      }
      exit(1);
    }
  }
}

void print_cmd_line_req() {
  const char* tx_data = NULL;
  if (req_valid(ed_req_index_0)) {
  tx_data = http_req_arr[ed_req_index_0];
  printf("http ED req_0     :'%s'\n", nformat(tx_data, strlen(tx_data)));
  }
  if (req_valid(ed_req_index_1)) {
  tx_data = http_req_arr[ed_req_index_1];
  printf("http ED req_1     :'%s'\n", nformat(tx_data, strlen(tx_data)));
  }

  if (req_valid(reg_req_index_0)) {
  tx_data = http_req_arr[reg_req_index_0];
  printf("http REG req_0    :'%s'\n", nformat(tx_data, strlen(tx_data)));
  }
  if (req_valid(reg_req_index_1)) {
  tx_data = http_req_arr[reg_req_index_1];
  printf("http REG req_1    :'%s'\n", nformat(tx_data, strlen(tx_data)));
  }
}

void set_time_point(time_point_t* ppoint) {
  if (!ppoint->is_set) {
    ppoint->is_set = 1;
    clock_gettime(CLOCK_MONOTONIC, &(ppoint->stime));
  }
}

void update_time_point(time_point_t* ppoint) {
  ppoint->is_set = 1;
  clock_gettime(CLOCK_MONOTONIC, &(ppoint->stime));
}

const char* time_point_str(time_point_t* ppoint) {
  double tm = 1000.0 * (ppoint->stime.tv_sec - start_time.tv_sec) + (1.0 * ppoint->stime.tv_nsec - start_time.tv_nsec) / 1000000.0;
  static char fmt_buf[64];
  snprintf(fmt_buf, sizeof(fmt_buf), "%.1f ms", tm);
  return fmt_buf;
}
