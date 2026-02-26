#ifndef __UTL_H__
#define __UTL_H__


#define ARRAY_LENGTH(arr)     (sizeof(arr) / sizeof(arr[0]))
#define PATH_SIZE             1024

#define RXTX_BUF_SIZE           (10*1024*1024)
extern char buff[RXTX_BUF_SIZE];
extern const char *server_ip;
extern uint16_t server_port;

extern const char *keylog_file;
extern const char *sess_in;
extern const char *sess_out;
extern unsigned int psk_key_idx;

extern size_t chunk_size;
extern int ed_req_index_0;   // early
extern int ed_req_index_1;   // early
extern int reg_req_index_0;   // regular
extern int reg_req_index_1;   // regular
extern size_t delay_ms;
extern const char *rx_edfile;
extern const char *rx_regfile;
extern const char *sni_name;

extern const char* http_req_arr[];
extern size_t http_req_arr_size;
static inline int req_valid(int idx) {
  return (idx >= 0 && (size_t)idx < http_req_arr_size) ? 1 : 0;
};

const char *nformat(const void *data, int len);
const char *bin2str(const void *data, size_t len);
int bin2hex(const void *bin, size_t bin_len, char *hex, size_t hex_len);
int hex2bin(const char *hex, size_t hex_len, void *bin, size_t bin_len);
const char *early_data_status_str(int err);

void trace_init();
void do_trace(const char *function, unsigned int line, const char *fmt, ...);
#define trace(...) do_trace(__func__, __LINE__, __VA_ARGS__)
#define terror(...) do_trace(__func__, __LINE__, __VA_ARGS__)
void parse_cmd_line(int argc, char **argv);
void print_cmd_line_req();

typedef struct {
  int is_set;
  struct timespec stime;
} time_point_t;
extern time_point_t first_tx_time;
extern time_point_t first_rx_time;
extern time_point_t last_rx_time;

void set_time_point(time_point_t* ppoint);
void update_time_point(time_point_t* ppoint);
const char* time_point_str(time_point_t* ppoint);

int connect_socket(const char *srv_ip, uint16_t srv_port);
int send_ssl_data(int fd, WOLFSSL *ssl, const void *data, size_t data_size);
int send_early_data(int fd, WOLFSSL *ssl, const void *data, size_t data_size);
size_t receive_ssl_data(int fd, WOLFSSL *ssl, void *data, size_t max_data_size);
void save_rx_file(void* data, size_t data_len, const char* fname);

#endif