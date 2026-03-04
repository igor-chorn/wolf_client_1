#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "utl.h"

////////////////////////////////////////////
// PSK wolf client
////////////////////////////////////////////
#define MAX_EARLY_DATA_SIZE     (64*1024)

#define PSK_BIN_KEY_SIZE        32
#define PSK_HEX_KEY_SIZE        64
// identity format:
//  [0]       : version
//  [1]       : psk key index (0..255)
//  [2]..[33] : 32 bytes binary client public key
#define IDENTITY_VERSION        1
#define IDENTITY_BIN_SIZE       (32 + 2)
#define IDENTITY_HEX_SIZE       (2*(32 + 2))


//#define SSL_PUB_KEY_DIR         "sslkeys/public/"
#define DEFAULT_PSK_KEY_INDEX   0
#define PSK_COUNT               256
#define PSK_BIN_KEY_SIZE        32

typedef struct {
  unsigned char psk[PSK_BIN_KEY_SIZE];
  unsigned char present;
}client_psk_t;
client_psk_t client_psk[PSK_COUNT] = {
    // TODO: psk + index
    {.present=1, .psk = {0x7e,0x46,0xef,0xb5,0xfd,0x79,0x81,0x33,0x1c,0xe0,0xc0,0x47,0x5e,0x40,0x69,0x25,0x44,0x28,0x16,0xbf,0x08,0xdb,0xdd,0xa1,0x73,0x59,0xd3,0x91,0x4e,0x8b,0x5d,0x32}},
    {.present=1, .psk = {0x97,0x28,0xf5,0xad,0x50,0x18,0x76,0x2d,0x29,0x7c,0x98,0x09,0x92,0x3b,0x17,0x00,0x24,0x1a,0xb2,0x6c,0xe9,0x30,0x60,0xb1,0x05,0x83,0xf8,0x18,0x3b,0xe4,0x62,0x64}},
    {.present=0}, // [2]
    {.present=1, .psk = {0xd2,0x1b,0x30,0x18,0x9a,0x7a,0x22,0x7a,0x57,0x78,0x8e,0xb2,0xe4,0x64,0x42,0x76,0xa0,0xd9,0x51,0x56,0x24,0xc2,0xb8,0x88,0xe5,0x2e,0xf9,0x80,0xd9,0x30,0x60,0x11}},
    {.present=0}, // [4]
    {.present=0}, // [5]
    {.present=0}, // [6]
    {.present=0}, // [7]
    {.present=0}, // [8]
    {.present=0}, // [9]
    {.present=1, .psk = {0x92,0x95,0x0e,0x14,0x8d,0x32,0xa5,0x40,0x6b,0xdc,0xe9,0xd7,0xb8,0x11,0xa7,0x7b,0x3b,0x4c,0xaa,0x3b,0x43,0x90,0x04,0xf9,0x2d,0x76,0xf5,0xe5,0x34,0x48,0x58,0x29}}, // [10]
    {.present=0}, // [11]
    {.present=1, .psk = {0x71,0x6d,0xde,0x58,0x80,0x70,0xe4,0x1d,0xdc,0x1a,0xb1,0xd9,0x58,0xad,0xee,0x0d,0x10,0xb2,0xf4,0x32,0xb8,0x6b,0xb7,0x04,0x72,0x8a,0x74,0x40,0x8e,0x7c,0x0f,0x49}}, // [12]
};


static WOLFSSL_CTX *psync_wolf_ctx = NULL;
static int wait_sock_ready_for_ssl(int sock, int psync_ssl_errno);
unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len);


int main(int argc, char **argv) {
    int total_rx = 0;
    const char* tx_data = NULL;
    int ret;

    //client_load_psk(SSL_PUB_KEY_DIR);
    parse_cmd_line(argc, argv);
    printf("server_ip         :%s\n", server_ip);
    printf("server_port       :%u\n", server_port);
    printf("keylogfile        :%s\n", keylog_file);
    print_cmd_line_req();
    printf("rx_edfile         :%s\n", rx_edfile);
    printf("rx_regfile        :%s\n", rx_regfile);
    printf("sni_name          :%s\n", sni_name);
    printf("psk_key_idx       :%u\n", psk_key_idx);
    remove(keylog_file);

    if (!client_psk[psk_key_idx].present){
        printf("wrong psk index\n");
        return 1;
    }

    for (size_t i = 0; i < PSK_COUNT; ++i){
        if (client_psk[i].present)
            printf("[%3lu] %s\n", i, bin2str(client_psk[i].psk, PSK_BIN_KEY_SIZE));
    }

    //wolfSSL_Debugging_ON();
    wolfSSL_Init();
    psync_wolf_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    wolfSSL_CTX_SetMinVersion(psync_wolf_ctx, WOLFSSL_TLSV1_3);
    wolfSSL_CTX_set_verify(psync_wolf_ctx, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_CTX_set_psk_client_callback(psync_wolf_ctx, my_psk_client_cb);

    ////////////////////////////////////////////////////
    trace_init();
    trace("starting");
    int fd = connect_socket(server_ip, server_port);
    if (fd < 0) {
        trace("cannot create socket");
        return 1;
    }

    WOLFSSL* ssl = wolfSSL_new(psync_wolf_ctx);
    if (!ssl)
        trace("error");

    wolfSSL_set_fd(ssl, fd);

    //////////////////////////////////////////////////////  EARLY DATA TX
    if (req_valid(ed_req_index_0)) {
        tx_data = http_req_arr[ed_req_index_0];
        send_early_data(fd, ssl, tx_data, strlen(tx_data));
    }
    if (req_valid(ed_req_index_1)) {
        if (delay_ms)
            usleep(delay_ms * 1000);
        tx_data = http_req_arr[ed_req_index_1];
        send_early_data(fd, ssl, tx_data, strlen(tx_data));
    }

    //////////////////////////////////////////////////////  SSL CONNECT
    trace("SSL connect start");
    while ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS){
        trace("ret:%d", ret);
        int psync_ssl_errno = wolfSSL_get_error(ssl, ret);
        if (wait_sock_ready_for_ssl(fd, psync_ssl_errno)) {
            trace("ssl negotiation failed");
            return 1;
        }
    }
    trace("SSL connect done");

    int early_data_status = wolfSSL_get_early_data_status(ssl);
    trace("%s", early_data_status_str(early_data_status));

    if (early_data_status == WOLFSSL_EARLY_DATA_ACCEPTED) {
        size_t rx_len = receive_ssl_data(fd, ssl, buff, sizeof(buff));
        total_rx += rx_len;
        if (rx_edfile)
            save_rx_file(buff, rx_len, rx_edfile);
    }

    //////////////////////////////////////////////////////  REGULAR TX/RX
    if (req_valid(reg_req_index_0)) {
        tx_data = http_req_arr[reg_req_index_0];
        send_ssl_data(fd, ssl, tx_data, strlen(tx_data));
    }
    if (req_valid(reg_req_index_1)) {
        if (delay_ms)
            usleep(delay_ms * 1000);
        tx_data = http_req_arr[reg_req_index_1];
        send_ssl_data(fd, ssl, tx_data, strlen(tx_data));
    }

    size_t rx_len = 0;
    if (req_valid(reg_req_index_0) || req_valid(reg_req_index_1)) {
        rx_len = receive_ssl_data(fd, ssl, buff, sizeof(buff));
        total_rx += rx_len;
        if (rx_regfile)
            save_rx_file(buff, rx_len, rx_regfile);
    }

    //////////////////////////////////////////////////////  STATISTICS
    trace("client tx/rx finished");

    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    WOLFSSL_SESSION* session   = wolfSSL_get_session(ssl);

    printf("SSL cipher suite            :%s\n", wolfSSL_CIPHER_get_name(cipher));
    printf("SSL version                 :%d\n", wolfSSL_GetVersion(ssl));
    printf("session is resumable        :%d\n", wolfSSL_SESSION_is_resumable(session));
    printf("session max early data size :%u\n", wolfSSL_SESSION_get_max_early_data(session));

    struct tcp_info tcp;
    socklen_t tcplen;
    tcplen = sizeof(tcp);
    getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&tcp, &tcplen);

    printf("tcpi_total_retrans          :%u\n", tcp.tcpi_total_retrans);
    printf("tcpi_lost                   :%u\n", tcp.tcpi_lost);
    printf("tcpi_retrans                :%u\n", tcp.tcpi_retrans);

    printf("first byte TX               :%s\n", time_point_str(&first_tx_time));
    printf("first byte RX               :%s\n", time_point_str(&first_rx_time));
    printf("last  byte RX               :%s\n", time_point_str(&last_rx_time));
    printf("total RX                    :%d\n", total_rx);

    printf("early data status           :%s\n", early_data_status_str(early_data_status));
    if (rx_edfile)
    printf("saved ED file               :%s\n", rx_edfile);
    if (rx_regfile)
    printf("saved REG file              :%s\n", rx_regfile);

    close(fd);
    return 0;
}
///////////////////////////////////////////////////////////////////////////////
#define PSYNC_SOCK_READ_TIMEOUT    180
#define PSYNC_SOCK_WRITE_TIMEOUT   120

static int wait_sock_ready_for_ssl(int sock, int psync_ssl_errno){
  fd_set fds, *rfds, *wfds;
  struct timeval tv;
  int res;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);

  if (psync_ssl_errno==WOLFSSL_ERROR_WANT_READ){
    rfds=&fds;
    wfds=NULL;
    tv.tv_sec=PSYNC_SOCK_READ_TIMEOUT;
  }
  else if (psync_ssl_errno==WOLFSSL_ERROR_WANT_WRITE){
    rfds=NULL;
    wfds=&fds;
    tv.tv_sec=PSYNC_SOCK_WRITE_TIMEOUT;
  }
  else{
    trace("fail");
    return -1;
  }

  tv.tv_usec=0;

  res=select(sock+1, rfds, wfds, NULL, &tv);

  if (res==1)
    return 0;

  trace("fail");
  return -1;
}
///////////////////////////////////////////////////////////////////////////////

unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    static unsigned char cached_key[32];
    trace("entry hint:'%s' identity:'%s' id_max_len:%u key_max_len:%u", hint, identity, id_max_len, key_max_len);
    trace("identity: %02x %02x %02x %02x", identity[0], identity[1], identity[2], identity[3]);

    if (identity[0] != 0) {
        memcpy(key, cached_key, 32);
        trace("exit fast cached key ret=32");
        return 32;
    }

    byte client_pub[32];
    byte secret[32];
    byte secret_hash[32];

    WC_RNG rng;
    wc_InitRng(&rng);

    curve25519_key client_key;
    wc_curve25519_init(&client_key);

    // Generate ephemeral key
    if (wc_curve25519_make_key(&rng, 32, &client_key) != 0){
        trace("error");
        return 0;
    }

///    wc_curve25519_export_public(&client_key, client_pub, NULL);
    word32 pub_len = sizeof(client_pub);
    wc_curve25519_export_public_ex(&client_key, client_pub, &pub_len, EC25519_LITTLE_ENDIAN);
    if (pub_len != 32){
        trace("error");
        return 0;
    }

    if (wc_curve25519_check_public(client_pub, 32, EC25519_LITTLE_ENDIAN) != 0){
        trace("error");
        return 0;
    }


    //------------------------------------
    // Build identity
    //------------------------------------
    byte identity_bin[34] = {IDENTITY_VERSION, psk_key_idx};
    memcpy(identity_bin + 2, client_pub, 32);

    char identity_hex[IDENTITY_HEX_SIZE + 1];
    bin2hex(identity_bin, sizeof(identity_bin),
            identity_hex, sizeof(identity_hex));

    strncpy(identity, identity_hex, id_max_len);
    trace("identity_hex:'%s'", identity_hex);

    //------------------------------------
    // Derive shared secret
    //------------------------------------

    curve25519_key server_key;
    wc_curve25519_init(&server_key);

    if (wc_curve25519_import_public_ex(client_psk[psk_key_idx].psk, 32, &server_key, EC25519_LITTLE_ENDIAN) != 0){
        trace("error");
        return 0;
    }
    trace("psk is imported");

    word32 secret_len = sizeof(secret);

    if (wc_curve25519_shared_secret_ex(&client_key, &server_key, secret, &secret_len, EC25519_LITTLE_ENDIAN) != 0){
        trace("error: cannot compute shared secret");
        return 0;
    }

    //------------------------------------
    // Hash → final PSK
    //------------------------------------

    wc_Sha256Hash(secret, secret_len, secret_hash);
    trace("Shared secret hash '%s'", bin2str(secret_hash, PSK_BIN_KEY_SIZE));

    //------------------------------------
    // Return PSK
    //------------------------------------

    memcpy(key, secret_hash, 32);
    memcpy(cached_key, secret_hash, 32);

    wc_curve25519_free(&client_key);
    wc_curve25519_free(&server_key);
    wc_FreeRng(&rng);

    trace("exit ok 32");
    return 32;
}
