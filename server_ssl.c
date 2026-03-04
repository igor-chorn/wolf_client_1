#include <errno.h>
#include <poll.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "utl.h"


#define SSL_HTTP_NPN_ADVERTISE  "\x08http/1.1"

#define SSL_CIPHERS \
  "ECDHE-RSA-AES128-GCM-SHA256:"\
  "ECDHE-RSA-AES256-GCM-SHA384:"\
  "ECDHE-RSA-CHACHA20-POLY1305:"\
  "DHE-RSA-AES128-GCM-SHA256:"\
  "DHE-RSA-AES256-GCM-SHA384:"\
  "DHE-RSA-CHACHA20-POLY1305:"\
  "ECDHE-RSA-AES128-SHA256:"\
  "ECDHE-RSA-AES256-SHA384:"\
  "DHE-RSA-AES128-SHA256:"\
  "DHE-RSA-AES256-SHA256"
// last 4 (from ECDHE-RSA-AES128-SHA256) are considered weak

#define TLS13_CIPHERS \
  "TLS_AES_128_GCM_SHA256:"\
  "TLS_AES_256_GCM_SHA384:"\
  "TLS_CHACHA20_POLY1305_SHA256:"\
  "TLS_AES_128_CCM_8_SHA256:"\
  "TLS_AES_128_CCM_SHA256"

#define MAX_EARLY_DATA_SIZE     (64*1024)
#define PSK_BIN_KEY_SIZE        32

// identity binary format (sent from client):
//  [0]       : version
//  [1]       : psk key index (0..255)
//  [2]..[33] : 32 bytes binary client public key
#define IDENTITY_VERSION        1
#define IDENTITY_BIN_SIZE       (32 + 2)
#define IDENTITY_HEX_SIZE       (2*(32 + 2))

extern SSL_CTX* server_ctx;
extern EVP_PKEY* get_server_psk(unsigned char idx);

static const unsigned char TLS_AES_128_GCM_SHA256[] = {0x13, 0x01};


static int ssl_npn_advertise(SSL */*ssl*/, const unsigned char **out, unsigned int *outlen, void */*arg*/){
  *out=(const unsigned char *)SSL_HTTP_NPN_ADVERTISE;
  *outlen=sizeof(SSL_HTTP_NPN_ADVERTISE)-1;
  return SSL_TLSEXT_ERR_OK;
}

const char *parse_server_name(const unsigned char *data_ptr, size_t data_len){
  // parsing is taken from openssl/test/helpers/handshake.c: client_hello_select_server_ctx()

  // 1 bytes - total data length
  size_t len = *(data_ptr++);
  len <<= 8;
  len += *(data_ptr++);
  trace("len:%lu", len);
  if (len + 2 != data_len)
    return NULL;
  data_len = len;

  // 1 byte - data type
  if (data_len == 0 || *data_ptr++ != TLSEXT_NAMETYPE_host_name)
    return NULL;
  data_len--;
  if (data_len <= 2)
    return NULL;

  // 2 bytes - server name length
  len = *(data_ptr++);
  len <<= 8;
  len += *(data_ptr++);
  if (len + 2 > data_len)
    return NULL;

  // N bytes - server name
  return (const char *)data_ptr;
}

static int client_hello_cb(SSL *ssl, int */*al*/, void */*arg*/){
  const char *servername = NULL;
  const unsigned char *data_ptr = NULL;
  size_t data_len = 0;

  int res=SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &data_ptr, &data_len);
  trace("res:%d data[%lu]:'%s'", res, data_len, bin2str(data_ptr, data_len));
  if (res==1 || data_len > 2)
    servername = parse_server_name(data_ptr, data_len);
  trace("servername:'%s'", servername);

  SSL_CTX *ctx = server_ctx; //servername ? site_get_ssl_ctx_by_servername(servername) : default_site_get_ssl_ctx();
  if (!ctx)
    return SSL_CLIENT_HELLO_ERROR;

  SSL_set_SSL_CTX(ssl, ctx);
  trace("exit ok servername:'%s'", servername);
  return SSL_CLIENT_HELLO_SUCCESS;
}

static int find_session_cb(SSL *ssl, const unsigned char *identity, size_t identity_len, SSL_SESSION **sess) {
  trace("entry identity[%lu]:%02x %02x %02x %02x", identity_len, identity[0], identity[1], identity[2], identity[3]);
  *sess = NULL;

  unsigned char identity_bin[IDENTITY_BIN_SIZE];
  if (!hex2bin((const char*)identity, identity_len, identity_bin, IDENTITY_BIN_SIZE)) {
    trace("error");
    return 1;
  }

  if (identity_bin[0] != IDENTITY_VERSION || identity_len != IDENTITY_HEX_SIZE) {
    trace("error");
    return 1;
  }

  EVP_PKEY* pkey=get_server_psk(identity_bin[1]);
  if (!pkey){
    trace("error. no key for idx:%x", identity_bin[1]);
    return 1;
  }

  // Compute shared secret: X25519(server_priv, client_pub)
  EVP_PKEY *client_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, identity_bin + 2, PSK_BIN_KEY_SIZE);
  if (client_pkey == NULL) {
    trace("error");
    return 1;
  }
  unsigned char secret[PSK_BIN_KEY_SIZE];
  size_t secret_len = PSK_BIN_KEY_SIZE;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx ||
    EVP_PKEY_derive_init(ctx) <= 0 ||
    EVP_PKEY_derive_set_peer(ctx, client_pkey) <= 0 ||
    EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(client_pkey);
    trace("error");
    return 1;
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(client_pkey);
  if (secret_len != PSK_BIN_KEY_SIZE) {
    trace("error");
    return 1;
  }
  unsigned char secret_hash[PSK_BIN_KEY_SIZE];
  SHA256(secret, PSK_BIN_KEY_SIZE, secret_hash);
  trace("secret_hash '%s'", bin2str(secret_hash, PSK_BIN_KEY_SIZE));

  // Create a new SSL_SESSION with the derived secret as PSK
  SSL_SESSION *session = SSL_SESSION_new();
  if (session == NULL) {
    trace("error");
    return 0;
  }
  if (SSL_SESSION_set1_master_key(session, secret_hash, secret_len) != 1 ||
    SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION) != 1) {
    SSL_SESSION_free(session);
    trace("error");
    return 0;
  }
  // Set a TLS1.3 ciphersuite for the session
  const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, TLS_AES_128_GCM_SHA256);
  if (cipher == NULL || SSL_SESSION_set_cipher(session, cipher) != 1) {
    SSL_SESSION_free(session);
    trace("error");
    return 0;
  }
  // Allow early data for this session
  if (SSL_SESSION_set_max_early_data(session, MAX_EARLY_DATA_SIZE)==0) {
    trace("error");
    return 0;
  }

  SSL_SESSION_up_ref(session);
  *sess = session;
  trace("Exit. key_index:%u", identity_bin[1]);
  return 1;  // continue with PSK
}

SSL_CTX *sssl_ctx_create(const char *crt, const char *key /*, EVP_PKEY *evp_pkey*/) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if(ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

  SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);

  SSL_CTX_set_options(ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
  SSL_CTX_set_options(ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);
#endif

  SSL_CTX_set_options(ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_TLS_D5_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);

  SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

  SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif

  SSL_CTX_set_next_protos_advertised_cb(ctx, ssl_npn_advertise, NULL);

  if ( SSL_CTX_use_certificate_chain_file(ctx, crt) <= 0) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if ( !SSL_CTX_check_private_key(ctx) ) {
    fprintf(stderr, "Private key is invalid.\n");
    return NULL;
  }

  if (SSL_CTX_set_cipher_list(ctx, SSL_CIPHERS)==0){
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if (SSL_CTX_set_ciphersuites(ctx, TLS13_CIPHERS)==0){
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if (SSL_CTX_set_max_early_data(ctx, MAX_EARLY_DATA_SIZE)==0)
    return NULL;
  SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY); // allow reuse saved session many times

  SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);
  SSL_CTX_set_psk_find_session_callback(ctx, find_session_cb);

  return ctx;
}
//////////////////////////////////////////////////////////////////////////////////////
extern int is_accepted;

#define READ_TIMEOUT_SEC    60
#define WRITE_TIMEOUT_SEC   60
#define DUMMY_BUF_SIZE      256

static int sslret(SSL *ssl, int ret){
  errno=0;
  int err=SSL_get_error(ssl, ret);
  if (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE)
    errno=EAGAIN;
  return -1;
}

static int sssl_poll(SSL *ssl, int ret, int sock){
  struct pollfd pfd;
  int err, tm;
  err=SSL_get_error(ssl, ret);
  trace("err:%d errno:%d", err, errno);

  if (err==SSL_ERROR_WANT_READ){
    pfd.events=POLLIN;
    tm=READ_TIMEOUT_SEC*1000;
  }
  else if (err==SSL_ERROR_WANT_WRITE){
    pfd.events=POLLOUT;
    tm=WRITE_TIMEOUT_SEC*1000;
  }
  else if (err==SSL_ERROR_SYSCALL && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)){
    pfd.events=POLLIN;
    tm=READ_TIMEOUT_SEC*1000;
  }
  else
    return -1;
  pfd.fd=sock;
  if (poll(&pfd, 1, tm)==1){
    if (pfd.revents&pfd.events)
      return 0;
    else
      return -1;
  }
  else
    return -1;
}

int poll_write(int sock){
  struct pollfd pfd;
  pfd.fd=sock;
  pfd.events=POLLOUT;
  if (poll(&pfd, 1, READ_TIMEOUT_SEC*1000)==1){
    if (pfd.revents&(POLLHUP|POLLERR))
      return -1;
    else
      return 0;
  }
  else
    return -1;
}

int sssl_read(int fd, SSL *ssl, void *data, int num){
  int ret;
  trace("entry. num:%d", num);

  if (!is_accepted){
    size_t early_len=0;

    ret=SSL_read_early_data(ssl, data, num, &early_len);
    trace("ERX ret:%d [%lu] '%s'", ret, early_len, nformat(data, early_len));

    if (ret==SSL_READ_EARLY_DATA_ERROR){
      ret = sslret(ssl, ret);
      trace("exit. early data read failed, return %d", ret);
      return ret;
    }

    if (ret==SSL_READ_EARLY_DATA_SUCCESS)
      return early_len;

    // here ret == SSL_READ_EARLY_DATA_FINISH

    while ((ret=SSL_accept(ssl))!=1){
      if (sssl_poll(ssl, ret, fd)){
        return -1;
      }
    }
    is_accepted=1;
    trace("SSL_accept ok");

    if (early_len != 0){
      trace("exit. early data done, return %d", (int)early_len);
      return early_len;
    }
  }

  ret=SSL_read(ssl, data, num);
  trace("RX ret:%d data:'%s'", ret, nformat(data, ret));
  if (ret<=0)
    ret = sslret(ssl, ret);
  trace("exit. return %d", ret);
  return ret;
}

int sssl_write(SSL *ssl, const void *data, int num){
  int ret;
  trace("entry. num:%d", num);

  if (!is_accepted){
    size_t tx_actual=0;
    ret=SSL_write_early_data(ssl, data, num, &tx_actual);
    trace("ETX num:%d ret:%d [%lu] '%s'", num, ret, tx_actual, nformat(data, tx_actual));

    if (ret==0)
      ret=sslret(ssl, ret);
    else
      ret=tx_actual;
    trace("exit. early data return %d", ret);
    return ret;
  }

  ret=SSL_write(ssl, data, num);
  trace("TX num:%d ret:%d data:'%s'", num, ret, nformat(data, ret));
  if (ret<=0)
    ret = sslret(ssl, ret);
  trace("exit. return %d", ret);
  return ret;
}
///////////////////////////////////////////////////////////////////////////
int http_read_request(int fd, SSL *ssl, void *data, int num) {
    trace("entry");
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ret;
    char buf[1024];

    while (1) {
        if (!SSL_pending(ssl)){
            ret=poll(&pfd, 1, 1000);
            trace("ret:%d errno:%d", ret, errno);
            if (ret==-1){
                if (errno==EINTR)
                    continue;
                else
                    goto err0;
            }
            else if (ret==0)
                goto err0;
        }

        ret = sssl_read(fd, ssl, buf, sizeof(buf));
        if (ret > 0){
            trace("exit");
            return ret;
        }
        if (ret==-1) {
            if (errno==EAGAIN)
                continue;
            else
                goto err0;
        }
        else if (ret==0)
            goto err0;
    }

err0:
    trace("exit fail");
    return -1;
}

int http_send_all(int fd, SSL *ssl, const void *data, int len){
  int res;

  while (len){
    res = sssl_write(ssl, data, len);
    if (res == -1) {
        if ((errno==EINTR || errno==EAGAIN) && !poll_write(fd))
            continue;
        return -1;
    }
    len-=res;
    data+=res;
  }
  return 0;
}

int sssl_destroy(int fd, SSL *ssl) {
  int ret;

  trace("entry");
  //sssl_read_leftover(conn);

  while ((ret=SSL_shutdown(ssl)) != 1)
    if (sssl_poll(ssl, ret, fd))
      break;
  SSL_free(ssl);
  trace("exit ret:%d", ret);
  return ret;
}
