# HOW TO BUILD COMMERCIAL WOLFSSL
./configure --prefix=$HOME/tmp\
 --exec-prefix=$HOME/tmp\
 --enable-static\
 --disable-shared\
 --disable-oldtls\
 --enable-debug\
 --enable-debug-code-points\
 --enable-debug-trace-errcodes\
 --enable-tls13\
 --enable-sha512\
 --enable-sha3\
 --enable-curve25519\
 --enable-rsapss\
 --enable-aes-bitsliced\
 --enable-keygen\
 --enable-opensslextra\
 --enable-earlydata\
 --enable-psk\
 --enable-tlsx\
 --enable-aesni\
 --enable-intelasm\
 --enable-keylog-export
make
make test


# How to run:
./psk_client


# Sample output:

$ ./psk_client
server_ip         :74.120.8.220
server_port       :443
keylogfile        :(null)
http ED req_0     :'GET /crossdomain.xml HTTP/1.1..Connection: keep-alive....'
rx_edfile         :(null)
rx_regfile        :(null)
sni_name          :(null)
psk_key_idx       :0
[  0] 7e46efb5fd7981331ce0c0475e406925442816bf08dbdda17359d3914e8b5d32
[  1] 9728f5ad5018762d297c9809923b1700241ab26ce93060b10583f8183be46264
[  3] d21b30189a7a227a57788eb2e4644276a0d9515624c2b888e52ef980d9306011
[ 10] 92950e148d32a5406bdce9d7b811a77b3b4caa3b439004f92d76f5e534485829
[ 12] 716dde588070e41ddc1ab1d958adee0d10b2f432b86bb704728a74408e7c0f49
  0.0 ms [main:104] starting
  0.0 ms [connect_socket:275] entry
143.1 ms [connect_socket:312] poll start timeout_ms:2000
143.1 ms [connect_socket:315] poll done, ret:1 errno:'Success' (0)
143.1 ms [connect_socket:324] exit fd:3
143.2 ms [send_early_data:369] poll start timeout_ms:2000
143.2 ms [send_early_data:372] poll done, ret:1 errno:'Success' (0)
145.0 ms [my_psk_client_cb:247] entry hint:'' identity:'' id_max_len:1536 key_max_len:64
145.0 ms [my_psk_client_cb:248] identity: 00 00 00 00
145.1 ms [my_psk_client_cb:296] identity_hex:'0100b0c73538a29b2517e0f0e54117698b1d6b672b7554b452741e409f4eaa825418'
145.1 ms [my_psk_client_cb:309] psk is imported
145.1 ms [my_psk_client_cb:323] Shared secret hash '7db90e92ba7798fc76659e3985fe65d4fd9e121c6812dbbc1a6ce20fdde30863'
145.1 ms [my_psk_client_cb:335] exit ok 32
145.2 ms [my_psk_client_cb:247] entry hint:'' identity:'0100b0c73538a29b2517e0f0e54117698b1d6b672b7554b452741e409f4eaa825418' id_max_len:1536 key_max_len:64
145.2 ms [my_psk_client_cb:248] identity: 30 31 30 30
145.2 ms [my_psk_client_cb:251] exit fast ret=32
145.2 ms [my_psk_client_cb:247] entry hint:'' identity:'0100b0c73538a29b2517e0f0e54117698b1d6b672b7554b452741e409f4eaa825418' id_max_len:1536 key_max_len:64
145.2 ms [my_psk_client_cb:248] identity: 30 31 30 30
145.2 ms [my_psk_client_cb:251] exit fast ret=32
145.8 ms [send_early_data:381] Ed TX [57 - 57] 'GET /crossdomain.xml HTTP/1.1..Connection: keep-alive....'
145.8 ms [send_early_data:398] exit. ret:57
145.8 ms [main:130] SSL connect start
293.7 ms [my_psk_client_cb:247] entry hint:'' identity:'0100b0c73538a29b2517e0f0e54117698b1d6b672b7554b452741e409f4eaa825418' id_max_len:1536 key_max_len:64
293.9 ms [my_psk_client_cb:248] identity: 30 31 30 30
293.9 ms [my_psk_client_cb:251] exit fast ret=32
ERR TRACE: src/tls13.c L 1526 BAD_FUNC_ARG (-173)
ERR TRACE: src/tls13.c L 1526 BAD_FUNC_ARG (-173)
296.4 ms [main:139] SSL connect done
296.5 ms [main:142] WOLFSSL_EARLY_DATA_ACCEPTED
296.5 ms [receive_ssl_data:427] entry
296.6 ms [receive_ssl_data:442] Reg RX [366] 'HTTP/1.1 200 OK..Server: CacheHTTPd v1.0..Date: Thu, 26 Feb 2026 14:59:41 +0000..Content-Type: application/xml..Content-Length: 117..Access-Control-Allow-Methods: GET..Access-Control-Max-Age: 86400..Connection: keep-alive..Keep-Alive: timeout=30....<?xml version="1.0" encoding="UTF-8"?>.<cross-domain-policy>.  <allow-access-from domain="*"/>.</cross-domain-policy>'
ERR TRACE: src/internal.c L 23168 ZERO_RETURN (-343)
105531.0 ms [receive_ssl_data:442] Reg RX [0] ''
105531.0 ms [receive_ssl_data:453] err:6
105531.0 ms [receive_ssl_data:458] break
105531.0 ms [receive_ssl_data:462] exit. ret:366
105531.0 ms [main:172] client tx/rx finished
ERR TRACE: ./src/ssl_sess.c L 1777 BAD_FUNC_ARG (-173)
SSL cipher suite            :TLS_AES_128_GCM_SHA256
SSL version                 :4
session is resumable        :0
ERR TRACE: ./src/ssl_sess.c L 3511 BAD_FUNC_ARG (-173)
session max early data size :4294967123
tcpi_total_retrans          :0
tcpi_lost                   :0
tcpi_retrans                :0
first byte TX               :145.8 ms
first byte RX               :296.6 ms
last  byte RX               :296.6 ms
total RX                    :366
early data status           :WOLFSSL_EARLY_DATA_ACCEPTED


