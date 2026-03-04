HEADERS = utl.h
CFLAGS=-g -Wall
#INCPATH=/home/igorc/lib_src/wolfssl
INCPATH=/home/igorc/proj/wolfssl-commercial
LIBPATH=$(INCPATH)/src/.libs/

all: psk_client server

utl.o: utl.c $(HEADERS)
	gcc -c utl.c -o utl.o -I$(INCPATH) $(CFLAGS)

utl_client.o: utl_client.c $(HEADERS)
	gcc -c utl_client.c -o utl_client.o -I$(INCPATH) $(CFLAGS)

psk_client: psk_client.c utl.o utl_client.o $(HEADERS)
	gcc -o psk_client -I$(INCPATH) -L$(LIBPATH) psk_client.c utl.o utl_client.o -lwolfssl -lm $(CFLAGS)

server_ssl.o: server_ssl.c
	gcc -c server_ssl.c -o server_ssl.o -I$(INCPATH) $(CFLAGS)

server: server.c server_ssl.o utl.o $(HEADERS)
	gcc -o server server.c server_ssl.o utl.o -lssl -lcrypto $(CFLAGS)

clean:
	rm -f *.o psk_client server
