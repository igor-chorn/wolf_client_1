HEADERS = utl.h
CFLAGS=-g -Wall
#INCPATH=/home/igorc/lib_src/wolfssl
INCPATH=/home/igorc/proj/wolfssl-commercial
LIBPATH=$(INCPATH)/src/.libs/

all: psk_client

utl.o: utl.c $(HEADERS)
	gcc -c utl.c -o utl.o -I$(INCPATH) $(CFLAGS)

psk_client: psk_client.c utl.o $(HEADERS)
	gcc -o psk_client -I$(INCPATH) -L$(LIBPATH) psk_client.c utl.o -lwolfssl -lm $(CFLAGS)

clean:
	rm -f *.o psk_client
