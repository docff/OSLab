###################################################
#
# Makefile
# Simple TCP/IP communication using sockets
#
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

CC = gcc

CRYPTODEVDIR=$(HOME)/Desktop/cs/cryptodev-linux-1.9

CFLAGS = -Wall -I$(CRYPTODEVDIR)
CFLAGS += -g
# CFLAGS += -O2 -fomit-frame-pointer -finline-functions

LIBS = 

BINS = encrypted-client encrypted-server

all: $(BINS)

socket-client: socket-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

socket-server: socket-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	
encrypted-client: encrypted-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

unencrypted-server: unencrypted-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o *~ $(BINS)
