###################################################
#
# Makefile
# Simple TCP/IP communication using sockets
#
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

CC = gcc

CFLAGS = -Wall
CFLAGS += -g
# CFLAGS += -O2 -fomit-frame-pointer -finline-functions

LIBS = 

BINS = unencrypted-client unencrypted-server

all: $(BINS)

socket-client: socket-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

socket-server: socket-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	
unencrypted-client: unencrypted-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

unencrypted-server: unencrypted-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o *~ $(BINS)
