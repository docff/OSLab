################################################################################
# 
# Makefile for virtio_crypto
#
# Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
# Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
#
################################################################################

# C compiler to use for building userspace applications
CC = gcc

# Extra CFLAGS used to compile the userspace helpers
# # e.g., -m32 if compiling in a 64-bit environment.
USER_CFLAGS = -Wall -Werror #-m32

# Remove comment to enable verbose output from the kernel build system
KERNEL_VERBOSE = 'V=1'
DEBUG = y

EXTRA_CFLAGS += -Wno-unused-variable
# Add your debugging flag (or not) to CFLAGS
# Warnings are errors.
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -g -DDEBUG=1 -Werror
else
  EXTRA_CFLAGS += -DDEBUG=0 -Werror
endif

obj-m := virtio_crypto.o
virtio_crypto-objs := crypto-module.o crypto-chrdev.o 

all: modules test_crypto test_fork_crypto my_test encrypted-client encrypted-server

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

modules:
	make -C $(KERNELDIR) M=$(PWD) modules

encrypted-client: encrypted-client.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)

unencrypted-server: unencrypted-server.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)

my_test: my_test.c
	$(CC) $(USER_CFLAGS) -o $@ $^

test_crypto: test_crypto.c
	$(CC) $(USER_CFLAGS) -o $@ $^

test_fork_crypto: test_fork_crypto.c
	$(CC) $(USER_CFLAGS) -o $@ $^

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f test_crypto
	rm -f test_fork_crypto
	rm -f my_test
	rm -f encrypted-client
	rm -f encrypted-server
