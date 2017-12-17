#!/bin/bash

make
rmmod virtio_crypto
insmod ./virtio_crypto.ko
