#ifndef VIRTIO_CRYPTO_H
#define VIRTIO_CRYPTO_H

#define DEBUG(str) \
	printf("[VIRTIO-CRYPTO] FILE[%s] LINE[%d] FUNC[%s] STR[%s]\n", \
	       __FILE__, __LINE__, __func__, str);
#define DEBUG_IN() DEBUG("IN")

#define VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN  0
#define VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE 1
#define VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL 2

#define TYPE_VIRTIO_CRYPTO "virtio-crypto"

#define CRYPTODEV_FILENAME  "/dev/crypto"

typedef struct VirtCrypto {
    VirtIODevice parent_obj;
} VirtCrypto;

#endif /* VIRTIO_CRYPTO_H */
