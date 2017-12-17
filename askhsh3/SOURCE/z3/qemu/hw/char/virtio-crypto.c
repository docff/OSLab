/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	unsigned int *syscall_type;
	int *cd;

	DEBUG("ENTERING HOST");
	DEBUG_IN();
	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	}

	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
	case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
		cd = elem.in_sg[0].iov_base;
		*cd = open("/dev/crypto", O_RDWR);
		if (*cd < 0) {
			DEBUG("FAILED TO OPEN");
			exit(1);
		}
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
		cd = elem.out_sg[1].iov_base;
		if (close(*cd) < 0) {
			DEBUG("FAILED TO CLOSE");
			exit(1);
		}
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
		u_int32_t *ses_id;
		u_int32_t ses_id_t;
		int *host_fd, *host_return_val;
		int host_fd_t, host_return_val_t;
		unsigned int *ioctl_cmd;
		unsigned char *session_key, *iv, *src, *dst;
		struct session_op *session_op;
		struct session_op session_op_t;
		struct crypt_op *crypt_op;
		struct crypt_op crypt_op_t;

		host_fd = elem.out_sg[1].iov_base;
		host_fd_t = *host_fd;

		ioctl_cmd = elem.out_sg[2].iov_base;

		host_return_val = elem.in_sg[0].iov_base;
		host_return_val_t = *host_return_val;

		switch (*ioctl_cmd) {
		case CIOCGSESSION:
			DEBUG("CIOCGSESSION");
			session_key = elem.out_sg[3].iov_base;
			session_op = elem.in_sg[1].iov_base;

			memset (&session_op_t, 0, sizeof(session_op_t));
			session_op_t.keylen = session_op->keylen;
			session_op_t.cipher = session_op->cipher;
			session_op_t.key = session_key;

			if (ioctl(host_fd_t, CIOCGSESSION, &session_op_t) < 0)
				host_return_val_t = 1;

			fprintf(stderr, "backend ses: %d\n", session_op_t.ses);
			session_op->ses = session_op_t.ses;

			break;
		case CIOCFSESSION:
			DEBUG("CIOCFSESSION");
			ses_id = elem.out_sg[3].iov_base;

			ses_id_t = *ses_id;
			if (ioctl(host_fd_t, CIOCFSESSION, &ses_id_t) < 0)
				host_return_val_t = 1;

			break;
		case CIOCCRYPT:
			DEBUG("CIOCCRYPT");
			crypt_op = elem.out_sg[3].iov_base;
			src = elem.out_sg[4].iov_base;
			iv = elem.out_sg[5].iov_base;
			dst = elem.in_sg[1].iov_base;

			memset (&crypt_op_t, 0, sizeof(crypt_op_t));
			crypt_op_t.ses = crypt_op->ses;
			crypt_op_t.len = crypt_op->len;
			crypt_op_t.src = src;
			crypt_op_t.iv = iv;
			crypt_op_t.dst = dst;
			crypt_op_t.op = crypt_op->op;

			if (ioctl(host_fd_t, CIOCCRYPT, &crypt_op_t) < 0)
				host_return_val_t = 1;

			break;
		}
		*host_return_val = host_return_val_t;
		break;

	default:
		DEBUG("Unknown syscall_type");
	}

	virtqueue_push(vq, &elem, 0);
	virtio_notify(vdev, vq);
	DEBUG("DONE ON HOST");
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
