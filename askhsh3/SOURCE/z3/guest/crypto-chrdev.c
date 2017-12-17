/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0, err, *host_fd,
			num_in, num_out;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct virtqueue *vq;
	unsigned int *syscall_type;
	unsigned long flags;
	struct scatterlist syscall_type_sg, host_fd_sg,
										 *sgs[2];

	debug("Entering open");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}
	vq = crdev->vq;

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	num_in = num_out = 0;
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	/**
	 * Wait for the host to process our data.
	 **/
	spin_lock_irqsave(&crdrvdata.lock, flags);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	/* If host failed to open() return -ENODEV. */
	if (*host_fd < 0) {
		ret = -ENODEV;
		goto fail;
	}
	ret = 0;
	crof->host_fd = *host_fd;
fail:
	debug("Leaving open");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0, num_in, num_out,
			err, *host_fd;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	unsigned int *syscall_type, len;
	unsigned long flags;
	struct scatterlist syscall_type_sg, host_fd_sg,
										 *sgs[2];

	debug("Entering close");
	/**
	 * Send data to the host.
	 **/
	num_in = num_out = 0;
	syscall_type = kmalloc(sizeof(unsigned int), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	host_fd = kmalloc(sizeof(int), GFP_KERNEL);
	*host_fd = crof->host_fd;
	sg_init_one(&host_fd_sg, host_fd, sizeof(host_fd));
	sgs[num_out++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	spin_lock_irqsave(&crdrvdata.lock, flags);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	kfree(crof);
	kfree(syscall_type);
	kfree(host_fd);
	debug("Leaving close");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	int err, *host_fd, *host_return_val;
	u_int32_t *ses_id;
	long ret = 0;
	unsigned long flags;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct session_op *session_op;
	struct crypt_op *crypt_op;
	struct scatterlist syscall_type_sg, host_fd_sg, icotl_cmd_sg,
										 ses_id_sg, session_op_sg, host_return_val_sg,
										 session_key_sg, ioctl_cmd_sg, crypt_op_sg,
										 iv_sg, src_sg, dst_sg,
	                   *sgs[8];
	unsigned int num_out, num_in, len,
					 *ioctl_cmd;
	unsigned int *syscall_type;
	unsigned char *session_key, *iv, *dst, *src;

	debug("Entering ioctl");
	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;
	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;
	ioctl_cmd = kmalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;

	/**
	 *  These are common to all ioctl commands.
	 **/
	num_out = num_in = 0;
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	ses_id = kmalloc(sizeof(*ses_id), GFP_KERNEL);
	session_op = kzalloc(sizeof(*session_op), GFP_KERNEL);
	crypt_op = kzalloc(sizeof(*crypt_op), GFP_KERNEL);
	session_key = kmalloc(sizeof(unsigned char), GFP_KERNEL);

	iv = kzalloc(sizeof(unsigned char), GFP_KERNEL);
	src = kzalloc(sizeof(unsigned char), GFP_KERNEL);
	dst = kzalloc(sizeof(unsigned char), GFP_KERNEL);
	host_return_val = kzalloc(sizeof(*host_return_val), GFP_KERNEL);

	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		if ((err = copy_from_user (session_op, (void __user *) arg, sizeof(*session_op))) > 0)
			return -EFAULT;

		kfree(session_key);
		session_key = kmalloc(session_op->keylen, GFP_KERNEL);
		if ((err = copy_from_user (session_key,  session_op->key, sizeof(session_op->keylen))) > 0)
			return -EFAULT;

		sg_init_one(&session_key_sg, session_key, session_op->keylen);
		sgs[num_out++] = &session_key_sg;

		sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
		sgs[num_out + num_in++] = &host_return_val_sg;
		sg_init_one(&session_op_sg, session_op, sizeof(*session_op));
		sgs[num_out + num_in++] = &session_op_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		if ((err = copy_from_user (ses_id, (void __user *) arg, sizeof(*ses_id))) > 0)
			return -EFAULT;

		sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
		sgs[num_out++] = &ses_id_sg;
		sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
		sgs[num_out + num_in++] = &host_return_val_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		if ((err = copy_from_user (crypt_op, (void __user *) arg, sizeof(*crypt_op))) > 0)
			return -EFAULT;
		
		kfree(iv); kfree(src); kfree(dst);
		iv = kmalloc(VIRTIO_CRYPTO_BLOCK_SIZE, GFP_KERNEL);
		if ((err = copy_from_user (iv,  crypt_op->iv, VIRTIO_CRYPTO_BLOCK_SIZE)) > 0)
			return -EFAULT;
		src = kmalloc(crypt_op->len, GFP_KERNEL);
		if ((err = copy_from_user (src, crypt_op->src, crypt_op->len)) > 0)
			return -EFAULT;
		dst = kmalloc(crypt_op->len, GFP_KERNEL);
		if ((err = copy_from_user (dst, crypt_op->dst, crypt_op->len)) > 0)
			return -EFAULT;

		sg_init_one(&crypt_op_sg, crypt_op, sizeof(*crypt_op));
		sgs[num_out++] = &crypt_op_sg;
		sg_init_one(&src_sg, src, crypt_op->len);
		sgs[num_out++] = &src_sg;
		sg_init_one(&iv_sg, iv, VIRTIO_CRYPTO_BLOCK_SIZE);
		sgs[num_out++] = &iv_sg;

		sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
		sgs[num_out + num_in++] = &host_return_val_sg;
		sg_init_one(&dst_sg, dst, crypt_op->len);
		sgs[num_out + num_in++] = &dst_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	/**
	 * Wait for the host to process our data.
	 **/
	if ((err = down_interruptible(&crdev->sem)) < 0)
		return -ERESTARTSYS;
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->sem);

	if (!(*host_return_val)) {
		switch (cmd) {
			case CIOCGSESSION:
				if ((err = copy_to_user ((void __user *) arg, session_op, sizeof(*session_op))) > 0)
					return -EFAULT;
				break;
			case CIOCFSESSION:
				if ((err = copy_to_user ((void __user *) arg, ses_id, sizeof(*ses_id))) > 0)
					return -EFAULT;
				break;
			case CIOCCRYPT:
				if ((err = copy_to_user (crypt_op->dst, dst, crypt_op->len)) > 0)
					return -EFAULT;
				if ((err = copy_to_user ((void __user *) arg, crypt_op, sizeof(*crypt_op))) > 0)
					return -EFAULT;
				break;
			default:
				debug("Unsupported ioctl command");
				break;
		}
	} else
		debug ("We fucked something up!");

	kfree(host_fd); kfree(ioctl_cmd);
	kfree(syscall_type); kfree(ses_id);
	kfree(session_op); kfree(session_key);
	kfree(host_return_val); kfree(iv);
	kfree(src); kfree(dst);
	kfree(crypt_op);

	debug("Leaving ioctl");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
