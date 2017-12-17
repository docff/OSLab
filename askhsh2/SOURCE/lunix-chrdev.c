/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < Giorgos Xypolitos >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	int ret = 0;
	struct lunix_sensor_struct *sensor;

	WARN_ON (!(sensor = state->sensor));
	if (state->buf_timestamp != sensor->msr_data[state->type]->last_update)
		ret = 1;

	return ret;
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	int update = 0, decimal, fraction, cooked_data = 0;
	uint32_t raw_data, timestamp;
	unsigned long flags;
	struct lunix_sensor_struct *sensor;
	
	WARN_ON (!(sensor = state->sensor));
	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	debug("update: grabbing spinlock, wish me luck\n");
	spin_lock_irqsave(&sensor->lock, flags);
	if (lunix_chrdev_state_needs_refresh(state) == 1) {
		update = 1;
		raw_data = sensor->msr_data[state->type]->values[0];
		timestamp = sensor->msr_data[state->type]->last_update;
	}
	spin_unlock_irqrestore(&sensor->lock, flags);
	debug("update: done with spinlocking\n");
	/* Why use spinlocks? See LDD3, p. 119 */

	/*
	 * Any new data available?
	 */
	if (update == 1) {
		debug("update: new data available\n");
		state->buf_timestamp = timestamp;
		switch (state->type) {
			case BATT:
				cooked_data = lookup_voltage[raw_data];
				break;
			case TEMP:
				cooked_data = lookup_temperature[raw_data];
				break;
			case LIGHT:
				cooked_data = lookup_light[raw_data];
				break;
			case N_LUNIX_MSR:
				return -EFAULT;
				break;
		}

		decimal = cooked_data / 1000;
		fraction = cooked_data % 1000;

		debug("update: done cooking data\n");
		if (cooked_data < 0)
			snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ,
					"-%d.%d\n", decimal, fraction);
		else
			snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ,
					"%d.%d\n", decimal, fraction);
		debug("update: new data %s\n", state->buf_data);

		state->buf_lim = strnlen(state->buf_data, LUNIX_CHRDEV_BUFSZ);
		debug("update: done with new data\n");
	} else {
		debug("update: no new data\n");
		return -EAGAIN;
	}
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	int ret, type;
	dev_t minor;
	struct lunix_chrdev_state_struct *state;

	debug("open: entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	minor = iminor(inode);
	type = minor & 3;
	if (type >= N_LUNIX_MSR)
		goto out;

	/* Allocate a new Lunix character device private state structure */
	debug("open: starting allocation for state_struct\n");
	state = kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);
	if (!state) {
		printk(KERN_ERR "open: failed to allocate memory for linux_chrdev_state_struct\n");
		ret = -EFAULT;
		goto out;
	}

	state->type = type;
	state->sensor = &lunix_sensors[(minor >> 3)];
	state->buf_lim = 0;
	state->buf_timestamp = 0;
	sema_init(&state->lock, 1);

	debug("open: allocation for linux_chrdev_state_struct complete\n");
	filp->private_data = state;
out:
	debug("open: leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	debug("release: freed linux_chrdev_state_struct\n");
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret = 0, rem = 0;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	debug("read: starting to read\n");
	/* Lock */
	if (down_interruptible(&state->lock))
		return -ERESTARTSYS;

	debug("read: locked\n");
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so)
	 */
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			up(&state->lock);
			if (filp->f_flags & O_NONBLOCK)
				return -EAGAIN;
			/* The process needs to sleep */
			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
				return -ERESTARTSYS;
			/* Acquire lock to loop */
			if (down_interruptible(&state->lock))
				return -ERESTARTSYS;
			/* See LDD3, page 153 for a hint */
		}
		debug("read: read something\n");
	}
	rem = state->buf_lim - *f_pos;
	if (rem > 0) {
		debug("read: haven't reached EOF\n");
		/* Determine the number of cached bytes to copy to userspace */
		ret = min(cnt, (size_t)(state->buf_lim - *f_pos));
		if (copy_to_user(usrbuf, state->buf_data + *f_pos, ret)) {
			ret = -EFAULT;
			goto out;
		}
		*f_pos += ret;
		/* Auto-rewind on EOF mode */
		if (*f_pos >= state->buf_lim) {
			debug("read: reached EOF after writing to userspace\n");
			*f_pos = 0;
			goto out;
		}
		goto out_locked;
	} else {
		*f_pos = 0;
		ret = 0;
		debug("read: reached EOF\n");
	}
out:
	debug("read: unlocking\n");
	up(&state->lock);
out_locked:
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
  .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("init: initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);

	/* register_chrdev_region */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");
	if (ret < 0) {
		debug("init: failed to register region, ret = %d\n", ret);
		goto out;
	}

	/* cdev_add */	
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	if (ret < 0) {
		debug("init: failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("init: completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("destroy: entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("destroy: leaving\n");
}
