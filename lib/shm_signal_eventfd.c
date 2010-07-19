/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * See include/linux/shm_signal.h for documentation
 *
 * Author:
 *      Gregory Haskins <ghaskins@novell.com>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/shm_signal.h>
#include <linux/workqueue.h>
#include <linux/eventfd.h>
#include <linux/slab.h>

/*
 * ---------------------------------------------
 * eventfd interface
 *
 * Allows a shm_signal to be triggered using a pair of eventfds
 * ---------------------------------------------
 */

struct _eventfd_signal {
	struct eventfd_ctx            *eventfd;
	struct shm_signal             *signal;
	poll_table                     pt;
	wait_queue_head_t             *wqh;
	wait_queue_t                   wait;
	struct work_struct             shutdown;
};

static void
eventfd_signal_shutdown(struct work_struct *work)
{
	struct _eventfd_signal *_signal;

	_signal = container_of(work, struct _eventfd_signal, shutdown);

	shm_signal_put(_signal->signal);
	eventfd_ctx_put(_signal->eventfd);
	kfree(_signal);
}

/*
 * Called with wqh->lock held and interrupts disabled
 */
static int
eventfd_signal_wakeup(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct _eventfd_signal *_signal;
	unsigned long flags = (unsigned long)key;

	_signal = container_of(wait, struct _eventfd_signal, wait);

	if (flags & POLLIN)
		/* An event has been signaled */
		_shm_signal_wakeup(_signal->signal);

	if (flags & POLLHUP) {
		/* The eventfd is closing, detach.. */
		__remove_wait_queue(_signal->wqh, &_signal->wait);
		schedule_work(&_signal->shutdown);
	}

	return 0;
}

static void
eventfd_signal_ptable(struct file *file, wait_queue_head_t *wqh, poll_table *pt)
{
	struct _eventfd_signal *_signal;

	_signal = container_of(pt, struct _eventfd_signal, pt);

	_signal->wqh = wqh;
	add_wait_queue(wqh, &_signal->wait);
}

int shm_signal_eventfd_bindfile(struct shm_signal *signal, struct file *file)
{
	struct _eventfd_signal *_signal;
	struct eventfd_ctx *eventfd = NULL;
	int ret = -EINVAL;

	_signal = kzalloc(sizeof(*_signal), GFP_KERNEL);
	if (!_signal)
		return -ENOMEM;

	eventfd = eventfd_ctx_fileget(file);
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto fail;
	}

	_signal->eventfd = eventfd;
	_signal->signal  = signal;
	INIT_WORK(&_signal->shutdown, eventfd_signal_shutdown);

	init_waitqueue_func_entry(&_signal->wait, eventfd_signal_wakeup);
	init_poll_funcptr(&_signal->pt, eventfd_signal_ptable);

	file->f_op->poll(file, &_signal->pt);

	return 0;

fail:
	if (eventfd && !IS_ERR(eventfd))
		eventfd_ctx_put(eventfd);

	kfree(_signal);

	return ret;
}
EXPORT_SYMBOL_GPL(shm_signal_eventfd_bindfile);

int shm_signal_eventfd_bindfd(struct shm_signal *signal, int fd)
{
	struct file *file = NULL;
	int ret = -EINVAL;

	file = eventfd_fget(fd);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto out;
	}

	ret = shm_signal_eventfd_bindfile(signal, file);

out:
	if (file && !IS_ERR(file))
		fput(file);

	return ret;
}
EXPORT_SYMBOL_GPL(shm_signal_eventfd_bindfd);
