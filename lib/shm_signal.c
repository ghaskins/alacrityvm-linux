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

int shm_signal_enable(struct shm_signal *s, int flags)
{
	struct shm_signal_irq *irq = &s->desc->irq[s->locale];
	unsigned long iflags;

	spin_lock_irqsave(&s->lock, iflags);

	irq->enabled = 1;
	wmb();

	if ((irq->dirty || irq->pending)
	    && !test_bit(shm_signal_in_wakeup, &s->flags)) {
		rmb();
		tasklet_schedule(&s->deferred_notify);
	}

	spin_unlock_irqrestore(&s->lock, iflags);

	return 0;
}
EXPORT_SYMBOL_GPL(shm_signal_enable);

int shm_signal_disable(struct shm_signal *s, int flags)
{
	struct shm_signal_irq *irq = &s->desc->irq[s->locale];

	irq->enabled = 0;
	wmb();

	return 0;
}
EXPORT_SYMBOL_GPL(shm_signal_disable);

/*
 * signaling protocol:
 *
 * each side of the shm_signal has an "irq" structure with the following
 * fields:
 *
 *    - enabled: controlled by shm_signal_enable/disable() to mask/unmask
 *               the notification locally
 *    - dirty:   indicates if the shared-memory is dirty or clean.  This
 *               is updated regardless of the enabled/pending state so that
 *               the state is always accurately tracked.
 *    - pending: indicates if a signal is pending to the remote locale.
 *               This allows us to determine if a remote-notification is
 *               already in flight to optimize spurious notifications away.
 */
int shm_signal_inject(struct shm_signal *s, int flags)
{
	/* Load the irq structure from the other locale */
	struct shm_signal_irq *irq = &s->desc->irq[!s->locale];

	/*
	 * We always mark the remote side as dirty regardless of whether
	 * they need to be notified.
	 */
	irq->dirty = 1;
	wmb();   /* dirty must be visible before we test the pending state */

	if (irq->enabled && !irq->pending) {
		rmb();

		/*
		 * If the remote side has enabled notifications, and we do
		 * not see a notification pending, we must inject a new one.
		 */
		irq->pending = 1;
		wmb(); /* make it visible before we do the injection */

		s->ops->inject(s);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(shm_signal_inject);

void _shm_signal_wakeup(struct shm_signal *s)
{
	struct shm_signal_irq *irq = &s->desc->irq[s->locale];
	int dirty;
	unsigned long flags;

	spin_lock_irqsave(&s->lock, flags);

	__set_bit(shm_signal_in_wakeup, &s->flags);

	/*
	 * The outer loop protects against race conditions between
	 * irq->dirty and irq->pending updates
	 */
	while (irq->enabled && (irq->dirty || irq->pending)) {

		/*
		 * Run until we completely exhaust irq->dirty (it may
		 * be re-dirtied by the remote side while we are in the
		 * callback).  We let "pending" remain untouched until we have
		 * processed them all so that the remote side knows we do not
		 * need a new notification (yet).
		 */
		do {
			irq->dirty = 0;
			/* the unlock is an implicit wmb() for dirty = 0 */
			spin_unlock_irqrestore(&s->lock, flags);

			if (s->notifier)
				s->notifier->signal(s->notifier);

			spin_lock_irqsave(&s->lock, flags);
			dirty = irq->dirty;
			rmb();

		} while (irq->enabled && dirty);

		barrier();

		/*
		 * We can finally acknowledge the notification by clearing
		 * "pending" after all of the dirty memory has been processed
		 * Races against this clearing are handled by the outer loop.
		 * Subsequent iterations of this loop will execute with
		 * pending=0 potentially leading to future spurious
		 * notifications, but this is an acceptable tradeoff as this
		 * will be rare and harmless.
		 */
		irq->pending = 0;
		wmb();

	}

	__clear_bit(shm_signal_in_wakeup, &s->flags);
	spin_unlock_irqrestore(&s->lock, flags);

}
EXPORT_SYMBOL_GPL(_shm_signal_wakeup);

void _shm_signal_release(struct kref *kref)
{
	struct shm_signal *s = container_of(kref, struct shm_signal, kref);

	s->ops->release(s);
}
EXPORT_SYMBOL_GPL(_shm_signal_release);

static void
deferred_notify(unsigned long data)
{
	struct shm_signal *s = (struct shm_signal *)data;

	_shm_signal_wakeup(s);
}

void shm_signal_init(struct shm_signal *s, enum shm_signal_locality locale,
		     struct shm_signal_ops *ops, struct shm_signal_desc *desc)
{
	memset(s, 0, sizeof(*s));
	kref_init(&s->kref);
	spin_lock_init(&s->lock);
	tasklet_init(&s->deferred_notify,
		     deferred_notify,
		     (unsigned long)s);
	s->locale   = locale;
	s->ops      = ops;
	s->desc     = desc;
}
EXPORT_SYMBOL_GPL(shm_signal_init);

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
