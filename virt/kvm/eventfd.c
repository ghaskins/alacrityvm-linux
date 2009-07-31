/*
 * kvm eventfd support - use eventfd objects to signal various KVM events
 *
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Author:
 *	Gregory Haskins <ghaskins@novell.com>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/kvm_host.h>
#include <linux/workqueue.h>
#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/eventfd.h>

/*
 * --------------------------------------------------------------------
 * irqfd: Allows an fd to be used to inject an interrupt to the guest
 *
 * Credit goes to Avi Kivity for the original idea.
 * --------------------------------------------------------------------
 */
struct _irqfd {
	struct kvm               *kvm;
	int                       gsi;
	struct list_head          list;
	poll_table                pt;
	wait_queue_head_t        *wqh;
	wait_queue_t              wait;
	struct work_struct        inject;
};

static void
irqfd_inject(struct work_struct *work)
{
	struct _irqfd *irqfd = container_of(work, struct _irqfd, inject);
	struct kvm *kvm = irqfd->kvm;

	mutex_lock(&kvm->irq_lock);
	kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 1);
	kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 0);
	mutex_unlock(&kvm->irq_lock);
}

static int
irqfd_wakeup(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct _irqfd *irqfd = container_of(wait, struct _irqfd, wait);
	unsigned long flags = (unsigned long)key;

	/*
	 * Assume we will be called with interrupts disabled
	 */
	if (flags & POLLIN)
		/*
		 * Defer the IRQ injection until later since we need to
		 * acquire the kvm->lock to do so.
		 */
		schedule_work(&irqfd->inject);

	if (flags & POLLHUP) {
		/*
		 * for now, just remove ourselves from the list and let
		 * the rest dangle.  We will fix this up later once
		 * the races in eventfd are fixed
		 */
		__remove_wait_queue(irqfd->wqh, &irqfd->wait);
		irqfd->wqh = NULL;
	}

	return 0;
}

static void
irqfd_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh,
			poll_table *pt)
{
	struct _irqfd *irqfd = container_of(pt, struct _irqfd, pt);

	irqfd->wqh = wqh;
	add_wait_queue(wqh, &irqfd->wait);
}

int
kvm_irqfd(struct kvm *kvm, int fd, int gsi, int flags)
{
	struct _irqfd *irqfd;
	struct file *file = NULL;
	int ret;
	unsigned int events;

	irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		return -ENOMEM;

	irqfd->kvm = kvm;
	irqfd->gsi = gsi;
	INIT_LIST_HEAD(&irqfd->list);
	INIT_WORK(&irqfd->inject, irqfd_inject);

	file = eventfd_fget(fd);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto fail;
	}

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd
	 */
	init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);
	init_poll_funcptr(&irqfd->pt, irqfd_ptable_queue_proc);

	events = file->f_op->poll(file, &irqfd->pt);

	mutex_lock(&kvm->lock);
	list_add_tail(&irqfd->list, &kvm->irqfds);
	mutex_unlock(&kvm->lock);

	/*
	 * Check if there was an event already queued
	 */
	if (events & POLLIN)
		schedule_work(&irqfd->inject);

	/*
	 * do not drop the file until the irqfd is fully initialized, otherwise
	 * we might race against the POLLHUP
	 */
	fput(file);

	return 0;

fail:
	if (file && !IS_ERR(file))
		fput(file);

	kfree(irqfd);
	return ret;
}

void
kvm_irqfd_init(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->irqfds);
}

void
kvm_irqfd_release(struct kvm *kvm)
{
	struct _irqfd *irqfd, *tmp;

	list_for_each_entry_safe(irqfd, tmp, &kvm->irqfds, list) {
		if (irqfd->wqh)
			remove_wait_queue(irqfd->wqh, &irqfd->wait);

		flush_work(&irqfd->inject);

		mutex_lock(&kvm->lock);
		list_del(&irqfd->list);
		mutex_unlock(&kvm->lock);

		kfree(irqfd);
	}
}
