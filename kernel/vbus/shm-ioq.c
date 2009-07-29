/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * IOQ helper for devices - This module implements an IOQ which has
 * been shared with a device via a vbus_shm segment.
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

#include <linux/ioq.h>
#include <linux/vbus_device.h>

struct _ioq {
	struct vbus_shm *shm;
	struct ioq ioq;
};

static void
_shm_ioq_release(struct ioq *ioq)
{
	struct _ioq *_ioq = container_of(ioq, struct _ioq, ioq);

	/* the signal is released by the IOQ infrastructure */
	vbus_shm_put(_ioq->shm);
	kfree(_ioq);
}

static struct ioq_ops _shm_ioq_ops = {
	.release = _shm_ioq_release,
};

int vbus_shm_ioq_attach(struct vbus_shm *shm, struct shm_signal *signal,
			int maxcount, struct ioq **ioq)
{
	struct _ioq *_ioq;
	struct ioq_ring_head *head = NULL;
	size_t ringcount;

	if (!signal)
		return -EINVAL;

	_ioq = kzalloc(sizeof(*_ioq), GFP_KERNEL);
	if (!_ioq)
		return -ENOMEM;

	head = (struct ioq_ring_head *)shm->ptr;

	if (head->magic != IOQ_RING_MAGIC)
		return -EINVAL;

	if (head->ver != IOQ_RING_VER)
		return -EINVAL;

	ringcount = head->count;

	if ((maxcount != -1) && (ringcount > maxcount))
		return -EINVAL;

	/*
	 * Sanity check the ringcount against the actual length of the segment
	 */
	if (IOQ_HEAD_DESC_SIZE(ringcount) != shm->len)
		return -EINVAL;

	_ioq->shm = shm;

	ioq_init(&_ioq->ioq, &_shm_ioq_ops, ioq_locality_south, head,
		 signal, ringcount);

	*ioq = &_ioq->ioq;

	return 0;
}
EXPORT_SYMBOL_GPL(vbus_shm_ioq_attach);

