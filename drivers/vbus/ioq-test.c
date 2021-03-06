/*
 * VBUS IOQ Test Driver
 *
 * This driver creates a single south -> north IOQ and uses it to
 * transport a few descriptors between the systems. This illustrates
 * the basic usage of IOQ. Some notes are included on how to connect
 * physically seperate systems together (blade system).
 *
 * Copyright (c) 2009 Ira W. Snyder <iws@ovro.caltech.edu>
 *
 * This file is licensed under the terms of the GNU General Public License
 * version 2. This program is licensed "as is" without any warranty of any
 * kind, whether express or implied.
 */

/* #define DEBUG 1 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/vbus.h>
#include <linux/vbus_client.h>
#include <linux/vbus_driver.h>

/*
 * The queue takes:
 * 52 bytes for the head
 * 28 bytes per descriptor
 *
 * Here are some common queue sizes:
 * 16  - 500 bytes
 * 32  - 948 bytes
 * 64  - 1844 bytes
 * 128 - 3636 bytes
 *
 * NOTE: the vbus design doesn't force power-of-two queue sizes,
 * NOTE: so you can use any size you'd like
 */
#define IOQT_COUNT 16

static const char driver_name[] = "ioq-test";

struct ioqt_system {
	char name[16];
	struct shm_signal signal;
	struct ioq ioq;
	struct ioq_notifier notifier;

	struct shm_signal *remote_signal;
};

/*
 * This is the shared IOQ descriptor table between two systems. It
 * would normally live in a PCI BAR.
 *
 * Both systems overlay an IOQ over this shared descriptor. See the
 * eventq_init() function for details.
 */
static struct ioq_ring_head *ioqt_head;

static struct ioqt_system south; /* host system */
static struct ioqt_system north; /* guest system */

/*----------------------------------------------------------------------------*/
/* SHM_SIGNAL Infrastructure                                                  */
/*----------------------------------------------------------------------------*/

static int
eventq_signal_inject(struct shm_signal *signal)
{
	struct ioqt_system *system = container_of(signal,
						  struct ioqt_system, signal);

	pr_debug("%s: called system %p signal %p\n", __func__, system, signal);
	pr_debug("%s: %s signalling remote\n", __func__, system->name);

	/*
	 * This is where you would tickle an MMIO register to
	 * generate a PCI interrupt to the remote system.
	 *
	 * Upon receiving the interrupt, the remote system's
	 * IRQ handler would then call the function below. This
	 * will wake up the IOQ notifier function.
	 */
	_shm_signal_wakeup(system->remote_signal);
	return 0;
}

static void
eventq_signal_release(struct shm_signal *signal)
{
	pr_debug("%s: called signal %p\n", __func__, signal);
}

static struct shm_signal_ops eventq_signal_ops = {
	.inject  = eventq_signal_inject,
	.release = eventq_signal_release,
};

/*----------------------------------------------------------------------------*/
/* IOQ Infrastructure                                                         */
/*----------------------------------------------------------------------------*/

static void
eventq_ioq_release(struct ioq *ioq)
{
	/* released as part of the vbus_pci object */
	pr_debug("%s: called ioq %p\n", __func__, ioq);
}

static struct ioq_ops eventq_ioq_ops = {
	.release = eventq_ioq_release,
};

/*----------------------------------------------------------------------------*/
/* IOQ Fill / Consume                                                         */
/*----------------------------------------------------------------------------*/

/*
 * This is a south -> north queue
 *
 * North side fills the IOQ with empty events
 * South side consumes some events (filling them with payload)
 * South side signals remote side
 * North side wakes up, processes events
 * North side signals remote side
 * South side wakes up, does nothing (but could take action)
 *
 * This means:
 * 1) North fills valid index, starting at tail
 * 2) South fills inuse index, starting at tail
 * 3) North processes inuse index, starting at head
 */

static int
eventq_north_fill(struct ioqt_system *system)
{
	struct ioq_iterator iter;
	int ret, i;

	/*
	 * We want to iterate on the "valid" index.  By default the iterator
	 * will not "autoupdate" which means it will not hypercall the host
	 * with our changes.  This is good, because we are really just
	 * initializing stuff here anyway.  Note that you can always manually
	 * signal the host with ioq_signal() if the autoupdate feature is not
	 * used.
	 */
	ret = ioq_iter_init(&system->ioq, &iter, ioq_idxtype_valid, 0);
	BUG_ON(ret < 0);

	/*
	 * Seek to the tail of the valid index (which should be our first
	 * item since the queue is brand-new)
	 */
	ret = ioq_iter_seek(&iter, ioq_seek_tail, 0, 0);
	BUG_ON(ret < 0);

	/*
	 * Now populate each descriptor with an empty vbus_event and mark it
	 * valid
	 */
	for (i = 0; i < IOQT_COUNT; i++) {
		struct ioq_ring_desc  *desc  = iter.desc;

		BUG_ON(iter.desc->valid);

		desc->cookie = (u64)i + 100;
		desc->ptr    = (u64)0;
		desc->len    = 0;
		desc->valid  = 1;

		/*
		 * This push operation will simultaneously advance the
		 * valid-tail index and increment our position in the queue
		 * by one.
		 */
		ret = ioq_iter_push(&iter, 0);
		BUG_ON(ret < 0);
	}

	return 0;
}

static int eventq_south_consume(struct ioqt_system *system)
{
	struct ioq_ring_desc *desc;
	struct ioq_iterator iter;
	int ret;

	/*
	 * Autoupdate can be used here, but we potentially create
	 * more wakeups than strictly necessary
	 *
	 * The bonus is that we never forget to ioq_signal() after
	 * consuming some cookies
	 */
	ret = ioq_iter_init(&system->ioq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_tail, 0, 0);
	BUG_ON(ret < 0);

	desc = iter.desc;
	pr_info("%s: CONSUME cookie %llu ptr %llu len %llu valid %d\n",
			__func__, desc->cookie, desc->ptr, desc->len,
			desc->valid);

	ret = ioq_iter_push(&iter, 0);
	BUG_ON(ret < 0);

	return 0;
}

/*----------------------------------------------------------------------------*/
/* IOQ Notifiers                                                              */
/*----------------------------------------------------------------------------*/

static void
eventq_south_wakeup(struct ioq_notifier *notifier)
{
	struct ioqt_system *system = container_of(notifier,
						  struct ioqt_system, notifier);

	pr_info("%s: %s eventq wakeup\n", __func__, system->name);
}

static void
eventq_north_wakeup(struct ioq_notifier *notifier)
{
	struct ioqt_system *system = container_of(notifier,
						  struct ioqt_system, notifier);
	struct ioq_iterator iter;
	int ret;

	pr_info("%s: %s eventq wakeup\n", __func__, system->name);

	/* We want to iterate on the head of the in-use index */
	ret = ioq_iter_init(&system->ioq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_head, 0, 0);
	BUG_ON(ret < 0);

	/*
	 * The EOM is indicated by finding a packet that is still owned by
	 * the south side.
	 *
	 * FIXME: This in theory could run indefinitely if the host keeps
	 * feeding us events since there is nothing like a NAPI budget.  We
	 * might need to address that
	 */
	while (!iter.desc->sown) {
		struct ioq_ring_desc *desc  = iter.desc;
		pr_info("%s: PROCESS cookie %llu\n", __func__, desc->cookie);

		/* Advance the in-use head */
		ret = ioq_iter_pop(&iter, 0);
		BUG_ON(ret < 0);
	}

	/* And let the south side know that we changed the queue */
	ioq_signal(&system->ioq, 0);
}

#if 0
static struct ioq_notifier eventq_notifier = {
	.signal = &eventq_wakeup,
};
#endif

/*----------------------------------------------------------------------------*/
/* Test Code                                                                  */
/*----------------------------------------------------------------------------*/

#define IOQT_LOCALITY_NORTH	0
#define IOQT_LOCALITY_SOUTH	1

static int eventq_init(struct ioqt_system *system, int locality)
{
	struct shm_signal_ops *shmops = &eventq_signal_ops;
	struct shm_signal_desc *desc = &ioqt_head->signal;
	struct ioq_ring_head *head = ioqt_head;
	struct shm_signal *signal = &system->signal;
	struct ioq_ops *ioqops = &eventq_ioq_ops;
	struct ioq *ioq = &system->ioq;

	enum shm_signal_locality shmloc;
	enum ioq_locality ioqloc;

	switch (locality) {
	case IOQT_LOCALITY_NORTH:
		shmloc = shm_locality_north;
		ioqloc = ioq_locality_north;
		strlcpy(system->name, "north", 16);
		system->notifier.signal = eventq_north_wakeup;
		break;
	case IOQT_LOCALITY_SOUTH:
		shmloc = shm_locality_south;
		ioqloc = ioq_locality_south;
		strlcpy(system->name, "south", 16);
		system->notifier.signal = eventq_south_wakeup;
		break;
	default:
		pr_err("%s: unsupported locality\n", __func__);
		return -EINVAL;
	}

	/* normally this would be host-only */
	desc->magic = SHM_SIGNAL_MAGIC;
	desc->ver   = SHM_SIGNAL_VER;

	/* both sides */
	shm_signal_init(signal, shmloc, shmops, desc);

	/* normally, this would be host-only */
	head->magic	= IOQ_RING_MAGIC;
	head->ver	= IOQ_RING_VER;
	head->count	= IOQT_COUNT;

	/* both sides */
	ioq_init(ioq, ioqops, ioqloc, head, signal, IOQT_COUNT);

	/* hook up the notifier, normally you'd want different functions */
	ioq->notifier = &system->notifier;
	ioq_notify_enable(ioq, 0);
	return 0;
}

static void run_tests(void)
{
	int i;

	eventq_init(&south, IOQT_LOCALITY_SOUTH);
	eventq_init(&north, IOQT_LOCALITY_NORTH);

	/* setup the remote signalling */
	north.remote_signal = &south.signal;
	south.remote_signal = &north.signal;

	pr_info("%s: north filling eventq\n", __func__);
	eventq_north_fill(&north);

	pr_info("%s: south begin consume loop\n", __func__);
	for (i = 0; i < 20; i++) {
		eventq_south_consume(&south);
		eventq_south_consume(&south);
		eventq_south_consume(&south);
		ioq_signal(&south.ioq, 0);
	}

	pr_info("%s: signalling north ioq (wakeup south)\n", __func__);
	ioq_signal(&north.ioq, 0);

	pr_info("%s: done signalling\n", __func__);

	/* free the IOQs (does nothing) */
	ioq_put(&north.ioq);
	ioq_put(&south.ioq);
}

/*----------------------------------------------------------------------------*/
/* Module Init / Exit                                                         */
/*----------------------------------------------------------------------------*/

static int __init ioqt_init(void)
{
	const size_t len = IOQ_HEAD_DESC_SIZE(IOQT_COUNT);

	pr_info("%s: starting IOQ tests\n", __func__);

	ioqt_head = kzalloc(len, GFP_KERNEL);
	if (!ioqt_head) {
		pr_err("%s: unable to allocate IOQ head\n", __func__);
		goto out_return;
	}

	run_tests();

	kfree(ioqt_head);

out_return:
	/* always return -ENODEV to force the module not to load */
	return -ENODEV;
}

static void __exit ioqt_exit(void)
{
	/* nothing to do */
}

MODULE_AUTHOR("Ira W. Snyder <iws@ovro.caltech.edu>");
MODULE_DESCRIPTION("VBUS IOQ Test Driver");
MODULE_LICENSE("GPL");

module_init(ioqt_init);
module_exit(ioqt_exit);
