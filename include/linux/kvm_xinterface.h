#ifndef __KVM_XINTERFACE_H
#define __KVM_XINTERFACE_H

/*
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kref.h>
#include <linux/module.h>
#include <linux/file.h>

struct kvm_xinterface;
struct kvm_xvmap;
struct kvm_xioevent;

enum {
	kvm_xioevent_flag_nr_pio,
	kvm_xioevent_flag_nr_max,
};

#define KVM_XIOEVENT_FLAG_PIO       (1 << kvm_xioevent_flag_nr_pio)

#define KVM_XIOEVENT_VALID_FLAG_MASK  ((1 << kvm_xioevent_flag_nr_max) - 1)

struct kvm_xinterface_ops {
	unsigned long (*copy_to)(struct kvm_xinterface *intf,
				 unsigned long gpa, const void *src,
				 unsigned long len);
	unsigned long (*copy_from)(struct kvm_xinterface *intf, void *dst,
				   unsigned long gpa, unsigned long len);
	struct kvm_xvmap* (*vmap)(struct kvm_xinterface *intf,
				  unsigned long gpa,
				  unsigned long len);
	struct kvm_xioevent* (*ioevent)(struct kvm_xinterface *intf,
					u64 addr,
					unsigned long len,
					unsigned long flags);
	void (*release)(struct kvm_xinterface *);
};

struct kvm_xinterface {
	struct module                   *owner;
	struct kref                      kref;
	const struct kvm_xinterface_ops *ops;
};

static inline void
kvm_xinterface_get(struct kvm_xinterface *intf)
{
	kref_get(&intf->kref);
}

static inline void
_kvm_xinterface_release(struct kref *kref)
{
	struct kvm_xinterface *intf;
	struct module *owner;

	intf = container_of(kref, struct kvm_xinterface, kref);

	owner = intf->owner;
	rmb();

	intf->ops->release(intf);
	module_put(owner);
}

static inline void
kvm_xinterface_put(struct kvm_xinterface *intf)
{
	kref_put(&intf->kref, _kvm_xinterface_release);
}

struct kvm_xvmap_ops {
	void (*release)(struct kvm_xvmap *vmap);
};

struct kvm_xvmap {
	struct kref                 kref;
	const struct kvm_xvmap_ops *ops;
	struct kvm_xinterface      *intf;
	void                       *addr;
	size_t                      len;
};

static inline void
kvm_xvmap_init(struct kvm_xvmap *vmap, const struct kvm_xvmap_ops *ops,
	       struct kvm_xinterface *intf)
{
	memset(vmap, 0, sizeof(vmap));
	kref_init(&vmap->kref);
	vmap->ops = ops;
	vmap->intf = intf;

	kvm_xinterface_get(intf);
}

static inline void
kvm_xvmap_get(struct kvm_xvmap *vmap)
{
	kref_get(&vmap->kref);
}

static inline void
_kvm_xvmap_release(struct kref *kref)
{
	struct kvm_xvmap *vmap;
	struct kvm_xinterface *intf;

	vmap = container_of(kref, struct kvm_xvmap, kref);

	intf = vmap->intf;
	rmb();

	vmap->ops->release(vmap);
	kvm_xinterface_put(intf);
}

static inline void
kvm_xvmap_put(struct kvm_xvmap *vmap)
{
	kref_put(&vmap->kref, _kvm_xvmap_release);
}

struct kvm_xioevent_ops {
	void (*deassign)(struct kvm_xioevent *ioevent);
};

struct kvm_xioevent {
	const struct kvm_xioevent_ops *ops;
	struct kvm_xinterface         *intf;
	void (*signal)(struct kvm_xioevent *ioevent, const void *val);
	void                          *priv;
};

static inline void
kvm_xioevent_init(struct kvm_xioevent *ioevent,
		  const struct kvm_xioevent_ops *ops,
		  struct kvm_xinterface *intf)
{
	memset(ioevent, 0, sizeof(vmap));
	ioevent->ops = ops;
	ioevent->intf = intf;

	kvm_xinterface_get(intf);
}

static inline void
kvm_xioevent_deassign(struct kvm_xioevent *ioevent)
{
	struct kvm_xinterface *intf = ioevent->intf;
	rmb();

	ioevent->ops->deassign(ioevent);
	kvm_xinterface_put(intf);
}

struct kvm_xinterface *kvm_xinterface_bind(int fd);

#endif /* __KVM_XINTERFACE_H */
