/*
 * KVM module interface - Allows external modules to interface with a guest
 *
 * Copyright 2009 Novell.  All Rights Reserved.
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

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/mmu_context.h>
#include <linux/kvm_host.h>
#include <linux/kvm_xinterface.h>
#include <linux/slab.h>

#include "iodev.h"

struct _xinterface {
	struct kvm             *kvm;
	struct task_struct     *task;
	struct mm_struct       *mm;
	struct kvm_xinterface   intf;
	struct kvm_memory_slot *slotcache[NR_CPUS];
};

struct _xvmap {
	struct kvm_memory_slot    *memslot;
	unsigned long              npages;
	struct kvm_xvmap           vmap;
};

struct _ioevent {
	u64                   addr;
	int                   length;
	enum kvm_bus          bus;
	struct kvm_io_device  dev;
	struct kvm_xioevent   ioevent;
};

static struct _xinterface *
to_intf(struct kvm_xinterface *intf)
{
	return container_of(intf, struct _xinterface, intf);
}

#define _gfn_to_hva(gfn, memslot) \
	(memslot->userspace_addr + (gfn - memslot->base_gfn) * PAGE_SIZE)

/*
 * gpa_to_hva() - translate a guest-physical to host-virtual using
 * a per-cpu cache of the memslot.
 *
 * The gfn_to_memslot() call is relatively expensive, and the gpa access
 * patterns exhibit a high degree of locality.  Therefore, lets cache
 * the last slot used on a per-cpu basis to optimize the lookup
 *
 * assumes slots_lock held for read
 */
static unsigned long
gpa_to_hva(struct _xinterface *_intf, unsigned long gpa)
{
	int                     cpu     = get_cpu();
	unsigned long           gfn     = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *memslot = _intf->slotcache[cpu];
	unsigned long           addr    = 0;

	if (!memslot
	    || gfn < memslot->base_gfn
	    || gfn >= memslot->base_gfn + memslot->npages) {

		memslot = gfn_to_memslot(_intf->kvm, gfn);
		if (!memslot)
			goto out;

		_intf->slotcache[cpu] = memslot;
	}

	addr = _gfn_to_hva(gfn, memslot) + offset_in_page(gpa);

out:
	put_cpu();

	return addr;
}

/*------------------------------------------------------------------------*/

static void *
_vmap(struct _xinterface *_intf, unsigned long addr, unsigned long offset,
      unsigned long npages)
{
	struct task_struct *p = _intf->task;
	struct mm_struct *mm = _intf->mm;
	struct page **page_list;
	void *ptr = NULL;
	int ret;

	if (npages > (PAGE_SIZE / sizeof(struct page *)))
		return NULL;

	page_list = (struct page **) __get_free_page(GFP_KERNEL);
	if (!page_list)
		return NULL;

	down_write(&mm->mmap_sem);

	ret = get_user_pages(p, mm, addr, npages, 1, 0, page_list, NULL);
	if (ret < 0)
		goto out;

	ptr = vmap(page_list, npages, VM_MAP, PAGE_KERNEL);
	if (ptr)
		mm->locked_vm += npages;

	ptr = ptr + offset;

out:
	up_write(&mm->mmap_sem);

	free_page((unsigned long)page_list);

	return ptr;
}

static void
_vunmap(struct _xinterface *_intf, void *addr, size_t npages)
{
	down_write(&_intf->mm->mmap_sem);

	vunmap((void *)((unsigned long)addr & PAGE_MASK));
	_intf->mm->locked_vm -= npages;

	up_write(&_intf->mm->mmap_sem);
}

static void
xvmap_release(struct kvm_xvmap *vmap)
{
	struct _xvmap *_xvmap = container_of(vmap, struct _xvmap, vmap);
	struct _xinterface *_intf = to_intf(_xvmap->vmap.intf);

	_vunmap(_intf, _xvmap->vmap.addr, _xvmap->npages);
	kfree(_xvmap);
}

const static struct kvm_xvmap_ops _xvmap_ops = {
	.release = xvmap_release,
};

/*------------------------------------------------------------------------*/

/*
 * This function is invoked in the cases where a process context other
 * than _intf->mm tries to copy data.  Otherwise, we use copy_to_user()
 */
static unsigned long
_slow_copy_to_user(struct _xinterface *_intf, unsigned long dst,
		    const void *src, unsigned long n)
{
	struct task_struct *p = _intf->task;
	struct mm_struct *mm = _intf->mm;

	while (n) {
		unsigned long offset = offset_in_page(dst);
		unsigned long len = PAGE_SIZE - offset;
		int ret;
		struct page *pg;
		void *maddr;

		if (len > n)
			len = n;

		down_read(&mm->mmap_sem);
		ret = get_user_pages(p, mm, dst, 1, 1, 0, &pg, NULL);

		if (ret != 1) {
			up_read(&mm->mmap_sem);
			break;
		}

		maddr = kmap_atomic(pg, KM_USER0);
		memcpy(maddr + offset, src, len);
		kunmap_atomic(maddr, KM_USER0);
		set_page_dirty_lock(pg);
		put_page(pg);
		up_read(&mm->mmap_sem);

		src += len;
		dst += len;
		n -= len;
	}

	return n;
}

static unsigned long
xinterface_copy_to(struct kvm_xinterface *intf, unsigned long gpa,
		   const void *src, unsigned long n)
{
	struct _xinterface *_intf = to_intf(intf);
	unsigned long dst;
	bool kthread = !current->mm;

	mutex_lock(&_intf->kvm->slots_lock);

	dst = gpa_to_hva(_intf, gpa);
	if (!dst)
		goto out;

	if (kthread)
		use_mm(_intf->mm);

	if (kthread || _intf->mm == current->mm)
		n = copy_to_user((void *)dst, src, n);
	else
		n = _slow_copy_to_user(_intf, dst, src, n);

	if (kthread)
		unuse_mm(_intf->mm);

out:
	mutex_unlock(&_intf->kvm->slots_lock);

	return n;
}

/*
 * This function is invoked in the cases where a process context other
 * than _intf->mm tries to copy data.  Otherwise, we use copy_from_user()
 */
static unsigned long
_slow_copy_from_user(struct _xinterface *_intf, void *dst,
		     unsigned long src, unsigned long n)
{
	struct task_struct *p = _intf->task;
	struct mm_struct *mm = _intf->mm;

	while (n) {
		unsigned long offset = offset_in_page(src);
		unsigned long len = PAGE_SIZE - offset;
		int ret;
		struct page *pg;
		void *maddr;

		if (len > n)
			len = n;

		down_read(&mm->mmap_sem);
		ret = get_user_pages(p, mm, src, 1, 1, 0, &pg, NULL);

		if (ret != 1) {
			up_read(&mm->mmap_sem);
			break;
		}

		maddr = kmap_atomic(pg, KM_USER0);
		memcpy(dst, maddr + offset, len);
		kunmap_atomic(maddr, KM_USER0);
		put_page(pg);
		up_read(&mm->mmap_sem);

		src += len;
		dst += len;
		n -= len;
	}

	return n;
}

static unsigned long
xinterface_copy_from(struct kvm_xinterface *intf, void *dst,
		     unsigned long gpa, unsigned long n)
{
	struct _xinterface *_intf = to_intf(intf);
	unsigned long src;
	bool kthread = !current->mm;

	mutex_lock(&_intf->kvm->slots_lock);

	src = gpa_to_hva(_intf, gpa);
	if (!src)
		goto out;

	if (kthread)
		use_mm(_intf->mm);

	if (kthread || _intf->mm == current->mm)
		n = copy_from_user(dst, (void *)src, n);
	else
		n = _slow_copy_from_user(_intf, dst, src, n);

	if (kthread)
		unuse_mm(_intf->mm);

out:
	mutex_unlock(&_intf->kvm->slots_lock);

	return n;
}

static struct kvm_xvmap *
xinterface_vmap(struct kvm_xinterface *intf,
		unsigned long gpa,
		unsigned long len)
{
	struct _xinterface         *_intf = to_intf(intf);
	struct _xvmap               *_xvmap;
	struct kvm_memory_slot     *memslot;
	struct kvm                 *kvm = _intf->kvm;
	int                         ret = -EINVAL;
	void                       *addr = NULL;
	off_t                       offset = offset_in_page(gpa);
	unsigned long               gfn = gpa >> PAGE_SHIFT;
	unsigned long               npages;

	mutex_lock(&kvm->slots_lock);

	memslot = gfn_to_memslot(kvm, gfn);
	if (!memslot)
		goto fail;

	/* Check if the request walks off the end of the slot */
	if ((offset + len) > (memslot->npages << PAGE_SHIFT))
		goto fail;

	npages = PAGE_ALIGN(len + offset) >> PAGE_SHIFT;

	addr = _vmap(_intf, _gfn_to_hva(gfn, memslot), offset, npages);
	if (!addr) {
		ret = -EFAULT;
		goto fail;
	}

	_xvmap = kzalloc(sizeof(*_xvmap), GFP_KERNEL);
	if (!_xvmap) {
		ret = -ENOMEM;
		goto fail;
	}

	_xvmap->memslot = memslot;
	_xvmap->npages  = npages;

	kvm_xvmap_init(&_xvmap->vmap, &_xvmap_ops, intf);
	_xvmap->vmap.addr = addr;
	_xvmap->vmap.len  = len;

	mutex_unlock(&kvm->slots_lock);

	return &_xvmap->vmap;

fail:
	if (addr)
		_vunmap(_intf, addr, len);

	mutex_unlock(&kvm->slots_lock);

	return ERR_PTR(ret);
}

/* MMIO/PIO writes trigger an event if the addr/val match */
static int
ioevent_write(struct kvm_io_device *dev, gpa_t addr, int len, const void *val)
{
	struct _ioevent *p = container_of(dev, struct _ioevent, dev);
	struct kvm_xioevent *ioevent = &p->ioevent;

	if (!(addr == p->addr && len == p->length))
		return -EOPNOTSUPP;

	if (!ioevent->signal)
		return 0;

	ioevent->signal(ioevent, val);
	return 0;
}

static const struct kvm_io_device_ops ioevent_device_ops = {
	.write = ioevent_write,
};

static void
ioevent_deassign(struct kvm_xioevent *ioevent)
{
	struct _ioevent    *p = container_of(ioevent, struct _ioevent, ioevent);
	struct _xinterface *_intf = to_intf(ioevent->intf);
	struct kvm         *kvm = _intf->kvm;

	kvm_io_bus_unregister_dev(kvm, p->bus, &p->dev);
	kfree(p);
}

static const struct kvm_xioevent_ops ioevent_intf_ops = {
	.deassign = ioevent_deassign,
};

static struct kvm_xioevent*
xinterface_ioevent(struct kvm_xinterface *intf,
		   u64 addr,
		   unsigned long len,
		   unsigned long flags)
{
	struct _xinterface         *_intf = to_intf(intf);
	struct kvm                 *kvm = _intf->kvm;
	int                         pio = flags & KVM_XIOEVENT_FLAG_PIO;
	enum kvm_bus                bus_idx = pio ? KVM_PIO_BUS : KVM_MMIO_BUS;

	struct _ioevent            *p;
	int                         ret;

	/* must be natural-word sized */
	switch (len) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	/* check for range overflow */
	if (addr + len < addr)
		return ERR_PTR(-EINVAL);

	/* check for extra flags that we don't understand */
	if (flags & ~KVM_XIOEVENT_VALID_FLAG_MASK)
		return ERR_PTR(-EINVAL);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto fail;
	}

	p->addr    = addr;
	p->length  = len;
	p->bus     = bus_idx;

	kvm_iodevice_init(&p->dev, &ioevent_device_ops);

	ret = kvm_io_bus_register_dev(kvm, bus_idx, &p->dev);
	if (ret < 0)
		goto fail;

	kvm_xioevent_init(&p->ioevent, &ioevent_intf_ops, intf);

	return &p->ioevent;

fail:
	kfree(p);

	return ERR_PTR(ret);

}

static unsigned long
xinterface_sgmap(struct kvm_xinterface *intf,
		 struct scatterlist *sgl, int nents,
		 unsigned long flags)
{
	struct _xinterface     *_intf   = to_intf(intf);
	struct task_struct     *p       = _intf->task;
	struct mm_struct       *mm      = _intf->mm;
	struct kvm             *kvm     = _intf->kvm;
	struct kvm_memory_slot *memslot = NULL;
	bool                    kthread = !current->mm;
	int                     ret;
	struct scatterlist     *sg;
	int                     i;

	mutex_lock(&kvm->slots_lock);

	if (kthread)
		use_mm(_intf->mm);

	for_each_sg(sgl, sg, nents, i) {
		unsigned long           gpa    = sg_dma_address(sg);
		unsigned long           len    = sg_dma_len(sg);
		unsigned long           gfn    = gpa >> PAGE_SHIFT;
		off_t                   offset = offset_in_page(gpa);
		unsigned long           hva;
		struct page            *pg;

		/* ensure that we do not have more than one page per entry */
		if ((PAGE_ALIGN(len + offset) >> PAGE_SHIFT) != 1) {
			ret = -EINVAL;
			break;
		}

		/* check for a memslot-cache miss */
		if (!memslot
		    || gfn < memslot->base_gfn
		    || gfn >= memslot->base_gfn + memslot->npages) {
			memslot = gfn_to_memslot(kvm, gfn);
			if (!memslot) {
				ret = -EFAULT;
				break;
			}
		}

		hva = (memslot->userspace_addr +
		       (gfn - memslot->base_gfn) * PAGE_SIZE);

		if (kthread || current->mm == mm)
			ret = get_user_pages_fast(hva, 1, 1, &pg);
		else
			ret = get_user_pages(p, mm, hva, 1, 1, 0, &pg, NULL);

		if (ret != 1) {
			if (ret >= 0)
				ret = -EFAULT;
			break;
		}

		sg_set_page(sg, pg, len, offset);
		ret = 0;
	}

	if (kthread)
		unuse_mm(_intf->mm);

	mutex_unlock(&kvm->slots_lock);

	return ret;
}

static void
xinterface_release(struct kvm_xinterface *intf)
{
	struct _xinterface *_intf = to_intf(intf);

	mmput(_intf->mm);
	put_task_struct(_intf->task);
	kvm_put_kvm(_intf->kvm);
	kfree(_intf);
}

struct kvm_xinterface_ops _xinterface_ops = {
	.copy_to     = xinterface_copy_to,
	.copy_from   = xinterface_copy_from,
	.vmap        = xinterface_vmap,
	.ioevent     = xinterface_ioevent,
	.sgmap       = xinterface_sgmap,
	.release     = xinterface_release,
};

struct kvm_xinterface *
kvm_xinterface_alloc(struct kvm *kvm, struct module *owner)
{
	struct _xinterface *_intf;
	struct kvm_xinterface *intf;

	_intf = kzalloc(sizeof(*_intf), GFP_KERNEL);
	if (!_intf)
		return ERR_PTR(-ENOMEM);

	intf = &_intf->intf;

	__module_get(owner);
	intf->owner = owner;
	kref_init(&intf->kref);
	intf->ops = &_xinterface_ops;

	kvm_get_kvm(kvm);
	_intf->kvm = kvm;

	_intf->task = current;
	get_task_struct(_intf->task);

	_intf->mm = get_task_mm(_intf->task);

	return intf;
}
