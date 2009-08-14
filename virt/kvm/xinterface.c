/*
 * KVM module interface - Allows external modules to interface with a guest
 *
 * This code is designed to be statically linked to the kernel, regardless
 * of the configuration of kvm.ko.  This allows the kvm_xinterface_find
 * routine to be stably exported without dependencies on, or race conditions
 * against acquiring the kvm.ko module itself.
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
#include <linux/kvm_host.h>
#include <linux/kvm_xinterface.h>

#include "iodev.h"

struct _xinterface {
	struct kvm            *kvm;
	struct task_struct    *task;
	struct mm_struct      *mm;
	struct kvm_xinterface  intf;
};

struct _xvmap {
	struct kvm_memory_slot    *memslot;
	unsigned long              npages;
	struct kvm_xvmap           vmap;
};

struct _ioevent {
	u64                   addr;
	int                   length;
	struct kvm_io_bus    *bus;
	struct kvm_io_device  dev;
	struct kvm_xioevent   ioevent;
};

static struct _xinterface *
to_intf(struct kvm_xinterface *intf)
{
	return container_of(intf, struct _xinterface, intf);
}

/* assumes slots_lock held for read */
static unsigned long
gpa_to_hva(struct _xinterface *_intf, unsigned long gpa)
{
	unsigned long addr;

	addr = gfn_to_hva(_intf->kvm, gpa >> PAGE_SHIFT);
	if (kvm_is_error_hva(addr))
		return 0;

	return addr + offset_in_page(gpa);
}

/*------------------------------------------------------------------------*/

/* assumes slots_lock held for read */
static void *
_vmap(struct _xinterface *_intf, unsigned long gpa, unsigned long npages)
{
	struct task_struct *p = _intf->task;
	struct mm_struct *mm = _intf->mm;
	struct page **page_list;
	void *ptr = NULL;
	unsigned long addr;
	int ret;

	addr = gpa_to_hva(_intf, gpa);

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

	ptr = ptr + offset_in_page(gpa);

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
	atomic_dec(&_xvmap->memslot->refs);
	kfree(_xvmap);
}

const static struct kvm_xvmap_ops _xvmap_ops = {
	.release = xvmap_release,
};

/*------------------------------------------------------------------------*/

static unsigned long
xinterface_copy_to(struct kvm_xinterface *intf, unsigned long gpa,
		   const void *src, unsigned long n)
{
	struct _xinterface *_intf = to_intf(intf);
	struct task_struct *p = _intf->task;
	struct mm_struct *mm = _intf->mm;
	unsigned long dst;

	down_read(&_intf->kvm->slots_lock);

	dst = gpa_to_hva(_intf, gpa);

	while (dst && n) {
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

	up_read(&_intf->kvm->slots_lock);

	return n;
}

static unsigned long
xinterface_copy_from(struct kvm_xinterface *intf, void *dst,
		     unsigned long gpa, unsigned long n)
{
	struct _xinterface *_intf = to_intf(intf);
	struct task_struct *p = _intf->task;
	struct mm_struct *mm = _intf->mm;
	unsigned long src;

	down_read(&_intf->kvm->slots_lock);

	src = gpa_to_hva(_intf, gpa);

	while (src && n) {
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

	up_read(&_intf->kvm->slots_lock);

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
	unsigned long               npages;

	down_read(&kvm->slots_lock);

	memslot = gfn_to_memslot(kvm, gpa >> PAGE_SHIFT);
	if (!memslot)
		goto fail;

	/* Check if the request walks off the end of the slot */
	if ((offset + len) > (memslot->npages << PAGE_SHIFT))
		goto fail;

	npages = PAGE_ALIGN(len + offset) >> PAGE_SHIFT;

	addr = _vmap(_intf, gpa, npages);
	if (!addr) {
		ret = -EFAULT;
		goto fail;
	}

	_xvmap = kzalloc(sizeof(*_xvmap), GFP_KERNEL);
	if (!_xvmap) {
		ret = -ENOMEM;
		goto fail;
	}

	atomic_inc(&memslot->refs);

	_xvmap->memslot = memslot;
	_xvmap->npages  = npages;

	kvm_xvmap_init(&_xvmap->vmap, &_xvmap_ops, intf);
	_xvmap->vmap.addr = addr;
	_xvmap->vmap.len  = len;

	up_read(&kvm->slots_lock);

	return &_xvmap->vmap;

fail:
	if (addr)
		_vunmap(_intf, addr, len);

	up_read(&kvm->slots_lock);

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
	struct kvm_io_bus          *bus = pio ? &kvm->pio_bus : &kvm->mmio_bus;
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
	p->bus     = bus;

	kvm_iodevice_init(&p->dev, &ioevent_device_ops);

	ret = kvm_io_bus_register_dev(kvm, bus, &p->dev);
	if (ret < 0)
		goto fail;

	kvm_xioevent_init(&p->ioevent, &ioevent_intf_ops, intf);

	return &p->ioevent;

fail:
	kfree(p);

	return ERR_PTR(ret);

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
