/*
 * Copyright 2009 Novell, Gregory Haskins.  All Rights Reserved.
 * Copyright 2012 Gregory Haskins.
 *
 * Author:
 *      Gregory Haskins <gregory.haskins@gmail.com>
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

#ifndef _LINUX_SHM_SIGNAL_EVENTFD_H
#define _LINUX_SHM_SIGNAL_EVENTFD_H

#include <linux/shm_signal.h>

/**
 * shm_signal_eventfd_bind() - Bind an eventfd to a SHM_SIGNAL
 * @s:        SHM_SIGNAL context
 *
 * Binds an eventfd to the shm_signal such that any signal to the eventfd
 * will trigger a notifier->signal() callback on the shm_signal.
 *
 **/
int shm_signal_eventfd_bindfd(struct shm_signal *signal, int fd);
int shm_signal_eventfd_bindfile(struct shm_signal *signal, struct file *file);

#endif /* _LINUX_SHM_SIGNAL_EVENTFD_H */
