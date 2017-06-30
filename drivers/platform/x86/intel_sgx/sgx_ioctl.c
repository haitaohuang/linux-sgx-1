/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Sean Christopherson <sean.j.christopherson@intel.com>
 */

#include "sgx.h"
#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/shmem_fs.h>

struct sgx_add_page_req {
	struct sgx_encl *encl;
	struct sgx_encl_page *encl_page;
	struct sgx_secinfo secinfo;
	u16 mrmask;
	struct list_head list;
};

static int sgx_find_and_get_encl(unsigned long addr, struct sgx_encl **encl)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret;

	if (addr & (PAGE_SIZE - 1))
		return -EINVAL;

	down_read(&mm->mmap_sem);

	ret = sgx_find_encl(mm, addr, &vma);
	if (!ret) {
		*encl = vma->vm_private_data;
		kref_get(&(*encl)->refcount);
	}

	up_read(&mm->mmap_sem);

	return ret;
}

/**
 * sgx_ioc_enclave_create - handler for SGX_IOC_ENCLAVE_CREATE
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_create
 *
 * Creates meta-data for an enclave and executes ENCLS(ECREATE)
 */
static long sgx_ioc_enclave_create(struct file *filep, unsigned int cmd,
				   unsigned long arg)
{
	struct sgx_enclave_create *createp = (struct sgx_enclave_create *)arg;
	void __user *src = (void __user *)createp->src;
	struct sgx_secs *secs;
	int ret;

	secs = kzalloc(sizeof(*secs),  GFP_KERNEL);
	if (!secs)
		return -ENOMEM;

	ret = copy_from_user(secs, src, sizeof(*secs));
	if (ret) {
		kfree(secs);
		return ret;
	}

	ret = sgx_encl_create(secs);

	kfree(secs);
	return ret;
}

/**
 * sgx_ioc_enclave_add_page - handler for SGX_IOC_ENCLAVE_ADD_PAGE
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_add_page
 *
 * Creates meta-data for an enclave page and enqueues ENCLS(EADD) that will
 * be processed by a worker thread later on.
 */
static long sgx_ioc_enclave_add_page(struct file *filep, unsigned int cmd,
				     unsigned long arg)
{
	struct sgx_enclave_add_page *addp = (void *)arg;
	unsigned long secinfop = (unsigned long)addp->secinfo;
	struct sgx_secinfo secinfo;
	struct sgx_encl *encl;
	struct page *data_page;
	void *data;
	int ret;

	ret = sgx_find_and_get_encl(addp->addr, &encl);
	if (ret)
		return ret;

	if (copy_from_user(&secinfo, (void __user *)secinfop,
			   sizeof(secinfo))) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -EFAULT;
	}

	data_page = alloc_page(GFP_HIGHUSER);
	if (!data_page) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -ENOMEM;
	}

	data = kmap(data_page);

	ret = copy_from_user((void *)data, (void __user *)addp->src, PAGE_SIZE);
	if (ret)
		goto out;

	ret = sgx_encl_add_page(encl, addp->addr, data, &secinfo, addp->mrmask);
	if (ret)
		goto out;

out:
	kref_put(&encl->refcount, sgx_encl_release);
	kunmap(data_page);
	__free_page(data_page);
	return ret;
}

/**
 * sgx_ioc_enclave_init - handler for SGX_IOC_ENCLAVE_INIT
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_init
 *
 * Flushes the remaining enqueued ENCLS(EADD) operations and executes
 * ENCLS(EINIT). Does a number of retries because EINIT might fail because of an
 * interrupt storm.
 */
static long sgx_ioc_enclave_init(struct file *filep, unsigned int cmd,
				 unsigned long arg)
{
	struct sgx_enclave_init *initp = (struct sgx_enclave_init *)arg;
	unsigned long sigstructp = (unsigned long)initp->sigstruct;
	unsigned long encl_id = initp->addr;
	struct sgx_sigstruct *sigstruct;
	struct sgx_einittoken *einittoken;
	struct sgx_encl *encl;
	struct page *initp_page;
	int ret;

	initp_page = alloc_page(GFP_HIGHUSER);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
	einittoken = (struct sgx_einittoken *)
		((unsigned long)sigstruct + PAGE_SIZE / 2);

	ret = copy_from_user(sigstruct, (void __user *)sigstructp,
			     sizeof(*sigstruct));
	if (ret)
		goto out;

	ret = sgx_find_and_get_encl(encl_id, &encl);
	if (ret)
		goto out;

	ret = sgx_encl_init(encl, sigstruct, einittoken);

	kref_put(&encl->refcount, sgx_encl_release);

out:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

static void sgx_ipi_cb(void *info)
{
}

static int sgx_emodpr(struct sgx_encl *encl, struct sgx_encl_page *page,
		      struct sgx_secinfo *secinfo)
{
	void *ptr;
	int ret;

	ptr = sgx_get_page(page->epc_page);
	ret = __emodpr(secinfo, ptr);
	sgx_put_page(ptr);

	if (ret) {
		sgx_err(encl, "EMODPR returned %d\n", ret);
		sgx_invalidate(encl, true);
		smp_call_function(sgx_ipi_cb, NULL, 1);
	}

	return ret;
}

static int sgx_emodt(struct sgx_encl *encl, struct sgx_encl_page *page,
		     struct sgx_secinfo *secinfo)
{

	u64 pt = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	void *ptr;
	int ret;

	ptr = sgx_get_page(page->epc_page);
	ret = __emodt(secinfo, ptr);
	sgx_put_page(ptr);

	if (ret) {
		sgx_err(encl, "EMODT returned %d\n", ret);
		sgx_invalidate(encl, true);
		smp_call_function(sgx_ipi_cb, NULL, 1);
	} else if (pt == SGX_SECINFO_TRIM) {
		page->flags |= SGX_ENCL_PAGE_TRIM;
	}

	return ret;
}

typedef int (*sgx_encl_page_op_t)(struct sgx_encl *encl,
				  struct sgx_encl_page *page,
				  struct sgx_secinfo *secinfo);

static int sgx_encl_mod_pages(struct sgx_encl *encl, unsigned long addr,
			      unsigned long length, struct sgx_secinfo *secinfo,
			      sgx_encl_page_op_t op)
{
	struct sgx_encl_page *page;
	struct vm_area_struct *vma;
	int ret;

	/* Address and length must align to page boundaries. */
	if ((addr & (PAGE_SIZE - 1)) || (length & (PAGE_SIZE - 1)) ||
	    addr < encl->base || length > encl->size)
		return -EINVAL;

	ret = sgx_validate_secinfo(secinfo);
	if (ret)
		return ret;

	down_read(&encl->mm->mmap_sem);
	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_DEAD)
		goto out;

	for ( ; addr < (addr + length); addr += PAGE_SIZE) {
		vma = sgx_find_vma(encl, addr);
		if (!vma) {
			ret = -EFAULT;
			break;
		}

		page = sgx_fault_page(vma, addr, SGX_FAULT_RESERVE);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}

		sgx_eblock(encl, page->epc_page);
		op(encl, page, secinfo);
		sgx_etrack(encl);
		smp_call_function(sgx_ipi_cb, NULL, 1);

		page->flags &= ~SGX_ENCL_PAGE_RESERVED;
	}

out:
	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
	return ret;
}

/**
 * sgx_ioc_enclave_mod_pages - handler for SGX_IOC_ENCLAVE_MOD_PAGES
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_mod_pages
 *
 * Changes type or permissions of a range of pages. This can be used in
 * collaboration with a trusted loader in the enclave construction with a
 * trusted run-time to trim unneeded pages. The trusted run-time must accept all
 * the changes before they become active.
 */
static long sgx_ioc_enclave_mod_pages(struct file *filep, unsigned int cmd,
				      unsigned long arg)
{
	struct sgx_enclave_mod_pages *params = (void *)arg;
	sgx_encl_page_op_t op;
	unsigned long secinfop = (unsigned long)params->secinfo;
	struct sgx_secinfo secinfo;
	struct sgx_encl *encl;
	int ret;

	switch (params->op) {
	case SGX_ENCLAVE_MOD_TYPE:
		op = sgx_emodt;
		break;
	case SGX_ENCLAVE_MOD_PROT:
		op = sgx_emodpr;
		break;
	default:
		return -EINVAL;
	}

	if (copy_from_user(&secinfo, (void __user *)secinfop, sizeof(secinfo)))
		return -EFAULT;

	ret = sgx_find_and_get_encl(params->addr, &encl);
	if (ret)
		return ret;

	ret = sgx_encl_mod_pages(encl, params->addr, params->length, &secinfo,
				 op);

	kref_put(&encl->refcount, sgx_encl_release);
	return ret;
}

/**
 * sgx_ioc_enclave_remove_pages - handler for SGX_IOC_ENCLAVE_REMOVE_PAGES
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_remove_pages
 *
 * Remove trimmed pages from an address range. Untrimmed and non-existing pages
 * are skipped. If the pages have not been accepted (with EACCEPT) by the
 * enclave, the function will stop iterating at that point and return -EFAULT to
 * the caller.
 */
static long sgx_ioc_enclave_remove_pages(struct file *filep, unsigned int cmd,
					 unsigned long arg)
{
	struct sgx_enclave_remove_pages *params = (void *)arg;
	unsigned long addr = params->addr;
	unsigned long length = params->length;
	struct sgx_encl *encl;
	struct sgx_encl_page *page;
	struct vm_area_struct *vma;
	int ret;

	ret = sgx_find_and_get_encl(params->addr, &encl);
	if (ret)
		return ret;

	/* Address and length must align to page boundaries. */
	if ((addr & (PAGE_SIZE - 1)) || (length & (PAGE_SIZE - 1)) ||
	    addr < encl->base || length > encl->size) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -EINVAL;
	}

	down_read(&encl->mm->mmap_sem);

	for ( ; addr < (addr + length); addr += PAGE_SIZE) {
		vma = sgx_find_vma(encl, addr);
		if (!vma) {
			/* should never happen */
			ret = -EFAULT;
			break;
		}

		page = sgx_fault_page(vma, addr, SGX_FAULT_RESERVE);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			if (ret == -ENOENT)
				continue;

			if (ret)
				break;

			if (page->flags & SGX_ENCL_PAGE_TRIM) {
				page->flags &= ~SGX_ENCL_PAGE_RESERVED;
				continue;
			}
		}

		mutex_lock(&encl->lock);
		zap_vma_ptes(vma, page->addr, PAGE_SIZE);
		ret = sgx_free_page(page->epc_page, encl);
		if (!ret) {
			encl->secs_child_cnt--;
			radix_tree_delete(&encl->page_tree,
					  page->addr >> PAGE_SHIFT);
			kfree(page);
		}
		mutex_unlock(&encl->lock);

		page->flags &= ~SGX_ENCL_PAGE_RESERVED;

		if (ret) {
			sgx_dbg(encl, "%s: EREMOVE returned %d\n", __func__,
				ret);
			ret = -EFAULT;
			break;
		}
	}

	up_read(&encl->mm->mmap_sem);
	kref_put(&encl->refcount, sgx_encl_release);
	return ret;
}

typedef long (*sgx_ioc_t)(struct file *filep, unsigned int cmd,
			  unsigned long arg);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	sgx_ioc_t handler = NULL;
	long ret;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		handler = sgx_ioc_enclave_create;
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		handler = sgx_ioc_enclave_add_page;
		break;
	case SGX_IOC_ENCLAVE_INIT:
		handler = sgx_ioc_enclave_init;
		break;
	case SGX_IOC_ENCLAVE_MOD_PAGES:
		if (!sgx_has_sgx2)
			return -ENOIOCTLCMD;
		handler = sgx_ioc_enclave_mod_pages;
		break;
	case SGX_IOC_ENCLAVE_REMOVE_PAGES:
		handler = sgx_ioc_enclave_remove_pages;
		if (!sgx_has_sgx2)
			return -ENOIOCTLCMD;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	if (copy_from_user(data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = handler(filep, cmd, (unsigned long)((void *)data));
	if (!ret && (cmd & IOC_OUT)) {
		if (copy_to_user((void __user *)arg, data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}

	return ret;
}
