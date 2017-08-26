/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Corporation.
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
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/pipe_fs_i.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/anon_inodes.h>
#include "sgx.h"

#define SGX_LE_PROXY_FD 3
#define SGX_LE_PROXY_PATH "/proc/self/fd/3"
#define SGX_LE_PROXY_TIMEOUT 500 /* ms */
#define SGX_LE_DEV_FD 4

extern unsigned char sgx_le_proxy[];
extern unsigned char sgx_le_proxy_end[];

struct sgx_le_ctx {
	struct pid *tgid;
	char *argv[2];
	struct file *pipes[2];
	struct file *exe_filp;
	struct file *dev_filp;
	struct crypto_shash *tfm;
	struct mutex lock;
};

struct sgx_le_ctx sgx_le_ctx;

static int sgx_le_create_pipe(struct sgx_le_ctx *ctx,
			      unsigned int fd)
{
	struct file *files[2];
	int ret;

	ret = create_pipe_files(files, 0);
	if (ret)
		goto out;

	ctx->pipes[fd] = files[fd ^ 1];
	ret = replace_fd(fd, files[fd], 0);
	fput(files[fd]);

out:
	return ret;
}

static int sgx_le_task_init(struct subprocess_info *subinfo, struct cred *new)
{
	struct sgx_le_ctx *ctx =
		(struct sgx_le_ctx *)subinfo->data;
	struct file *dev_filp;
	int ret;

	ret = replace_fd(SGX_LE_PROXY_FD, ctx->exe_filp, 0);
	if (ret < 0)
		return ret;

	dev_filp = anon_inode_getfile("[/dev/sgx]", &sgx_fops, NULL, O_RDWR);
	if (IS_ERR(dev_filp))
		return PTR_ERR(dev_filp);

	ret = replace_fd(SGX_LE_DEV_FD, dev_filp, 0);
	if (ret < 0)
		return ret;
	fput(dev_filp);

	ret = sgx_le_create_pipe(ctx, 0);
	if (ret < 0)
		return ret;

	ret = sgx_le_create_pipe(ctx, 1);
	if (ret < 0)
		return ret;

	ctx->tgid = get_pid(task_tgid(current));

	return 0;
}

static void sgx_le_stop(struct sgx_le_ctx *ctx)
{
	int i;

	if (ctx->tgid)
		kill_pid(ctx->tgid, SIGKILL, 1);

	for (i = 0; i < ARRAY_SIZE(ctx->pipes); i++) {
		if (ctx->pipes[i]) {
			fput(ctx->pipes[i]);
			ctx->pipes[i] = NULL;
		}
	}

	if (ctx->tgid) {
		put_pid(ctx->tgid);
		ctx->tgid = NULL;
	}
}

static int sgx_le_start(struct sgx_le_ctx *ctx)
{
	struct subprocess_info *subinfo;
	int ret;

	if (ctx->tgid)
		return 0;

	ctx->argv[0] = SGX_LE_PROXY_PATH;
	ctx->argv[1] = NULL;

	subinfo = call_usermodehelper_setup(ctx->argv[0], ctx->argv,
					    NULL, GFP_KERNEL, sgx_le_task_init,
					    NULL, &sgx_le_ctx);
	if (!subinfo)
		return -ENOMEM;

	ret = call_usermodehelper_exec(subinfo, UMH_WAIT_EXEC);
	if (ret) {
		sgx_le_stop(ctx);
		return ret;
	}

	return 0;
}

static int sgx_le_read(struct file *file, void *data, unsigned int len)
{
	ssize_t ret;

	ret = kernel_read(file, 0, data, len);

	if (ret != len && ret >= 0)
		return -ENOMEM;

	if (ret < 0)
		return ret;

	return 0;
}

static int sgx_le_write(struct file *file, const void *data,
			unsigned int len)
{
	ssize_t ret;

	ret = kernel_write(file, data, len, 0);

	if (ret != len && ret >= 0)
		return -ENOMEM;

	if (ret < 0)
		return ret;

	return 0;
}

int sgx_le_init(struct sgx_le_ctx *ctx)
{
	struct crypto_shash *tfm;
	struct file *exe_filp;
	unsigned long len;
	ssize_t ret;

	len = (unsigned long)&sgx_le_proxy_end - (unsigned long)&sgx_le_proxy;

	exe_filp = shmem_file_setup("[sgx_le_proxy]", len, 0);
	if (IS_ERR(exe_filp)) {
		ret = PTR_ERR(exe_filp);
		return ret;
	}

	ret = sgx_le_write(exe_filp, &sgx_le_proxy, len);
	if (ret)
		goto out;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		goto out;
	}

	ctx->tfm = tfm;
	ctx->exe_filp = exe_filp;
	mutex_init(&ctx->lock);

	return 0;
out:
	fput(exe_filp);
	return ret;
}

void sgx_le_exit(struct sgx_le_ctx *ctx)
{
	mutex_lock(&ctx->lock);
	sgx_le_stop(ctx);
	fput(ctx->exe_filp);
	crypto_free_shash(ctx->tfm);
	mutex_unlock(&ctx->lock);
}

int sgx_le_get_token(struct sgx_le_ctx *ctx,
		     const struct sgx_sigstruct *sigstruct,
		     struct sgx_einittoken *token)
{
	u8 mrsigner[32];
	ssize_t ret;

	mutex_lock(&ctx->lock);

	ret = sgx_get_key_hash(ctx->tfm, sigstruct->modulus, mrsigner);
	if (ret)
		goto out_unlock;

	ret = sgx_le_start(ctx);
	if (ret)
		goto out_unlock;

	ret = sgx_le_write(ctx->pipes[0], sigstruct, sizeof(*sigstruct));
	if (ret)
		goto out_stop;

	ret = sgx_le_write(ctx->pipes[0], mrsigner, sizeof(mrsigner));
	if (ret)
		goto out_stop;

	ret = sgx_le_read(ctx->pipes[1], token, sizeof(*token));

out_stop:
	sgx_le_stop(ctx);
out_unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}
