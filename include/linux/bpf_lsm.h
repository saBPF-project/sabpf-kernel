/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2020 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/msg.h>
#include <linux/ipc.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/lsm_hooks.h>

#ifdef CONFIG_BPF_LSM

#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	RET bpf_lsm_##NAME(__VA_ARGS__);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

struct bpf_storage_blob {
	struct bpf_local_storage __rcu *storage;
};

extern struct lsm_blob_sizes bpf_lsm_blob_sizes;

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog);

bool bpf_lsm_is_sleepable_hook(u32 btf_id);

static inline struct bpf_storage_blob *bpf_inode(
	const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;

	return inode->i_security + bpf_lsm_blob_sizes.lbs_inode;
}

static inline struct bpf_storage_blob *bpf_task(
	const struct task_struct *task)
{
	if (unlikely(!task->security))
		return NULL;

	return task->security + bpf_lsm_blob_sizes.lbs_task;
}

/* systopia contrib start */
static inline struct bpf_storage_blob *bpf_cred(
	const struct cred *cred)
{
	if (unlikely(!cred->security))
		return NULL;
	
	return cred->security + bpf_lsm_blob_sizes.lbs_cred;
}

static inline struct bpf_storage_blob *bpf_msg(
	const struct msg_msg *msg)
{
	if (unlikely(!msg->security))
		return NULL;
	
	return msg->security + bpf_lsm_blob_sizes.lbs_msg_msg;
}

static inline struct bpf_storage_blob *bpf_ipc(
	const struct kern_ipc_perm *ipc)
{
	if (unlikely(!ipc->security))
		return NULL;
	
	return ipc->security + bpf_lsm_blob_sizes.lbs_ipc;
}

static inline struct bpf_storage_blob *bpf_file(
	const struct file *file)
{
	if (unlikely(!file->f_security))
		return NULL;
	
	return file->f_security + bpf_lsm_blob_sizes.lbs_file;
}
/* systopia contrib end */

extern const struct bpf_func_proto bpf_inode_storage_get_proto;
extern const struct bpf_func_proto bpf_inode_storage_delete_proto;
extern const struct bpf_func_proto bpf_task_storage_get_proto;
extern const struct bpf_func_proto bpf_task_storage_delete_proto;
/* systopia contrib start */
extern const struct bpf_func_proto bpf_cred_storage_get_proto;
extern const struct bpf_func_proto bpf_cred_storage_delete_proto;
extern const struct bpf_func_proto bpf_msg_storage_get_proto;
extern const struct bpf_func_proto bpf_msg_storage_delete_proto;
extern const struct bpf_func_proto bpf_ipc_storage_get_proto;
extern const struct bpf_func_proto bpf_ipc_storage_delete_proto;
extern const struct bpf_func_proto bpf_file_storage_get_proto;
extern const struct bpf_func_proto bpf_file_storage_delete_proto;
/* systopia contrib end */
void bpf_inode_storage_free(struct inode *inode);
void bpf_task_storage_free(struct task_struct *task);
/* systopia contrib start */
void bpf_cred_storage_free(struct cred *cred);
void bpf_msg_storage_free(struct msg_msg *msg);
void bpf_ipc_storage_free(struct kern_ipc_perm *ipc);
void bpf_file_storage_free(struct file *file);
/* systopia contrib end */

#else /* !CONFIG_BPF_LSM */

static inline bool bpf_lsm_is_sleepable_hook(u32 btf_id)
{
	return false;
}

static inline int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
				      const struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

static inline struct bpf_storage_blob *bpf_inode(
	const struct inode *inode)
{
	return NULL;
}

static inline struct bpf_storage_blob *bpf_task(
	const struct task_struct *task)
{
	return NULL;
}

/* systopia contrib start */
static inline struct bpf_storage_blob *bpf_cred(
	const struct cred *cred)
{
	return NULL;
}

static inline struct bpf_storage_blob *bpf_msg(
	const struct msg_msg *msg)
{
	return NULL;
}

static inline struct bpf_storage_blob *bpf_ipc(
	const struct kern_ipc_perm *ipc)
{
	return NULL;
}

static inline struct bpf_storage_blob *bpf_file(
	const struct file *file)
{
	return NULL;
}
/* systopia contrib end */

static inline void bpf_inode_storage_free(struct inode *inode)
{
}

static inline void bpf_task_storage_free(struct task_struct *task)
{
}

/* systopia contrib start */
static inline void bpf_cred_storage_free(struct cred *cred)
{
}

static inline void bpf_msg_storage_free(struct msg_msg *msg)
{
}

static inline void bpf_ipc_storage_free(struct kern_ipc_perm *ipc)
{
}

static inline void bpf_file_storage_free(struct file *file)
{
}
/* systopia contrib end */

#endif /* CONFIG_BPF_LSM */

#endif /* _LINUX_BPF_LSM_H */
