// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Systopia-UBC.
 */

#include <linux/lsm_hooks.h>
#include <linux/bpf-cgroup.h>

static int cgbpf_file_permission(struct file *file, int mask)
{
	return BPF_CGROUP_RUN_PROG_LSM_FILEPERMISSION(file, mask);
}

static int cgbpf_file_open(struct file *file)
{
	return BPF_CGROUP_RUN_PROG_LSM_FILEOPEN(file);
}

static int cgbpf_file_alloc_security(struct file *file)
{
	return BPF_CGROUP_RUN_PROG_LSM_FILEALLOC(file);
}

static void cgbpf_file_free_security(struct file *file)
{
	BPF_CGROUP_RUN_PROG_LSM_FILEFREE(file);
}

static int cgbpf_socket_create(int family, int type, int protocol, int kern)
{
	return BPF_CGROUP_RUN_PROG_LSM_SOCKETCREATE(family, type, protocol, kern);
}

static int cgbpf_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return BPF_CGROUP_RUN_PROG_LSM_SOCKETBIND(sock, address, addrlen);
}

static int cgbpf_socket_listen(struct socket *sock, int backlog)
{
	return BPF_CGROUP_RUN_PROG_LSM_SOCKETLISTEN(sock, backlog);
}

static int cgbpf_socket_accept(struct socket *sock, struct socket *newsock)
{
	return BPF_CGROUP_RUN_PROG_LSM_SOCKETACCEPT(sock, newsock);
}

/*!
 * @brief Add provenance hooks to security_hook_list.
 */
static struct security_hook_list cgbpf_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_permission,          cgbpf_file_permission),
	LSM_HOOK_INIT(file_open,                cgbpf_file_open),
	LSM_HOOK_INIT(file_alloc_security,      cgbpf_file_alloc_security),
	LSM_HOOK_INIT(file_free_security,       cgbpf_file_free_security),
	LSM_HOOK_INIT(socket_create,       	cgbpf_socket_create),
	LSM_HOOK_INIT(socket_bind,       	cgbpf_socket_bind),
	LSM_HOOK_INIT(socket_listen,       	cgbpf_socket_listen),
	LSM_HOOK_INIT(socket_accept,       	cgbpf_socket_accept),
};

static int __init cgbpf_init(void)
{
	pr_info("cgBPF: running.\n");
	security_add_hooks(cgbpf_hooks, ARRAY_SIZE(cgbpf_hooks), "cgbpf");
	return 0;
}

/* set blob size and init function */
DEFINE_LSM(cgbpf) = {
	.name = "cgbpf",
	.init = cgbpf_init,
};
