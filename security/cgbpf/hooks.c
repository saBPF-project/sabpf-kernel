// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Systopia-UBC.
 */

#include <linux/lsm_hooks.h>

static int cgbpf_file_permission(struct file *file, int mask)
{
	return 0;
}

static int cgbpf_file_open(struct file *file)
{
	return 0;
}

/*!
 * @brief Add provenance hooks to security_hook_list.
 */
static struct security_hook_list cgbpf_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_permission,          cgbpf_file_permission),
	LSM_HOOK_INIT(file_open,                cgbpf_file_open),
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