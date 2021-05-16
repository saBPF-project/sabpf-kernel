// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Systopia-UBC.
 */

#include <linux/lsm_hooks.h>

static int dummy_file_permission(struct file *file, int mask)
{
	return 0;
}

static int dummy_file_open(struct file *file)
{
	return 0;
}

static int dummy_file_alloc_security(struct file *file)
{
	return 0;
}

static void dummy_file_free_security(struct file *file)
{
	return;
}

/*!
 * @brief Add provenance hooks to security_hook_list.
 */
static struct security_hook_list dummy_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_permission,          dummy_file_permission),
	LSM_HOOK_INIT(file_open,                dummy_file_open),
	LSM_HOOK_INIT(file_alloc_security,      dummy_file_alloc_security),
	LSM_HOOK_INIT(file_free_security,       dummy_file_free_security),
};

static int __init dummy_init(void)
{
	pr_info("dummy LSM: running.\n");
	security_add_hooks(dummy_hooks, ARRAY_SIZE(dummy_hooks), "dummy");
	return 0;
}

/* set blob size and init function */
DEFINE_LSM(dummy) = {
	.name = "dummy",
	.init = dummy_init,
}; 
