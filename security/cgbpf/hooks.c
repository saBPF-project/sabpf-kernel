// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Systopia-UBC.
 */

#include <linux/lsm_hooks.h>

/* For every LSM hook that allows attachment of BPF programs, declare a
 * function where a BPF program can be attached, and call the cgroup handler.
 */
#define LSM_HOOK(RET, DEFAULT, NAME, ...)	\
noinline RET cgbpf_##NAME(__VA_ARGS__)	\
{						\
	return DEFAULT;				\
}

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

/*!
 * @brief Add provenance hooks to security_hook_list.
 */
static struct security_hook_list cgbpf_hooks[] __lsm_ro_after_init = {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	LSM_HOOK_INIT(NAME, cgbpf_##NAME),
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
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
