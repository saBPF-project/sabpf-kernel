// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Systopia-UBC.
 */

#include <linux/lsm_hooks.h>
#include <linux/cgbpf_lsm.h>
#include "cgbpf_lsm.h"

/*
 * Run the eBPF programs of the hook indexed by the type t (<hook>_type) with the arguments
 * packed into an array of u64 integers as the context.
 */
static inline int __run_progs(enum lsm_hook_type t, struct bpf_cgroup_lsm_ctx *ctx)
{
	struct cgbpf_lsm_hook *h = &cgbpf_lsm_hooks_list[t];
	struct bpf_prog_array_item *item;
	struct bpf_prog_array *array;
	int ret, retval = 0;

	/*
	 * Some hooks might get called before the securityFS is initialized,
	 * this will result in a NULL pointer exception.
	 */
	if (!cgbpf_lsm_fs_initialized)
		return 0;

	preempt_disable();
	rcu_read_lock();

	array = rcu_dereference(h->progs);
	if (!array)
		goto out;

	for (item = array->items; item->prog; item++) {
		pr_info("CGBPF LSM: TODO Running BPF program.\n");
		/*
		ret = BPF_PROG_RUN(item->prog, args);
		if (ret < 0) {
			retval = ret;
			break;
		}*/
	}
out:
	rcu_read_unlock();
	preempt_enable();
	return IS_ENABLED(CONFIG_SECURITY_BPF_ENFORCE) ? retval : 0;
}

static int cgbpf_lsm_file_permission(struct file *file, int mask)
{
	struct bpf_cgroup_lsm_ctx ctx = {
		.file = file,
		.mask = mask,
	};
	
	return __run_progs(file_permission_type, &ctx);
}

static int cgbpf_lsm_file_open(struct file *file)
{
	struct bpf_cgroup_lsm_ctx ctx = {
		.file = file,
	};
	
	return __run_progs(file_open_type, &ctx);
}

/*
 * Initialize the cgbpf_lsm_hooks_list for each of the hooks defined in hooks.h.
 * The list contains information for each of the hook and can be indexed by the
 * its type to initialize security FS, attach, detach and execute eBPF programs
 * for the hook.
 */
struct cgbpf_lsm_hook cgbpf_lsm_hooks_list[] = {
	#define CGBPF_LSM_HOOK(h, ...)					\
		[h##_type] = {						\
			.h_type = h##_type,				\
			.mutex = __MUTEX_INITIALIZER(			\
				cgbpf_lsm_hooks_list[h##_type].mutex),	\
			.name = #h,					\
		},
	#include "hooks.h"
	#undef CGBPF_LSM_HOOK
};

/*
 * Initialize cgbpf_hooks for each of the hooks defined in hooks.h.
 */
static struct security_hook_list cgbpf_hooks[] __lsm_ro_after_init = {
	#define CGBPF_LSM_HOOK(h, ...) LSM_HOOK_INIT(h, cgbpf_lsm_##h),
	#include "hooks.h"
	#undef CGBPF_LSM_HOOK
};

static int __init cgbpf_init(void)
{
	pr_info("CGBPF LSM: Running...\n");
	security_add_hooks(cgbpf_hooks, ARRAY_SIZE(cgbpf_hooks), "cgbpf");
	return 0;
}

/* set blob size and init function */
DEFINE_LSM(cgbpf) = {
	.name = "cgbpf",
	.init = cgbpf_init,
};
