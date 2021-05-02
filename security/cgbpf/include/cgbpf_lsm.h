/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _CGBPF_LSM_H
#define _CGBPF_LSM_H

#include <linux/bpf_event.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include "fs.h"

/*
 * This enum indexes one of the LSM hooks defined in hooks.h.
 * Each value of the enum is defined as <hook>_type.
 */
enum lsm_hook_type {
	#define CGBPF_LSM_HOOK(hook, ...) hook##_type,
	#include "hooks.h"
	#undef CGBPF_LSM_HOOK
	__MAX_LSM_HOOK_TYPE,
};

/*
 * This data structure contains all the information required by the LSM for a
 * a hook.
 */
struct cgbpf_lsm_hook {
	/*
	 * The name of the security hook, a file with this name will be created
	 * in the securityfs.
	 */
	const char *name;
	/*
	 * The type of the LSM hook, the LSM uses this to index the list of the
	 * hooks to run the eBPF programs that may have been attached.
	 */
	enum lsm_hook_type h_type;
	/*
	 * The dentry of the file created in securityfs.
	 */
	struct dentry *h_dentry;
	/*
	 * The mutex must be held when updating the progs attached to the hook.
	 */
	struct mutex mutex;
	/*
	 * The eBPF programs that are attached to this hook.
	 */
	struct bpf_prog_array __rcu *progs;
};

extern struct cgbpf_lsm_hook cgbpf_lsm_hooks_list[];

#define lsm_for_each_hook(hook) \
	for ((hook) = &cgbpf_lsm_hooks_list[0]; \
	     (hook) < &cgbpf_lsm_hooks_list[__MAX_LSM_HOOK_TYPE]; \
	     (hook)++)

#endif /* _CGBPF_LSM_H */ 
