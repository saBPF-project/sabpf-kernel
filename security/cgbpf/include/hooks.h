/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Systopia-UBC.
 *
 * The hooks for the cgroup LSM are declared in this file.
 *
 * This header MUST NOT be included directly and is included inline
 * for generating various data structurs for the hooks using the
 * following pattern:
 *
 * #define CGBPF_LSM_HOOK RET NAME(PROTO);
 * #include "hooks.h"
 * #undef CGBPF_LSM_HOOK
 *
 * Format:
 *
 *	CGBPF_LSM_HOOK(NAME, RET, PROTO, ARGS)
 *
 */

#define CGBPF_LSM_ARGS(args...) args

CGBPF_LSM_HOOK(file_permission,
	     int,
	     CGBPF_LSM_ARGS(struct file *file, int mask),
	     CGBPF_LSM_ARGS(file, mask)) 
CGBPF_LSM_HOOK(file_open,
	     int,
	     CGBPF_LSM_ARGS(struct file *file),
	     CGBPF_LSM_ARGS(file))
