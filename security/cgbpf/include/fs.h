/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _CGBPF_LSM_FS_H
#define _CGBPF_LSM_FS_H

#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/types.h>

bool is_cgbpf_lsm_hook_file(struct file *f);

/*
 * The name of the directory created in securityfs
 *
 *	/sys/kernel/security/<dir_name>
 */
#define CGBPF_LSM_SFS_NAME "cgbpf"

#endif /* _CGBPF_LSM_FS_H */ 
