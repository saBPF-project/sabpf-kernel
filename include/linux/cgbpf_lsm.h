/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_CGBPF_LSM_H
#define _LINUX_CGBPF_LSM_H

#include <linux/bpf.h>

#ifdef CONFIG_SECURITY_CGBPF
extern int cgbpf_lsm_fs_initialized;
#endif /* CONFIG_SECURITY_CGBPF */

#endif /* _LINUX_CGBPF_LSM_H */
