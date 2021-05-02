# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SECURITY_CGBPF) := cgbpf.o

cgbpf-y := hooks.o ops.o lsm_fs.o

ccflags-y := -I$(srctree)/security/cgbpf -I$(srctree)/security/cgbpf/include
