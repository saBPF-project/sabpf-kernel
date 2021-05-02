// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Systopia-UBC.
 */
 
 #include <linux/filter.h>
 #include <linux/bpf.h>
 
 const struct bpf_prog_ops cgroup_lsm_prog_ops = {
 };
 
 const struct bpf_verifier_ops cgroup_lsm_verifier_ops = {
 };
