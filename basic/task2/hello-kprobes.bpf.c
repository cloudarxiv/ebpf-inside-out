// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(probe_do_unlinkat_entry, int dfd, struct filename *f)
{
	pid_t pid;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
	filename = BPF_CORE_READ(f, name);
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(probe_do_unlinkat_exit, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}

// Step 1: Add a kprobe for do_mkdirat
/**
 * Note that mkdir has different parameters than do_unlinkat.
 * You will need to adjust the parameters in the kprobe function accordingly.
 * 
 * You can see prototypes in the kernel source code or documentation.
 * https://elixir.bootlin.com/linux/v6.15.6/source/fs/internal.h#L62
 */



// Step 2: Add a kprobe for do_rmdir
/**
 * Similar to do_mkdirat, you will need to adjust the parameters for do_rmdir.
 * 
 * The function prototype can be found in the kernel source code or documentation.
 * https://elixir.bootlin.com/linux/v6.15.6/source/fs/internal.h#L57
 */




