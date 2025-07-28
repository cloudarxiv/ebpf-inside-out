/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef int pid_t;

// Step 1: Add a global variable to store a process ID (Default to 0)
/// @description "Process ID to trace"
const volatile pid_t tpid = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	// Step 2: Only allow the given PID to print
	if (tpid != pid) {
		return 0;
	}

	bpf_printk("Hello eBPF: sys_enter_write triggered BPF from PID %d.\n", pid);
	return 0;
}
