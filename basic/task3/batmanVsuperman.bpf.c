/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

typedef int pid_t;

pid_t target_pid = 0; // Global variable to store the target PID

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int lex_luthor(struct trace_event_raw_sys_enter *ctx)
{
    char local_buf[256];
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (target_pid != 0 && pid != target_pid) {
        // If a target PID is set and the current PID does not match, skip
        return 0;
    }

    int fd = ctx->args[0]; // File descriptor passed to write
    const char *buf = (const char *)ctx->args[1]; // Buffer passed to write
    size_t count = ctx->args[2]; // Count of bytes passed to write

    int ret = bpf_probe_read_user_str(local_buf, sizeof(local_buf), buf);

    if (ret < 0) {
        bpf_printk("Failed to read buffer: %d\n", ret);
        return 0; // Skip if reading the buffer fails
    }

    if (bpf_strncmp(local_buf, sizeof("I am Superman\n"), "I am Superman\n") == 0 && fd == 1) {
        bpf_probe_write_user(buf,     "I am Batman  \n", sizeof("I am Batman  \n"));
    }

	return 0;
}
