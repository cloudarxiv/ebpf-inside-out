/* SPDX-License-Identifier: Apache-2.0 */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

typedef int pid_t;

// Step 1: Add a global variable to store a Superman's ID (Default to 0)
/// @description "Superman's PID"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int lex_luthor(struct trace_event_raw_sys_enter *ctx)
{
    char local_buf[256];
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // Step 2: Only track Superman

    /*
    * The format of the args can be found in:
    * /sys/kernel/debug/tracing/events/syscalls/sys_enter_write
    *
    * it is as follows:
    * args[0]: unsigned int fd; // File descriptor
    * args[1]: const char *buf; // Write buffer
    * args[2]: size_t count;    // Number of bytes to write
    */
    int fd = ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    size_t count = ctx->args[2];

    int ret = bpf_probe_read_user_str(local_buf, sizeof(local_buf), buf);
    if (ret < 0) {
        bpf_printk("Failed to read buffer: %d\n", ret);
        return 0;
    }

    // Step 4: Remove this output
    bpf_printk("Lex Luthor: Superman said '%s' from PID %d.\n", local_buf, pid);

    // Step 3: Change the output to "I am Batman" if the buffer contains "I am Superman"
    /* You may use Memory Helpers and Utility Helpers to achieve this
    *  https://docs.ebpf.io/linux/helper-function/
    */


	return 0;
}
