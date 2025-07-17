#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES	101
#define TASK_COMM_LEN	64

struct counts {
	unsigned int rcount;
    unsigned int wcount;
    char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct counts);
} values SEC(".maps");

unsigned int map_curr_count = 0;

SEC("tp/syscalls/sys_enter_execve")
int execve_entry(struct trace_event_raw_sys_enter *ctx)
{
    struct counts count;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (map_curr_count >= MAX_ENTRIES) {
        return 0;
    }

    __builtin_memset(count.comm, '\x00', TASK_COMM_LEN);
    
    bpf_probe_read_user(count.comm, sizeof(count.comm), (void *)ctx->args[0]);
    
    if (bpf_strncmp(count.comm, sizeof("/usr/bin/bash"), "/usr/bin/bash") != 0) {
        return 0;
    }

    count.rcount = 0;
    count.wcount = 0;
    
    __sync_fetch_and_add(&map_curr_count, 1);
    bpf_map_update_elem(&values, &pid, &count, BPF_ANY);
    bpf_printk("PID %d (%s) started execve", pid, count.comm);  
}

SEC("tp/syscalls/sys_enter_exit")
int prog_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct counts *count;

    count = bpf_map_lookup_elem(&values, &pid);
    if (!count) {
        return 0;
    }

    bpf_printk("PID %d (%s), read count: %u, write count: %u",
               pid, count->comm, count->rcount, count->wcount);
    
    bpf_map_delete_elem(&values, &pid);
    __sync_fetch_and_sub(&map_curr_count, 1);

    return 0;
}

SEC("tp/syscalls/sys_enter_exit_group")
int prog_exit_group(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct counts *count;

    count = bpf_map_lookup_elem(&values, &pid);
    if (!count) {
        return 0;
    }

    bpf_printk("PID %d (%s), read count: %u, write count: %u",
               pid, count->comm, count->rcount, count->wcount);
    
    bpf_map_delete_elem(&values, &pid);
    __sync_fetch_and_sub(&map_curr_count, 1);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int read_entry(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct counts *count;

    count = bpf_map_lookup_elem(&values, &pid);
    if (!count) {
        return 0;
    } 
    
    count->rcount++;
    bpf_map_update_elem(&values, &pid, count, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int write_entry(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct counts *count;

    count = bpf_map_lookup_elem(&values, &pid);
    if (!count) {
        return 0;
    }

    count->wcount++;
    bpf_map_update_elem(&values, &pid, count, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";