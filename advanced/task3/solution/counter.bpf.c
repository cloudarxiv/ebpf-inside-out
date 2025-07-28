#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common_kern_user.h"

// Stats map
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, 1);
} stats SEC(".maps");

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

static __always_inline
void xdp_stats_record_action(struct xdp_md *ctx)
{
    int key = 0;
    /* Lookup in kernel BPF-side return pointer to actual data record */
    struct datarec *rec = bpf_map_lookup_elem(&stats, &key);
    if (!rec)
        return;

    lock_xadd(&rec->rx_packets, 1);
    /* Step #2: Add byte counters */
    __u64 bytes = ctx->data_end - ctx->data;
    lock_xadd(&rec->rx_bytes, bytes);
}

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int action = XDP_PASS;
out:
    xdp_stats_record_action(ctx);
    return action;
}
