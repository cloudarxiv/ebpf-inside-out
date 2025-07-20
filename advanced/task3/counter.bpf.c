#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common_kern_user.h"

// Stats map
struct
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct datarec),
    .max_entries = 1,
} stats SEC(".maps");

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
    if (action >= XDP_ACTION_MAX)
        return XDP_ABORTED;

    if (action != XDP_PASS)
        return action;

    /* Lookup in kernel BPF-side return pointer to actual data record */
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (!rec)
        return XDP_ABORTED;

    lock_xadd(&rec->rx_packets, 1);
    /* Step #1: Add byte counters */

    return action;
}

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 action = XDP_PASS; /* Default action */

out:
    return xdp_stats_record_action(ctx, action);
}
