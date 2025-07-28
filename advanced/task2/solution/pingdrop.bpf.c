/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header returns the type of its contents
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, protocol for IPv4), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
										void *data_end,
										struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	if (eth + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	__u16 h_proto = eth->h_proto; /* network-byte-order */
	return h_proto;				  /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/* Step 1: Implement icmp parser and return type of icmp packet */
static __always_inline int parse_icmphdr(struct hdr_cursor *nh, void *data_end, struct icmphdr **icmphdr)
{
	struct icmphdr *icmp = nh->pos;
	int hdrsize = sizeof(*icmp);

	if (icmp + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmphdr = icmp;

	return icmp->type;
}


/// @ifindex 2
/// @flags 0
SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct icmphdr *icmph; /* To be used in Step 2 */

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?).
	 */
	/* Assignment additions go below here */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IP))
	{
		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		/* Step 2
		* Check if the ICMP packet is an echo request
		*/
		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		/* Step 3: if the packet is icmp and sequence number is odd then drop it */
		if (bpf_ntohs(icmph->un.echo.sequence)% 2 == 1)
			action = XDP_DROP;
	}

out:
	return action;
}

char _license[] SEC("license") = "GPL";