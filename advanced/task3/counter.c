#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include "common_kern_user.h"
#include "counter.skel.h" // The generated skeleton

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static const char *xdp_action_names[XDP_ACTION_MAX] = {
    [XDP_ABORTED] = "XDP_ABORTED",
    [XDP_DROP] = "XDP_DROP",
    [XDP_PASS] = "XDP_PASS",
    [XDP_TX] = "XDP_TX",
    [XDP_REDIRECT] = "XDP_REDIRECT",
    [XDP_UNKNOWN] = "XDP_UNKNOWN",
};

const char *action2str(__u32 action)
{
    if (action < XDP_ACTION_MAX)
        return xdp_action_names[action];
    return NULL;
}

/* Timing helpers */
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0)
    {
        fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
        exit(EXIT_FAIL);
    }
    return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record
{
    __u64 timestamp;
    struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record
{
    struct record stats[1]; /* Step#2: Add more stats records */
};

static double calc_period(struct record *r, struct record *p)
{
    double period_ = 0;
    __u64 period = 0;

    period = r->timestamp - p->timestamp;
    if (period > 0)
        period_ = ((double)period / NANOSEC_PER_SEC);

    return period_;
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev)
{
    struct record *rec, *prev;
    double period;
    __u64 packets;
    double pps; /* packets per sec */
    /* Step #1: Add byte counters */

    /* Step #2: Print other XDP actions stats  */
    for (int i = 0; i < 1; i++)
    {
        char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
                    " period:%f\n";
        const char *action = action2str(i);
        rec = &stats_rec->stats[i];
        prev = &stats_prev->stats[i];

        period = calc_period(rec, prev);
        if (period == 0)
            return;

        packets = rec->total.rx_packets - prev->total.rx_packets;
        /* Step #1: Add byte counters */

        bytes = rec->total.rx_bytes - prev->total.rx_bytes;
        /* Step #1: Add byte counters */

        /* Step #1: Modify according to byte counters */
        printf(fmt, action, rec->total.rx_packets, pps, period);
    }
}

void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
    if ((bpf_map_lookup_elem(fd, &key, value)) != 0)
    {
        fprintf(stderr,
                "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
    }
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
    struct datarec value;

    /* Get time as close as possible to reading map contents */
    rec->timestamp = gettime();

    switch (map_type)
    {
    case BPF_MAP_TYPE_ARRAY:
        map_get_value_array(fd, key, &value);
        break;
    default:
        fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
                map_type);
        return false;
        break;
    }

    rec->total.rx_packets = value.rx_packets;
    /* Step #1: Add byte counters */
    return true;
}

static void stats_collect(int map_fd, __u32 map_type,
                          struct stats_record *stats_rec)
{

    __u32 key = XDP_PASS;

    /* Step #2: Collect other XDP actions stats  */
    for (key = 0; key < 1; key++)
    {
        map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
    }
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
    struct stats_record prev, record = {0};

    /* Trick to pretty printf with thousands separators use %' */
    setlocale(LC_NUMERIC, "en_US");

    /* Print stats "header" */
    printf("\n");
    printf("%-12s\n", "XDP-action");

    /* Get initial reading quickly */
    stats_collect(map_fd, map_type, &record);
    usleep(1000000 / 4);

    while (!exiting)
    {
        prev = record; /* struct copy */
        stats_collect(map_fd, map_type, &record);
        stats_print(&record, &prev);
        sleep(interval);
        clear();
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load and attach the BPF program
    struct pingdrop_bpf *skel = pingdrop_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex < 0)
    {
        perror("if_nametoindex");
        pingdrop_bpf__destroy(skel);
        return 1;
    }

    if (bpf_program__attach_xdp(skel->progs.xdp, ifindex) < 0)
    {
        fprintf(stderr, "Failed to attach XDP program\n");
        pingdrop_bpf__destroy(skel);
        return 1;
    }

    int stats_map_fd = bpf_map__fd(skel->maps.stats);

    stats_poll(stats_map_fd, info.type, interval);

    // Cleanup and detach
    bpf_xdp_detach(ifindex, 0, NULL);
    pingdrop_bpf__detach(skel);
    pingdrop_bpf__destroy(skel);
    return 0;
}