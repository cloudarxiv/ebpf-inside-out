#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <locale.h>
#include <net/if.h>
#include "common_kern_user.h"
#include "counter.skel.h" // The generated skeleton

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
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
        exit(EXIT_FAILURE);
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
    struct record stats[1]; /* Step#3: Add more stats records */
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

    /* Step #4: Modify to also print bytes per second */
    char *fmt = "%'11lld pkts (%'10.0f pps) period:%f\n";
    
    rec = &stats_rec->stats[0];
    prev = &stats_prev->stats[0];

    period = calc_period(rec, prev);
    if (period == 0)
        return;

    packets = rec->total.rx_packets - prev->total.rx_packets;
    pps = packets / period; /* packets per second */

    printf(fmt, rec->total.rx_packets, pps, period);
}

void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
    if ((bpf_map_lookup_elem(fd, &key, value)) != 0)
    {
        fprintf(stderr,
                "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
    }
}

static void stats_collect(int map_fd,
                          struct stats_record *stats_rec)
{

    struct datarec value;

    stats_rec->stats[0].timestamp = gettime();
    
    map_get_value_array(map_fd, 0, &value);
    
    /* Step #5: Collect byte records */
    stats_rec->stats[0].total.rx_packets = value.rx_packets;
}

static void stats_poll(int map_fd, int interval)
{
    struct stats_record prev, record = {0};

    /* Trick to pretty printf with thousands separators use %' */
    setlocale(LC_NUMERIC, "en_US");

    /* Print stats "header" */
    printf("\n");
    printf("%-12s\n", "XDP-action");

    /* Get initial reading quickly */
    stats_collect(map_fd, &record);
    usleep(1000000 / 4);

    while (!exiting)
    {
        prev = record; /* struct copy */
        stats_collect(map_fd, &record);
        stats_print(&record, &prev);
        sleep(interval);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    int interval = 1;

    const char *ifname = argv[1];

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load and attach the BPF program
    struct counter_bpf *skel = counter_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex < 0)
    {
        perror("if_nametoindex");
        counter_bpf__destroy(skel);
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_parser_func);
    if (prog_fd < 0)
    {        
        fprintf(stderr, "Failed to get program fd\n");
        counter_bpf__destroy(skel);
        return 1;
    }

    if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL) < 0)
    {
        fprintf(stderr, "Failed to attach XDP program to interface %s\n", ifname);
        counter_bpf__destroy(skel);
        return 1;
    }

    int stats_map_fd = bpf_map__fd(skel->maps.stats);

    stats_poll(stats_map_fd, interval);

    // Cleanup and detach
    bpf_xdp_detach(ifindex, 0, NULL);
    counter_bpf__detach(skel);
    counter_bpf__destroy(skel);
    return 0;
}