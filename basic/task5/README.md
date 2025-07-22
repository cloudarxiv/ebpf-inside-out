# Basic Task 3: Using eBPF for high speed network packet processing
XDP (eXpress Data Path) is a high-performance, programmable data path in the Linux kernel, designed for packet processing at the network interface level. By attaching eBPF programs directly to network device drivers, XDP can intercept and handle packets before they reach the kernel’s networking stack. This allows for extremely low-latency and efficient packet processing, making it ideal for tasks like DDoS defense, load balancing, and traffic filtering. In fact, XDP can achieve throughput as high as 24 million packets per second (Mpps) per core.

## Basic information
- Program type: `BPF_PROG_TYPE_XDP`
- Hook used: `xdp`

## Setup and running the example
Set the ifindex of the network interface you want to attach the XDP program to. You can find the ifindex by running `ip link` and looking for the interface name (e.g., `eth0`, `ens33`, etc.).

Compile the eBPF program using the `ecc` command:

```console
$ ecc hello-xdp.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Then load and run the program using the `ecli` command:

```console
$ sudo ecli run package.json
Running eBPF program...
```

Create a new terminal, run some commands, and then exit the shell you should check the kernel trace log to see the output of the eBPF program:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```

You can also modify the eBPF program to drop packets by returning `XDP_DROP` instead of `XDP_PASS`. This will prevent the packets from being processed further in the kernel, effectively dropping them. Note that dropping packets can lead to network disruptions, so use this feature with caution.