# Advanced Task 2: Parsing and Dropping ICMP Packets with eBPF
In this task, we will extend our understanding of eBPF by implementing a program that parses ICMP packets and drops every odd packets.

To achieve this you have to implement the following:
1. **Implement the `parse_icmphdr` function**: This function should parse the ICMP header and return the ICMP type.
2. **Modify the main function**: In the main function, after parsing the Ethernet and IP headers, check if the packet is an ICMP echo request. If it is, check the sequence number of the ICMP packet. If the sequence number is odd, drop the packet.

## Running the eBPF program
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

After running the program, you can test it by sending ICMP echo requests (pings) to the interface. You should see that every odd ping is dropped, while even pings are allowed through.