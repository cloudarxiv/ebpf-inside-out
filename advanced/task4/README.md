# Advanced Task 4: Packet redirection with eBPF
In this task, we will use eBPF to redirect packets from one socket to another without going through the kernel's networking stack. This task will help you understand how to use eBPF for packet manipulation and redirection.

## Basic information
- Program types: `BPF_PROG_TYPE_SOCK_OPS`, `BPF_PROG_TYPE_SK_MSG`
- Hook used: `sock_ops`, `sk_msg`

## Overview
### `BPF_MAP_TYPE_SOCKHASH`
The `BPF_MAP_TYPE_SOCKHASH` is a special type of map that allows you to store socket objects. It can be used to redirect packets from one socket to another. This is useful for implementing features like load balancing, packet filtering, and more.

In this task, there are two main eBPF programs:

- The first program is an eBPF sockops program. It is invoked when a socket operation occurs, such as when a socket is created or connected. In our case, it is used to store socket details of all locally connected sockets in a `BPF_MAP_TYPE_SOCKHASH` map.
- The second program is an eBPF sk_msg program. It is invoked when a message is sent on a socket preset in the `BPF_MAP_TYPE_SOCKHASH` map. We use this program to redirect packets from one socket to another without going through the kernel's networking stack.

## Running the eBPF program
Compile the eBPF programs using Makefile:

```console
$ make -j
```

For this task `load.sh` and `unload.sh` scripts are provided to load and unload the eBPF programs. 

Load the eBPF programs using the `load.sh` script:

```console
$ sudo ./load.sh
```

Once you are done with the task, you can unload the eBPF programs using the `unload.sh` script:

```console
$ sudo ./unload.sh
```

## Observations

After loading the eBPF programs, you can observe the behavior of the socket operations and message redirection. You can use tools  `tcpdump` to monitor the network traffic and see how packets are redirected from one socket to another.

Perform the following steps two times. First without the eBPF programs loaded and then with the eBPF programs loaded to see the difference in behavior.

### Steps to observe the network traffic:
1. In a terminal run tcpdump to monitor the traffic on localhost interface and port 5001:

```console
$ sudo tcpdump -i lo port 5001
```

2. In another terminal, run a iperf3 server on port 5001:

```console
$ iperf3 -s 127.0.0.1 -p 5001 -4
```

3. In a third terminal, run a iperf3 client to send traffic to the server:

```console
$ iperf3 -c 127.0.0.1 -p 5001 -4
```

4. You should see the request and response packets in the `tcpdump` output, indicating that the packets are being redirected correctly.

You will observe that with the eBPF programs loaded, the number of packets sent and recieved is very less as only TCP connection establishment and termination packets are sent thourgh the kernel's networking stack. The actual data packets are redirected directly between the sockets without going through the kernel's networking stack. You will also see transfer speed difference in the `iperf3` output. In this case, the transfer speed is slightly lower with the eBPF programs loaded, which indicates that eBPF is not suitable for all network use cases, rather some specific use cases and scenarios.

