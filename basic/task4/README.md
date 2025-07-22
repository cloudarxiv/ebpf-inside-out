# Basic Task 4: Using eBPF maps to store and retrieve data
In this task, we will create an eBPF programs that uses eBPF maps. There are five eBPF programs in this task, each attached to diferent tracepoints. When a `/usr/bin/bash` process is started, the eBPF program will use the pid as the key and store the process name in a map. During reads and writes of the process the eBPF program will also update the map with the current count of reads and writes. When the process exits, the eBPF program will print the pid, process name, and the number of reads and writes.

## Basic information
- Program type: `BPF_PROG_TYPE_TRACEPOINT`
- Hook used: `tp/syscalls/sys_enter_execve`, `tp/syscalls/sys_enter_exit`, `tp/syscalls/sys_enter_exit_group`, `tp/syscalls/sys_enter_read`, `tp/syscalls/sys_enter_write
- Map type: `BPF_MAP_TYPE_HASH`

## Setup and running the example

Compile the eBPF program using the `ecc` command:

```console
$ ecc hello-maps.bpf.c
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

