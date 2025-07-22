# Basic Task 2: Using Kprobes with eBPF
In this task, we will explore the use of kprobes in eBPF programs. Kprobes allow us to define our own callback functions and dynamically insert probes into almost all functions in the kernel or modules. We will create a simple eBPF program that uses kprobes to log when a specific kernel function in our case `do_unlinkat` is called.

## Basic information
- Program type: `BPF_PROG_TYPE_KPROBE`
- Hook used: `kprobe/do_unlinkat`

More details here: [eBPF docs](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)

We will use kprobes to trace the `do_unlinkat` function and also use kretprobes to see the return value of the function.

## Running the example

Compile the eBPF program using the `ecc` command:

```console
$ ecc hello-kprobes.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Then load and run the program using the `ecli` command:

```console
$ sudo ecli run package.json
Running eBPF program...
```

While the program is running, open another terminal and run the following
```console
$ touch test1
$ rm test1
$ touch test2
$ rm test2
```

You can check the kernel trace log to see the output of the eBPF program:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

## Next steps

Now add more eBPF programs to trace other kernel functions using kprobes. Specifically, trace `do_mkdirat` and `do_rmdir` functions. You can follow the same pattern as shown in the `do_unlinkat` example.

Once done you can compile and run the program again:

```console
$ ecc hello-kprobes.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Running eBPF program...
```

You can then try creating and removing directories to see the output in the kernel trace log:

```console
$ mkdir test_dir1
$ rmdir test_dir1
$ mkdir test_dir2
$ rmdir test_dir2
```

Check the kernel trace log again:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```