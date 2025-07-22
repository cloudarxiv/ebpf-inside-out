# Basic Task 3: Hijacking write system calls with eBPF
In this task, we will create an eBPF program that hijacks the `write` system call and modifies the output to say "I am Batman" instead of "I am Superman". This is a fun exercise to demonstrate how eBPF can be used to intercept and modify system calls.

## Basic information
- Program type: `BPF_PROG_TYPE_TRACEPOINT`
- Hook used: `tp/syscalls/sys_enter_write`

## Setup and running the example
First, add logic to the eBPF program to only track the `write` system calls made by superman process.

Then compile the eBPF program using the `ecc` command:

```console
$ ecc justice-league.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

In another console, compile and run the superman program. First it will print it's PID and then
it will print "I am Superman" repeatedly:

```console
$ clang superman.c -o superman
$ ./superman
```

Then load and run the program using the `ecli` command:

```console
$ sudo ecli run package.json --superman=12345
Running eBPF program...
```

While the program is running, you can check the kernel trace log to see the output of the eBPF program:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: Batman: Superman said 'I am Superman' from PID 12345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: Batman: Superman said 'I am Superman' from PID 12345.
```

## Next steps

Now extend the eBPF program to print "I am Batman" instead of "I am Superman". You can do this by modifying the output string in the eBPF program.

Once implemented, you can see that while running the program, the output will be modified:

```console
$ ecc justice-league.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json --superman=12345
Running eBPF program...
```

The output of the superman process will now be:

```console
$ ./superman
Pid: 12345
I am Superman
I am Superman
I am Superman
I am Batman
I am Batman
I am Batman
```

