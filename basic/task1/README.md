# Basic Task 1: A Simple Hello World eBPF Program

We will start with a simple eBPF program that prints a message in the kernel trace log when a write system call is done. We will use the eunomia-bpf compiler toolchain to compile it into a BPF bytecode file along with a package.json file that contains details about its hookpoints, eBPF programs, etc. We can then load and run the program using the ecli tool. For the sake of the example, we can temporarily disregard the user space program.

## Basic information
- Program type: `BPF_PROG_TYPE_TRACEPOINT`
- Hook used: `tp/syscalls/sys_enter_write`

### Tracepoint primer
Tracepoints are a kernel static instrumentation technique, technically just trace functions placed in the kernel source code, which are essentially probe points with control conditions inserted into the source code, allowing post-processing with additional processing functions. For example, the most common static tracing method in the kernel is printk, which outputs log messages. For example, there are tracepoints at the start and end of system calls, scheduler events, file system operations, and disk I/O. Tracepoints were first introduced in Linux version 2.6.32 in 2009. Tracepoints are a stable API and their number is limited.

## Running the example

Compile the eBPF program using the `ecc` command:

```console
$ ecc ecc hello.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Then load and run the program using the `ecli` command:

```console
$ sudo ecli run package.json
Running eBPF program...
```

While the program is running, you can check the kernel trace log to see the output of the eBPF program:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "BPF triggered sys_enter_write"
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: Hello eBPF: sys_enter_write triggered BPF from PID 3840345.
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: Hello eBPF: sys_enter_write triggered BPF from PID 3840345.
```

## Next steps

Now extend the eBPF program to print only when a specific process (e.g., `bash`) performs a write operation. You can do this by checking the PID of the process in the eBPF program and only printing the message if it matches the desired PID. To accompilish this you should use global variables.

Global variables act argument passing mechanism in eBPF programs, allowing userspace programs to provide parameters during eBPF program loading. This is very useful when filtering specific conditions or modifying the behavior of eBPF programs.

Steps have been provided in the program comments to achieve this.

Once implemented you can see that while running the program you can pass the PID of the process you want to filter.

```console
$ ecli package.json -h
Usage: hello_bpf [--help] [--version] [--verbose] [--pid_target VAR]

Optional arguments:
  -h, --help    shows help message and exits 
  -v, --version prints version information and exits 
  --verbose     prints libbpf debug information 
  --pid_target  Process ID to trace 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.
```

You can then run the program with a specific PID:

```console
$ sudo ecli package.json --pid_target 12345
Running eBPF program... 
```

You can then check the kernel trace log again to see if the output is filtered based on the specified PID
```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              <...>-12345 [010] d... 3220701.101143: bpf_trace_printk: Hello eBPF: sys_enter_write triggered BPF from PID 12345.
``` 
