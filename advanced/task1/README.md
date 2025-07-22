# Advanced Task 1: Making our own Loader for eBPF Programs using libbpf
In this task, we will learn how kernel-space and user-space eBPF programs work together. We will also learn how to use the native libbpf to develop user-space programs, package eBPF applications into executable files, and distribute them across different kernel versions.

## libbpf primer
libbpf is a C language library to assist in loading and running eBPF programs. It provides a set of C APIs for interacting with the eBPF system, allowing developers to write user-space programs more easily to load and manage eBPF programs. These user-space programs are typically used for system performance analysis, monitoring, or optimization.

## Running the eBPF program
Use the following commands to compile and run the eBPF program using your loader:

```console
$ git submodule update --init --recursive
$ make
$ sudo ./hello
```

## Next Steps
Now that you have a basic understanding of how to use libbpf, let's try to implement process filtering in the eBPF program and use the loader to update the filtering pid just like we did in basic task 1.