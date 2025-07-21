# eBPF inside-out
This repository contains eBPF tutorials and examples that introduces eBPF concepts for tracing, security, networking, and more.
It uses eunomia-bpf and libbpf to show how to write eBPF programs in C and load them into the kernel.

## Getting Started
To get started, follow these steps:

```
git clone https://github.com/cloudarxiv/ebpf-inside-out.git
cd ebpf-inside-out
git submodule update --init --recursive
make install-deps
make setup-tools
```

## Going throgh the examples
The examples are organized into three directories:
- `basic`
- `advanced`
- `extras`

Each of these directories contains subdirectories for different eBPF concepts and use cases. Moreover they contains tasks that can be done for learning purposes. We recommend going through the examples in order, starting with the `basic` directory and progressing to the `advanced` and `extras` directories.
