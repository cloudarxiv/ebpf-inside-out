# Advanced Task 3: Network telemetry with eBPF
In this task, we will use eBPF to implement a simple network telemetry program that counts the number of packets and the number of
bytes received on a specific network interface. This task will help you understand how to use eBPF for network monitoring and telemetry. In this task, you will use MAPS to share data between the eBPF program and user space. 


## Running the eBPF program
Set the ifindex of the network interface you want to attach the XDP program to. You can find the ifindex by running `ip link` and looking for the interface name (e.g., `eth0`, `ens33`, etc.).

Compile the eBPF program and loader using Makefile:

```console
$ make
```

Then run the loader program by providing the ifindex of the network interface:

```console
$ sudo ./counter <ifindex>
```

By default, the program will show the number of packets received on the specified interface every second. You can stop the program by pressing `Ctrl+C`.

## Next steps
Your task is to extend this program to also print the number of bytes received every second on the specified interface. 

Placeholder has been provided in the code comments to achieve this.
