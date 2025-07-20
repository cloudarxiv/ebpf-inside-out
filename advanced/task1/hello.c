// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct hello_bpf *skel;
	int err;

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = hello_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	if (argc == 2) {
		pid_t pid = atoi(argv[1]);
		// Step 1: Set target PID to trace specific process
		/* You can set the target PID in the BPF skeleton's rodata section 
		 * You will need to use the same global variable name as in the BPF program
		 */
	}

	/* Load & verify BPF programs */
	err = hello_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = hello_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	while (!exiting) {
		sleep(1);
	}

cleanup:
	/* Clean up */
	hello_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}