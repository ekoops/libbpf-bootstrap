// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Meta */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/uio.h>
#include "task_iter.h"
#include "task_iter.skel.h"

static struct env {
	bool verbose;
} env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static const char *get_task_state(__u32 state)
{
	/* Taken from:
	 * https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L85
	 * There are a lot more states not covered here but these are common ones.
	 */
	switch (state) {
	case 0x0000:
		return "RUNNING";
	case 0x0001:
		return "INTERRUPTIBLE";
	case 0x0002:
		return "UNINTERRUPTIBLE";
	case 0x0200:
		return "WAKING";
	case 0x0400:
		return "NOLOAD";
	case 0x0402:
		return "IDLE";
	case 0x0800:
		return "NEW";
	default:
		return "<unknown>";
	}
}

static void handle_event(void *data, size_t *events_num)
{
	(*events_num)++;
	// struct task_info *tinfo = (struct task_info *)data;
	// if (tinfo->kstack_len <= 0) {
	// 	printf("Error getting kernel stack for task. Task Info. Pid: %d. Process Name: %s. Kernel Stack Error: %d. State: %s\n",
	// 	       tinfo->pid, tinfo->comm, tinfo->kstack_len, get_task_state(tinfo->state));
	// } else {
	// 	printf("Task Info. Pid: %d. Process Name: %s. Kernel Stack Len: %d. State: %s\n",
	// 	       tinfo->pid, tinfo->comm, tinfo->kstack_len, get_task_state(tinfo->state));
	// }
}

static int handle_ringbuf_event(void *ctx, void *data, size_t data_sz)
{
	handle_event(data, ctx);
	return 0;
}

static int read_from_ringbuf(const int iter_fd, struct ring_buffer *ringbuf)
{
	uint8_t byte = 0;
	const ssize_t ret = read(iter_fd, &byte, sizeof(byte));
	if (ret < 0) {
		return (int)ret;
	}
	int res = 0;
	while ((res = ring_buffer__poll(ringbuf, 100 /* timeout, ms */)) > 0) {
	}
	return res;
}

static int read_from_syscall(const int iter_fd, size_t *events_num)
{
	const int IOVEC_COUNT = 100;
	char buffers[IOVEC_COUNT][sizeof(struct task_info)];
	struct iovec iovecs[IOVEC_COUNT];
	for (int i = 0; i < IOVEC_COUNT; i++) {
		iovecs[i].iov_base = buffers[i];
		iovecs[i].iov_len = sizeof(buffers[i]);
	}
	while (true) {
		const ssize_t ret = readv(iter_fd, iovecs, IOVEC_COUNT);
		if (ret < 0) {
			if (errno == EAGAIN)
				continue;

			return -errno;
		}
		if (ret == 0) {
			return 0;
		}
		const size_t iovec_num = ret / sizeof(struct task_info);
		if ((double)iovec_num != (double)ret / sizeof(struct task_info)) {
			return -1;
		}
		for (size_t i = 0; i < iovec_num; i++) {
			handle_event(buffers[i], events_num);
		}
	}
}

static int parse_args(int argc, char **argv, pid_t *pid_filter, uint8_t *use_ringbuf, size_t *iters_num) {
	*pid_filter = 0;
	*use_ringbuf = 0;
	*iters_num = 1000;

	int err = 0;
	if (argc > 1) {
		errno = 0;
		*pid_filter = (pid_t)strtol(argv[1], NULL, 10);
		err = -errno;
		if (err != 0 || pid_filter < 0) {
			fprintf(stderr, "Failed to parse pid_filter '%s'\n", argv[1]);
			return err;
		}
	}

	if (argc > 2) {
		errno = 0;
		*use_ringbuf = (uint8_t)strtol(argv[2], NULL, 10);
		err = -errno;
		if (err != 0 || use_ringbuf < 0) {
			fprintf(stderr, "Failed to parse use_ringbuf '%s'\n", argv[1]);
			return err;
		}
	}

	if (argc > 3) {
		errno = 0;
		*iters_num = (uint8_t)strtol(argv[3], NULL, 10);
		err = -errno;
		if (err != 0 || iters_num < 0) {
			fprintf(stderr, "Failed to parse iters_num '%s'\n", argv[1]);
			return err;
		}
	}

	return err;
}

int main(int argc, char **argv)
{
	struct task_iter_bpf *skel;
	int iter_fd = -1;
	int ret;
	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;

	struct ring_buffer *ringbuf = NULL;

	pid_t pid_filter = 0;
	uint8_t use_ringbuf = 0;
	size_t iters_num = 0;
	int err = parse_args(argc, argv, &pid_filter, &use_ringbuf, &iters_num);
	if (err != 0) {
		return err;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application */
	skel = task_iter_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto cleanup;
	}

	/* Parameterize BPF code. */
	skel->rodata->use_ringbuf = use_ringbuf;

	/* Load & verify BPF programs */
	err = task_iter_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach BPF iterator program */
	memset(&linfo, 0, sizeof(linfo));
	linfo.task.pid = pid_filter; /* If the pid is set to zero, no filtering logic is applied */
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	skel->links.get_tasks = bpf_program__attach_iter(skel->progs.get_tasks, &opts);
	if (!skel->links.get_tasks) {
		err = -errno;
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// This is used to count the number of events.
	size_t events_num = 0;

	/* Set up ring buffer polling */
	if (use_ringbuf) {
		ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_ringbuf_event,
					   &events_num, NULL);
		if (!ringbuf) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto cleanup;
		}
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_tasks));
	if (iter_fd < 0) {
		err = -1;
		fprintf(stderr, "Failed to create iter\n");
		goto cleanup;
	}

	while (iters_num--) {
		if (use_ringbuf) {
			printf("Using ring buffer\n");
			ret = read_from_ringbuf(iter_fd, ringbuf);
		} else {
			printf("Using seq file\n");
			ret = read_from_syscall(iter_fd, &events_num);
		}
		if (ret < 0) {
			err = -ret;
			break;
		}
		printf("RETRIEVED EVENTS: %lu\n", events_num);
		events_num = 0;
		close(iter_fd);
		iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_tasks));
		if (iter_fd < 0) {
			err = -1;
			fprintf(stderr, "Failed to create iter at iter %lu\n", iters_num);
			goto cleanup;
		}
	}

cleanup:
	/* Clean up */
	close(iter_fd);
	task_iter_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
