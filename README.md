# Linux kernel exploitation experiments

This is a playground for the Linux kernel exploitation experiments.
Only basic methods. Just for fun.

__Contents:__

| __File__ | __Description__ |
| -------- | --------------- |
| __drill_mod.c__ | a small Linux kernel module with nice vulnerabilities, you can interact with it via a simple procfs interface |
| __drill.h__ | a header file describing the `drill_mod.ko` interface |
| __drill_test.c__ | a test for `drill_mod.ko`, it should also pass if the kernel is built with `CONFIG_KASAN=y` |
| __drill_uaf_callback.c__ | a basic use-after-free exploit invoking a callback in the freed `drill_item_t` struct; it performs control flow hijack and gains LPE |
| __drill_uaf_write_msg_msg.c__ | a basic use-after-free exploit writing data to the freed `drill_item_t` struct and overwriting a `msg_msg` kernel object; it performs out-of-bounds reading of the kernel memory |
| __drill_uaf_write_pipe_buffer.c__ | a basic use-after-free exploit writing data to the freed `drill_item_t` struct and overwriting a `pipe_buffer` kernel object; it performs the Dirty Pipe attack and gains LPE |
| __drill_uaf_write_dirty_pagetable.c__ | a basic use-after-free exploit writing data to the freed `drill_item_t` struct and overwriting a kernel page table; it performs the Dirty Pagetable attack and gains LPE |

N.B. Only basic exploit techniques here.

For some of them, Linux kernel security hardening should be disabled
(see [Troubleshooting](https://github.com/a13xp0p0v/kernel-hack-drill?tab=readme-ov-file#troubleshooting)).

License: GPL-3.0.

__Have fun!__

## Repositories

 - At GitHub: <https://github.com/a13xp0p0v/kernel-hack-drill>
 - At Codeberg: <https://codeberg.org/a13xp0p0v/kernel-hack-drill> (go there if something goes wrong with GitHub)
 - At GitFlic: <https://gitflic.ru/project/a13xp0p0v/kernel-hack-drill>

[1]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1792&desc=2

## Setup Guide

> [!WARNING]
> Do not use vulnerable `drill_mod.ko` on your production systems!

### Variant I: running on Ubuntu Server 24.04 virtual machine

Prepare the toolchain:
```
sudo apt install git make gcc
```

Obtain the `kernel-hack-drill` source code:
```
git clone https://github.com/a13xp0p0v/kernel-hack-drill.git
```

Compile the `drill_mod.ko` kernel module and other binaries:
```
cd kernel-hack-drill
make
```

Install and test `drill_mod.ko`:
```
sudo insmod drill_mod.ko
./drill_test
```

Ensure that you see these three lines in the output:
```
[+] drill_act is opened
	[...]
[+] looks like normal functionality in drill.ko works fine
	[...]
[+] looks like error handling in drill.ko works fine
```

Done! Now you can try the PoC-exploits for the vulnerabilities in `drill_mod.ko`.

### Variant II: running on a self-made virtual machine

#### 1. Create a rootfs image with `debootstrap`

Create a basic `Debian Bookworm` rootfs image:
```
cd ~ && touch rootfs.img
dd if=/dev/zero of=rootfs.img bs=1M count=2048
mkfs.ext4 rootfs.img
sudo mkdir /mnt/rootfs
sudo mount rootfs.img /mnt/rootfs
sudo apt install debian-archive-keyring
sudo debootstrap bookworm /mnt/rootfs http://deb.debian.org/debian/
# chroot into /mnt/rootfs and make additional tweaks, like adding a user
sudo umount /mnt/rootfs
```

#### 2. Prepare the Linux kernel

Get the needed tools:
```
sudo apt install git make gcc flex bison libncurses5-dev libssl-dev libelf-dev dwarves xz-utils zstd
```

Get a tarball from https://kernel.org, or get the source code with `git`:
```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git ~/linux
```

Create the kernel config:
```
make defconfig
```

For a Debian-based rootfs, enable the required options:
```
./scripts/config -e CONFIG_CONFIGFS_FS -e CONFIG_SECURITYFS
```

Build kernel:
```
make -j`nproc`
```

#### 3. Prepare the `drill_mod.ko` kernel module

Obtain the `kernel-hack-drill` source code:
```
git clone https://github.com/a13xp0p0v/kernel-hack-drill.git
```

Build:
```
cd kernel-hack-drill
KPATH=~/linux/ make
```

Here the `KPATH` environment variable contains the path to the Linux kernel source code that we got earlier.

#### 4. Start the virtual machine

Run the VM using `qemu-system-x86_64`:
```
qemu-system-x86_64 \
-s \
-enable-kvm \
-m 2G \
-cpu qemu64 \
-smp 2 \
-drive file=~/rootfs.img \
-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
-net nic,model=e1000 \
-nographic \
-no-reboot \
-kernel ~/linux/arch/x86/boot/bzImage \
-append "console=ttyS0 earlyprintk=serial net.ifnames=0 root=/dev/sda" \
-pidfile vm.pid \
2>&1 | tee vm.log
```

#### 5. Install and test `drill_mod.ko`

Transfer built files via `ssh`:
```
scp -r -P 10021 kernel-hack-drill user@localhost:/home/user/.
```

Install the module with `insmod`:
```
user@hostname ~> sudo insmod drill_mod.ko
[sudo] password for user:
[   23.925524] drill_mod: loading out-of-tree module taints kernel.
[   23.928631] drill: start hacking
user@hostname ~>
```

Run the tests:
```
./drill_test
```

Ensure you see these three lines in the output:
```
[+] drill_act is opened
	[...]
[+] looks like normal functionality in drill.ko works fine
	[...]
[+] looks like error handling in drill.ko works fine
```

Done! Now you can try the PoC-exploits for the vulnerabilities in `drill_mod.ko`.

### Troubleshooting

#### Handling the version mismatch issues

One day, you might encounter an error like this:
```
user@hostname ~> sudo insmod drill.ko
insmod: ERROR: could not insert module drill.ko: Invalid module format
user@hostname ~ [1]>
```

In that case, make sure that:
1. After fetching a new kernel with `git` you have rebuilt your module.
2. Your kernel path has not changed and the `KPATH` environment variable contains the correct path.

#### Disabling the Linux kernel security hardening features

Basic `ret2usr` attack requires:

 - Adding `pti=off nokaslr` boot arguments for the Linux kernel,
 - Running `qemu-system-x86_64` with `-cpu qemu64,-smep,-smap` arguments.
