# Linux kernel exploitation experiments

This is a playground for the Linux kernel exploitation experiments.
Only basic methods. Just for fun.

__Contents:__

  - __drill_mod.c__ - a small Linux kernel module with nice vulnerabilities. You can interact with it via a simple procfs interface.
  - __drill.h__ - a header file describing the `drill_mod.ko` interface.
  - __drill_test.c__ - a test for `drill_mod.ko`. It should also pass if the kernel is built with `CONFIG_KASAN=y`.
  - __drill_uaf_callback.c__ - a basic use-after-free exploit invoking a callback in the freed `drill_item_t` struct.
  - __drill_uaf_write_msg_msg.c__ - a basic use-after-free exploit writing data to the freed `drill_item_t` struct and overwriting a `msg_msg` kernel object.
  - __drill_uaf_write_pipe_buffer.c__ - a basic use-after-free exploit writing data to the freed `drill_item_t` struct and overwriting a `pipe_buffer` kernel object.

N.B. Only basic exploit techniques here.

So compile your kernel with `x86_64_defconfig` and run it with `pti=off nokaslr` boot arguments.

Also don't forget to run `qemu-system-x86_64` with `-cpu qemu64,-smep,-smap`.

License: GPL-3.0.

Have fun!

## Repositories

 - At GitHub: <https://github.com/a13xp0p0v/kernel-hack-drill>
 - At Codeberg: <https://codeberg.org/a13xp0p0v/kernel-hack-drill> (go there if something goes wrong with GitHub)
 - At GitFlic: <https://gitflic.ru/project/a13xp0p0v/kernel-hack-drill>

[1]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1792&desc=2

## Setup Guide

> [!WARNING]
> Do not run this module on your host!

### Running on Ubuntu Server 24 VM

Prepare toolchain:
```bash
sudo apt install git make gcc
```
Obtain `kernel-hack-drill` sources:
```bash
git clone https://github.com/a13xp0p0v/kernel-hack-drill.git
```
Compile the __drill__ module and other binaries:
```bash
cd kernel-hack-drill
make
```
Install and test the __drill__ module:
```bash
sudo insmod drill_mod.ko 
./drill_test
```
Ensure that you see these three lines in the output:
```bash
[+] drill_act is opened
	[...]
[+] looks like normal functionality in drill.ko works fine
	[...]
[+] looks like error handling in drill.ko works fine
```

### Running on a VM with the `debootstrap` image

#### Rootfs setup

Create a basic Debian bookworm image:
```bash
cd ~ && touch rootfs.img
dd if=/dev/zero of=rootfs.img bs=1M count=2048
mkfs.ext4 rootfs.img 
sudo mkdir /mnt/rootfs
sudo mount rootfs.img /mnt/rootfs
sudo apt install debian-archive-keyring
sudo debootstrap bookworm /mnt/rootfs http://deb.debian.org/debian/
# chroot into /mnt/rootfs and make additional tweaks, like adding user
sudo umount /mnt/rootfs
```

#### Kernel Setup

##### Obtain utilites and sources

Prepare build requirements:
```bash
sudo apt install git make gcc flex bison libncurses5-dev libssl-dev libelf-dev dwarves xz-utils zstd
```
Get the tarball from https://kernel.org, or get the source tree with `git`:
```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git ~/linux
```

##### Build

Create the kernel config:
```bash
make defconfig
```
For a Debian-based rootfs, enable the required configurations:
```
./scripts/config -e CONFIG_CONFIGFS_FS -e CONFIG_SECURITYFS
```
Build the kernel:
```
make olddefconfig
make -j`nproc` 
```

#### Setting up the drill module

Obtain `kernel-hack-drill` sources:
```
git clone https://github.com/a13xp0p0v/kernel-hack-drill.git
```
Build:
```bash
cd kernel-hack-drill
make KPATH=~/linux/
``` 

#### Start the virtual machine

Run the VM with `qemu`:
```bash
qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel ~/linux/arch/x86/boot/bzImage \
	-append "pti=off nokaslr console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file=~/rootfs.img \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic \
	-pidfile vm.pid \
	2>&1 | tee vm.log
```

#### Add the drill

Transfer built files via `ssh`:
```
scp -r -P 10021 kernel-hack-drill user@localhost:/home/user/.
```
Install the module with `insmod`:
```bash
user@hostname ~> sudo insmod drill_mod.ko
[sudo] password for user: 
[   23.925524] drill_mod: loading out-of-tree module taints kernel.
[   23.928631] drill: start hacking
user@hostname ~>
```

#### Test your setup

Run the tests:
```bash
./drill_test
```
Ensure you see these three lines in the output:
```bash
[+] drill_act is opened
	[...]
[+] looks like normal functionality in drill.ko works fine
	[...]
[+] looks like error handling in drill.ko works fine
```

### Handling version missmatch issues

One day, you might encounter this error:
```bash
user@hostname ~> sudo insmod drill.ko
insmod: ERROR: could not insert module drill.ko: Invalid module format
user@hostname ~ [1]>
```
In such a case, make sure that:
1. After fetching a new kernel with `git` you  have __rebuilt__ your module.
2. Your kernel path has not changed, or the __KPATH__ contains the correct path.

## Usage

Now try to exploit the vulnerabilities in drill_mod.ko after the setup is complete:
- __drill_uaf_callback__
- __drill_uaf_write_msg_msg__
- __drill_uaf_write_pipe_buffer.c__ -
