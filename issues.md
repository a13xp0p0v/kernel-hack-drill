Export of Github issues for [a13xp0p0v/kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill).

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

