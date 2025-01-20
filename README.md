# Linux kernel exploitation experiments

This is a playground for the Linux kernel exploitation experiments.
Only basic methods. Just for fun.

__Contents:__

  - __drill_mod.c__ - a small Linux kernel module with nice vulnerabilities. You can interact with it via a simple procfs interface.
  - __drill.h__ - a header file describing the `drill_mod.ko` interface.
  - __drill_test.c__ - a test for `drill_mod.ko`. It should also pass if the kernel is built with `CONFIG_KASAN=y`.
  - __drill_exploit_uaf_callback.c__ - a basic use-after-free exploit overwriting a callback in the `drill_item_t` struct.

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
