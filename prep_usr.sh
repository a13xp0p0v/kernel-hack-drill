#!/bin/sh
set -x

umount /sys/kernel/debug
mount -o uid=1000,gid=1000 -t debugfs none /sys/kernel/debug

insmod msuhack.ko

su -l a13x

