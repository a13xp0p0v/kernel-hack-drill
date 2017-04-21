#!/bin/sh
set -x

insmod msuhack.ko

echo $$ > /sys/kernel/debug/tracing/set_ftrace_pid
echo 1 > /sys/kernel/debug/tracing/events/kmem/kmalloc/enable
echo 1 > /sys/kernel/debug/tracing/events/kmem/kfree/enable
exec ./msuexploit

