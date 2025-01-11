#!/bin/sh
set -x

insmod drill_mod.ko

echo $$ > /sys/kernel/debug/tracing/set_ftrace_pid
echo 1 > /sys/kernel/debug/tracing/events/kmem/kmalloc/enable
echo 1 > /sys/kernel/debug/tracing/events/kmem/kmalloc_node/enable
echo 1 > /sys/kernel/debug/tracing/events/kmem/kmem_cache_alloc/enable
echo 1 > /sys/kernel/debug/tracing/events/kmem/kmem_cache_alloc_node/enable
echo 1 > /sys/kernel/debug/tracing/events/kmem/kmem_cache_free/enable
echo 1 > /sys/kernel/debug/tracing/events/kmem/kfree/enable
exec /home/user/drill_exploit_uaf

