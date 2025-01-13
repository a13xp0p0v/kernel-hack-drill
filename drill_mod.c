/*
 * The module for kernel exploiting experiments
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include "drill.h"

struct drill_t {
	struct proc_dir_entry *proc_entry;
	struct drill_item_t *item;
};

static struct drill_t drill; /* initialized by zeros */

static void drill_callback(void) {
	pr_notice("normal drill_callback 0x%lx!\n",
				(unsigned long)drill_callback);
}

static int drill_act_exec(long act, char *arg1_str, char *arg2_str)
{
	int ret = 0;

	switch (act) {
	case DRILL_ACT_ALLOC:
		drill.item = kzalloc(DRILL_ITEM_SIZE, GFP_KERNEL);
		if (drill.item == NULL) {
			pr_err("drill: not enough memory for item\n");
			ret = -ENOMEM;
			break;
		}

		pr_notice("drill: kmalloc'ed item at 0x%lx (size %d)\n",
				(unsigned long)drill.item, DRILL_ITEM_SIZE);

		drill.item->foo = 0x4141414141414141lu;
		drill.item->bar = 0x4242424242424242lu;
		drill.item->callback = drill_callback;
		break;

	case DRILL_ACT_CALLBACK:
		pr_notice("drill: exec callback 0x%lx for item 0x%lx\n",
					(unsigned long)drill.item->callback,
					(unsigned long)drill.item);
		drill.item->callback(); /* No check, BAD BAD BAD */
		break;

	case DRILL_ACT_SAVE_VAL:
		unsigned long val = 0;
		unsigned long offset = 0;
		unsigned long *data_addr = NULL;

		ret = kstrtoul(arg1_str, 0, &val);
		if (ret) {
			pr_err("drill: save_val: bad value %s\n", arg1_str);
			ret = -EINVAL;
			break;
		}

		ret = kstrtoul(arg2_str, 0, &offset);
		if (ret) {
			pr_err("drill: save_val: bad offset %s\n", arg2_str);
			ret = -EINVAL;
			break;
		}

		if (offset > DRILL_ITEM_SIZE -
				sizeof(struct drill_item_t) - sizeof(val)) {
			pr_err("drill: save_val: oob offset %ld\n", offset);
			ret = -EINVAL;
			break;
		}

		data_addr = (unsigned long *)(drill.item->data + offset);
		pr_notice("drill: save val 0x%lx to item 0x%lx at data offset %ld (at 0x%lx)\n",
					val, (unsigned long)drill.item,
					offset, (unsigned long)data_addr);
		*data_addr = val;

		pr_notice("drill: item dump:\n");
		print_hex_dump(KERN_INFO, "drill: ", DUMP_PREFIX_ADDRESS,
			       16, 1, drill.item, DRILL_ITEM_SIZE, false);
		break;

	case DRILL_ACT_FREE:
		pr_notice("drill: free item at 0x%lx\n",
					(unsigned long)drill.item);
		kfree(drill.item);
		break;

	case DRILL_ACT_RESET:
		drill.item = NULL;
		pr_notice("drill: set item ptr to NULL\n");
		break;

	default:
		pr_err("drill: invalid act %ld\n", act);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static ssize_t drill_act_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	char buf[DRILL_ACT_SIZE] = { 0 };
	size_t size = DRILL_ACT_SIZE - 1; /* last byte will be \0 anyway */
	char *buf_ptr = buf;
	char *act_str = NULL;
	char *arg1_str = NULL;
	char *arg2_str = NULL;
	unsigned long act = 0;

	BUG_ON(*ppos != 0);

	if (count < size)
		size = count;

	if (copy_from_user(&buf, user_buf, size)) {
		pr_err("drill: act_write: copy_from_user failed\n");
		return -EFAULT;
	}

	act_str = strsep(&buf_ptr, " ");

	arg1_str = strsep(&buf_ptr, " ");

	arg2_str = strsep(&buf_ptr, " ");

	ret = kstrtoul(act_str, 10, &act);
	if (ret) {
		pr_err("drill: act_write: parsing act failed\n");
		return ret;
	}

	ret = drill_act_exec(act, arg1_str, arg2_str);
	if (ret == 0)
		ret = count; /* success, claim we got the whole input */

	return ret;
}

static const struct proc_ops drill_act_fops = {
	.proc_write = drill_act_write,
};

static int __init drill_init(void)
{
	drill.proc_entry = proc_create("drill_act", S_IWUSR | S_IWGRP | S_IWOTH,
				       NULL, &drill_act_fops);
	if (!drill.proc_entry) {
		printk("failed to create /proc/drill_act");
		return -ENOMEM;
	}

	pr_notice("drill: start hacking\n");

	return 0;
}

static void __exit drill_exit(void)
{
	pr_notice("drill: stop hacking\n");
	proc_remove(drill.proc_entry);
}

module_init(drill_init)
module_exit(drill_exit)

MODULE_AUTHOR("Alexander Popov <alex.popov@linux.com>");
MODULE_DESCRIPTION("The module for kernel exploiting experiments");
MODULE_LICENSE("GPL v2");
