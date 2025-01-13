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
	pr_notice("normal drill_callback %lx!\n",
				(unsigned long)drill_callback);
}

static int drill_act_exec(long act, char *arg1_str, char *arg2_str)
{
	int ret = 0;

	switch (act) {
	case DRILL_ACT_ALLOC:
		drill.item = kmalloc(DRILL_ITEM_SIZE, GFP_KERNEL);
		if (drill.item == NULL) {
			pr_err("drill: not enough memory for item\n");
			ret = -ENOMEM;
			break;
		}

		pr_notice("drill: kmalloc'ed item at %lx (size %d)\n",
				(unsigned long)drill.item, DRILL_ITEM_SIZE);

		drill.item->callback = drill_callback;
		break;

	case DRILL_ACT_CALLBACK:
		pr_notice("drill: exec callback %lx for item %lx\n",
					(unsigned long)drill.item->callback,
					(unsigned long)drill.item);
		drill.item->callback(); /* No check, BAD BAD BAD */
		break;

	case DRILL_ACT_SAVE_VAL:
		pr_notice("drill: try to save val '%s' at offset '%s' for item %lx\n",
				arg1_str, arg2_str, (unsigned long)drill.item);

		break;

	case DRILL_ACT_FREE:
		pr_notice("drill: free item at %lx\n",
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
