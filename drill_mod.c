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
	struct drill_item_t **items;
};

static struct drill_t drill; /* initialized by zeros */

static void drill_callback(void) {
	pr_notice("normal drill_callback 0x%lx!\n",
				(unsigned long)drill_callback);
}

static int drill_act_exec(long act,
			  char *arg1_str,
			  char *arg2_str,
			  char *arg3_str)
{
	int ret = 0;
	unsigned long n = 0;
	unsigned long val = 0;
	unsigned long offset = 0;
	unsigned long *data_addr = NULL;

	if (!arg1_str) {
		pr_err("drill: item number is missing\n");
		return -EINVAL;
	}

	ret = kstrtoul(arg1_str, 0, &n);
	if (ret) {
		pr_err("drill: invalid item number %s\n", arg1_str);
		return -EINVAL;
	}
	if (n >= DRILL_N) {
		pr_err("drill: bad item number %lu (max %d)\n", n, DRILL_N - 1);
		return -EINVAL;
	}
	pr_notice("drill: gonna work with item %lu\n", n);

	switch (act) {
	case DRILL_ACT_ALLOC:
		drill.items[n] = kzalloc(DRILL_ITEM_SIZE, GFP_KERNEL);
		if (drill.items[n] == NULL) {
			pr_err("drill: not enough memory for item\n");
			return -ENOMEM;
		}

		pr_notice("drill: kmalloc'ed item %lu (0x%lx, size %d)\n",
			  n, (unsigned long)drill.items[n], DRILL_ITEM_SIZE);

		drill.items[n]->foobar = 0x41414141a5a5a5a5u;
		drill.items[n]->callback = drill_callback;
		break;

	case DRILL_ACT_CALLBACK:
		pr_notice("drill: exec callback 0x%lx for item %lu (0x%lx)\n",
					(unsigned long)drill.items[n]->callback,
					n, (unsigned long)drill.items[n]);
		drill.items[n]->callback(); /* No check, BAD BAD BAD */
		break;

	case DRILL_ACT_SAVE_VAL:
		if (!arg2_str) {
			pr_err("drill: save_val: missing value\n");
			return -EINVAL;
		}

		if (!arg3_str) {
			pr_err("drill: save_val: missing offset\n");
			return -EINVAL;
		}

		ret = kstrtoul(arg2_str, 0, &val);
		if (ret) {
			pr_err("drill: save_val: bad value %s\n", arg2_str);
			return -EINVAL;
		}

		ret = kstrtoul(arg3_str, 0, &offset);
		if (ret) {
			pr_err("drill: save_val: bad offset %s\n", arg3_str);
			return -EINVAL;
		}

		if (offset > DRILL_ITEM_SIZE -
				sizeof(struct drill_item_t) - sizeof(val)) {
			pr_err("drill: save_val: oob offset %ld\n", offset);
			return -EINVAL;
		}

		data_addr = (unsigned long *)(drill.items[n]->data + offset);
		pr_notice("drill: save val 0x%lx to item %lu (0x%lx) at data offset %ld (0x%lx)\n",
					val, n, (unsigned long)drill.items[n],
					offset, (unsigned long)data_addr);
		*data_addr = val;  /* No check, BAD BAD BAD */

		pr_notice("drill: item %lu dump:\n", n);
		print_hex_dump(KERN_INFO, "drill: ", DUMP_PREFIX_ADDRESS,
			       16, 1, drill.items[n], DRILL_ITEM_SIZE, false);
		break;

	case DRILL_ACT_FREE:
		pr_notice("drill: free item %lu (0x%lx)\n",
					n, (unsigned long)drill.items[n]);
		kfree(drill.items[n]);  /* No check, BAD BAD BAD */
		break;

	case DRILL_ACT_RESET:
		drill.items[n] = NULL;
		pr_notice("drill: set item %lu ptr to NULL\n", n);
		break;

	default:
		pr_err("drill: invalid act %ld\n", act);
		return -EINVAL;
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
	char *arg3_str = NULL;
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

	arg3_str = strsep(&buf_ptr, " ");

	ret = kstrtoul(act_str, 10, &act);
	if (ret) {
		pr_err("drill: act_write: parsing act failed\n");
		return ret;
	}

	ret = drill_act_exec(act, arg1_str, arg2_str, arg3_str);
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
		pr_err("failed to create /proc/drill_act\n");
		return -ENOMEM;
	}

	drill.items = kzalloc(sizeof(struct drill_item_t *) * DRILL_N, GFP_KERNEL);
	if (!drill.items) {
		pr_err("failed to allocate drill items\n");
		proc_remove(drill.proc_entry);
		return -ENOMEM;
	}
	pr_notice("drill: start hacking\n");

	return 0;
}

static void __exit drill_exit(void)
{
	pr_notice("drill: stop hacking\n");
	kfree(drill.items);
	proc_remove(drill.proc_entry);
}

module_init(drill_init)
module_exit(drill_exit)

MODULE_AUTHOR("Alexander Popov <alex.popov@linux.com>");
MODULE_DESCRIPTION("The module for kernel exploiting experiments");
MODULE_LICENSE("GPL v2");
