/*
 * The module for kernel exploiting experiments
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <asm/uaccess.h>

#define ACT_SIZE 5

enum msuhack_act_t {
	MSUHACK_ACT_NONE = 0,
	MSUHACK_ACT_ALLOC = 1,
	MSUHACK_ACT_CALLBACK = 2,
	MSUHACK_ACT_FREE = 3
};

struct msuhack_t {
	struct dentry *dir;
	struct msuhack_item_t *item;
};

static struct msuhack_t msuhack; /* initialized by zeros */

#define MSUHACK_ITEM_SIZE 7000

struct msuhack_item_t {
	u32 foo;
	void (*callback)(void);
	char bar[1];
};

static void msuhack_callback(void) {
	pr_notice("normal msuhack_callback %p!\n", msuhack_callback);
}

static int msuhack_act_exec(long act)
{
	int ret = 0;

	switch (act) {
	case MSUHACK_ACT_ALLOC:
		msuhack.item = kmalloc(MSUHACK_ITEM_SIZE, GFP_KERNEL);
		if (msuhack.item == NULL) {
			pr_err("msuhack: not enough memory for item\n");
			ret = -ENOMEM;
			break;
		}

		pr_notice("msuhack: kmalloc'ed item at %p (size %d)\n",
					msuhack.item, MSUHACK_ITEM_SIZE);

		msuhack.item->callback = msuhack_callback;
		break;

	case MSUHACK_ACT_CALLBACK:
		pr_notice("msuhack: exec callback %p for item %p\n",
					msuhack.item->callback, msuhack.item);
		msuhack.item->callback(); /* No check, BAD BAD BAD */
		break;

	case MSUHACK_ACT_FREE:
		pr_notice("msuhack: free item at %p\n", msuhack.item);
		kfree(msuhack.item);
		break;

	default:
		pr_err("msuhack: invalid act %ld\n", act);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static ssize_t msuhack_act_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	char buf[ACT_SIZE] = { 0 };
	size_t size = ACT_SIZE - 1;
	long new_act = 0;

	BUG_ON(*ppos != 0);

	if (count < size)
		size = count;

	if (copy_from_user(&buf, user_buf, size)) {
		pr_err("msuhack: act_write: copy_from_user failed\n");
		return -EFAULT;
	}

	buf[size] = '\0';
	new_act = simple_strtol(buf, NULL, 0);

	ret = msuhack_act_exec(new_act);
	if (ret == 0)
		ret = count; /* success, claim we got the whole input */

	return ret;
}

static const struct file_operations msuhack_act_fops = {
	.write = msuhack_act_write,
};

static int __init msuhack_init(void)
{
	struct dentry *act_file = NULL;

	pr_notice("msuhack: start hacking\n");

	msuhack.dir = debugfs_create_dir("msuhack", NULL);
	if (msuhack.dir == ERR_PTR(-ENODEV) || msuhack.dir == NULL) {
		pr_err("creating msuhack dir failed\n");
		return -ENOMEM;
	}

	act_file = debugfs_create_file("msuhack_act", S_IWUGO,
					msuhack.dir, NULL, &msuhack_act_fops);
	if (act_file == ERR_PTR(-ENODEV) || act_file == NULL) {
		pr_err("creating msuhack_act file failed\n");
		debugfs_remove_recursive(msuhack.dir);
		return -ENOMEM;
	}

	return 0;
}

static void __exit msuhack_exit(void)
{
	pr_notice("msuhack: stop hacking\n");
	debugfs_remove_recursive(msuhack.dir);
}

module_init(msuhack_init)
module_exit(msuhack_exit)

MODULE_AUTHOR("Alexander Popov <alex.popov@linux.com>");
MODULE_DESCRIPTION("The module for kernel exploiting experiments");
MODULE_LICENSE("GPL v2");
