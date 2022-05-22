#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/mm.h>

#define MAX_SIZE 128

static struct proc_dir_entry *proc_ent;
static char output[MAX_SIZE];
static int out_len;
static struct task_struct* taskp;

static ssize_t proc_read(struct file *fp, char __user *ubuf, size_t len, loff_t *pos)
{
    int count; /* the number of characters to be copied */

    if (*pos == 0) {
        /* a new read, update process' status */
        /* TODO */
    }

    if (out_len - *pos > len) {
        count = len;
    } else {
        count = out_len - *pos;
    }

    pr_info("Reading the proc file\n");
    if (copy_to_user(ubuf, output + *pos, count)) return -EFAULT;
    *pos += count;
    
    return count;
}

static ssize_t proc_write(struct file *fp, const char __user *ubuf, size_t len, loff_t *pos)
{
    int pid;

    if (*pos > 0) return -EFAULT;
    pr_info("Writing the proc file\n");
    if(kstrtoint_from_user(ubuf, len, 10, &pid)) return -EFAULT;

    taskp = get_pid_task(find_get_pid(pid), PIDTYPE_PID);

    *pos += len;
    return len;
}

static const struct proc_ops proc_ops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

static int __init watch_init(void)
{
    proc_ent = proc_create("watch", 0666, NULL, &proc_ops);
    if (!proc_ent) {
        proc_remove(proc_ent);
        pr_alert("Error: Could not initialize /proc/watch\n");
        return -EFAULT;
    }
    pr_info("/proc/watch created\n");
    return 0;
}

static void __exit watch_exit(void)
{
    proc_remove(proc_ent);
    pr_info("/proc/watch removed\n");
}

module_init(watch_init);
module_exit(watch_exit);
MODULE_LICENSE("GPL");