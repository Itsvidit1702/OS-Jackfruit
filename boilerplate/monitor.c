/*
 * monitor.c - Multi-Container Memory Monitor (Linux Kernel Module)
 *
 * Implements Task 4:
 *   - /dev/container_monitor character device
 *   - ioctl: MONITOR_REGISTER / MONITOR_UNREGISTER
 *   - Kernel linked list of monitored containers (spinlock-protected)
 *   - Periodic timer callback: RSS check, soft-limit warn, hard-limit kill
 *   - Clean teardown on rmmod
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME        "container_monitor"
#define CHECK_INTERVAL_SEC 1

/* ================================================================
 * TODO 1 — Per-container tracking node
 *
 * Each registered container gets one heap-allocated node in
 * container_list.  The struct list_head is the standard kernel
 * intrusive linked-list anchor.
 *
 * soft_warned prevents the soft-limit message from being printed
 * on every timer tick after the first exceedance.
 * ================================================================ */
struct monitored_entry {
    pid_t         pid;
    char          container_id[MONITOR_NAME_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int           soft_warned;      /* 1 after first warning emitted */
    struct list_head list;          /* kernel linked-list linkage    */
};

/* ================================================================
 * TODO 2 — Global list and lock
 *
 * We use a spinlock (not a mutex) because the timer callback runs
 * in softirq (atomic) context where sleeping is not permitted.
 * spin_lock_irqsave/irqrestore also disables local interrupts so
 * the timer callback cannot deadlock with the ioctl handler if
 * they fire on the same CPU.
 * ================================================================ */
static LIST_HEAD(container_list);
static DEFINE_SPINLOCK(list_lock);

/* ================================================================
 * Internal device / timer state (provided)
 * ================================================================ */
static struct timer_list monitor_timer;
static dev_t             dev_num;
static struct cdev       c_dev;
static struct class     *cl;

/* ================================================================
 * Provided: get_rss_bytes
 *
 * Returns RSS in bytes for pid, or -1 if the task no longer exists.
 * Uses RCU read lock + get_task_mm so it is safe to call from
 * atomic context (the timer callback).
 * ================================================================ */
static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct   *mm;
    long rss_pages = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -1;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);

    return rss_pages * PAGE_SIZE;
}

/* ================================================================
 * Provided: log_soft_limit_event
 * ================================================================ */
static void log_soft_limit_event(const char *container_id, pid_t pid,
                                  unsigned long limit_bytes, long rss_bytes)
{
    printk(KERN_WARNING
           "[container_monitor] SOFT LIMIT container=%s pid=%d "
           "rss=%ld bytes limit=%lu bytes\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ================================================================
 * Provided: kill_process
 * ================================================================ */
static void kill_process(const char *container_id, pid_t pid,
                          unsigned long limit_bytes, long rss_bytes)
{
    struct task_struct *task;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        send_sig(SIGKILL, task, 1);
    rcu_read_unlock();

    printk(KERN_WARNING
           "[container_monitor] HARD LIMIT container=%s pid=%d "
           "rss=%ld bytes limit=%lu bytes — SIGKILL sent\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ================================================================
 * TODO 3 — timer_callback: periodic RSS enforcement
 *
 * Fires every CHECK_INTERVAL_SEC seconds.
 *
 * For each entry in container_list:
 *   • get_rss_bytes() returns -1  → process gone, remove entry
 *   • rss > hard_limit            → kill + remove entry
 *   • rss > soft_limit (once)     → log warning, set soft_warned=1
 *
 * list_for_each_entry_safe is mandatory here because we may
 * call list_del() inside the loop.  It saves the next pointer
 * before entering the body so deletion is safe.
 *
 * spin_lock_irqsave saves and disables local IRQs to prevent
 * a deadlock if the ioctl handler is interrupted by the timer
 * on the same CPU.
 * ================================================================ */
static void timer_callback(struct timer_list *t)
{
    struct monitored_entry *entry, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&list_lock, flags);

    list_for_each_entry_safe(entry, tmp, &container_list, list) {
        long rss = get_rss_bytes(entry->pid);

        if (rss < 0) {
            /* Process has exited — remove stale entry */
            printk(KERN_INFO
                   "[container_monitor] PID %d gone, removing entry '%s'\n",
                   entry->pid, entry->container_id);
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        if ((unsigned long)rss > entry->hard_limit_bytes) {
            /* Hard limit exceeded: kill and clean up */
            kill_process(entry->container_id, entry->pid,
                         entry->hard_limit_bytes, rss);
            list_del(&entry->list);
            kfree(entry);

        } else if ((unsigned long)rss > entry->soft_limit_bytes
                   && !entry->soft_warned) {
            /* Soft limit: emit one warning */
            log_soft_limit_event(entry->container_id, entry->pid,
                                 entry->soft_limit_bytes, rss);
            entry->soft_warned = 1;
        }
    }

    spin_unlock_irqrestore(&list_lock, flags);

    /* Re-arm the timer for the next interval */
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

/* ================================================================
 * monitor_ioctl — handles MONITOR_REGISTER and MONITOR_UNREGISTER
 *
 * TODO 4 — MONITOR_REGISTER:
 *   Allocate a new monitored_entry, populate from the user-space
 *   monitor_request, insert into container_list under the spinlock.
 *
 * TODO 5 — MONITOR_UNREGISTER:
 *   Find the matching entry by PID + container_id, remove and free
 *   it under the spinlock.  Return -ENOENT if not found.
 * ================================================================ */
static long monitor_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct monitor_request req;
    unsigned long flags;

    (void)f;

    if (cmd != MONITOR_REGISTER && cmd != MONITOR_UNREGISTER)
        return -EINVAL;

    /* Copy the request struct from user space safely */
    if (copy_from_user(&req, (struct monitor_request __user *)arg, sizeof(req)))
        return -EFAULT;

    /* ---- REGISTER ---- */
    if (cmd == MONITOR_REGISTER) {
        struct monitored_entry *entry;

        printk(KERN_INFO
               "[container_monitor] Register container=%s pid=%d "
               "soft=%lu hard=%lu\n",
               req.container_id, req.pid,
               req.soft_limit_bytes, req.hard_limit_bytes);

        /* Basic sanity check */
        if (req.soft_limit_bytes > req.hard_limit_bytes) {
            printk(KERN_WARNING
                   "[container_monitor] Rejected: soft > hard for '%s'\n",
                   req.container_id);
            return -EINVAL;
        }

        /* Allocate node — GFP_KERNEL is fine; ioctl runs in process context */
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) return -ENOMEM;

        entry->pid              = req.pid;
        entry->soft_limit_bytes = req.soft_limit_bytes;
        entry->hard_limit_bytes = req.hard_limit_bytes;
        entry->soft_warned      = 0;
        strncpy(entry->container_id, req.container_id, MONITOR_NAME_LEN - 1);
        entry->container_id[MONITOR_NAME_LEN - 1] = '\0';
        INIT_LIST_HEAD(&entry->list);

        spin_lock_irqsave(&list_lock, flags);
        list_add(&entry->list, &container_list);
        spin_unlock_irqrestore(&list_lock, flags);

        return 0;
    }

    /* ---- UNREGISTER ---- */
    printk(KERN_INFO
           "[container_monitor] Unregister container=%s pid=%d\n",
           req.container_id, req.pid);

    {
        struct monitored_entry *entry, *tmp;
        int found = 0;

        spin_lock_irqsave(&list_lock, flags);
        list_for_each_entry_safe(entry, tmp, &container_list, list) {
            if (entry->pid == req.pid &&
                strncmp(entry->container_id, req.container_id,
                        MONITOR_NAME_LEN) == 0) {
                list_del(&entry->list);
                kfree(entry);
                found = 1;
                break;
            }
        }
        spin_unlock_irqrestore(&list_lock, flags);

        return found ? 0 : -ENOENT;
    }
}

/* ================================================================
 * File operations
 * ================================================================ */
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

/* ================================================================
 * Module init
 * ================================================================ */
static int __init monitor_init(void)
{
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    cl = class_create(DEVICE_NAME);
#else
    cl = class_create(THIS_MODULE, DEVICE_NAME);
#endif
    if (IS_ERR(cl)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEVICE_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    timer_setup(&monitor_timer, timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);

    printk(KERN_INFO "[container_monitor] Module loaded. /dev/%s ready.\n",
           DEVICE_NAME);
    return 0;
}

/* ================================================================
 * TODO 6 — Module exit: free all remaining entries
 *
 * del_timer_sync() waits for any running timer callback to complete
 * before returning, so we know no callback is touching the list
 * when we free it.  We still take the spinlock for correctness.
 * ================================================================ */
static void __exit monitor_exit(void)
{
    struct monitored_entry *entry, *tmp;
    unsigned long flags;

    /* Stop timer first — no more callbacks after this returns */
    timer_delete_sync(&monitor_timer);

    /* Free every remaining list node */
    spin_lock_irqsave(&list_lock, flags);
    list_for_each_entry_safe(entry, tmp, &container_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&list_lock, flags);

    /* Tear down the character device */
    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "[container_monitor] Module unloaded cleanly.\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Supervised multi-container memory monitor");
