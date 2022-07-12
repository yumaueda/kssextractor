#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
#define COPY_FROM_KERNEL_NOFAULT probe_kernel_read
#else
#define COPY_FROM_KERNEL_NOFAULT copy_from_kernel_nofault
#endif

#define DEVICE_NAME THIS_MODULE->name


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuma Ueda");
MODULE_DESCRIPTION("LKM to dump kallsyms_names");


static unsigned long num_syms_vaddr;
static unsigned long names_vaddr;
// 0 when kaslr is disabled
static unsigned long kaslr_offset;
static size_t names_size;
static char *names_buf;


// kallsyms_num_syms vaddr from System.map
module_param(num_syms_vaddr, ulong, S_IRUSR);
// kallsyms_names_vaddr from System.map
module_param(names_vaddr, ulong, S_IRUSR);
module_param(kaslr_offset, ulong, S_IRUSR);


static struct dentry *kallsyms_root;
static struct dentry *ksnames;


static ssize_t my_read(struct file *fp,
        char __user * const buf,
        size_t count,
        loff_t *off)
{
    printk(KERN_INFO "%s: my_read fp=%p",
            DEVICE_NAME, fp);
    printk(KERN_INFO "%s: my_read buf=%p",
            DEVICE_NAME, buf);
    printk(KERN_INFO "%s: my_read count=%ld",
            DEVICE_NAME, count);
    printk(KERN_INFO "%s: my_read off=%lld",
            DEVICE_NAME, *off);
    printk(KERN_INFO "%s: my_read names_buf=%p",
            DEVICE_NAME, names_buf);
    printk(KERN_INFO "%s: my_read names_size=%ld",
            DEVICE_NAME, names_size);

    return simple_read_from_buffer(buf, count, off,
            names_buf, names_size);
}

const static struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .read  = my_read,
};


// from drivers/char/mem.c start

/*
 *  static inline bool should_stop_iteration(void)
 *  {
 *      if (need_resched())
 *          cond_resched();
 *      return fatal_signal_pending(current);
 *  }
 */

static inline unsigned long size_inside_page(
        unsigned long start, unsigned long size)
{
    unsigned long sz;

    sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

    return min(sz, size);
}

// from drivers/char/mem.c end

static int __init my_init(void)
{
    unsigned int num_syms, i;
    long r;

    u8 *names_ptr_start;
    u8 *names_ptr;
    u8 len;
    u8 *names_buf_cur;
    size_t sz;
    size_t names_size_remain;


    num_syms_vaddr += kaslr_offset;
    names_vaddr    += kaslr_offset;

    // kallsyms_num_syms does not exist across pages
    // cuz of optimization done by compiler
    r = COPY_FROM_KERNEL_NOFAULT(&num_syms,
            (void *)num_syms_vaddr, sizeof(num_syms));
    if (r < 0) {
        printk(KERN_ERR "%s: COPY_FROM_KERNEL_NOFAULT \
                ERROR CODE %ld\n", DEVICE_NAME, r);
        return r;
    }

    names_ptr = names_ptr_start = (u8 *)names_vaddr;


    printk(KERN_INFO "%s: Inserting kssextractor ksnames \
            into the kernel ...\n", DEVICE_NAME);
    printk(KERN_INFO "%s: num_syms_vaddr=%lu\n",
            DEVICE_NAME, num_syms_vaddr);
    printk(KERN_INFO "%s: names_vaddr=%lu\n",
            DEVICE_NAME, names_vaddr);
    printk(KERN_INFO "%s: kaslr_offset=%lu\n",
            DEVICE_NAME, kaslr_offset);
    printk(KERN_INFO "%s: num_syms_paddr=%lu\n",
            DEVICE_NAME, __pa(num_syms_vaddr));
    printk(KERN_INFO "%s: names_paddr=%lu\n",
            DEVICE_NAME, __pa(names_vaddr));
    printk(KERN_INFO "%s: num_syms=%u\n",
            DEVICE_NAME, num_syms);
    printk(KERN_INFO "%s: names_ptr=%p\n",
            DEVICE_NAME, names_ptr);

    print_hex_dump(KERN_INFO, "names_ptr: ", DUMP_PREFIX_NONE,
            16, 1, names_ptr, 10, true);

    // calculate size of kallsyms_names names_size
    //
    // * len in kallsyms_names does not exist across pages
    // cuz its size is 1B
    for (i = 0; i < num_syms; i++) {
        r = COPY_FROM_KERNEL_NOFAULT(&len,
                (void *)names_ptr, sizeof(len));
        if (r < 0) {
            printk(KERN_ERR "%s: COPY_FROM_KERNEL_NOFAULT \
                    ERROR CODE %ld\n", DEVICE_NAME, r);
            return r;
        }
        if (len == 0) {
            printk(KERN_ERR "%s: kallsyms_names len should \
                    never be zero. maybe invalid addresses \
                    are given.\n", DEVICE_NAME);
            return -EFAULT;
        }
        //printk(KERN_INFO "%s: len=%hhu\n",
        //       DEVICE_NAME, len);
        names_ptr += (len + 1);
    }

    names_size = (size_t)(names_ptr - names_ptr_start);
    printk(KERN_INFO "%s: names_size=%lu\n",
            DEVICE_NAME, names_size);


    if (!(kallsyms_root = debugfs_lookup("kallsyms", NULL))) {
        // create a debugfs file
        kallsyms_root = debugfs_create_dir("kallsyms", NULL);
        if (IS_ERR(kallsyms_root)) {
            printk(KERN_ERR "%s: debugfs_create_dir ERROR CODE \
                    %ld\n", DEVICE_NAME, PTR_ERR(kallsyms_root));
            return (int)PTR_ERR(kallsyms_root);
        }
    }

    ksnames = debugfs_create_file(DEVICE_NAME, S_IRUSR,
            kallsyms_root, NULL, &my_fops);
    if (IS_ERR(ksnames)) {
        printk(KERN_ERR "%s: debugfs_create_file ERROR CODE \
                %ld\n", DEVICE_NAME, PTR_ERR(ksnames));
        return (int)PTR_ERR(ksnames);
    }


    // buffer maps kallsyms_names's copy
    names_ptr -= names_size;
    printk(KERN_INFO "%s: names_ptr=%p\n",
            DEVICE_NAME, names_ptr);


    if (!(names_buf = kmalloc(names_size, GFP_KERNEL))) {
        printk(KERN_ERR "%s: kmalloc ERROR CODE %d\n",
                DEVICE_NAME, -ENOMEM);
        return -ENOMEM;
    }
    printk(KERN_INFO "%s: names_buf=%p\n",
        DEVICE_NAME, names_buf);
    names_buf_cur = names_buf;
    names_size_remain = names_size;

    while (names_size_remain > 0) {
        sz = size_inside_page(__pa(names_ptr), names_size_remain);

        r = COPY_FROM_KERNEL_NOFAULT(names_buf_cur, names_ptr, sz);
        if (r < 0) {
            printk(KERN_ERR "%s: COPY_FROM_KERNEL_NOFAULT \
                    ERROR CODE %ld\n", DEVICE_NAME, r);
            goto failed_need_free;
        }

        names_size_remain -= sz;
        names_ptr += sz;
        names_buf_cur += sz;
    }

    print_hex_dump(KERN_INFO, "names_buf: ", DUMP_PREFIX_NONE,
            16, 1, names_buf, 10, true);

    printk(KERN_INFO "%s: done.\n", DEVICE_NAME);

    return 0;

//TODO: debugfs remove logic after error occured

failed_need_free:

    kfree(names_buf);
    return r;
}

static void __exit my_exit(void)
{
    printk(KERN_INFO "%s: removing kssextractor ksnames \
            from the kernel ...\n", DEVICE_NAME);


    //debugfs_remove(ksnames);
    debugfs_remove_recursive(kallsyms_root);

    kfree(names_buf);


    printk(KERN_INFO "%s: done.\n", DEVICE_NAME);

    return;
}


module_init(my_init);
module_exit(my_exit);
