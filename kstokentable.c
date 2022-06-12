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
#define TOKEN_NUM 256


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuma Ueda");
MODULE_DESCRIPTION("LKM to dump kallsyms_token_table");


static unsigned long token_table_vaddr;
// 0 when kaslr is disabled
static unsigned long kaslr_offset;

static u8 *token_table_buf;
static size_t token_table_size;


// kallsyms_token_table_vaddr from System.map
module_param(token_table_vaddr, ulong, S_IRUSR);
module_param(kaslr_offset, ulong, S_IRUSR);


static struct dentry *kallsyms_root;
static struct dentry *kstokentable;


static ssize_t my_read(struct file *fp,
        char __user * const buf,
        size_t count,
        loff_t *off)
{
    return simple_read_from_buffer(buf, count, off,
            token_table_buf, token_table_size);
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
    u8 *token_table_ptr_start;
    u8 *token_table_ptr;
    int token_read_count;
    long r;
    u8 e;
    u8 *token_table_buf_cur;
    size_t sz;
    size_t token_table_size_remain;


    token_table_vaddr += kaslr_offset;
    token_table_ptr =
        token_table_ptr_start = (u8 *)token_table_vaddr;
    token_read_count = 0;


    printk(KERN_INFO "%s: Inserting kssextracter kstokentable \
            into the kernel ...\n", DEVICE_NAME);
    printk(KERN_INFO "%s: token_table_vaddr=%lu\n",
            DEVICE_NAME, token_table_vaddr);
    printk(KERN_INFO "%s: kaslr_offset=%lu\n",
            DEVICE_NAME, kaslr_offset);
    printk(KERN_INFO "%s: token_table_ptr=%p\n",
            DEVICE_NAME, token_table_ptr);


    while (token_read_count != TOKEN_NUM) {
        // sizeof(e) == 1
        r = COPY_FROM_KERNEL_NOFAULT(&e,
                (void *)token_table_ptr, sizeof(e));
        if (r < 0) {
            printk(KERN_ERR "%s: COPY_FROM_KERNEL_NOFAULT \
                    ERROR CODE %ld\n", DEVICE_NAME, r);
            return r;
        }

        token_table_ptr++;
        if (e == (u8)0)
            token_read_count++;
    }

    token_table_size = (size_t)(token_table_ptr - token_table_ptr_start);
    printk(KERN_INFO "%s: token_table_size=%lu\n",
            DEVICE_NAME, token_table_size);


    if (!(kallsyms_root = debugfs_lookup("kallsyms", NULL))) {
        // create a debugfs file
        kallsyms_root = debugfs_create_dir("kallsyms", NULL);
        if (IS_ERR(kallsyms_root)) {
            printk(KERN_ERR "%s: debugfs_create_dir ERROR CODE \
                    %ld\n", DEVICE_NAME, PTR_ERR(kallsyms_root));
            return (int)PTR_ERR(kallsyms_root);
        }
    }

    kstokentable = debugfs_create_file(DEVICE_NAME, S_IRUSR,
            kallsyms_root, NULL, &my_fops);
    if (IS_ERR(kstokentable)) {
        printk(KERN_ERR "%s: debugfs_create_file ERROR CODE \
                %ld\n", DEVICE_NAME, PTR_ERR(kstokentable));
        return (int)PTR_ERR(kstokentable);
    }


    // buffer maps kallsyms_token_table's copy
    token_table_ptr -= token_table_size;
    printk(KERN_INFO "%s: token_table_ptr=%p\n",
            DEVICE_NAME, token_table_ptr);


    if (!(token_table_buf= kmalloc(token_table_size, GFP_KERNEL))) {
        printk(KERN_ERR "%s: kmalloc ERROR CODE %d\n",
                DEVICE_NAME, -ENOMEM);
        return -ENOMEM;
    }
    printk(KERN_INFO "%s: token_table_buf=%p\n",
        DEVICE_NAME, token_table_buf);
    token_table_buf_cur = token_table_buf;
    token_table_size_remain = token_table_size;

    while (token_table_size_remain > 0) {
        sz = size_inside_page(__pa(token_table_ptr), token_table_size_remain);

        r = COPY_FROM_KERNEL_NOFAULT(token_table_buf_cur, token_table_ptr, sz);
        if (r < 0) {
            printk(KERN_ERR "%s: COPY_FROM_KERNEL_NOFAULT \
                    ERROR CODE %ld\n", DEVICE_NAME, r);
            goto failed_need_free;
        }

        token_table_size_remain -= sz;
        token_table_ptr += sz;
        token_table_buf_cur += sz;
    }

    print_hex_dump(KERN_INFO, "token_table_buf: ", DUMP_PREFIX_NONE,
            16, 1, token_table_buf, 10, true);

    printk(KERN_INFO "%s: done.\n", DEVICE_NAME);

    return 0;


failed_need_free:

    kfree(token_table_buf);
    return r;
}

static void __exit my_exit(void)
{
    printk(KERN_INFO "%s: removing kssextracter kstokentable \
            from the kernel ...\n", DEVICE_NAME);


    //debugfs_remove(kstokentable);
    debugfs_remove_recursive(kallsyms_root);

    kfree(token_table_buf);


    printk(KERN_INFO "%s: done.\n", DEVICE_NAME);

    return;
}


module_init(my_init);
module_exit(my_exit);
