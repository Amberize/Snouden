#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>				//file_operation
#include <linux/platform_device.h>	//udev
#include <linux/printk.h>			//printk
#include <linux/uaccess.h>			//copy_to_user
#include <linux/slab.h>				//kmalloc
#include <linux/kthread.h>			//kthread
#include <linux/mutex.h>			//mutex
#include <linux/delay.h>			//sleep
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#define DRIVER_AUTHOR "Valera Amberize Pesternikov <gnompl@gmail.com>"
#define DRIVER_DESC "Driver to crypt Snouden messages"

#define DEVICE_NAME "snouden"
#define BUFFER_SIZE 256

typedef struct {
    int flag;
    char *buf;
    int buf_size;
    int buf_count;
    int op_count;
    int silent;
    struct task_struct *thread;
    struct mutex lock;
} snouden_t;

static int major;
static struct class *snouden_class;
static snouden_t *global_snouden;

static int device_open(struct inode *inode, struct file *file)
{
	file->private_data = global_snouden;

	printk(KERN_INFO "snouden : Device opened\n");

	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "snouden : Device released\n");

	return 0;
}

static ssize_t device_read(struct file *file, char *buffer, size_t size, loff_t *offset)
{
	int read_size;
	int ret;

	snouden_t *snouden = file->private_data;

	if(!snouden)
		return -1;

	if(*offset >= snouden->buf_count)
		return 0;

	if(size > snouden->buf_count)
		read_size = snouden->buf_count;
	else
		read_size = size;
	*offset += size;

	char* xor_buf = kmalloc(read_size, GFP_KERNEL);

	int i;
	for(i = 0; i < read_size; i++)
		xor_buf[i] ^= snouden->buf[i];

	ret = copy_to_user(buffer, xor_buf, read_size);
	if(ret)
		return -1;

	unsigned char *md5_buf;
	struct scatterlist sg[1];
	struct crypto_hash *tfm;
	struct hash_desc desc;

	md5_buf = kmalloc(sizeof(unsigned char)*16, GFP_KERNEL);
	if(md5_buf == NULL)
		return -1;
	memset(md5_buf, 0x00, 16);

	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm))
		return -1;

	desc.tfm = tfm;
	desc.flags = 0;

	sg_init_one(&sg, snouden->buf, read_size-1);
	crypto_hash_init(&desc);

	crypto_hash_update(&desc, &sg, read_size-1);
	crypto_hash_final(&desc, md5_buf);

	printk("Initial Md5: ");
	for(i = 0; i < 16; i++)
		printk("%02x", md5_buf[i]);
	printk("\n");

	sg_init_one(&sg, xor_buf, read_size-1);
	crypto_hash_init(&desc);

	crypto_hash_update(&desc, &sg, read_size-1);
	crypto_hash_final(&desc, md5_buf);

	printk("XOR Md5: ");
	for(i = 0; i < 16; i++)
		printk("%02x", md5_buf[i]);
	printk("\n");

	kfree(xor_buf);
	kfree(md5_buf);

	printk(KERN_INFO "Read %d chars\n", read_size);

	return read_size;
}

static ssize_t device_write(struct file *file, const char *buffer, size_t size, loff_t * offset)
{
	int write_size;
	int ret;

	snouden_t *snouden = file->private_data;

	if(!snouden)
		return -1;

	if (size > snouden->buf_size)
		write_size = snouden->buf_size;
	else
		write_size = size;

	ret = copy_from_user(snouden->buf, buffer, write_size);
	if(ret)
		return -1;

	snouden->buf_count = write_size;

	printk(KERN_INFO "Wrote %d chars\n", write_size);	
	
	return write_size;
}

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

static int __init init_snouden(void)
{
	printk(KERN_INFO "snouden : Hello, Snouden!\n");

	snouden_t *snouden;

	snouden_class = class_create(THIS_MODULE, DEVICE_NAME);
	if(IS_ERR(snouden_class))
	{
		printk(KERN_ALERT "snouden : Failed create class device\n");
		return -1;
	}

	major = register_chrdev(0, DEVICE_NAME, &fops);
	if(major < 0)
	{
		printk(KERN_ALERT "snouden : Failed register char device\n");
		return -1;
	}

	snouden = kmalloc(sizeof(snouden_t), GFP_KERNEL);
	if(!snouden)
	{
		printk(KERN_ALERT "snouden : Failed allocate memory\n");
		return -1;
	}

	global_snouden = snouden;

	memset(snouden, 0, sizeof(snouden_t));

	snouden->buf_size = BUFFER_SIZE;
	snouden->buf = kmalloc(snouden->buf_size, GFP_KERNEL);
	mutex_init(&snouden->lock);

	struct device *dev;
	dev = device_create(snouden_class, NULL, MKDEV(major, 0), snouden, DEVICE_NAME"%d", 0);
	if(IS_ERR(dev))
	{
		printk(KERN_ALERT "snouden : Failed register device\n");
		return -1;
	}

	return 0;
}

static void __exit exit_snouden(void)
{
	printk(KERN_INFO "snouden : We'll remember you, Snouden!\n");

	device_destroy(snouden_class, MKDEV(major, 0));
	class_destroy(snouden_class);

	unregister_chrdev(major, DEVICE_NAME);
	
	kfree(global_snouden->buf);
	kfree(global_snouden);
}

module_init(init_snouden);
module_exit(exit_snouden);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);