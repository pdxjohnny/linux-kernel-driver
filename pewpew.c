#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
MODULE_LICENSE("GPL");

#define MODULE_STR "pewpew"
#define INFO KERN_INFO MODULE_STR ": "
#define ERR  KERN_ERR  MODULE_STR ": "

int pewpew_open(struct inode *inode, struct file *flip);
ssize_t pewpew_read(struct file *flip, char __user *buff, size_t count, loff_t *offp);
ssize_t pewpew_write(struct file *flip, const char __user *buff, size_t count, loff_t *offp);
int pewpew_release(struct inode *inode, struct file *filp);

struct pewpew_dev {
  dev_t dev;
  unsigned int count;
  char name[255];
  struct cdev cdev;
  int syscall_val;
};
struct pewpew_dev pewpew;

struct file_operations pewpew_fops = {
  .open = pewpew_open,
  .read = pewpew_read,
  .write = pewpew_write,
  .release = pewpew_release,
};

static int syscall_val = 40;
module_param(syscall_val, int, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(syscall_val, "Initial value of syscall_val");

int pewpew_open(struct inode *inode, struct file *flip) {
	flip->private_data = container_of(inode->i_cdev, struct pewpew_dev, cdev);
  ((struct pewpew_dev *)flip->private_data)->syscall_val = syscall_val;
  printk(INFO "Open starting syscall_val at %d\n", syscall_val);
	return 0;
}

ssize_t pewpew_read(struct file *flip, char __user *buff, size_t count, loff_t *offp) {
  int err;
  char *kbuff;
  const unsigned int kbuff_size = 255;
  struct pewpew_dev *p = flip->private_data;
  /* Make sure we got a buffer from userspace */
  if (buff == NULL) {
    printk(ERR "NULL buffer from userspace\n");
    return -EINVAL;
  }
  /* Allocate a kernel buffer big enough to hold any int as a string */
  kbuff = kmalloc(kbuff_size, GFP_KERNEL);
  /* Check if allocation was successful */
  if (kbuff == NULL) {
    printk(ERR "failed to allocate kernel buffer\n");
    return -ENOMEM;
  }
  /* Format syscall_val into the kernel buffer */
  err = sprintf(kbuff, "%d", p->syscall_val);
  /* Find the length of the string we are writing back */
  count = strnlen(kbuff, kbuff_size);
  /* Copy the contents of the user buffer to the kernel buffer */
  copy_to_user(buff, kbuff, count);
  /* Free the kernel buffer */
  kfree(kbuff);
  printk(INFO "Read complete, syscall_val was %d\n", p->syscall_val);
  /* Return length of the string written back */
  return count;
}

ssize_t pewpew_write(struct file *flip, const char __user *buff, size_t count, loff_t *offp) {
  int err;
  char *kbuff;
  struct pewpew_dev *p = flip->private_data;
  /* Make sure we got a buffer from userspace */
  if (buff == NULL) {
    printk(ERR "NULL buffer from userspace\n");
    return -EINVAL;
  }
  /* Allocate a kernel buffer of the same size as the user one */
  kbuff = kmalloc(sizeof(*buff) * count, GFP_KERNEL);
  /* Check if allocation was successful */
  if (kbuff == NULL) {
    printk(ERR "failed to allocate kernel buffer\n");
    return -ENOMEM;
  }
  /* Copy the contents of the user buffer to the kernel buffer */
  copy_from_user(kbuff, buff, (sizeof(*buff) * count) + 1);
  kbuff[sizeof(*buff) * count] = '\0';
  /* Parse the kernel buffer into the pewpew_dev syscall_val */
  err = kstrtoint(kbuff, 10, &p->syscall_val);
  /* Free the kernel buffer */
  kfree(kbuff);
  /* Check if parse was successful */
  if (err < 0) {
    printk(ERR "failed to parse integer\n");
    return -EINVAL;
  }
  printk(INFO "Write complete, syscall_val is now %d\n", p->syscall_val);
  /* Return length that was given on success */
  return count;
}

int pewpew_release(struct inode *inode, struct file *filp) {
  return 0;
}

static int __init pewpew_init(void) {
  int err;
  printk(INFO "Initializing...\n");
  /* Initialize our device structure */
  memset(&pewpew, 0, sizeof(pewpew));
  pewpew.count = 1;
  /* Get value from module parameter. */
  pewpew.syscall_val = syscall_val;
  printk(INFO "syscall_val starting at %d\n", pewpew.syscall_val);
  strcpy(pewpew.name, MODULE_STR);
  /* Obtain a device number */
  err = alloc_chrdev_region(&pewpew.dev, 0, pewpew.count, pewpew.name);
  if (err) {
    printk(ERR "failed to alloc_chrdev_region\n");
    return 0;
  }
  /* Initialize the character device structure */
  cdev_init(&pewpew.cdev, &pewpew_fops);
  pewpew.cdev.owner = THIS_MODULE;
  pewpew.cdev.ops = &pewpew_fops;
  /* Add the character device */
  err = cdev_add(&pewpew.cdev, pewpew.dev, pewpew.count);
  if (err) {
    unregister_chrdev_region(pewpew.dev, pewpew.count);
    printk(ERR "failed to cdev_add\n");
    return 0;
  }
  printk(INFO "Initialized\n");
  return 0;
}

static void __exit pewpew_exit(void) {
  printk(INFO "Exiting...\n");
  /* Remove our character device */
  cdev_del(&pewpew.cdev);
  /* Unregister our device number */
  unregister_chrdev_region(pewpew.dev, pewpew.count);
  printk(INFO "Exited successfully\n");
}

module_init(pewpew_init);
module_exit(pewpew_exit);
