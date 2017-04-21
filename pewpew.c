#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/version.h>
#include <asm/uaccess.h>
MODULE_LICENSE("GPL");

#define MODULE_STR "pewpew"
#define INFO KERN_INFO MODULE_STR ": "
#define ERR  KERN_ERR  MODULE_STR ": "
const char pewpew_driver_name[] = MODULE_STR;

#define DEV_82583V_LEDCTL                     0x00E00
#define DEV_82583V_LEDCTL_MODE_ACTIVE         0x0E
#define DEV_82583V_LEDCTL_BLINK_MODE          (1 << 5)
#define DEV_82583V_LEDCTL_IVRT                (1 << 6)
#define DEV_82583V_LEDCTL_BLINK               (1 << 7)
#define DEV_82583V_LEDCTL_LED0(X)             ((X) << 0)
#define DEV_82583V_LEDCTL_LED1(X)             ((X) << 8)

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
static inline void pci_release_mem_regions(struct pci_dev *pdev) {
  return pci_release_selected_regions(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
}
#endif

int pewpew_open(struct inode *inode, struct file *flip);
ssize_t pewpew_read(struct file *flip, char __user *buff, size_t count, loff_t *offp);
ssize_t pewpew_write(struct file *flip, const char __user *buff, size_t count, loff_t *offp);
int pewpew_release(struct inode *inode, struct file *filp);
int pewpew_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
void pewpew_remove(struct pci_dev *pdev);

struct pewpew_dev {
  dev_t dev;
  unsigned int count;
  char name[255];
  struct cdev cdev;
  struct pci_dev *pdev;
  void *addr;
};
struct pewpew_dev pewpew;

static struct pci_device_id pewpew_pci_tbl[] = {
   { PCI_VDEVICE(INTEL, 0x150C), 0 },
   { 0 }
};
MODULE_DEVICE_TABLE(pci, pewpew_pci_tbl);

static struct pci_driver pewpew_driver = {
  .name     = MODULE_STR,
  .id_table = pewpew_pci_tbl,
  .probe    = pewpew_probe,
  .remove   = pewpew_remove,
};

struct file_operations pewpew_fops = {
  .open = pewpew_open,
  .read = pewpew_read,
  .write = pewpew_write,
  .release = pewpew_release,
};

int pewpew_probe(struct pci_dev *pdev, const struct pci_device_id *ent) {
  int bars, err;
  resource_size_t mmio_start, mmio_len;

  err = pci_enable_device_mem(pdev);
  if (err) {
    printk(INFO "could not pci_enable_device_mem: %d\n", err);
    return err;
  }

  bars = pci_select_bars(pdev, IORESOURCE_MEM);
  err = pci_request_selected_regions_exclusive(pdev, bars, pewpew_driver_name);
  if (err) {
    printk(ERR "failed to pci_request_selected_regions_exclusive %d\n", err);
    goto err_pci_reg;
  }

  /* AER (Advanced Error Reporting) hooks */
  pci_enable_pcie_error_reporting(pdev);

  pci_set_master(pdev);
  /* PCI config space info */
  err = pci_save_state(pdev);
  if (err) {
    printk(ERR "couldn\'t pci_save_state\n");
    goto err_pci_reg;
  }

  /* Map into memory */
  mmio_start = pci_resource_start(pdev, 0);
  mmio_len = pci_resource_len(pdev, 0);
  printk(INFO "mapping %lld of memory starting at %p\n",
      mmio_len, (void *)mmio_start);
  pewpew.addr = ioremap(mmio_start, mmio_len);
  if (!pewpew.addr) {
    printk(ERR "failed to setup memory mapped I/O with ioremap\n");
    goto err_ioremap;
  }

  /* Save the PCI device for later use */
  pewpew.pdev = pdev;
  /* Display the value of LEDCTL */
  printk(INFO "LEDCTL: %08x\n", *((u32 *)(pewpew.addr + DEV_82583V_LEDCTL)));
  return 0;

err_ioremap:
  iounmap(pewpew.addr);
  pci_release_mem_regions(pdev);
err_pci_reg:
  pci_disable_device(pdev);
  return err;
}

void pewpew_remove(struct pci_dev *pdev) {
  /* Clear it all (probably bad) */
  *((u32 *)(pewpew.addr + DEV_82583V_LEDCTL)) = 0;
  iounmap(pewpew.addr);
  pci_release_mem_regions(pdev);
  pci_disable_device(pdev);
  pewpew.pdev = NULL;
  pewpew.addr = NULL;
}

int pewpew_open(struct inode *inode, struct file *flip) {
  /* Make sure we are connected to the PCI device */
  if (pewpew.pdev == NULL || pewpew.addr == NULL) {
    return -ENODEV;
  }
	return 0;
}

ssize_t pewpew_read(struct file *flip, char __user *buff, size_t count, loff_t *offp) {
  int err;
  char *kbuff;
  const unsigned int kbuff_size = 255;
  /* Make sure we are connected to the PCI device */
  if (pewpew.pdev == NULL || pewpew.addr == NULL) {
    return -ENODEV;
  }
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
  /* Format LEDCTL into the kernel buffer */
  err = sprintf(kbuff, "%x", *((u32 *)(pewpew.addr + DEV_82583V_LEDCTL)));
  /* Make sure we don't write back a string larger than the receiving
   * buffer can hold */
  if (count < strnlen(kbuff, kbuff_size)) {
    return -ENOMEM;
  }
  /* Find the length of the string we are writing back */
  count = strnlen(kbuff, kbuff_size);
  /* Copy the contents of the user buffer to the kernel buffer */
  copy_to_user(buff, kbuff, count);
  /* Free the kernel buffer */
  kfree(kbuff);
  printk(INFO "Read complete, LEDCTL is %x\n", *((u32 *)(pewpew.addr + DEV_82583V_LEDCTL)));
  /* Return length of the string written back */
  return count;
}

ssize_t pewpew_write(struct file *flip, const char __user *buff, size_t count, loff_t *offp) {
  int err;
  u32 led_val;
  char *kbuff;
  /* Make sure we are connected to the PCI device */
  if (pewpew.pdev == NULL || pewpew.addr == NULL) {
    return -ENODEV;
  }
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
  /* Parse the kernel buffer into led_val */
  err = kstrtoint(kbuff, 16, &led_val);
  /* Set LEDCTL to 32-bit led_val */
  *((u32 *)(pewpew.addr + DEV_82583V_LEDCTL)) = led_val;
  /* Free the kernel buffer */
  kfree(kbuff);
  /* Check if parse was successful */
  if (err < 0) {
    printk(ERR "failed to parse integer\n");
    return -EINVAL;
  }
  printk(INFO "Write complete, LEDCTL is %x\n", *((u32 *)(pewpew.addr + DEV_82583V_LEDCTL)));
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
  printk(INFO "Registering pci driver\n");
  return pci_register_driver(&pewpew_driver);
}

static void __exit pewpew_exit(void) {
  printk(INFO "Exiting...\n");
  /* Remove our character device */
  cdev_del(&pewpew.cdev);
  /* Unregister our device number */
  unregister_chrdev_region(pewpew.dev, pewpew.count);
  /* Unregister our PCI driver */
  pci_unregister_driver(&pewpew_driver);
  printk(INFO "Exited successfully\n");
}

module_init(pewpew_init);
module_exit(pewpew_exit);
