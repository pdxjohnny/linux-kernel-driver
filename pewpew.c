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
#define LED0_ON     (u32)(\
        DEV_82583V_LEDCTL_LED0(DEV_82583V_LEDCTL_MODE_ACTIVE|\
            DEV_82583V_LEDCTL_IVRT))
#define LEDCTL      (*((u32 *)(pewpew.addr + DEV_82583V_LEDCTL)))

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
void pewpew_timer_callback(unsigned long unused);

struct pewpew_dev {
  dev_t dev;
  unsigned int count;
  char name[255];
  struct cdev cdev;
  struct pci_dev *pdev;
  void *addr;
  struct timer_list timer;
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

/* Default Blink Rate */
#define DBL 2
static int blink_rate = DBL;
module_param(blink_rate, int, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(blink_rate, "blinks-per-second rate");

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
  LEDCTL &= ~(LED0_ON);
  iounmap(pewpew.addr);
  pci_release_mem_regions(pdev);
  pci_disable_device(pdev);
  pewpew.pdev = NULL;
  pewpew.addr = NULL;
}

int pewpew_open(struct inode *inode, struct file *flip) {
  int err;
  /* Make sure we are connected to the PCI device */
  if (pewpew.pdev == NULL || pewpew.addr == NULL) {
    return -ENODEV;
  }
  // TODO start blinking on open
  /* Setup the timer, no need to pass argument to callback because we
   * are shamlessly using globals all over. */
  setup_timer(&pewpew.timer, pewpew_timer_callback, 0);
  /* Turn the LED on */
  LEDCTL |= LED0_ON;
  /* Start the timer */
  err = mod_timer(&pewpew.timer,
      jiffies + msecs_to_jiffies(500 / blink_rate));
  if (err) {
    printk(ERR "mod_timer gave error %d\n", err);
  }
	return 0;
}

ssize_t pewpew_read(struct file *flip, char __user *buff, size_t count, loff_t *offp) {
  int err;
  char *kbuff;
  const unsigned int kbuff_size = 255;
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
  /* Format blink_rate into the kernel buffer */
  err = sprintf(kbuff, "%d", blink_rate);
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
  printk(INFO "Read complete, blink_rate is %d\n", blink_rate);
  /* Make sure we are connected to the PCI device */
  if (pewpew.pdev == NULL || pewpew.addr == NULL) {
    return -ENODEV;
  }
  /* Return length of the string written back */
  return count;
}

ssize_t pewpew_write(struct file *flip, const char __user *buff, size_t count, loff_t *offp) {
  int err;
  int tmp;
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
  /* Parse the kernel buffer into tmp */
  err = kstrtoint(kbuff, 10, &tmp);
  /* Free the kernel buffer */
  kfree(kbuff);
  /* Check if parse was successful and tmp is postive */
  if (err < 0 || tmp <= 0) {
    printk(ERR "failed to parse integer or negative\n");
    return -EINVAL;
  }
  blink_rate = tmp;
  printk(INFO "Write complete, blink_rate is %d\n", blink_rate);
  /* Return length that was given on success */
  return count;
}

int pewpew_release(struct inode *inode, struct file *filp) {
  /* Make sure we are connected to the PCI device */
  if (pewpew.pdev == NULL || pewpew.addr == NULL) {
    return -ENODEV;
  }
  /* Remove the timer */
  del_timer_sync(&pewpew.timer);
  /* Turn off the LEDs */
  LEDCTL &= ~(LED0_ON);
  return 0;
}

void pewpew_timer_callback(unsigned long unused) {
  int err;
  /* Make sure blink_rate is valid */
  if (blink_rate <= 0) {
    printk(ERR "blink_rate has been set to %d which is invalid."
       " It has been reset to the default of %d\n", blink_rate, DBL);
    blink_rate = DBL;
  }
  /* Turn on or off the LED depending on where we are in the cycle */
  if ((LEDCTL & LED0_ON) == LED0_ON) {
    /* LED is on need to turn off */
    printk(INFO "LED is on turning off\n");
    LEDCTL &= ~(LED0_ON);
  } else {
    /* LED is off need to turn on */
    printk(INFO "LED is off turning on\n");
    LEDCTL |= LED0_ON;
  }
  /* Turn the timer on */
  err = mod_timer(&pewpew.timer,
      jiffies + msecs_to_jiffies(500 / blink_rate));
  if (err) {
    printk(ERR "mod_timer gave error %d\n", err);
  }
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
  /* Remove the timer */
  del_timer_sync(&pewpew.timer);
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
