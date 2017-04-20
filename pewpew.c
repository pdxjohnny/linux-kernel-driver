#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <asm/uaccess.h>
MODULE_LICENSE("GPL");

#define MODULE_STR "pewpew"
#define INFO KERN_INFO MODULE_STR ": "
#define ERR  KERN_ERR  MODULE_STR ": "

#define DEV_82583V_LEDCTL                     0x00E00
#define DEV_82583V_LEDCTL_MODE_ACTIVE         0x0E
#define DEV_82583V_LEDCTL_BLINK_MODE          (1 << 5)
#define DEV_82583V_LEDCTL_IVRT                (1 << 6)
#define DEV_82583V_LEDCTL_BLINK               (1 << 7)
#define DEV_82583V_LEDCTL_LED0(X)             ((X) << 0)
#define DEV_82583V_LEDCTL_LED1(X)             ((X) << 8)

int pewpew_open(struct inode *inode, struct file *flip);
ssize_t pewpew_read(struct file *flip, char __user *buff, size_t count, loff_t *offp);
ssize_t pewpew_write(struct file *flip, const char __user *buff, size_t count, loff_t *offp);
int pewpew_release(struct inode *inode, struct file *filp);
static int pewpew_probe(struct pci_dev *pdev, const struct pci_device_id *ent);

struct pewpew_dev {
  dev_t dev;
  unsigned int count;
  char name[255];
  struct cdev cdev;
  int syscall_val;
  void *addr;
};
struct pewpew_dev pewpew;

static const struct pci_device_id pewpew_pci_tbl = {
   { PCI_VDEVICE(0x8086, 0x150C), 4 },
   { 0, 0, 0, 0, 0, 0, 0 }
};

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

static int syscall_val = 40;
module_param(syscall_val, int, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(syscall_val, "Initial value of syscall_val");

static int pewpew_probe(struct pci_dev *pdev, const struct pci_device_id *ent) {
  int err;
  err = pci_enable_device_mem(pdev);
  if (err) {
    printk(INFO "could not pci_enable_device_mem: %d\n", err);
    return err;
  }

  pci_using_dac = 0;
  err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
  if (!err) {
    pci_using_dac = 1;
  } else {
    err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev,
					"No usable DMA configuration, aborting\n");
			goto err_dma;
		}
  }

  bars = pci_select_bars(pdev, IORESOURCE_MEM);
  err = pci_request_selected_regions_exclusive(pdev, bars, MODULE_NAME);
  if (err) {
    printk(ERR "%d\n", err);
    goto err_pci_reg;
  }

  /* AER (Advanced Error Reporting) hooks */
  pci_enable_pcie_error_reporting(pdev);

  pci_set_master(pdev);
  /* PCI config space info */
  err = pci_save_state(pdev);
  if (err) {
  }

  if (!(pci_resource_flags(pdev, 1) & IORESOURCE_MEM)) {
    printk(ERR "no IORESOURCE_MEM in pci_resource_flags\n");
    return -EINVAL;
  }

  /* Map into memory */
  flash_start = pci_resource_start(pdev, 1);
  flash_len = pci_resource_len(pdev, 1);
  printk(INFO "mapping %d of memory starting at %p\n",
      flash_start, flash_len);
  pewpew_dev->addr = ioremap(flash_start, flash_len);
  if (!pewpew_dev->addr) {
    printk(ERR "failed to setup memory mapped I/O with ioremap\n");
    return -EINVAL;
  }
  /* Clear it all (probably bad) */
  *((u32 *)(pewpew_dev->addr + DEV_82583V_LEDCTL)) = 0;
  /* Turn on LED0 */
  *((u32 *)(pewpew_dev->addr + DEV_82583V_LEDCTL)) |= (u32)(
      DEV_82583V_LEDCTL_LED0(DEV_82583V_LEDCTL_MODE_ACTIVE|
          DEV_82583V_LEDCTL_BLINK_MODE|DEV_82583V_LEDCTL_IVRT|
          DEV_82583V_LEDCTL_BLINK));
  /* Turn on LED1 */
  *((u32 *)(mem + DEV_82583V_LEDCTL)) |= (u32)(
      DEV_82583V_LEDCTL_LED1(DEV_82583V_LEDCTL_MODE_ACTIVE|
          DEV_82583V_LEDCTL_BLINK_MODE|DEV_82583V_LEDCTL_IVRT|
          DEV_82583V_LEDCTL_BLINK));
  /* Display the new value */
  printk(INFO "LEDCTL: %08x\n", *((u32 *)(mem + DEV_82583V_LEDCTL)));
  return 0;

err_register:
  if (!(adapter->flags & FLAG_HAS_AMT))
    e1000e_release_hw_control(adapter);
err_eeprom:
  if (hw->phy.ops.check_reset_block && !hw->phy.ops.check_reset_block(hw))
    e1000_phy_hw_reset(&adapter->hw);
err_hw_init:
  kfree(adapter->tx_ring);
  kfree(adapter->rx_ring);
err_sw_init:
  if ((adapter->hw.flash_address) && (hw->mac.type < e1000_pch_spt))
    iounmap(adapter->hw.flash_address);
  e1000e_reset_interrupt_capability(adapter);
err_flashmap:
  iounmap(adapter->hw.hw_addr);
err_ioremap:
  free_netdev(netdev);
err_alloc_etherdev:
  pci_release_mem_regions(pdev);
err_pci_reg:
err_dma:
  pci_disable_device(pdev);
  return err;
}

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
  printk(INFO "Registering pci driver\n");
  return pci_register_driver(&pewpew_driver);
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
