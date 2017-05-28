#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>
MODULE_LICENSE("GPL");

#define MODULE_STR "pewpew"
#define INFO KERN_INFO MODULE_STR ": "
#define ERR  KERN_ERR  MODULE_STR ": "
const char pewpew_driver_name[] = MODULE_STR;

/* CTRL */
#define CTRL        (*((u32 *)(pewpew.addr + 0x00000)))
#define CTRL_FD                     0
#define CTRL_GIO_MASTER_DISABLE     2
#define CTRL_ASDE                   5
#define CTRL_SLU                    6
#define CTRL_SPEED                  8
#define CTRL_FRCSPD                 11
#define CTRL_FRCDPLX                12
#define CTRL_RST                    26
#define CTRL_RFCE                   27
#define CTRL_TFCE                   28
#define CTRL_PHY_RST                31
/* STATUS 9.2.2.2 */
#define STATUS      (*((u32 *)(pewpew.addr + 0x00008)))
/* ICR */
#define ICR         (*((u32 *)(pewpew.addr + 0x000C0)))
/* IMS */
#define IMS         (*((u32 *)(pewpew.addr + 0x000D0)))
#define IMS_LSC                     2
#define IMS_RXDMT                   4
#define IMS_RXO                     6
#define IMS_RXT                     7
/* IMC */
#define IMC         (*((u32 *)(pewpew.addr + 0x000D8)))
#define IMC_LSC                     2
#define IMC_RXDMT                   4
#define IMC_RXO                     6
#define IMC_RXT                     7
/* GCR */
#define GCR         (*((u32 *)(pewpew.addr + 0x05B00)))
#define GCR2        (*((u32 *)(pewpew.addr + 0x05B64)))
/* MDIC */
#define MDIC        (*((u32 *)(pewpew.addr + 0x00020)))
/* Send and receive */
#define RCTL        (*((u32 *)(pewpew.addr + 0x00100)))
#define RCTL_EN                    1
#define RDBAL       (*((u32 *)(pewpew.addr + 0x02800)))
#define RDBAH       (*((u32 *)(pewpew.addr + 0x02804)))
#define RDLEN       (*((u32 *)(pewpew.addr + 0x02808)))
#define RDH         (*((u32 *)(pewpew.addr + 0x02810)))
#define RDT         (*((u32 *)(pewpew.addr + 0x02818)))
#define TCTL        (*((u32 *)(pewpew.addr + 0x00400)))
#define TCTL_EN                    1
#define TCTL_CT                    4
#define TDBAL       (*((u32 *)(pewpew.addr + 0x03800)))
#define TDBAH       (*((u32 *)(pewpew.addr + 0x03804)))
#define TDLEN       (*((u32 *)(pewpew.addr + 0x03808)))
#define TDH         (*((u32 *)(pewpew.addr + 0x03810)))
#define TDT         (*((u32 *)(pewpew.addr + 0x03818)))
/* LEDCTL */
#define LEDCTL      (*((u32 *)(pewpew.addr + 0x00E00)))
#define LEDCTL_MODE_ACTIVE         0x0E
#define LEDCTL_BLINK_MODE          (1 << 5)
#define LEDCTL_IVRT                (1 << 6)
#define LEDCTL_BLINK               (1 << 7)
#define LEDCTL_LED0(X)             ((X) << 0)
#define LEDCTL_LED1(X)             ((X) << 8)
#define LED0_ON     (u32)(LEDCTL_LED0(LEDCTL_MODE_ACTIVE|LEDCTL_IVRT))

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,8,0)
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

#define NUM_DESC                      16
#define DESC_STATUS_DD                0
#define DESC_STATUS_EOP               1
#define DESC_STATUS_VP                3
#define DESC_STATUS_UDPCS             4
#define DESC_STATUS_TCPCS             5
#define DESC_STATUS_IPCS              6
#define DESC_ERROR_CE                 0
#define DESC_ERROR_SE                 1
#define DESC_ERROR_SEQ                2
#define DESC_ERROR_CXE                4
#define DESC_ERROR_TCPE               5
#define DESC_ERROR_IPE                6
struct desc {
  __le64  dma_buf;
  __le16  length;
  __le16  checksum;
  u8      status;
  u8      error;
  __le16  vlan;
};
struct d_wrap {
  struct desc *d;
  void *buf;
};

struct pewpew_dev {
  dev_t dev;
  unsigned int count;
  char name[255];
  struct cdev cdev;
  struct pci_dev *pdev;
  void *addr;
  struct work_struct work;
  struct d_wrap *rx_ring;
  struct d_wrap *tx_ring;
  dma_addr_t rx_dma_addr;
  dma_addr_t tx_dma_addr;
  u32 icr;
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

static void pewpew_work_handler(struct work_struct *work) {
  printk(INFO "worker: pewpew.icr is %08x\n", pewpew.icr);
  printk(INFO "worker: ICR is %08x\n", ICR);
  if (pewpew.icr & (1 << IMS_RXT)) {
    printk(INFO "worker: RXT: Receiver Timer Interrupt\n");
  }
  if (pewpew.icr & (1 << IMS_RXO)) {
    printk(INFO "worker: RXO: Receiver Overrun\n");
  }
  if (pewpew.icr & (1 << IMS_RXDMT)) {
    printk(INFO "worker: RXDMT: Receive Descriptor minimum threshold hit\n");
  }
  if (pewpew.icr & (1 << IMS_LSC)) {
    printk(INFO "worker: LSC: Link Status Change\n");
  }
}

int pewpew_init_ring(struct pci_dev *pdev, struct d_wrap **r,
    dma_addr_t *dma_addr) {
  int i = 0;
  struct desc *dma_ring;
  struct d_wrap *ring;

  ring = vmalloc(sizeof(struct d_wrap) * NUM_DESC);
  if (!ring) {
    goto d_wrap_fail;
  }
  *r = ring;

  dma_ring = dma_alloc_coherent(&pdev->dev,
      sizeof(struct desc) * NUM_DESC, dma_addr, GFP_KERNEL);
  if (!dma_ring) {
    goto dma_ring_fail;
  }

  for (i = 0; i < NUM_DESC; ++i) {
    ring[i].d = &(dma_ring[i]);
    ring[i].buf = dma_alloc_coherent(&pdev->dev,
        2048, &ring[i].d->dma_buf, GFP_KERNEL);
    ring[i].d->dma_buf = cpu_to_le64(ring[i].d->dma_buf);
    if (!ring[i].buf) {
      goto desc_fail;
    }
  }
  return 0;

desc_fail:
  for (--i; i >= 0; --i) {
    dma_free_coherent(&pdev->dev, 2048,
        ring[i].buf, ring[i].d->dma_buf);
  }
  dma_free_coherent(&pdev->dev, sizeof(struct desc) * NUM_DESC,
      ring[0].d, *dma_addr);
dma_ring_fail:
  vfree(ring);
d_wrap_fail:
  *r = NULL;
  return -ENOMEM;
}

void pewpew_free_ring(struct pci_dev *pdev, struct d_wrap **r,
    dma_addr_t *dma_addr) {
  int i;
  struct d_wrap *ring = *r;
  for (i = NUM_DESC - 1; i >= 0; --i) {
    dma_free_coherent(&pdev->dev, 2048,
        ring[i].buf, ring[i].d->dma_buf);
  }
  dma_free_coherent(&pdev->dev, sizeof(struct desc) * NUM_DESC,
      ring[0].d, *dma_addr);
  vfree(ring);
  *r = NULL;
}

static irqreturn_t pewpew_irq_handler(int irq, void *data) {
  pewpew.icr = ICR;
  schedule_work(&pewpew.work);
  return IRQ_HANDLED;
}

int pewpew_init_device(struct pci_dev *pdev) {
  int err;
  /* Steps to initialize device (from data sheet 4.6)
   * 1. Disable Interrupts
   * 2. Issue Global Reset and preform General Configuration
   * 3. Setup the PHY and link
   * 4. Initialize all statistical counters
   * 5. Initialize Receive
   * 6. Initialize Transmit
   * 7. Enable Interrupts
   */
  /* 1. Disable Interrupts */
  IMC = 0xFFFFFFFF;
  /* 2. Global Reset and General Configuration */
  CTRL |= (1 << CTRL_RST);
  /* Make sure PHY has been reset. */
  msleep(50);
  /* We reset so we need to disable interrupts again. */
  IMC = 0xFFFFFFFF;
  /* GCR bit 22 should be set to 1b by software during
   * initialization.
   */
  GCR |= (1 << 22);
  GCR2 |= (1 << 0);
  /* Call upon the magic of the old gods raise the PHY from death */
  MDIC = 0x1831af08;
  /* 5. Receive Initialization */
  /* Program the receive address register per the station address.
   * This can come from the NVM or from any other means, for example,
   * on some systems, this comes from the system EEPROM not the NVM
   * on a Network Interface Card (NIC).
   */
  /* Program RCTL with appropriate values. If initializing it at this
   * stage, it is best to leave the receive logic disabled (EN = 0b)
   * until the receive descriptor ring has been initialized. If VLANs
   * are not used, software should clear the VFE bit. Then there is
   * no need to initialize the VFTA array. Select the receive
   * descriptor type. Note that if using the header split RX
   * descriptors, tail and head registers should be incremented by
   * two per descriptor.
   */
  /* 5.1 Initialize the Receive Control Register */
  /* To properly receive packets requires simply that the receiver is
   * enabled. This should be
   * done only after all other setup is accomplished. If software
   * uses the Receive Descriptor
   * Minimum Threshold Interrupt, that value should be set.
   */
  /* Allocate a region of memory for the receive descriptor list.
   */
  /* Receive buffers of appropriate size should be allocated and
   * pointers to these buffers should be stored in the descriptor
   * ring.
   */
  err = pewpew_init_ring(pdev, &pewpew.rx_ring, &pewpew.rx_dma_addr);
  if (err) {
    return err;
  }
  err = pewpew_init_ring(pdev, &pewpew.tx_ring, &pewpew.tx_dma_addr);
  if (err) {
    return err;
  }
  /* Program the descriptor base address with the address of the
   * region.
   */
  RDBAL = (pewpew.rx_dma_addr) & 0xffffffff;
  RDBAH = (pewpew.rx_dma_addr >> 32) & 0xffffffff;
  /* Set the length register to the size of the descriptor ring.
   */
  RDLEN = NUM_DESC;
  /* If needed, program the head and tail registers. Note: the head
   * and tail pointers are initialized (by hardware) to zero after a
   * power-on or a software-initiated device reset.
   */
  RDH = NUM_DESC - 1;
  /* The tail pointer should be set to point one descriptor beyond
   * the end.
   */
  RDT = NUM_DESC;
  printk(INFO "RCTL is: %08x\n", RCTL);
  RCTL |= (1 << RCTL_EN);
  printk(INFO "RCTL is: %08x\n", RCTL);
  TDBAL = (pewpew.tx_dma_addr) & 0xffffffff;
  TDBAH = (pewpew.tx_dma_addr >> 32) & 0xffffffff;
  TDLEN = NUM_DESC;
  TDH = NUM_DESC - 1;
  TDT = NUM_DESC;
  printk(INFO "TCTL is: %08x\n", TCTL);
  TCTL |= (1 << TCTL_EN)|(16 << TCTL_CT);
  printk(INFO "TCTL is: %08x\n", TCTL);
  /* Program the interrupt mask register to pass any interrupt that
   * the software device driver cares about. Suggested bits include
   * RXT, RXO, RXDMT and LSC. There is no reason to enable the
   * transmit interrupts.
   */
  printk(INFO "IMS is: %08x\n", IMS);
  IMS = ((1 << IMS_RXT)|(1 << IMS_RXO)|(1 << IMS_RXDMT)|(1 << IMS_LSC));
  printk(INFO "IMS is: %08x\n", IMS);
  return err;
}

int pewpew_probe(struct pci_dev *pdev, const struct pci_device_id *ent) {
  int bars, err, pci_using_dac;
  resource_size_t mmio_start, mmio_len;

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
      printk(ERR "No usable DMA configuration, aborting\n");
      goto err_dma;
    }
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

  /* Interrupt setup */
  pci_enable_msi(pdev);
  err = request_irq(pdev->irq, pewpew_irq_handler, 0, "pewpew_int", 0);
  if (err) {
    goto err_irq;
  }

  /* Initialize device as called for by 82583V datasheet 4.6 */
  return pewpew_init_device(pdev);

err_irq:
err_ioremap:
  iounmap(pewpew.addr);
  pci_release_mem_regions(pdev);
err_pci_reg:
err_dma:
  pci_disable_device(pdev);
  return err;
}

void pewpew_remove(struct pci_dev *pdev) {
  /* Clear it all (probably bad) */
  LEDCTL &= ~(LED0_ON);
  pewpew_free_ring(pdev, &pewpew.rx_ring, &pewpew.rx_dma_addr);
  pewpew_free_ring(pdev, &pewpew.tx_ring, &pewpew.tx_dma_addr);
  iounmap(pewpew.addr);
  free_irq(pdev->irq, 0);
  pci_disable_msi(pdev);
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
  // TODO start blinking on open
  /* Turn the LED on */
  LEDCTL |= LED0_ON;
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
  /* Turn off the LEDs */
  LEDCTL &= ~(LED0_ON);
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
  /* workqueue */
  INIT_WORK(&pewpew.work, pewpew_work_handler);
  printk(INFO "Initialized\n");
  printk(INFO "Registering pci driver\n");
  return pci_register_driver(&pewpew_driver);
}

static void __exit pewpew_exit(void) {
  printk(INFO "Exiting...\n");
  /* Remove the workqueue */
  cancel_work_sync(&pewpew.work);
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
