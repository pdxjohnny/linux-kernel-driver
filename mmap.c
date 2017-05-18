#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pci/pci.h>

#define DEV_82583V_GOOD_PACKETS_RECEIVED      0x04074
#define DEV_82583V_LEDCTL                     0x00E00
#define DEV_82583V_LEDCTL_MODE_ACTIVE         0x0E
#define DEV_82583V_LEDCTL_BLINK_MODE          (1 << 5)
#define DEV_82583V_LEDCTL_IVRT                (1 << 6)
#define DEV_82583V_LEDCTL_BLINK               (1 << 7)
#define DEV_82583V_LEDCTL_LED0(X)             ((X) << 0)
#define DEV_82583V_LEDCTL_LED1(X)             ((X) << 8)
#define DEV_82583V_LEDCTL_LED2(X)             ((X) << 16)
#define GREEN_LEFT(X)                         DEV_82583V_LEDCTL_LED2(X)
#define AMBER_LEFT(X)                         DEV_82583V_LEDCTL_LED0(X)
#define GREEN_RIGHT(X)                        DEV_82583V_LEDCTL_LED1(X)

#define VENDOR_ID                             0x8086
#define DEVICE_ID                             0x1501

int main() {
  struct pci_access *pacc;
  struct pci_dev *dev;
  unsigned int c;
  int i;
  uint32_t ledctl;
  long base = 0, size = 0;
  char namebuf[1024], *name;

  /* Find the PCI device we want */
  pacc = pci_alloc();
  pci_init(pacc);
  pci_scan_bus(pacc);
  for (dev = pacc->devices; dev; dev = dev->next)	{
    pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);
    if (dev->vendor_id == VENDOR_ID && dev->device_id == DEVICE_ID) {
      base = (long) dev->base_addr[0];
      size = (long) dev->size[0];
      break;
    }
  }
  pci_cleanup(pacc);
  if (!base || !size) {
    printf("Error could not find PCI device\n");
    return EXIT_FAILURE;
  }
  /* Open /dev/mem */
  int fd = open("/dev/mem", O_RDWR|O_SYNC);
  if (fd < 0) {
    perror("Error opening /dev/mem");
    return EXIT_FAILURE;
  }
  /* Use the information we got from libpci (base and size) to map */
  void *mem = mmap(NULL, size, PROT_READ|PROT_WRITE,
      MAP_SHARED, fd, base);
  if (mem == MAP_FAILED) {
    perror("Error mmaping /dev/mem");
    return EXIT_FAILURE;
  }
  /* Save the current LEDCTL value */
  ledctl = *((uint32_t *)(mem + DEV_82583V_LEDCTL));
  /* Print it for the user to read */
  printf("LEDCTL: %08x\n", ledctl);
  /* Turn both green LEDs (LED0 and LED2) on for 2 seconds */
  *((uint32_t *)(mem + DEV_82583V_LEDCTL)) = (uint32_t)(
      GREEN_LEFT(DEV_82583V_LEDCTL_MODE_ACTIVE|
        DEV_82583V_LEDCTL_IVRT)|
      GREEN_RIGHT(DEV_82583V_LEDCTL_MODE_ACTIVE|
        DEV_82583V_LEDCTL_IVRT)
      );
  sleep(2);
  /* Turn all LEDs off for 2 seconds */
  *((uint32_t *)(mem + DEV_82583V_LEDCTL)) = 0;
  sleep(2);
  /* Loop 5 times and turn each LED (amber, green on right, green on
   * left) on for 1 second */
  for (i = 0; i < 5; ++i) {
    /* Turn on LED1 amber */
    *((uint32_t *)(mem + DEV_82583V_LEDCTL)) = (uint32_t)(
        AMBER_LEFT(DEV_82583V_LEDCTL_MODE_ACTIVE|
            DEV_82583V_LEDCTL_IVRT));
    sleep(1);
    /* Turn on LED0 green on right */
    *((uint32_t *)(mem + DEV_82583V_LEDCTL)) = (uint32_t)(
        GREEN_RIGHT(DEV_82583V_LEDCTL_MODE_ACTIVE|
            DEV_82583V_LEDCTL_IVRT));
    sleep(1);
    /* Turn on LED2 green on left */
    *((uint32_t *)(mem + DEV_82583V_LEDCTL)) = (uint32_t)(
        GREEN_LEFT(DEV_82583V_LEDCTL_MODE_ACTIVE|
            DEV_82583V_LEDCTL_IVRT));
    sleep(1);
  }
  /* Restore LEDCTL to initial value */
  *((uint32_t *)(mem + DEV_82583V_LEDCTL)) = ledctl;
  /* Read and print the contents of the Good Packets Received
   * statistics register */
  printf("Good Packets Received: %d\n", *((uint32_t *)(mem + DEV_82583V_GOOD_PACKETS_RECEIVED)));
  /* Unmap /dev/mem */
  munmap(mem, size);
  /* Close /dev/mem */
  close(fd);
  return 0;
}
