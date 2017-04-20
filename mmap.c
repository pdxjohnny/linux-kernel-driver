#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Map 128K at the address provided by `lspci -s 03:00.0 -v` */
#define DEV_82583V                            0xFEBE0000
#define DEV_82583V_LENGTH                     (1 << 17)

#define DEV_82583V_LEDCTL                     0x00E00
#define DEV_82583V_LEDCTL_MODE_ACTIVE         0x0E
#define DEV_82583V_LEDCTL_BLINK_MODE          (1 << 5)
#define DEV_82583V_LEDCTL_IVRT                (1 << 6)
#define DEV_82583V_LEDCTL_BLINK               (1 << 7)
#define DEV_82583V_LEDCTL_LED0(X)             ((X) << 0)
#define DEV_82583V_LEDCTL_LED1(X)             ((X) << 8)

int main() {
  /* Open /dev/mem */
  int fd = open("/dev/mem", O_RDWR|O_SYNC);
  /* Map 128K at the address provided by `lspci -s 03:00.0 -v` */
  void *mem = mmap(NULL, DEV_82583V_LENGTH, PROT_READ|PROT_WRITE,
      MAP_SHARED, fd, DEV_82583V);
  /* Clear it all (probably bad) */
  *((uint32_t *)(mem + DEV_82583V_LEDCTL)) = 0;
  /* Turn on LED0 */
  *((uint32_t *)(mem + DEV_82583V_LEDCTL)) |= (uint32_t)(
      DEV_82583V_LEDCTL_LED0(DEV_82583V_LEDCTL_MODE_ACTIVE|
          DEV_82583V_LEDCTL_BLINK_MODE|DEV_82583V_LEDCTL_IVRT|
          DEV_82583V_LEDCTL_BLINK));
  /* Turn on LED1 */
  *((uint32_t *)(mem + DEV_82583V_LEDCTL)) |= (uint32_t)(
      DEV_82583V_LEDCTL_LED1(DEV_82583V_LEDCTL_MODE_ACTIVE|
          DEV_82583V_LEDCTL_BLINK_MODE|DEV_82583V_LEDCTL_IVRT|
          DEV_82583V_LEDCTL_BLINK));
  /* Display the new value */
  printf("LEDCTL: %08x\n", *((uint32_t *)(mem + DEV_82583V_LEDCTL)));
  /* Unmap /dev/mem */
  munmap(mem, DEV_82583V_LENGTH);
  /* Close /dev/mem */
  close(fd);
  return 0;
}
