#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>


#define DEV_NAME "/dev/pewpew0"

#define DEV_82583V_LEDCTL_MODE_ACTIVE         0x0E
#define DEV_82583V_LEDCTL_BLINK_MODE          (1 << 5)
#define DEV_82583V_LEDCTL_IVRT                (1 << 6)
#define DEV_82583V_LEDCTL_BLINK               (1 << 7)
#define DEV_82583V_LEDCTL_LED0(X)             ((X) << 0)
#define DEV_82583V_LEDCTL_LED1(X)             ((X) << 8)


int main() {
  int fd, n;
  uint32_t led_val;
  const unsigned int buff_size = 255;
  char buff[buff_size];

  fd = open(DEV_NAME, O_RDWR);
  if (fd < 0) {
    perror("Error opening " DEV_NAME);
    return EXIT_FAILURE;
  }

  if (read(fd, buff, buff_size) < 1) {
    perror("Error reading from " DEV_NAME);
    return EXIT_FAILURE;
  }

  printf("LEDCTL: %s\n", buff);

  /* Turn on LED0 */
  led_val = (uint32_t)(
      DEV_82583V_LEDCTL_LED0(DEV_82583V_LEDCTL_MODE_ACTIVE|
          DEV_82583V_LEDCTL_BLINK_MODE|DEV_82583V_LEDCTL_IVRT|
          DEV_82583V_LEDCTL_BLINK));

  memset(buff, 0, buff_size);
  sprintf(buff, "%x", led_val);

  if (write(fd, buff, strlen(buff)) != strlen(buff)) {
    perror("Error writing to " DEV_NAME);
    return EXIT_FAILURE;
  }

  memset(buff, 0, buff_size);
  if (read(fd, buff, buff_size) < 1) {
    perror("Error reading from " DEV_NAME);
    return EXIT_FAILURE;
  }

  printf("LEDCTL: %s\n", buff);

  sleep(2);

  /* Turn off LED0 */
  led_val = 0;

  memset(buff, 0, buff_size);
  sprintf(buff, "%x", led_val);

  if (write(fd, buff, strlen(buff)) != strlen(buff)) {
    perror("Error writing to " DEV_NAME);
    return EXIT_FAILURE;
  }

  memset(buff, 0, buff_size);
  if (read(fd, buff, buff_size) < 1) {
    perror("Error reading from " DEV_NAME);
    return EXIT_FAILURE;
  }

  printf("LEDCTL: %s\n", buff);

  return EXIT_SUCCESS;
}
