#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEV_NAME "/dev/pewpew0"

int main(int argc, char **argv) {
  int fd, i, n, blink_rate;
  const unsigned int buff_size = 255;
  char buff[buff_size];

  fd = open(DEV_NAME, O_RDWR);
  if (fd < 0) {
    perror("Error opening " DEV_NAME);
    return EXIT_FAILURE;
  }

  for (i = 1; i < argc; i++) {
    memset(buff, 0, buff_size);
    if (read(fd, buff, buff_size) < 1) {
      perror("Error reading from " DEV_NAME);
      return EXIT_FAILURE;
    }

    printf("Blink Rate: %s\n", buff);

    sleep(2);

    // /* Set Blink Rate */
    // blink_rate = atoi(argv[i]);
    // printf("Setting Blink Rate to: %d\n", blink_rate);

    // memset(buff, 0, buff_size);
    // sprintf(buff, "%d", blink_rate);

    // if (write(fd, buff, strlen(buff)) != strlen(buff)) {
    //   perror("Error writing to " DEV_NAME);
    //   return EXIT_FAILURE;
    // }

    // sleep(2);
  }

  close(fd);

  return EXIT_SUCCESS;
}
