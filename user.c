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
  int fd;
  uint16_t pack = 0;
  uint8_t head = 0, tail = 0;

  fd = open(DEV_NAME, O_RDWR);
  if (fd < 0) {
    perror("Error opening " DEV_NAME);
    return EXIT_FAILURE;
  }

  if (read(fd, &pack, sizeof(pack)) != sizeof(pack)) {
    perror("Error reading from " DEV_NAME);
    return EXIT_FAILURE;
  }

  head = ((pack >> 8) & 0xff);
  tail = ((pack >> 0) & 0xff);

  printf("HEAD: %d\n", head);
  printf("TAIL: %d\n", tail);

  close(fd);
  return EXIT_SUCCESS;
}
