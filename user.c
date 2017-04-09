#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>


#define DEV_NAME "/dev/pewpew0"

int main(int argc, char **argv) {
  int fd, n;
  const unsigned int buff_size = 255;
  char buff[buff_size];

  if (argc != 2) {
    printf("Usage: %s number\n", argv[0]);
    return EXIT_FAILURE;
  }

  fd = open(DEV_NAME, O_RDWR);
  if (fd < 0) {
    perror("Error opening " DEV_NAME);
    return EXIT_FAILURE;
  }

  if (read(fd, buff, buff_size) < 1) {
    perror("Error reading from " DEV_NAME);
    return EXIT_FAILURE;
  }

  printf("%s\n", buff);

  if (write(fd, argv[1], strlen(argv[1])) != strlen(argv[1])) {
    perror("Error writing to " DEV_NAME);
    return EXIT_FAILURE;
  }

  memset(buff, 0, buff_size);
  if (read(fd, buff, buff_size) < 1) {
    perror("Error reading from " DEV_NAME);
    return EXIT_FAILURE;
  }

  printf("%s\n", buff);

  return EXIT_SUCCESS;
}
