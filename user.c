#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>


#define DEV_NAME "/dev/pewpew0"

int read_it() {
  int fd, n;
  const unsigned int buff_size = 255;
  char buff[buff_size];

  fd = open(DEV_NAME, O_RDONLY);
  if (fd < 0) {
    perror("Error opening " DEV_NAME);
    return EXIT_FAILURE;
  }

  if (read(fd, buff, buff_size) < 1) {
    perror("Error reading from " DEV_NAME);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int write_it(char *buff) {
  int fd, n;

  fd = open(DEV_NAME, O_WRONLY);
  if (fd < 0) {
    perror("Error opening " DEV_NAME);
    return EXIT_FAILURE;
  }

  if (write(fd, buff, strlen(buff)) != strlen(buff)) {
    perror("Error writing to " DEV_NAME);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
  if (argc == 2) {
    return write_it(argv[1]);
  } else {
    return read_it();
  }
}
