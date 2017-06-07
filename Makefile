MODULE = pewpew
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += $(MODULE).o

all: default

default:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
	gcc -o user user.c
	gcc -o mmap mmap.c -lpci

clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean
	rm -f user mmap

load: default
	sudo ./loadmodule.sh
