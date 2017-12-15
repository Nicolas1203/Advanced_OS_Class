obj-m := highmem.o
KDIR := /lib/modules/4.10.0-38-generic/build
PWD := $(shell pwd)

all: highmem.c
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean