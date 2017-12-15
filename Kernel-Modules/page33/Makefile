obj-m := kmallocANDvmalloc.o
KDIR := /lib/modules/4.10.0-38-generic/build
PWD := $(shell pwd)

all: kmallocANDvmalloc.c
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean