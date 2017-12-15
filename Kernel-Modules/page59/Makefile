obj-m := percpu2.o
KDIR := /lib/modules/4.10.0-38-generic/build
PWD := $(shell pwd)

all: percpu2.c
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean