obj-m := KeyboardInterrupt.o
KDIR := /lib/modules/4.10.0-40-generic/build
PWD := $(shell pwd)

all: KeyboardInterrupt.c
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean
