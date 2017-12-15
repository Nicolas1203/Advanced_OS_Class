obj-m += llma.o
obj-m += kmallocANDvmalloc.o
obj-m += slablayer.o
obj-m += highmem.o
obj-m += percpu.o
obj-m += percpu2.o
KDIR := /lib/modules/4.10.0-38-generic/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean