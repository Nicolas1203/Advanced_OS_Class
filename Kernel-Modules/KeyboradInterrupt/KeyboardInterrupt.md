Keyboard Interrupt - Nicolas MICHEL
=================================

This is the report concerning the implementation of Keyboard Interrupt kernel module

Makefile Code
------------

	obj-m := KeyboardInterrupt.o
	KDIR := /lib/modules/4.10.0-40-generic/build
	PWD := $(shell pwd)

	all: KeyboardInterrupt.c
		make -C $(KDIR) SUBDIRS=$(PWD) modules

	clean:
		make -C $(KDIR) SUBDIRS=$(PWD) clean


KeyboardInterrupt.c Code
------------------------

	#include <linux/module.h>
	#include <linux/kernel.h>
	#include <linux/init.h>
	#include <linux/interrupt.h>

	#define PRINT_PREF "[KEYBOARDINTERRUPT]: "

	static irqreturn_t keyboard_interrupt(int irq,void *data){

	    unsigned char code = inb(0x60);

	    printk(PRINT_PREF "%c",code);
			return IRQ_HANDLED;
	}

	static int __init my_mod_init(void)
	{
	  if(request_irq(1,keyboard_interrupt,IRQF_SHARED, "keyboard_interrupt",(void *)(keyboard_interrupt))){
		printk(PRINT_PREF " Entering module.¥n");
		return 0;
	  }
	}

	static void __exit my_mod_exit(void)
	{
		free_irq(1,(void *)(keyboard_interrupt));
		printk(PRINT_PREF "Exiting module.¥n");
	}

	module_init(my_mod_init);
	module_exit(my_mod_exit);

	MODULE_LICENSE("GPL");

The log after pressing some keys

	Nov 29 00:14:45 nicolas-Lemur kernel: [18772.444672] [KEYBOARDINTERRUPT]:  Entering module.Â¥n
	Nov 29 00:14:50 nicolas-Lemur kernel: [18772.574607] [KEYBOARDINTERRUPT]: 
	Nov 29 00:14:50 nicolas-Lemur kernel: [18777.447862] [KEYBOARDINTERRUPT]: *
	Nov 29 00:14:50 nicolas-Lemur kernel: [18777.522954] [KEYBOARDINTERRUPT]: ' 
	Nov 29 00:14:51 nicolas-Lemur kernel: [18759.038157] [KEYBOARDINTERRUPT]: Exiting module.Â¥n
