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
