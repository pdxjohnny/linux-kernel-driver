#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
MODULE_LICENSE("GPL");

#define MODULE_STR "pewpew"
#define INFO KERN_INFO MODULE_STR ": "

static int __init pewpew_init(void) {
  printk(INFO "Initializing");
  return 0;
}

static void __exit pewpew_exit(void) {
  printk(INFO "Exiting");
}

module_init(pewpew_init);
module_exit(pewpew_exit);
