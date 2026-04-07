#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x9a2204ee, "cdev_del" },
	{ 0x5993e57, "crypto_alloc_skcipher" },
	{ 0xaabf26de, "crypto_destroy_tfm" },
	{ 0x8bc9ed41, "crypto_alloc_shash" },
	{ 0xad3ed76f, "class_destroy" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x77a368f0, "device_destroy" },
	{ 0x2cf56265, "__dynamic_pr_debug" },
	{ 0x52c5c991, "__kmalloc_noprof" },
	{ 0xfdac4b8e, "crypto_shash_digest" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x75ca79b5, "__fortify_panic" },
	{ 0x250fc927, "crypto_skcipher_setkey" },
	{ 0x43babd19, "sg_init_one" },
	{ 0x86d8abac, "crypto_skcipher_decrypt" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0x4ef9f748, "crypto_skcipher_encrypt" },
	{ 0x441d0de9, "__kmalloc_large_noprof" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0xcc3c86a2, "kmalloc_caches" },
	{ 0xc7eed486, "__kmalloc_cache_noprof" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x92997ed8, "_printk" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x29811fb, "class_create" },
	{ 0x89ea8231, "cdev_init" },
	{ 0xb10b4af7, "cdev_add" },
	{ 0xfdf2efa9, "device_create" },
	{ 0x5fb309e8, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "1BF4E6399A0A1D9CBE5877E");
MODULE_INFO(rhelversion, "10.3");
