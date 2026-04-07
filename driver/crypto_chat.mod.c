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
	{ 0xcf00b3dc, "cdev_del" },
	{ 0xceededcc, "crypto_alloc_skcipher" },
	{ 0x3857e746, "crypto_destroy_tfm" },
	{ 0x6669037b, "crypto_alloc_shash" },
	{ 0xe2240b07, "class_destroy" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x553834d3, "device_destroy" },
	{ 0x2cf56265, "__dynamic_pr_debug" },
	{ 0x52c5c991, "__kmalloc_noprof" },
	{ 0x1a388bde, "crypto_shash_digest" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x75ca79b5, "__fortify_panic" },
	{ 0xb1635050, "crypto_skcipher_setkey" },
	{ 0x43babd19, "sg_init_one" },
	{ 0x3f33796b, "crypto_skcipher_decrypt" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0x373e05ea, "crypto_skcipher_encrypt" },
	{ 0x441d0de9, "__kmalloc_large_noprof" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x50fb491d, "kmalloc_caches" },
	{ 0xc319e7ef, "__kmalloc_cache_noprof" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x92997ed8, "_printk" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x3e339862, "class_create" },
	{ 0xbc62cf0b, "cdev_init" },
	{ 0x58c79e6e, "cdev_add" },
	{ 0xbcec6e8d, "device_create" },
	{ 0xb1fc7b7a, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "AC6ED0E816F10C5F71EC86C");
MODULE_INFO(rhelversion, "10.2");
