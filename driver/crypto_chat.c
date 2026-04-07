// =============================================================================
// crypto_chat.c — Linux Kernel Driver
//
// Platform  : CentOS 7/8  x86_64 (kernel 3.10 – 5.x)
// Crypto    : AES-256-CBC (encrypt/decrypt) + SHA-256 (hash / KDF)
// Interface : char device /dev/crypto_chat, IOCTL API
// =============================================================================

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/version.h>

/* Kernel crypto API */
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <crypto/aes.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>

#include "crypto_chat.h"

#define DRIVER_NAME    "crypto_chat"
#define DRIVER_VERSION 0x0100   /* 1.0 */
#define DRIVER_AUTHOR  "CryptoChatDev"
#define DRIVER_DESC    "AES-256-CBC + SHA-256 crypto driver for chat application"

/* ── Module globals ──────────────────────────────────────── */
static int            major_number;
static struct class  *crypto_chat_class  = NULL;
static struct device *crypto_chat_device = NULL;
static struct cdev    crypto_chat_cdev;
static dev_t          dev_num;

static DEFINE_MUTEX(crypto_chat_mutex);

/* ── Forward declarations ────────────────────────────────── */
static int     crypto_chat_open   (struct inode *, struct file *);
static int     crypto_chat_release(struct inode *, struct file *);
static long    crypto_chat_ioctl  (struct file *, unsigned int, unsigned long);

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = crypto_chat_open,
    .release        = crypto_chat_release,
    .unlocked_ioctl = crypto_chat_ioctl,
};

/* =============================================================================
 * Helper: AES-256-CBC via kernel skcipher API
 * ============================================================================= */
/*
 * do_aes_cbc - thực hiện mã hóa/giải mã AES-256-CBC bằng Kernel Crypto API.
 *
 * @key:        khóa AES-256 (AES_KEY_SIZE = 32 bytes)
 * @iv:         vector khởi tạo AES-CBC (AES_IV_SIZE bytes, thường 16)
 * @input:      dữ liệu đầu vào (plaintext khi encrypt=1, ciphertext khi encrypt=0)
 * @input_len:  độ dài dữ liệu đầu vào (u32)
 * @output:     buffer đầu ra (được hàm ghi vào)
 * @output_len: con trỏ lưu độ dài dữ liệu đầu ra thực tế
 * @encrypt:    nếu != 0 thì encrypt, nếu 0 thì decrypt
 *
 * Luồng xử lý:
 * - Khi encrypt=1: dùng PKCS#7 padding để bảo đảm đầu vào luôn bội số của block (16 byte).
 *   Trường hợp input_len == 0 vẫn hợp lệ (sẽ tạo ra 1 block padding).
 * - Khi encrypt=0: yêu cầu input_len phải là bội số của AES block size; sau khi giải mã
 *   sẽ kiểm tra và loại bỏ PKCS#7 padding.
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - mã lỗi âm (ví dụ -EINVAL, -ENOMEM, -EBADMSG) khi gặp lỗi.
 */
static int do_aes_cbc(const u8 *key, const u8 *iv,
                      const u8 *input, u32 input_len,
                      u8 *output, u32 *output_len,
                      int encrypt)
{
    struct crypto_skcipher *tfm  = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg_in, sg_out;
    u8 *in_buf  = NULL;
    u8 *out_buf = NULL;
    u8  local_iv[AES_IV_SIZE];
    u32 work_len;
    int ret = 0;

    if (encrypt) {
        /* PKCS#7: always pad 1–16 bytes so ciphertext is block-aligned */
        u8 pad = AES_BLOCK_SIZE_VAL - (input_len % AES_BLOCK_SIZE_VAL);
        work_len = input_len + pad;

        in_buf  = kzalloc(work_len, GFP_KERNEL);
        out_buf = kzalloc(work_len, GFP_KERNEL);
        if (!in_buf || !out_buf) { ret = -ENOMEM; goto out; }

        memcpy(in_buf, input, input_len);
        memset(in_buf + input_len, pad, pad);
    } else {
        /* Ciphertext must be block-aligned */
        work_len = input_len;
        if (work_len == 0 || work_len % AES_BLOCK_SIZE_VAL != 0) {
            return -EINVAL;
        }

        in_buf  = kzalloc(work_len, GFP_KERNEL);
        out_buf = kzalloc(work_len, GFP_KERNEL);
        if (!in_buf || !out_buf) { ret = -ENOMEM; goto out; }

        memcpy(in_buf, input, input_len);
    }

    memcpy(local_iv, iv, AES_IV_SIZE);

    tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("%s: crypto_alloc_skcipher failed: %ld\n",
               DRIVER_NAME, PTR_ERR(tfm));
        ret = PTR_ERR(tfm);
        tfm = NULL;
        goto out;
    }

    ret = crypto_skcipher_setkey(tfm, key, AES_KEY_SIZE);
    if (ret) {
        pr_err("%s: setkey failed: %d\n", DRIVER_NAME, ret);
        goto out;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out;
    }

    sg_init_one(&sg_in,  in_buf,  work_len);
    sg_init_one(&sg_out, out_buf, work_len);
    skcipher_request_set_crypt(req, &sg_in, &sg_out, work_len, local_iv);

    ret = encrypt ? crypto_skcipher_encrypt(req)
                  : crypto_skcipher_decrypt(req);
    if (ret) {
        pr_err("%s: %s failed: %d\n", DRIVER_NAME,
               encrypt ? "encrypt" : "decrypt", ret);
        goto out;
    }

    if (!encrypt) {
        /* Remove PKCS#7 padding */
        u8 pad = out_buf[work_len - 1];
        if (pad == 0 || pad > AES_BLOCK_SIZE_VAL) {
            ret = -EBADMSG;
            goto out;
        }
        *output_len = work_len - pad;
    } else {
        *output_len = work_len;
    }

    memcpy(output, out_buf, *output_len);

out:
    if (req)     skcipher_request_free(req);
    if (tfm)     crypto_free_skcipher(tfm);
    kfree(in_buf);
    kfree(out_buf);
    return ret;
}

/* =============================================================================
 * Helper: SHA-256 via kernel shash API
 * ============================================================================= */
/*
 * do_sha256 - tính SHA-256 cho một vùng dữ liệu trong kernel.
 *
 * @data:      con trỏ tới dữ liệu cần băm
 * @data_len:  kích thước dữ liệu (bytes)
 * @digest:    buffer đích lưu kết quả SHA-256 (ít nhất SHA256_DIGEST_SIZE bytes)
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - mã lỗi âm khi alloc crypto/shash thất bại hoặc digest thất bại.
 */
static int do_sha256(const u8 *data, u32 data_len, u8 *digest)
{
    struct crypto_shash *tfm  = NULL;
    struct shash_desc   *desc = NULL;
    size_t desc_size;
    int ret = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("%s: crypto_alloc_shash failed: %ld\n",
               DRIVER_NAME, PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    desc_size = sizeof(*desc) + crypto_shash_descsize(tfm);
    desc = kzalloc(desc_size, GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto out;
    }

    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, data, data_len, digest);
    if (ret)
        pr_err("%s: sha256 digest failed: %d\n", DRIVER_NAME, ret);

out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/* =============================================================================
 * Helper: PBKDF2-like key derivation using iterated SHA-256
 *         SHA256(SHA256(password || salt) || iteration_count) × 4096 rounds
 * ============================================================================= */
/*
 * do_derive_key - dẫn xuất khóa AES từ password và salt bằng cách lặp SHA-256.
 *
 * Mục tiêu: biến (password, salt) thành khóa độ dài AES_KEY_SIZE (32 bytes) để dùng cho AES-256.
 *
 * Giả định/điều kiện đầu vào:
 * - password_len <= MAX_PASSWORD_LEN (để tránh tràn buffer tạm)
 * - salt: driver đang dùng salt kích thước 16 bytes (do memcpy salt, 16)
 *
 * Thuật toán (tương tự PBKDF2 nhưng dạng rút gọn):
 * - tmp0 = SHA256(password || salt)
 * - lặp 4096 lần: tmp = SHA256(tmp || i_le32)
 * - kết quả: derived_key = tmp[0:AES_KEY_SIZE]
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - mã lỗi âm nếu bước SHA-256 nào đó thất bại.
 */
static int do_derive_key(const u8 *password, u32 pwd_len,
                         const u8 *salt,     u8 *derived_key)
{
    u8  buf[MAX_PASSWORD_LEN + 16 + 4];
    u8  tmp[SHA256_DIGEST_SIZE];
    int i, ret;
    u32 round_le;

    /* Initial hash: SHA256(password || salt) */
    memcpy(buf, password, pwd_len);
    memcpy(buf + pwd_len, salt, 16);
    ret = do_sha256(buf, pwd_len + 16, tmp);
    if (ret) return ret;

    /* 4096 iterations */
    for (i = 0; i < 4096; i++) {
        round_le = cpu_to_le32(i);
        memcpy(buf, tmp, SHA256_DIGEST_SIZE);
        memcpy(buf + SHA256_DIGEST_SIZE, &round_le, 4);
        ret = do_sha256(buf, SHA256_DIGEST_SIZE + 4, tmp);
        if (ret) return ret;
    }

    memcpy(derived_key, tmp, AES_KEY_SIZE);
    return 0;
}

/* =============================================================================
 * IOCTL handler
 * ============================================================================= */
/*
 * crypto_chat_ioctl - xử lý các lệnh IOCTL từ user-space cho driver `/dev/crypto_chat`.
 *
 * @filp: file instance từ user-space (không dùng trực tiếp)
 * @cmd:  mã IOCTL (phải thuộc CRYPTO_IOC_MAGIC)
 * @arg:  con trỏ user-space trỏ tới struct yêu cầu/đầu ra tương ứng với cmd
 *
 * Hành vi:
 * - Kiểm tra IOCTL type hợp lệ.
 * - Với từng cmd: allocate request struct trong kernel, copy_from_user để lấy dữ liệu,
 *   validate độ dài, khóa `crypto_chat_mutex` để tuần tự hóa các thao tác crypto,
 *   gọi helper tương ứng (AES/SHA/KDF), rồi copy_to_user để trả kết quả.
 *
 * Giá trị trả về:
 * - ret >= 0 khi thành công (thường là 0)
 * - mã lỗi âm khi gặp lỗi copy/validate/crypto
 * - -ENOTTY nếu cmd không thuộc driver.
 */
static long crypto_chat_ioctl(struct file *filp,
                               unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    if (_IOC_TYPE(cmd) != CRYPTO_IOC_MAGIC) return -ENOTTY;

    switch (cmd) {

    /* ── AES-256-CBC Encrypt ───────────────────────────────── */
    case IOCTL_AES_ENCRYPT: {
        struct crypto_aes_req *req;

        req = kzalloc(sizeof(*req), GFP_KERNEL);
        if (!req) return -ENOMEM;

        if (copy_from_user(req, (void __user *)arg, sizeof(*req))) {
            kfree(req); return -EFAULT;
        }

        /* Allow empty plaintext (input_len == 0).
         * We still need to PKCS#7-pad during AES encryption, which produces
         * one full block, so input_len==0 is valid for encryption.
         */
        if (req->input_len > MAX_DATA_SIZE) {
            kfree(req); return -EINVAL;
        }

        mutex_lock(&crypto_chat_mutex);
        ret = do_aes_cbc(req->key, req->iv,
                         req->input,  req->input_len,
                         req->output, &req->output_len,
                         1 /* encrypt */);
        mutex_unlock(&crypto_chat_mutex);

        if (!ret && copy_to_user((void __user *)arg, req, sizeof(*req))) {
            ret = -EFAULT;
        }

        kfree(req);
        break;
    }

    /* ── AES-256-CBC Decrypt ───────────────────────────────── */
    case IOCTL_AES_DECRYPT: {
        struct crypto_aes_req *req;

        req = kzalloc(sizeof(*req), GFP_KERNEL);
        if (!req) return -ENOMEM;

        if (copy_from_user(req, (void __user *)arg, sizeof(*req))) {
            kfree(req); return -EFAULT;
        }

        if (req->input_len == 0 || req->input_len > MAX_DATA_SIZE) {
            kfree(req); return -EINVAL;
        }

        mutex_lock(&crypto_chat_mutex);
        ret = do_aes_cbc(req->key, req->iv,
                         req->input,  req->input_len,
                         req->output, &req->output_len,
                         0 /* decrypt */);
        mutex_unlock(&crypto_chat_mutex);

        if (!ret && copy_to_user((void __user *)arg, req, sizeof(*req))) {
            ret = -EFAULT;
        }

        kfree(req);
        break;
    }

    /* ── SHA-256 Hash ──────────────────────────────────────── */
    case IOCTL_SHA256_HASH: {
        struct crypto_hash_req *req;

        req = kzalloc(sizeof(*req), GFP_KERNEL);
        if (!req) return -ENOMEM;

        if (copy_from_user(req, (void __user *)arg, sizeof(*req))) {
            kfree(req); return -EFAULT;
        }

        if (req->data_len > MAX_DATA_SIZE) {
            kfree(req); return -EINVAL;
        }

        mutex_lock(&crypto_chat_mutex);
        ret = do_sha256(req->data, req->data_len, req->digest);
        mutex_unlock(&crypto_chat_mutex);

        if (!ret && copy_to_user((void __user *)arg, req, sizeof(*req))) {
            ret = -EFAULT;
        }

        kfree(req);
        break;
    }

    /* ── Key Derivation (password → AES key) ──────────────── */
    case IOCTL_DERIVE_KEY: {
        struct crypto_kdf_req *req;

        req = kzalloc(sizeof(*req), GFP_KERNEL);
        if (!req) return -ENOMEM;

        if (copy_from_user(req, (void __user *)arg, sizeof(*req))) {
            kfree(req); return -EFAULT;
        }

        if (req->password_len == 0 ||
            req->password_len > MAX_PASSWORD_LEN) {
            kfree(req); return -EINVAL;
        }

        mutex_lock(&crypto_chat_mutex);
        ret = do_derive_key(req->password, req->password_len,
                            req->salt, req->derived_key);
        mutex_unlock(&crypto_chat_mutex);

        if (!ret && copy_to_user((void __user *)arg, req, sizeof(*req))) {
            ret = -EFAULT;
        }

        kfree(req);
        break;
    }

    /* ── Get driver version ────────────────────────────────── */
    case IOCTL_GET_VERSION: {
        u32 ver = DRIVER_VERSION;
        if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
            ret = -EFAULT;
        break;
    }

    default:
        return -ENOTTY;
    }

    return ret;
}

/* =============================================================================
 * File operations
 * ============================================================================= */
/*
 * crypto_chat_open - callback khi user mở device char `/dev/crypto_chat`.
 * Hiện tại hàm chỉ ghi log mức debug và trả về 0 để cho phép mở.
 */
static int crypto_chat_open(struct inode *inode, struct file *filp)
{
    pr_debug("%s: device opened\n", DRIVER_NAME);
    return 0;
}

/*
 * crypto_chat_release - callback khi user đóng device char.
 * Hiện tại hàm chỉ ghi log mức debug và trả về 0.
 */
static int crypto_chat_release(struct inode *inode, struct file *filp)
{
    pr_debug("%s: device released\n", DRIVER_NAME);
    return 0;
}

/* =============================================================================
 * Module init / exit
 * ============================================================================= */
/*
 * crypto_chat_init - hàm init module.
 *
 * Công việc:
 * 1. alloc_chrdev_region: cấp số major/minor cho char device.
 * 2. class_create: tạo lớp thiết bị (để tạo node /dev).
 * 3. cdev_init + cdev_add: đăng ký file_operations.
 * 4. device_create: tạo node `/dev/crypto_chat`.
 * 5. kiểm tra kernel crypto có hỗ trợ `cbc(aes)` và `sha256` hay không (log warning nếu thiếu).
 *
 * Giá trị trả về:
 * - 0 khi khởi tạo thành công
 * - mã lỗi âm khi một bước nào đó thất bại (có goto cleanup cho các bước đã tạo).
 */
static int __init crypto_chat_init(void)
{
    int ret;

    pr_info("%s: loading driver v%d.%d — AES-256-CBC + SHA-256\n",
            DRIVER_NAME,
            (DRIVER_VERSION >> 8) & 0xFF,
             DRIVER_VERSION & 0xFF);

    /* 1. Allocate device number */
    ret = alloc_chrdev_region(&dev_num, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        pr_err("%s: alloc_chrdev_region failed: %d\n", DRIVER_NAME, ret);
        return ret;
    }
    major_number = MAJOR(dev_num);

    /* 2. Create device class */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    crypto_chat_class = class_create(CRYPTO_CHAT_CLASS_NAME);
#else
    crypto_chat_class = class_create(THIS_MODULE, CRYPTO_CHAT_CLASS_NAME);
#endif
    if (IS_ERR(crypto_chat_class)) {
        ret = PTR_ERR(crypto_chat_class);
        pr_err("%s: class_create failed: %d\n", DRIVER_NAME, ret);
        goto err_unreg;
    }

    /* 3. Init and add cdev */
    cdev_init(&crypto_chat_cdev, &fops);
    crypto_chat_cdev.owner = THIS_MODULE;
    ret = cdev_add(&crypto_chat_cdev, dev_num, 1);
    if (ret) {
        pr_err("%s: cdev_add failed: %d\n", DRIVER_NAME, ret);
        goto err_class;
    }

    /* 4. Create /dev/crypto_chat */
    crypto_chat_device = device_create(crypto_chat_class, NULL,
                                       dev_num, NULL,
                                       CRYPTO_CHAT_DEV_NAME);
    if (IS_ERR(crypto_chat_device)) {
        ret = PTR_ERR(crypto_chat_device);
        pr_err("%s: device_create failed: %d\n", DRIVER_NAME, ret);
        goto err_cdev;
    }

    /* 5. Verify kernel crypto subsystem has AES + SHA-256 */
    {
        struct crypto_skcipher *t = crypto_alloc_skcipher("cbc(aes)", 0, 0);
        if (IS_ERR(t)) {
            pr_warn("%s: WARNING — cbc(aes) not in kernel crypto\n",
                    DRIVER_NAME);
        } else {
            crypto_free_skcipher(t);
            pr_info("%s: cbc(aes) ✓\n", DRIVER_NAME);
        }
    }
    {
        struct crypto_shash *t = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(t)) {
            pr_warn("%s: WARNING — sha256 not in kernel crypto\n",
                    DRIVER_NAME);
        } else {
            crypto_free_shash(t);
            pr_info("%s: sha256 ✓\n", DRIVER_NAME);
        }
    }

    pr_info("%s: /dev/%s created (major=%d)\n",
            DRIVER_NAME, CRYPTO_CHAT_DEV_NAME, major_number);
    return 0;

err_cdev:   cdev_del(&crypto_chat_cdev);
err_class:  class_destroy(crypto_chat_class);
err_unreg:  unregister_chrdev_region(dev_num, 1);
    return ret;
}

/*
 * crypto_chat_exit - hàm cleanup khi module unload.
 *
 * Công việc (ngược lại với init):
 * - hủy node `/dev/crypto_chat`
 * - xóa cdev, destroy class
 * - unregister chrdev region
 * - ghi log driver unloaded
 */
static void __exit crypto_chat_exit(void)
{
    device_destroy(crypto_chat_class, dev_num);
    cdev_del(&crypto_chat_cdev);
    class_destroy(crypto_chat_class);
    unregister_chrdev_region(dev_num, 1);
    pr_info("%s: driver unloaded\n", DRIVER_NAME);
}

module_init(crypto_chat_init);
module_exit(crypto_chat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION("1.0");
