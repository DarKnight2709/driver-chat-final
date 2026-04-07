# CryptoChat — Socket Chat với Kernel Driver Mã Hóa

## Tổng quan kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                     USERSPACE                               │
│                                                             │
│   ┌──────────┐   IOCTL   ┌──────────┐   TCP Socket        │
│   │  server  │◄─────────►│crypto_lib│◄──────────────────  │
│   │  client  │           │  .c/.h   │   (USB NIC: eth/enx)│
│   └──────────┘           └────┬─────┘                      │
├────────────────────────────── │ ────────────────────────────┤
│                     KERNEL    │ (syscall boundary)          │
│                               ▼                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │            crypto_chat.ko  (Character Device)        │  │
│   │  /dev/crypto_chat                                    │  │
│   │                                                      │  │
│   │  ┌──────────────────┐  ┌────────────────────────┐   │  │
│   │  │  AES-256-CBC      │  │  SHA-256               │   │  │
│   │  │  crypto_skcipher  │  │  crypto_shash          │   │  │
│   │  │  (cbc(aes))       │  │  (sha256)              │   │  │
│   │  └──────────────────┘  └────────────────────────┘   │  │
│   │           ▲                        ▲                  │  │
│   │           └──────────┬─────────────┘                  │  │
│   │                      ▼                                │  │
│   │           Linux Kernel Crypto API                     │  │
│   └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Cấu trúc dự án

```
crypto_chat/
├── driver/
│   ├── crypto_chat.h     ← Header dùng chung kernel + userspace
│   ├── crypto_chat.c     ← Kernel module (AES + SHA2)
│   └── Makefile
├── app/
│   ├── crypto_lib.h      ← Wrapper userspace cho IOCTL
│   ├── crypto_lib.c
│   ├── server.c          ← Chat server đa client
│   ├── client.c          ← Chat client tương tác (terminal)
│   ├── gui_client.c      ← Chat client giao diện GTK3 (GUI)
│   ├── test_crypto.c     ← Smoke test driver
│   └── Makefile
├── install.sh            ← Script cài đặt tự động
└── README.md
```

## Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|---|---|
| OS | CentOS 7 / CentOS 8 (x86_64) |
| Kernel | 3.10 – 5.x |
| Gói | `kernel-devel`, `gcc`, `make`, `sqlite-devel` |
| Card mạng | USB NIC (r8152, ax88179, usbnet…) hoặc bất kỳ NIC nào |
| Quyền | `root` để nạp module |

```bash
# Cài gói cần thiết
sudo yum install -y kernel-devel-$(uname -r) gcc make sqlite-devel
```

## Cài đặt nhanh

```bash
chmod +x install.sh
sudo ./install.sh
```

Script sẽ tự động:
1. Kiểm tra kernel-devel và USB NIC
2. Build và nạp `crypto_chat.ko`
3. Build server, client, test
4. Chạy smoke test để xác nhận driver hoạt động

## Build thủ công

```bash
# 1. Build kernel module
cd driver/
make
sudo insmod crypto_chat.ko
sudo chmod 666 /dev/crypto_chat

# 2. Build ứng dụng
cd ../app/
make

# 3. Chạy test
sudo ./test_crypto
```

## Sử dụng

### Khởi động Server
```bash
cd app/
sudo ./server 9090
```

### Client Terminal (cùng máy)
```bash
./client 127.0.0.1 9090
```

### Client GUI — Giao diện đồ họa GTK3
```bash
# Cài GTK3 (nếu chưa có)
sudo yum install gtk3-devel

# Build GUI client
make gui_client

# Chạy
./gui_client 127.0.0.1 9090
```

**Tính năng GUI:**
- Giao diện login đầy đủ (server, port, username, password)
- Dark theme hiện đại (Catppuccin palette)
- Danh sách online users (sidebar, tự động refresh)
- Tin nhắn riêng tư: double-click tên user để gửi PM
- Format tin nhắn theo màu: hệ thống (cam), riêng tư (xanh), join/leave (xanh lá)
- Thanh trạng thái hiển thị mã hóa + số user online
- Hỗ trợ các lệnh: /list, /msg, /quit trong ô nhập tin nhắn

### Kết nối Client (qua USB NIC — máy khác trong mạng)
```bash
# Tìm IP của server
ip addr show   # xem địa chỉ IP của USB NIC (ví dụ: 192.168.1.100)

# Từ máy client (terminal hoặc GUI)
./client 192.168.1.100 9090
./gui_client 192.168.1.100 9090
```

### Lệnh trong chat
```
/list              — Xem danh sách người dùng online
/msg <user> <text> — Gửi tin nhắn riêng tư
/quit              — Thoát
<text>             — Gửi broadcast cho tất cả
```

### Tài khoản mặc định
| Username | Password |
|---|---|
| alice | password123 |
| bob | secret456 |
| charlie | hello789 |
| admin | admin@CryptoChat#2024 |

### Lưu trữ người dùng (SQLite)
- Server lưu user trong SQLite tại `app/users.db`.
- Bảng `users` chứa `username` (PRIMARY KEY) và `password_hash` (SHA-256, 32 byte).
- Các tài khoản mặc định được seed bằng `INSERT` an toàn khi server khởi động; user mới đăng ký sẽ được lưu bền vững qua lần restart.

## Giao thức bảo mật

### Mã hóa tin nhắn (AES-256-CBC)
```
Mỗi message:
  1. Tạo IV ngẫu nhiên 16 bytes
  2. Mã hóa payload: AES-256-CBC(session_key, IV, payload)
  3. Tính HMAC: SHA-256(type || payload_len || IV || ciphertext)
  4. Gửi frame: [version|type|len|IV|HMAC|ciphertext]
```

### Xác thực người dùng (SHA-256)
```
  Client:
    password_hash = SHA-256(password)   ← qua kernel driver
    Gửi: AES({username, password_hash}) với bootstrap key=0

  Server:
    So sánh password_hash với DB
    Nếu khớp: sinh session_salt ngẫu nhiên
    Trả về: salt (dùng để đồng bộ session key)

  Cả hai bên derive session key:
    session_key = PBKDF2-SHA256(SERVER_SECRET, session_salt, 4096 rounds)
```

### Wire format
```c
struct chat_frame {
    uint8_t  version;           // PROTO_VERSION = 1
    uint8_t  type;              // MSG_TYPE_*
    uint16_t payload_len;       // số byte ciphertext
    uint8_t  iv[16];            // AES IV (random mỗi message)
    uint8_t  hmac[32];          // SHA-256 integrity check
    uint8_t  payload[4096];     // AES-256-CBC ciphertext
};
```

## IOCTL API của Driver

```c
// AES-256-CBC mã hóa
ioctl(fd, IOCTL_AES_ENCRYPT, &crypto_aes_req);

// AES-256-CBC giải mã
ioctl(fd, IOCTL_AES_DECRYPT, &crypto_aes_req);

// SHA-256 băm
ioctl(fd, IOCTL_SHA256_HASH, &crypto_hash_req);

// Dẫn xuất khóa từ mật khẩu
ioctl(fd, IOCTL_DERIVE_KEY, &crypto_kdf_req);

// Lấy phiên bản driver
ioctl(fd, IOCTL_GET_VERSION, &version);
```

## Gỡ lỗi

```bash
# Xem log kernel
dmesg | grep crypto_chat

# Kiểm tra module đã nạp chưa
lsmod | grep crypto_chat

# Kiểm tra device node
ls -la /dev/crypto_chat

# Gỡ module
sudo rmmod crypto_chat
```

## Ghi chú về USB NIC

Driver `crypto_chat.ko` hoạt động độc lập với card mạng — nó chỉ cung cấp dịch vụ mã hóa/giải mã qua `/dev/crypto_chat`. Ứng dụng chat sử dụng TCP socket thông thường, hoạt động trên mọi giao tiếp mạng kể cả:

- USB NIC (r8152, ax88179, ASIX, Realtek RTL8152B…)
- Card mạng tích hợp (e1000, e1000e, igb…)
- WiFi (wlan0)
- Loopback (127.0.0.1) cho test local

Để kiểm tra USB NIC:
```bash
lsusb          # liệt kê thiết bị USB
dmesg | grep -i usb | grep -i eth    # log USB network
ip link show   # xem interface (enx..., usb0, eth0...)
```
