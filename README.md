# CryptoChat — Socket Chat với Kernel Driver Mã Hóa

## 🔐 Tổng quan kiến trúc

CryptoChat là hệ thống nhắn tin bảo mật sử dụng mô hình Client-Server, trong đó mọi thao tác mã hóa (AES-256-CBC) và băm mật khẩu (SHA-256) được thực hiện trực tiếp tại **Kernel Level** thông qua một Linux Kernel Module chuyên biệt.

```
┌─────────────────────────────────────────────────────────────┐
│                     USERSPACE (Ứng dụng)                    │
│                                                             │
│   ┌──────────┐   IOCTL   ┌──────────┐   TCP Socket        │
│   │  Server  │◄─────────►│crypto_lib│◄──────────────────  │
│   │  Client  │           │  .c/.h   │   (Mọi giao tiếp mạng)│
│   └──────────┘           └────┬─────┘                      │
├────────────────────────────── │ ────────────────────────────┤
│                     KERNEL (Driver)                         │
│                               ▼                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │            crypto_chat.ko  (Character Device)        │  │
│   │  /dev/crypto_chat                                    │  │
│   │                                                      │  │
│   │  ┌──────────────────┐  ┌────────────────────────┐   │  │
│   │  │  AES-256-CBC      │  │  SHA-256               │   │  │
│   │  │  Linux Crypto API │  │  Linux Crypto API      │   │  │
│   │  └──────────────────┘  └────────────────────────┘   │  │
│   └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 📂 Cấu trúc dự án

```
driver-final/
├── driver/                ← Mã nguồn Kernel Module
│   ├── crypto_chat.c      ← Xử lý AES/SHA2 qua Crypto API
│   ├── crypto_chat.h      ← Shared definitions (IOCTL codes)
│   └── Makefile
├── app/                   ← Mã nguồn ứng dụng Userspace
│   ├── server/            ← Chat Server đa luồng
│   │   ├── core/          ← Logic xử lý chat & broadcast
│   │   ├── db/            ← Quản lý người dùng qua SQLite
│   │   └── protocol/      ← Định nghĩa frame & wire format
│   ├── client/            ← Chat Client (CLI & GUI)
│   │   ├── src/           ← Source code GTK3 & Logic
│   │   ├── resources/     ← Icon, hình ảnh (1024x1024 Square)
│   │   └── include/       ← Headers cho client
│   ├── crypto_lib.c       ← Wrapper IOCTL gọi xuống Driver
│   ├── setup_app.sh       ← Script thiết lập Desktop & Permissions
│   └── Makefile
├── install.sh             ← Script cài đặt tổng thể (One-click)
└── README.md
```

## 🚀 Cài đặt nhanh

Yêu cầu hệ thống: **CentOS 7/8 (x86_64)**, đã cài `kernel-devel`, `gcc`, `make`, `sqlite-devel` và `gtk3-devel`.

```bash
# Cấp quyền và chạy cài đặt tổng thể
chmod +x install.sh
sudo ./install.sh
```

**Script này sẽ tự động:**
1. Build & nạp Kernel Driver.
2. Thiết lập quyền `/dev/crypto_chat` bền vững (udev rules).
3. Build Server & GUI Client.
4. Cài đặt Icon cao cấp & Shortcut vào Menu ứng dụng của hệ thống.

## 📱 Sử dụng

### 1. Khởi động Server
```bash
cd app/
./chat_server 8888
```

### 2. Khởi động Client
*   **Cách 1:** Tìm ứng dụng **"CryptoChat"** trong danh sách ứng dụng của máy tính và mở.
*   **Cách 2:** Chạy lệnh `./app/gui_client 127.0.0.1 8888`

### 3. Tài khoản mặc định
| Username | Password |
|---|---|
| alice | password123 |
| admin | admin@CryptoChat#2024 |

## 🛠 Tính năng nổi bật

-   **Kernel Encryption:** Mã hóa AES-256-CBC thực thi trong Kernel, bảo mật tối đa.
-   **GTK3 GUI:** Giao diện Dark mode hiện đại, danh sách sidebar người dùng online.
-   **Persistence:** Lưu trữ user bền vững bằng SQLite.
-   **Desktop Integrated:** Tích hợp sâu vào hệ thống Linux (Icon, Launcher).
-   **Private Messaging:** Hỗ trợ gửi tin nhắn riêng tư giữa các user.

## 🩺 Kiểm tra hệ thống

```bash
# Kiểm tra driver
lsmod | grep crypto_chat    # Xem module đã nạp chưa
dmesg | grep crypto_chat    # Xem log hoạt động của driver
ls -la /dev/crypto_chat     # Kiểm tra file thiết bị
```
