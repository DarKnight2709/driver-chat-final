# =============================================================================
# Makefile — Kernel module (CentOS 7/8 x86_64)
# Usage:
#   make              — build the module
#   make clean        — remove build artefacts
#   make install      — insmod + set /dev permissions
#   make uninstall    — rmmod
# =============================================================================

# Kernel build directory — adjust if using a custom kernel
KDIR   ?= /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

# Module name
obj-m  := crypto_chat.o

.PHONY: all clean install uninstall

all:
	@echo "[*] Building crypto_chat kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "[✓] Build complete: crypto_chat.ko"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f Module.symvers modules.order

install: all
	@echo "[*] Loading module..."
	@sudo insmod crypto_chat.ko || true
	@sleep 1
	@sudo chmod 666 /dev/crypto_chat
	@echo "[✓] /dev/crypto_chat ready"
	@lsmod | grep crypto_chat

uninstall:
	@echo "[*] Removing module..."
	@sudo rmmod crypto_chat 2>/dev/null || true
	@echo "[✓] Module removed"

# Show kernel messages from this driver
log:
	@dmesg | grep crypto_chat | tail -20

# Quick smoke-test (requires the app to be built)
test: install
	@echo "[*] Running smoke test..."
	@cd ../app && ./test_crypto
