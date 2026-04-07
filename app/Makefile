# =============================================================================
# Makefile — Userspace chat apps (CentOS 7/8 x86_64)
#
# Targets:
#   make            — build server, client, test (+ gui_client if GTK3 found)
#   make gui_client — build GTK3 GUI client (requires gtk3-devel)
#   make clean      — remove binaries
# =============================================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -I../driver
LDFLAGS = -lpthread -lsqlite3

SRCS_COMMON = crypto_lib.c
SRCS_SERVER = server.c $(SRCS_COMMON)
SRCS_CLIENT = client.c $(SRCS_COMMON)
SRCS_TEST   = test_crypto.c $(SRCS_COMMON)
SRCS_GUI    = gui_client.c $(SRCS_COMMON)

# GTK3 detection
GTK3_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK3_LIBS   := $(shell pkg-config --libs   gtk+-3.0 2>/dev/null)
HAS_GTK3    := $(if $(GTK3_CFLAGS),yes,no)

# Base targets always built
TARGETS = server client test_crypto

# Auto-add GUI if GTK3 is available
ifeq ($(HAS_GTK3),yes)
TARGETS += gui_client
endif

.PHONY: all clean run_server run_client run_gui test

all: $(TARGETS)
	@echo ""
ifeq ($(HAS_GTK3),yes)
	@echo "[+] All targets built (including GUI client)"
else
	@echo "[+] Core targets built (GUI skipped — install gtk3-devel for GUI)"
endif

server: $(SRCS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[✓] server built"

client: $(SRCS_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[✓] client built"

test_crypto: $(SRCS_TEST)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[✓] test_crypto built"

gui_client: $(SRCS_GUI)
ifeq ($(HAS_GTK3),yes)
	$(CC) $(CFLAGS) $(GTK3_CFLAGS) -o $@ $^ $(LDFLAGS) $(GTK3_LIBS)
	@echo "[✓] gui_client built (GTK3)"
else
	@echo "[!] GTK3 not found. Install with: sudo yum install gtk3-devel"
	@false
endif

clean:
	rm -f server client test_crypto gui_client *.o

run_server: server
	@sudo ./server $(PORT)

run_client: client
	@./client $(HOST) $(PORT)

run_gui: gui_client
	@./gui_client $(HOST) $(PORT)

test: test_crypto
	@sudo ./test_crypto
