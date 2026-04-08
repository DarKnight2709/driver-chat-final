

# =============================================================================
# Root Makefile — orchestrate sub-projects
# Usage (at repository root):
#   make        -> build app and driver
#   make clean  -> clean app and driver
# =============================================================================

SUBDIRS := app driver

.PHONY: all clean app driver install uninstall test

all: app driver
	@echo "[+] Root build complete"

app:
	@$(MAKE) -C app

driver:
	@$(MAKE) -C driver

clean:
	@for d in $(SUBDIRS); do \
		echo "[*] Cleaning $$d"; \
		$(MAKE) -C $$d clean || exit $$?; \
	done
	@echo "[+] Root clean complete"

install:
	@$(MAKE) -C driver install

uninstall:
	@$(MAKE) -C driver uninstall

test:
	@$(MAKE) -C app test
