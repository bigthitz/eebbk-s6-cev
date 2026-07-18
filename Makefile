# ============================================================
#  CVE-2026-43499 GhostLock - OPPO K9 Build System
#  Target: aarch64-linux-android (Android NDK)
# ============================================================

# NDK 配置
NDK_ROOT ?= $(ANDROID_NDK_HOME)
API ?= 33

# 编译器 - 由外部传入（CI 必须指定完整路径）
# 本地开发可设: export CC=/path/to/ndk/.../aarch64-linux-android33-clang
CC ?= clang

CFLAGS := -O2 -Wall -Wextra -fPIE -pie -I.
LDFLAGS := -fPIE -pie -pthread

# 目标
TRIGGER_BIN := ghostlock_trigger
EXPLOIT_BIN := ghostlock_exploit

.PHONY: all trigger exploit clean info

all: trigger exploit

# --- Trigger POC + Exploit (分开编译，方便调试) ---
trigger: $(TRIGGER_BIN)

$(TRIGGER_BIN): trigger.c
	@echo "[BUILD] CC = $(CC)"
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ built successfully"

exploit: $(EXPLOIT_BIN)

$(EXPLOIT_BIN): exploit.c target.h
	@echo "[BUILD] CC = $(CC)"
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ built successfully"

# --- 编译信息 ---
info:
	@echo "================================"
	@echo " GhostLock Build Config"
	@echo "================================"
	@echo " CC       = $(CC)"
	@echo " NDK_ROOT = $(NDK_ROOT)"
	@echo " API      = $(API)"
	@echo "================================"

clean:
	rm -f $(TRIGGER_BIN) $(EXPLOIT_BIN)
