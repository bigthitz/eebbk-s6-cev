# ============================================================
#  CVE-2026-43499 GhostLock - OPPO K9 Build System
#  Target: aarch64-linux-android (Android NDK)
# ============================================================

# NDK 配置 - CI 环境自动检测，本地可手动指定
NDK_ROOT ?= $(ANDROID_NDK_HOME)
ifeq ($(strip $(NDK_ROOT)),)
    NDK_ROOT := $(HOME)/android-ndk
endif
API ?= 33

# 编译器 - CI 传入则直接用，否则从 NDK 查找
CC ?= aarch64-linux-android$(API)-clang
ifeq ($(shell which $(CC) 2>/dev/null),)
    CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(CC)
endif

CFLAGS := -O2 -Wall -Wextra -fPIE -pie -I.
LDFLAGS := -fPIE -pie -pthread

# 目标
TRIGGER_BIN := ghostlock_trigger
EXPLOIT_BIN := ghostlock_exploit

.PHONY: all trigger exploit clean push push_trigger push_exploit info

all: trigger exploit

# --- Trigger POC (漏洞验证) ---
trigger: $(TRIGGER_BIN)

$(TRIGGER_BIN): trigger.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[OK] Trigger built: $@"

# --- Full Exploit (完整提权) ---
exploit: $(EXPLOIT_BIN)

$(EXPLOIT_BIN): exploit.c target.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[OK] Exploit built: $@"

# --- 推送到设备 ---
push: push_trigger push_exploit

push_trigger: $(TRIGGER_BIN)
	adb push $(TRIGGER_BIN) /data/local/tmp/
	adb shell chmod 755 /data/local/tmp/$(TRIGGER_BIN)

push_exploit: $(EXPLOIT_BIN)
	adb push $(EXPLOIT_BIN) /data/local/tmp/
	adb shell chmod 755 /data/local/tmp/$(EXPLOIT_BIN)

# --- 编译信息 ---
info:
	@echo "================================"
	@echo " GhostLock Build Config"
	@echo "================================"
	@echo " NDK_ROOT = $(NDK_ROOT)"
	@echo " API      = $(API)"
	@echo " CC       = $(CC)"
	@echo "================================"

clean:
	rm -f $(TRIGGER_BIN) $(EXPLOIT_BIN)
