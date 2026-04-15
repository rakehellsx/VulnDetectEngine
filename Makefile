# =============================================================================
# VulnDetectEngine 顶层 Makefile
# 支持 Linux (GCC) 和 Windows (MinGW-w64 交叉编译)
#
# 用法:
#   make                  - 编译所有目标（DetectEngine.so + AttackSimulator）
#   make engine           - 仅编译检测引擎共享库
#   make simulator        - 仅编译攻击模拟器
#   make test             - 运行集成测试
#   make clean            - 清理构建产物
#   make install          - 安装到 /usr/local/lib 和 /usr/local/include
# =============================================================================

# ---------- 编译器配置 ----------
CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Wno-unused-parameter \
           -fvisibility=hidden \
           -D_GNU_SOURCE \
           -DVULNDETECT_EXPORTS
LDFLAGS :=

# ---------- 目录配置 ----------
ROOT_DIR    := $(shell pwd)
ENGINE_DIR  := $(ROOT_DIR)/DetectEngine
SIM_DIR     := $(ROOT_DIR)/AttackSimulator
RULEDB_DIR  := $(ROOT_DIR)/RuleDB
BUILD_DIR   := $(ROOT_DIR)/build
BIN_DIR     := $(ROOT_DIR)/bin

# ---------- 引擎源文件 ----------
ENGINE_SRCS := \
    $(ENGINE_DIR)/src/engine_core.c   \
    $(ENGINE_DIR)/src/proto_parser.c  \
    $(ENGINE_DIR)/src/rule_engine.c   \
    $(ENGINE_DIR)/src/logger.c        \
    $(ENGINE_DIR)/src/dllmain.c       \
    $(ENGINE_DIR)/third_party/cJSON/cJSON.c

ENGINE_INCS := \
    -I$(ENGINE_DIR)/include \
    -I$(ENGINE_DIR)/third_party/cJSON \
    -I/usr/include/ndpi

ENGINE_OBJS := $(patsubst $(ROOT_DIR)/%.c,$(BUILD_DIR)/%.o,$(ENGINE_SRCS))
ENGINE_LIB  := $(BIN_DIR)/libVulnDetectEngine.so

# ---------- 攻击模拟器源文件 ----------
SIM_SRCS := \
    $(SIM_DIR)/src/main.c            \
    $(SIM_DIR)/src/attack_smb.c      \
    $(SIM_DIR)/src/attack_rdp.c      \
    $(SIM_DIR)/src/attack_http.c     \
    $(SIM_DIR)/src/attack_network.c  \
    $(SIM_DIR)/src/attack_shellcode.c

SIM_INCS  := -I$(SIM_DIR)/include
SIM_OBJS  := $(patsubst $(ROOT_DIR)/%.c,$(BUILD_DIR)/%.o,$(SIM_SRCS))
SIM_BIN   := $(BIN_DIR)/AttackSimulator

# ---------- TestApp 源文件 ----------
TESTAPP_SRCS := $(ROOT_DIR)/TestApp/src/main.c
TESTAPP_OBJS := $(BUILD_DIR)/TestApp/src/main.o
TESTAPP_BIN  := $(BIN_DIR)/TestApp

# ---------- 链接库 ----------
ENGINE_LIBS  := -lpcap -lpthread -lm -lndpi -lgcrypt -lgpg-error
SIM_LIBS     := # 仅 libc + ws2_32 (Linux 下无需)
TESTAPP_LIBS := -L$(BIN_DIR) -lVulnDetectEngine -lpthread -lndpi -lgcrypt -lgpg-error

# ---------- 调试/发布模式 ----------
ifeq ($(DEBUG),1)
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# =============================================================================
# 目标
# =============================================================================

.PHONY: all engine simulator test clean install dirs

all: dirs engine simulator testapp
	@echo ""
	@echo "=========================================="
	@echo "  构建完成！"
	@echo "  引擎库: $(ENGINE_LIB)"
	@echo "  模拟器: $(SIM_BIN)"
	@echo "  宿主程序: $(TESTAPP_BIN)"
	@echo "=========================================="

dirs:
	@mkdir -p $(BUILD_DIR)/DetectEngine/src
	@mkdir -p $(BUILD_DIR)/DetectEngine/third_party/cJSON
	@mkdir -p $(BUILD_DIR)/AttackSimulator/src
	@mkdir -p $(BIN_DIR)

# ---------- 编译引擎共享库 ----------
engine: dirs $(ENGINE_LIB)

$(ENGINE_LIB): $(ENGINE_OBJS)
	@echo "[LD] $@"
	$(CC) -shared -fPIC -o $@ $^ $(ENGINE_LIBS)
	@echo "[OK] 引擎库编译成功: $@"

$(BUILD_DIR)/DetectEngine/%.o: $(ENGINE_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -fPIC $(ENGINE_INCS) -c $< -o $@

$(BUILD_DIR)/DetectEngine/third_party/cJSON/%.o: $(ENGINE_DIR)/third_party/cJSON/%.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -fPIC $(ENGINE_INCS) -c $< -o $@

# ---------- 编译 TestApp 宿主程序 ----------
testapp: dirs engine $(TESTAPP_BIN)

$(TESTAPP_BIN): $(TESTAPP_OBJS) $(ENGINE_LIB)
	@echo "[LD] $@"
	$(CC) -o $@ $(TESTAPP_OBJS) $(TESTAPP_LIBS)
	@echo "[OK] 宿主程序编译成功: $@"

$(BUILD_DIR)/TestApp/src/%.o: $(ROOT_DIR)/TestApp/src/%.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -I$(ENGINE_DIR)/include -c $< -o $@

# ---------- 编译攻击模拟器 ----------
simulator: dirs $(SIM_BIN)

$(SIM_BIN): $(SIM_OBJS)
	@echo "[LD] $@"
	$(CC) -o $@ $^ $(SIM_LIBS)
	@echo "[OK] 攻击模拟器编译成功: $@"

$(BUILD_DIR)/AttackSimulator/%.o: $(SIM_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) $(SIM_INCS) -c $< -o $@

# ---------- 集成测试 ----------
test: all
	@echo ""
	@echo "=========================================="
	@echo "  运行集成测试"
	@echo "=========================================="
	@cd $(ROOT_DIR) && bash scripts/run_test.sh

# ---------- 清理 ----------
clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "[OK] 清理完成"

# ---------- 安装 ----------
install: engine
	@install -d /usr/local/lib /usr/local/include
	@install -m 755 $(ENGINE_LIB) /usr/local/lib/
	@install -m 644 $(ENGINE_DIR)/include/VulnDetectEngine.h /usr/local/include/
	@ldconfig
	@echo "[OK] 安装完成"
