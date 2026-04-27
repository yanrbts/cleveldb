# ==========================================
# Optimized Makefile for libtinytun & vfast
# ==========================================

CC      := gcc
CFLAGS  := -O3 -ggdb -Wall -Wextra -D_GNU_SOURCE -std=gnu11 -Isrc -Itest
LDFLAGS := -luring -lpthread -lradcli -lcrypto

# Directories
SRC_DIR  := src
TEST_DIR := test
BIN_DIR  := bin
OBJ_DIR  := $(BIN_DIR)/obj

# 1. 明确各程序的主入口 (Main Entry Points)
SERVER_MAIN := $(SRC_DIR)/vfast_server.c
CLIENT_MAIN := $(SRC_DIR)/vfast_client.c
REFLEX_MAIN := $(SRC_DIR)/vfreflex.c

# 2. 明确各程序的生成目标路径
SERVER_BIN  := $(BIN_DIR)/vfast_server
CLIENT_BIN  := $(BIN_DIR)/vfast_client
REFLEX_BIN  := $(BIN_DIR)/vfreflex

# 3. 库文件源码：排除掉所有包含 main 的文件
# 剩下的会自动包含 tun.c, linenoise.c, cmd.c 等
EXCLUDE_SRCS := $(SERVER_MAIN) $(CLIENT_MAIN) $(REFLEX_MAIN)
LIB_SRCS     := $(filter-out $(EXCLUDE_SRCS), $(wildcard $(SRC_DIR)/*.c))
LIB_OBJS     := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(LIB_SRCS))

# Test Programs in test/
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c, $(BIN_DIR)/%, $(TEST_SRCS))

# Default target
all: directories $(SERVER_BIN) $(CLIENT_BIN) $(REFLEX_BIN) $(TEST_BINS)

# 创建目录
directories:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)

# 编译服务器
$(SERVER_BIN): $(SERVER_MAIN) $(LIB_OBJS)
	@echo "  LD (SERVER) $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 编译客户端
$(CLIENT_BIN): $(CLIENT_MAIN) $(LIB_OBJS)
	@echo "  LD (CLIENT) $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 编译命令行工具 (vfreflex)
$(REFLEX_BIN): $(REFLEX_MAIN) $(LIB_OBJS)
	@echo "  LD (REFLEX) $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# 链接测试程序
$(BIN_DIR)/%: $(TEST_DIR)/%.c $(LIB_OBJS)
	@echo "  LD (TEST)   $@"
	@$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# 清理
clean:
	@echo "  CLEAN   $(BIN_DIR)"
	@rm -rf $(BIN_DIR)

.PHONY: all clean directories