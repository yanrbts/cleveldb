# ==========================================
# Optimized Makefile for libtinytun & vfast
# ==========================================

CC      := gcc
CFLAGS  := -O3 -Wall -Wextra -D_GNU_SOURCE -std=gnu11 -Isrc
LDFLAGS := -luring

# Directories
SRC_DIR  := src
TEST_DIR := test
BIN_DIR  := bin
OBJ_DIR  := $(BIN_DIR)/obj

# 1. 明确服务端主程序
SERVER_MAIN := $(SRC_DIR)/vfast_server.c
SERVER_BIN  := $(BIN_DIR)/vfast_server

CLIENT_MAIN := $(SRC_DIR)/vfast_client.c
CLIENT_BIN  := $(BIN_DIR)/vfast_client

# 2. 库文件源码：排除掉包含 main 的 vfast.c
# 这样链接测试程序时才不会冲突
LIB_SRCS := $(filter-out $(SERVER_MAIN) $(CLIENT_MAIN), $(wildcard $(SRC_DIR)/*.c))
LIB_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(LIB_SRCS))

# Test Programs in test/
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c, $(BIN_DIR)/%, $(TEST_SRCS))

# Default target: 现在包含服务端编译
all: directories $(SERVER_BIN) $(CLIENT_BIN) $(TEST_BINS)

# Create bin and obj directories
directories:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)

# 3. 编译服务端的规则
$(SERVER_BIN): $(SERVER_MAIN) $(LIB_OBJS)
	@echo "  LD (SERVER) $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 4. 编译客户端的规则
$(CLIENT_BIN): $(CLIENT_MAIN) $(LIB_OBJS)
	@echo "  LD (CLIENT) $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compile library objects (exclude main files)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Link test programs (using the library objects)
$(BIN_DIR)/%: $(TEST_DIR)/%.c $(LIB_OBJS)
	@echo "  LD (TEST)   $@"
	@$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# Clean up
clean:
	@echo "  CLEAN   $(BIN_DIR)"
	@rm -rf $(BIN_DIR)

.PHONY: all clean directories