# 编译器与全局选项
CC = gcc
CFLAGS = -Wall -Wextra -O3 -g -I.
LDFLAGS = -luring

# 目标程序名
SERVER_BIN = vfserver
CLIENT_BIN = vfclient

# 1. 自动获取目录下所有的 .c 文件
ALL_SRCS = $(wildcard *.c)

# 2. 提取公共组件：排除掉含有 main 函数的业务入口文件
# 这里假设你的业务入口就是 server.c 和 client.c
COMMON_SRCS = $(filter-out server.c client.c, $(ALL_SRCS))
COMMON_OBJS = $(COMMON_SRCS:.c=.o)

# 默认编译目标
all: $(SERVER_BIN) $(CLIENT_BIN)

# 编译服务端：链接 server.o 和所有公共组件
$(SERVER_BIN): server.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 编译客户端：链接 client.o 和所有公共组件
$(CLIENT_BIN): client.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 通用编译规则：将每个 .c 生成 .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理构建产物
clean:
	rm -f *.o $(SERVER_BIN) $(CLIENT_BIN)

# 辅助命令：快速配置网卡（需 sudo）
setup_srv:
	sudo ip addr add 10.0.0.1/24 dev vfast_srv 2>/dev/null || true
	sudo ip link set vfast_srv up

setup_cli:
	sudo ip addr add 10.0.0.2/24 dev vfast_cli 2>/dev/null || true
	sudo ip link set vfast_cli up

.PHONY: all clean setup_srv setup_cli