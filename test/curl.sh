#!/bin/bash

# 目标 URL 和 Header
TARGET_URL="http://124.163.161.96"
HOST_HEADER="www.163.com"
TOTAL_COUNT=10000

echo "开始执行 $TOTAL_COUNT 次请求..."

for ((i=1; i<=TOTAL_COUNT; i++))
do
    # 执行 curl
    # -v: 详细模式
    # -L: 跟随重定向
    # -s: 静默模式（隐藏进度条，方便查看 -v 的输出）
    # -o /dev/null: 将输出的网页内容丢弃，只看过程
    curl -v -L "$TARGET_URL" -H "Host: $HOST_HEADER" -s -o /dev/null
    
    # 每 100 次打印一次进度
    if (( i % 100 == 0 )); then
        echo "已完成进度: $i / $TOTAL_COUNT"
    fi
done

echo "任务完成。"