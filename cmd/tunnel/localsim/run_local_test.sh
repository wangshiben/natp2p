#!/bin/bash
# 本地全套模拟测试脚本
# 模拟 5 个独立进程: index, relay, http-server, tunnel-server, tunnel-client
# 端到端验证 20MB 文件完整传输

set -u

BIN=/tmp/tuntest/bin
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOG_DIR="$SCRIPT_DIR/results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

# 端口分配
INDEX_PORT=19000
RELAY_PORT=19001
HTTP_PORT=15173
TUN_LISTEN_PORT=18888
FILE_SIZE_MB=20

PIDS=()
cleanup() {
    echo ""
    echo "[清理] 停止所有进程..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null
    done
}
trap cleanup EXIT

echo "================================================================"
echo "          NAT P2P Tunnel 本地全套模拟测试"
echo "================================================================"
echo "日志目录: $LOG_DIR"
echo "组件端口: index=$INDEX_PORT relay=$RELAY_PORT http=$HTTP_PORT tunnel=$TUN_LISTEN_PORT"
echo "测试文件: ${FILE_SIZE_MB}MB"
echo ""

# ---------- 步骤1: 启动 Index Server ----------
echo "[步骤1] 启动 Index Server (:$INDEX_PORT)"
$BIN/nodeserver -mode index -listen ":$INDEX_PORT" -public "127.0.0.1:$INDEX_PORT" \
    > "$LOG_DIR/1_index.log" 2>&1 &
PIDS+=($!)
sleep 2
if grep -q "已就绪" "$LOG_DIR/1_index.log"; then
    INDEX_ID=$(grep "节点 ID:" "$LOG_DIR/1_index.log" | awk '{print $NF}')
    echo "  ✅ Index 启动成功, ID=${INDEX_ID:0:16}..."
else
    echo "  ❌ Index 启动失败"; cat "$LOG_DIR/1_index.log"; exit 1
fi

# ---------- 步骤2: 启动 Relay Server ----------
echo "[步骤2] 启动 Relay Server (:$RELAY_PORT, 注册到 index)"
$BIN/nodeserver -mode relay -listen ":$RELAY_PORT" -public "127.0.0.1:$RELAY_PORT" \
    -index "127.0.0.1:$INDEX_PORT" > "$LOG_DIR/2_relay.log" 2>&1 &
PIDS+=($!)
sleep 3
if grep -q "已注册到 index" "$LOG_DIR/2_relay.log"; then
    echo "  ✅ Relay 启动并注册成功"
else
    echo "  ⚠️  Relay 注册状态未确认, 继续..."
    cat "$LOG_DIR/2_relay.log"
fi

# ---------- 步骤3: 启动 HTTP 文件服务器 ----------
echo "[步骤3] 启动 HTTP 文件服务器 (:$HTTP_PORT, ${FILE_SIZE_MB}MB 文件)"
$BIN/httpfileserver -port "$HTTP_PORT" -size "$FILE_SIZE_MB" \
    > "$LOG_DIR/3_httpserver.log" 2>&1 &
PIDS+=($!)
sleep 3
EXPECTED_SHA=$(grep "SHA256:" "$LOG_DIR/3_httpserver.log" | head -1 | awk '{print $NF}')
if curl -s "http://127.0.0.1:$HTTP_PORT/health" | grep -q "ok"; then
    echo "  ✅ HTTP 服务器就绪, 文件 SHA256=${EXPECTED_SHA:0:16}..."
else
    echo "  ❌ HTTP 服务器启动失败"; cat "$LOG_DIR/3_httpserver.log"; exit 1
fi
echo "$EXPECTED_SHA" > "$LOG_DIR/expected_sha256.txt"

# ---------- 步骤4: 启动 Tunnel Server ----------
echo "[步骤4] 启动 Tunnel Server (转发到 127.0.0.1:$HTTP_PORT, 固定 relay)"
$BIN/tunserver -target "127.0.0.1:$HTTP_PORT" -relay "127.0.0.1:$RELAY_PORT" \
    -index "127.0.0.1:$INDEX_PORT" > "$LOG_DIR/4_tunserver.log" 2>&1 &
PIDS+=($!)
sleep 5
if grep -q "已就绪" "$LOG_DIR/4_tunserver.log"; then
    SERVER_NODE_ID=$(grep "本节点 ID:" "$LOG_DIR/4_tunserver.log" | awk '{print $NF}')
    echo "  ✅ Tunnel Server 就绪, NodeID=${SERVER_NODE_ID:0:16}..."
else
    echo "  ❌ Tunnel Server 启动失败"; cat "$LOG_DIR/4_tunserver.log"; exit 1
fi

# ---------- 步骤5: 启动 Tunnel Client ----------
echo "[步骤5] 启动 Tunnel Client (监听 127.0.0.1:$TUN_LISTEN_PORT)"
$BIN/tunclient -target "$SERVER_NODE_ID" -listen "127.0.0.1:$TUN_LISTEN_PORT" \
    -relay "127.0.0.1:$RELAY_PORT" -index "127.0.0.1:$INDEX_PORT" \
    > "$LOG_DIR/5_tunclient.log" 2>&1 &
PIDS+=($!)
sleep 8
if grep -q "已建立隧道连接" "$LOG_DIR/5_tunclient.log"; then
    echo "  ✅ Tunnel Client 已建立隧道连接"
else
    echo "  ❌ Tunnel Client 连接失败"; cat "$LOG_DIR/5_tunclient.log"; exit 1
fi

# ---------- 步骤6: 功能验证 ----------
echo ""
echo "[步骤6] 端到端功能验证"
echo "--------------------------------------------------------------"

# 6.1 健康检查
echo -n "  6.1 健康检查 (经隧道): "
HEALTH=$(curl -s -m 10 "http://127.0.0.1:$TUN_LISTEN_PORT/health" 2>&1)
if echo "$HEALTH" | grep -q "ok"; then
    echo "✅ $HEALTH"
else
    echo "❌ 失败: $HEALTH"
fi

# 6.2 校验和获取
echo -n "  6.2 获取文件校验和 (经隧道): "
TUNNEL_SHA=$(curl -s -m 10 "http://127.0.0.1:$TUN_LISTEN_PORT/checksum" 2>&1)
if [ "$TUNNEL_SHA" = "$EXPECTED_SHA" ]; then
    echo "✅ 一致"
else
    echo "⚠️  ${TUNNEL_SHA:0:16}..."
fi

# 6.3 完整文件传输 (核心测试)
echo "  6.3 完整 ${FILE_SIZE_MB}MB 文件传输测试:"
DOWNLOAD_FILE="$LOG_DIR/downloaded.bin"
START_TIME=$(date +%s.%N)
HTTP_CODE=$(curl -s -m 120 -w "%{http_code}" -o "$DOWNLOAD_FILE" \
    "http://127.0.0.1:$TUN_LISTEN_PORT/file" 2>&1)
END_TIME=$(date +%s.%N)
ELAPSED=$(echo "$END_TIME - $START_TIME" | bc)

if [ "$HTTP_CODE" = "200" ]; then
    DOWNLOADED_SIZE=$(stat -c%s "$DOWNLOAD_FILE" 2>/dev/null || echo 0)
    DOWNLOADED_SHA=$(sha256sum "$DOWNLOAD_FILE" | awk '{print $1}')
    SPEED=$(echo "scale=2; $DOWNLOADED_SIZE / 1024 / 1024 / $ELAPSED" | bc)
    echo "      HTTP状态: $HTTP_CODE"
    echo "      下载大小: $DOWNLOADED_SIZE 字节"
    echo "      耗时: ${ELAPSED}s, 速度: ${SPEED} MB/s"
    if [ "$DOWNLOADED_SHA" = "$EXPECTED_SHA" ]; then
        echo "      ✅ SHA256 校验通过, 文件完整传输!"
        TRANSFER_OK=1
    else
        echo "      ❌ SHA256 不匹配! 期望 ${EXPECTED_SHA:0:16} 实际 ${DOWNLOADED_SHA:0:16}"
        TRANSFER_OK=0
    fi
else
    echo "      ❌ 下载失败, HTTP $HTTP_CODE"
    TRANSFER_OK=0
fi

# ---------- 步骤7: 生成报告数据 ----------
echo ""
echo "[步骤7] 保存测试结果"
cat > "$LOG_DIR/result.txt" << RESULT_EOF
测试时间: $(date)
组件状态:
  Index Server: 就绪 (ID ${INDEX_ID:0:16})
  Relay Server: 就绪
  HTTP Server: 就绪 (${FILE_SIZE_MB}MB)
  Tunnel Server: 就绪 (NodeID ${SERVER_NODE_ID:0:16})
  Tunnel Client: 已连接
传输结果:
  文件大小: $DOWNLOADED_SIZE 字节
  传输耗时: ${ELAPSED}s
  传输速度: ${SPEED} MB/s
  期望SHA256: $EXPECTED_SHA
  实际SHA256: $DOWNLOADED_SHA
  完整性: $([ "$TRANSFER_OK" = "1" ] && echo "✅ 通过" || echo "❌ 失败")
RESULT_EOF

cat "$LOG_DIR/result.txt"

echo ""
echo "================================================================"
if [ "${TRANSFER_OK:-0}" = "1" ]; then
    echo "  ✅ 本地全套模拟测试通过"
else
    echo "  ❌ 本地测试失败"
fi
echo "  日志目录: $LOG_DIR"
echo "================================================================"

# 清理下载的大文件,只保留日志
rm -f "$DOWNLOAD_FILE"
