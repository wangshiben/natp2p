#!/bin/bash
set -u
BIN=/tmp/tuntest/bin
LOG_DIR="$1"
RELAY=129.0.0.1:9000
INDEX=193.0.0.1:9000
FILE_SIZE_MB=20
TUN_LISTEN_PORT=18888
HTTP_PORT=15173
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; sleep 1; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

echo "[1] httpfileserver :$HTTP_PORT (${FILE_SIZE_MB}MB)"
$BIN/httpfileserver -port $HTTP_PORT -size $FILE_SIZE_MB > "$LOG_DIR/http.log" 2>&1 & PIDS+=($!)
sleep 2
EXPECTED_SHA=$(grep "SHA256:" "$LOG_DIR/http.log" | head -1 | awk '{print $NF}')
echo "  SHA=$EXPECTED_SHA"; echo "$EXPECTED_SHA" > "$LOG_DIR/expected_sha.txt"
curl -s http://127.0.0.1:$HTTP_PORT/health && echo "  health ok"

echo "[2] tunserver → relay=$RELAY index=$INDEX"
$BIN/tunserver -target "127.0.0.1:$HTTP_PORT" -relay "$RELAY" -index "$INDEX" > "$LOG_DIR/tunserver.log" 2>&1 & PIDS+=($!)
sleep 7
SID=$(grep "本节点 ID:" "$LOG_DIR/tunserver.log" | awk '{print $NF}')
echo "  server nodeID=$SID"; echo "$SID" > "$LOG_DIR/server_id.txt"
if [ -z "$SID" ]; then echo "  ❌ tunserver 未就绪"; cat "$LOG_DIR/tunserver.log"; exit 1; fi

echo "[3] tunclient :$TUN_LISTEN_PORT → target=$SID"
$BIN/tunclient -target "$SID" -listen "127.0.0.1:$TUN_LISTEN_PORT" -relay "$RELAY" -index "$INDEX" > "$LOG_DIR/tunclient.log" 2>&1 & PIDS+=($!)
sleep 10
if grep -q "已建立隧道连接" "$LOG_DIR/tunclient.log"; then echo "  ✅ 隧道已建立"; else echo "  ⚠️ 隧道未确认"; cat "$LOG_DIR/tunclient.log"; fi

echo "[4] 功能验证"
echo -n "  health(经隧道): "; curl -s -m 15 http://127.0.0.1:$TUN_LISTEN_PORT/health; echo
for run in 1 2 3; do
  echo "  == 传输迭代 $run =="
  DL="$LOG_DIR/dl_$run.bin"
  T0=$(date +%s.%N)
  CODE=$(curl -s -m 180 -w "%{http_code}" -o "$DL" http://127.0.0.1:$TUN_LISTEN_PORT/file)
  T1=$(date +%s.%N)
  EL=$(echo "$T1 - $T0" | bc)
  SZ=$(stat -c%s "$DL" 2>/dev/null || echo 0)
  SHA=$(sha256sum "$DL" | awk '{print $1}')
  SP=$(echo "scale=2; $SZ/1024/1024/$EL" | bc)
  OK=$([ "$SHA" = "$EXPECTED_SHA" ] && echo "✅一致" || echo "❌不符")
  echo "    HTTP=$CODE 大小=$SZ 耗时=${EL}s 速度=${SP}MB/s SHA=$OK"
  echo "$run,$CODE,$SZ,$EL,$SP,$OK" >> "$LOG_DIR/results.csv"
  rm -f "$DL"
done
echo "DONE"
exit 0
