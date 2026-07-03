#!/bin/bash
set -u
BIN=/tmp/tuntest/bin
LOG_DIR="$1"; N="$2"
RELAY=129.0.0.1:9000; INDEX=193.0.0.1:9000
for n in httpfileserver tunserver tunclient; do pkill -x "$n" 2>/dev/null; done; sleep 1
declare -a P
cleanup(){ for x in "${P[@]:-}"; do kill -9 "$x" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
$BIN/httpfileserver -port 15173 -size 20 > "$LOG_DIR/hp.log" 2>&1 & P+=($!)
sleep 2
$BIN/tunserver -target "127.0.0.1:15173" -relay "$RELAY" -index "$INDEX" > "$LOG_DIR/tsp.log" 2>&1 & P+=($!)
sleep 8
SID=$(grep "本节点 ID:" "$LOG_DIR/tsp.log" | awk '{print $NF}')
[ -z "$SID" ] && { echo "tunserver FAIL"; exit 0; }
$BIN/tunclient -target "$SID" -listen "127.0.0.1:18888" -relay "$RELAY" -index "$INDEX" > "$LOG_DIR/tcp.log" 2>&1 & P+=($!)
sleep 12
# N 个并发下载,计总时间
T0=$(date +%s.%N)
for i in $(seq 1 $N); do
  curl -s -m300 -o /dev/null "http://127.0.0.1:18888/file" &
done
wait
T1=$(date +%s.%N); EL=$(echo "$T1-$T0"|bc)
TOTAL=$(echo "$N*20"|bc)
echo "$N 并发流: 传 ${TOTAL}MB 总耗时=${EL}s 聚合速度=$(echo "scale=3;$TOTAL/$EL"|bc)MB/s (单流均摊=$(echo "scale=3;$TOTAL/$EL/$N"|bc))"
