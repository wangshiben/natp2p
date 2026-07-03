#!/bin/bash
# 用法: perftest.sh <LOG_DIR> <WINDOW> <CHUNK> <标签>
set -u
BIN=/tmp/tuntest/bin
LOG_DIR="$1"; WIN="$2"; CHUNK="$3"; TAG="$4"
RELAY=129.0.0.1:9000; INDEX=193.0.0.1:9000
for n in httpfileserver tunserver tunclient; do pkill -x "$n" 2>/dev/null; done; sleep 1
declare -a P
cleanup(){ for x in "${P[@]:-}"; do kill -9 "$x" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
$BIN/httpfileserver -port 15173 -size 20 > "$LOG_DIR/http_$TAG.log" 2>&1 & P+=($!)
sleep 2
SHA=$(grep "SHA256:" "$LOG_DIR/http_$TAG.log" | head -1 | awk '{print $NF}')
TUNNEL_SEND_WINDOW=$WIN TUNNEL_MAX_CHUNK=$CHUNK $BIN/tunserver -target "127.0.0.1:15173" -relay "$RELAY" -index "$INDEX" > "$LOG_DIR/tsrv_$TAG.log" 2>&1 & P+=($!)
sleep 8
SID=$(grep "本节点 ID:" "$LOG_DIR/tsrv_$TAG.log" | awk '{print $NF}')
if [ -z "$SID" ]; then echo "$TAG: tunserver FAIL"; exit 0; fi
TUNNEL_SEND_WINDOW=$WIN TUNNEL_MAX_CHUNK=$CHUNK $BIN/tunclient -target "$SID" -listen "127.0.0.1:18888" -relay "$RELAY" -index "$INDEX" > "$LOG_DIR/tcli_$TAG.log" 2>&1 & P+=($!)
sleep 12
grep -q "已建立隧道连接" "$LOG_DIR/tcli_$TAG.log" || { echo "$TAG: tunnel UNCONFIRMED"; }
# 传一次20MB计时
DL="$LOG_DIR/dl_$TAG.bin"; T0=$(date +%s.%N)
CODE=$(curl -s -m300 -w "%{http_code}" -o "$DL" http://127.0.0.1:18888/file)
T1=$(date +%s.%N); EL=$(echo "$T1-$T0"|bc); SZ=$(stat -c%s "$DL" 2>/dev/null||echo 0)
DS=$(sha256sum "$DL" 2>/dev/null|awk '{print $1}'); SP=$(echo "scale=3;$SZ/1048576/$EL"|bc)
OK=$([ "$DS" = "$SHA" ]&&echo OK||echo MISMATCH)
echo "$TAG (win=$WIN chunk=$CHUNK): HTTP=$CODE 大小=$SZ 耗时=${EL}s 速度=${SP}MB/s SHA=$OK"
rm -f "$DL"
