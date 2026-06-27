# NAT P2P Tunnel 本地全套模拟测试报告

**测试时间**: 2026-06-27  
**测试类型**: 本地全套独立进程模拟  
**测试结果**: ✅ 全部通过

---

## 1. 测试目标

在单机上启动 5 个独立进程，完整模拟生产环境的 P2P 隧道拓扑，验证：
1. Index Server / Relay Server 的注册与发现机制
2. Tunnel Server 将请求转发到本地服务端口
3. Tunnel Client 监听本地端口并经隧道访问对端服务
4. **20MB 文件的端到端完整传输与 SHA256 完整性校验**

---

## 2. 测试架构

```
┌──────────────┐     ┌──────────────┐
│ Index Server │◄────┤ Relay Server │   (relay 注册到 index)
│  :19000      │     │  :19001      │
└──────────────┘     └──────┬───────┘
                            │ (双方经同一 relay 桥接)
            ┌───────────────┴────────────────┐
            │                                │
   ┌────────▼────────┐              ┌────────▼────────┐
   │  Tunnel Client  │              │  Tunnel Server  │
   │  监听 :18888    │═══隧道══════►│  NodeID 路由    │
   └─────────────────┘              └────────┬────────┘
            ▲                                │ 转发
   curl localhost:18888              ┌───────▼────────┐
                                     │  HTTP Server   │
                                     │  :15173 (20MB) │
                                     └────────────────┘
```

**数据流**: `curl → 127.0.0.1:18888 (client) → relay :19001 → server node → 127.0.0.1:15173 (http) → 20MB 文件原路返回`

---

## 3. 测试组件

| 组件 | 程序 | 端口 | 角色 |
|------|------|------|------|
| Index Server | `nodeserver -mode index` | 19000 | 中继中心，relay 注册入口 |
| Relay Server | `nodeserver -mode relay` | 19001 | 中转，注册到 index |
| HTTP Server | `httpfileserver` | 15173 | 提供 20MB 测试文件 |
| Tunnel Server | `tunserver` | (P2P) | 转发到 127.0.0.1:15173 |
| Tunnel Client | `tunclient` | 18888 | 本地监听，经隧道转发 |

**程序源码位置**: `/root/natP2p/cmd/tunnel/`
- `httpfileserver/main.go` — HTTP 文件服务器（生成随机文件 + SHA256）
- `nodeserver/main.go` — 非交互式 index/relay 启动器
- `server/main.go` — 隧道服务端
- `client/main.go` — 隧道客户端（支持参数 + 交互式输入）

**测试脚本**: `/root/natP2p/cmd/tunnel/localsim/run_local_test.sh`

---

## 4. 测试流程

1. **步骤1** 启动 Index Server (`:19000`)，记录 NodeID
2. **步骤2** 启动 Relay Server (`:19001`)，注册到 index
3. **步骤3** 启动 HTTP 文件服务器，生成 20MB 随机文件并计算 SHA256
4. **步骤4** 启动 Tunnel Server，固定 relay，转发到 `127.0.0.1:15173`，输出 NodeID
5. **步骤5** 启动 Tunnel Client，连接 server NodeID，监听 `127.0.0.1:18888`
6. **步骤6** 端到端验证：
   - 6.1 健康检查 `GET /health`
   - 6.2 校验和获取 `GET /checksum`
   - 6.3 完整文件下载 `GET /file` + SHA256 校验
7. **步骤7** 保存结果并清理进程

---

## 5. 测试结果

### 5.1 组件启动

| 组件 | 结果 |
|------|------|
| Index Server | ✅ 启动成功 |
| Relay Server | ✅ 启动并注册到 index |
| HTTP Server | ✅ 就绪，生成 20MB 文件 |
| Tunnel Server | ✅ 就绪，固定 relay |
| Tunnel Client | ✅ 已建立隧道连接 |

### 5.2 功能验证

| 验证项 | 结果 |
|--------|------|
| 健康检查（经隧道） | ✅ `{"status":"ok"}` |
| 校验和一致性 | ✅ 隧道返回 SHA256 与源一致 |
| 20MB 文件完整传输 | ✅ SHA256 校验通过 |

### 5.3 性能数据（3 轮测试）

| 轮次 | 文件大小 | 耗时 | 速度 | 完整性 |
|------|---------|------|------|--------|
| 第 1 轮 | 20,971,520 字节 | 0.656s | 30.49 MB/s | ✅ |
| 第 2 轮 | 20,971,520 字节 | 0.648s | 30.85 MB/s | ✅ |
| 第 3 轮 | 20,971,520 字节 | 0.656s | 30.47 MB/s | ✅ |
| **平均** | **20 MB** | **0.653s** | **30.60 MB/s** | **✅ 100%** |

**SHA256 示例**（第 1 轮）:
```
期望: bade409921eb83ea75a9e4b92bc9521038c75bf45b391b5a5636329d92506662
实际: bade409921eb83ea75a9e4b92bc9521038c75bf45b391b5a5636329d92506662
```

---

## 6. 结论

✅ **本地全套模拟测试完全通过**

1. 五个独立进程协同工作正常，模拟了完整的生产拓扑
2. Index/Relay 注册发现机制正常
3. 隧道转发逻辑正确，HTTP 请求/响应完整透传
4. **20MB 文件三轮传输 SHA256 全部一致，零数据损坏**
5. 本地环回（RTT≈0）下吞吐稳定在 **~30 MB/s**

### 关键观察

本地测试的高吞吐（30 MB/s）建立在 **RTT 接近 0** 的环回网络上。这一数据将作为对比基线，用于评估真实跨公网部署的性能表现（见部署测试报告）。

---

## 7. 复现方法

```bash
cd /root/natP2p
# 编译所有组件到 /tmp/tuntest/bin/
mkdir -p /tmp/tuntest/bin
go build -o /tmp/tuntest/bin/httpfileserver ./cmd/tunnel/httpfileserver/
go build -o /tmp/tuntest/bin/nodeserver ./cmd/tunnel/nodeserver/
go build -o /tmp/tuntest/bin/tunserver ./cmd/tunnel/server/
go build -o /tmp/tuntest/bin/tunclient ./cmd/tunnel/client/

# 一键运行全套测试
bash cmd/tunnel/localsim/run_local_test.sh
```

**日志目录**: `/root/natP2p/cmd/tunnel/localsim/results_<时间戳>/`
- `1_index.log` / `2_relay.log` / `3_httpserver.log` / `4_tunserver.log` / `5_tunclient.log`
- `result.txt` — 测试结果汇总

---

**报告生成时间**: 2026-06-27  
**测试结论**: ✅ 通过（3/3 轮，平均 30.60 MB/s，完整性 100%）
