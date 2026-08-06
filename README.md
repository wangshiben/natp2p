
# natp2p

适用于中国宝宝体质的go-p2p依赖库(施工中)

## 特别鸣谢

linux.do 社区，是整个项目开始idea的来源。

> 真诚、友善、团结、专业，共建你我引以为荣之社区。

## 运行日志

框架统一使用 `logx` 输出 `Debug`、`Info`、`Warn` 和 `Error`。设置 `BNFS_LOG_DIRECTORY` 后，各级日志分别写入 `debug.log`、`info.log`、`warn.log` 和 `error.log`；达到大小或时间阈值后，后台自动打包到 `archive/*.tar.gz`。归档过程先原子切换活动文件，进程异常退出后会继续处理 `.pending` 文件。

```text
BNFS_LOG_DIRECTORY=/var/log/bnfs
BNFS_LOG_LEVEL=info
BNFS_LOG_MAX_SIZE_MIB=64
BNFS_LOG_ROTATE_INTERVAL=24h
BNFS_LOG_RETENTION=720h
BNFS_LOG_CONSOLE=true
BNFS_LOG_ERROR_STACK=true
```

日志目录为空时只输出到控制台。`BNFS_LOG_ERROR_STACK=false` 可关闭 Error 调用栈；错误文本仍会保留。可复用框架包禁止调用 `panic`、`os.Exit`、`log.Fatal/Panic`、`runtime.Goexit` 或进程信号 Kill，运行期异常必须返回错误或只隔离当前连接。长期运行命令只允许在参数、密钥、监听器及准入等启动阶段非零退出；一次性验证/检查 CLI 可用退出码表达结果。所有命令强制退出点均受精确审计计数约束，新增或移动到其他函数必须经过代码审核并同步更新策略测试。
