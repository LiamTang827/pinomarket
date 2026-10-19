# 从能运行到能维护：v0.2 学习路线

先把项目当成一个可重复的小实验：三名买家向一笔固定价格卖单提交订单，程序模拟节点接收、承诺、排队、解密与成交。每次只改一个条件，观察结果，再读对应代码。无需先学完 Go 或密码学。

## 先运行并保留一份结果

在项目根目录执行。下面创建新的临时父目录，两个输出子目录均尚不存在；重复运行不会覆盖旧结果。

```sh
learning_dir=$(mktemp -d "${TMPDIR:-/tmp}/pinocchio-learning.XXXXXX")
./scripts/go.sh run ./cmd/pinocchio run -scenario normal -out "$learning_dir/normal"
./scripts/go.sh run ./cmd/pinocchio run -scenario omission -out "$learning_dir/omission"
./scripts/go.sh run ./cmd/pinocchio audit -file "$learning_dir/omission/report.json"
./scripts/go.sh run ./cmd/pinocchio replay -file "$learning_dir/normal/report.json"
```

`normal` 看正常成交；`omission` 看节点承诺后漏列订单的证据。打开 `report.json` 看全貌，`events.jsonl` 看时间线，`metrics.json` 看计数。`audit` 核验现有报告的签名、流程和账本；`replay` 重跑配置比较语义结果，新随机密钥会使文件内容不同。

第一次练习可复制正常场景，把 Alice 的数量从 4 改为 5，另存文件再运行，观察最后一笔成交及剩余库存。接着只降低 Alice 的初始余额，看“登记成功”和“成交成功”为何会分开。这样每次都有一个能亲自验证的问题。

## 按这个顺序读

1. `protocol/types.go` 的 `Order`：`struct` 是一组字段，`[]Order` 是订单切片，`map[string]int64` 是按账户名查余额。金额单位为分；`owner:nonce` 标识一条命令。
2. `protocol/market.go` 的 `Execute`：跟着一笔买单读条件判断与余额更新。`(m *Market)` 表示方法可修改市场；初始库存 10 份，每份 60 分。
3. `scenarios/normal.json`，再对照 `Config` 与 `Validate`：JSON 字段如何变成 Go 数据，哪些输入被拒绝。
4. `protocol/simulator.go`：先看 `DefaultConfig`，再看 `Run`，沿收包、承诺、登记、服务锁序、解密、执行追踪事件。
5. `protocol/crypto.go`：看 `Seal`、`lock`、`Open`，理解签名、密文和释放条件。
6. `types.go` 的 `Evidence.Verify`，再看 `report_audit.go`、`market_audit.go`：前者检查签名矛盾，后两者离线核验报告并独立重算账本。

读到 `if err != nil`，先理解“失败就返回”；暂时跳过不熟悉的语法，沿输入、判断、状态变化、输出四步画流程。签名证据能证明成员说过互相矛盾的话，不能证明现实收包时间；普通超时也不能直接判定说谎。

## 怎样开始修改

| 想改什么 | 先看哪里 |
|---|---|
| 买家、数量、轮次、延迟、余额 | 复制 `scenarios/normal.json`，用 `run -config 新文件 -out 新目录` |
| 新增内置故障场景、队列与计数 | `simulator.go` |
| 撮合、限价、撤单规则 | `market.go`；同步维护独立的 `market_audit.go` 和测试 |
| 输入字段、校验约束 | `types.go` |
| 命令与输出文件 | `cmd/pinocchio/main.go` |

网络时间是虚拟时间，节点仍在同一进程。共同最终确认由理想协调器完成；理想保管器集中保存完整密钥。真实实现的是 Ed25519 签名和 AES-GCM 认证加密，并未实现 BFT 共识或真正门限解密。不要凭直觉更改签名上下文、随机数、密钥处理或签名人数约束。

修改后运行 `./scripts/go.sh test ./...`，再对新输出执行 `audit` 和 `replay`。先给要改的行为补一个能失败的测试，再实现它；遇到错误先读报错及对应测试，保留原始结果方便比较。
