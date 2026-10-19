# 从能运行到能维护：Go 学习路线

先跟一笔订单走完，再逐步读代码。你无需先学完 Go、共识或密码学。现在有两个入口：v0.3 是本机多个独立进程的真实协议，v0.2 是方便控制变量的单进程模拟。

## 第一次：先运行真实流程

在仓库根目录执行，需要 Go >=1.23 和 C 编译器。首次构建会下载依赖。

```sh
./scripts/network-demo.sh runs/learning-live-01 offline
```

目录必须尚不存在；下一次可换成 `runs/learning-live-02`。脚本启动五个节点，再停掉第五个，其余四个继续处理 Alice、Bob、Carol 的买单。完成后自动停掉自己启动的进程，所以此时看保存的文件，而不是再请求在线 `network status`。

依次打开：

1. `runs/learning-live-01/alice-receipt.json`：Alice 发出的密文包、各节点的承诺签名、哪些节点联系失败。
2. `runs/learning-live-01/audit.json`：多少订单完成、多少份共识提交签名、最终余额与库存是否通过检查。
3. `runs/learning-live-01/node0.log`：实际节点运行记录。关闭节点时的连接退出信息不等于订单处理失败。

网络目录含演示私钥，不能提交到 Git。真实模式说明与手动节点命令见 [LIVE_PROTOCOL.zh-CN.md](LIVE_PROTOCOL.zh-CN.md)。

### 想让节点一直开着？

先构建、初始化一个新的目录：

```sh
./scripts/go.sh build -o bin/pinocchio ./cmd/pinocchio
bin/pinocchio network init -dir runs/learning-manual-01
```

在五个终端分别启动 `node0` 到 `node4`。例如第一个终端运行：

```sh
bin/pinocchio network node -config runs/learning-manual-01/node0.json
```

第五个终端对应 `node4.json`。再开一个终端，执行：

```sh
bin/pinocchio network ready -dir runs/learning-manual-01
bin/pinocchio network open -dir runs/learning-manual-01
bin/pinocchio network submit -dir runs/learning-manual-01 -owner alice -quantity 4 -nonce 0 -out runs/learning-manual-01/alice-receipt.json
bin/pinocchio network wait -dir runs/learning-manual-01 -processed 1
bin/pinocchio network status -dir runs/learning-manual-01
bin/pinocchio network audit -dir runs/learning-manual-01 -out runs/learning-manual-01/audit.json
```

这时可以直接看状态。提交窗口按区块高度关闭，超过窗口需等本轮登记，再 `network open` 开新一轮；不要在旧窗口继续提交。每名用户的新命令使用新的 `-nonce`。结束时在五个节点终端分别按 Ctrl+C；再次使用同一配置启动节点会读取磁盘状态，不要重新初始化覆盖它。

## 第二次：用模拟只改一个条件

模拟可精确控制虚拟消息时间，适合先理解“承诺成功”与“成交成功”为何不同。

```sh
learning_dir=$(mktemp -d "${TMPDIR:-/tmp}/pinocchio-learning.XXXXXX")
./scripts/go.sh run ./cmd/pinocchio run -scenario normal -out "$learning_dir/normal"
./scripts/go.sh run ./cmd/pinocchio run -scenario omission -out "$learning_dir/omission"
./scripts/go.sh run ./cmd/pinocchio audit -file "$learning_dir/omission/report.json"
./scripts/go.sh run ./cmd/pinocchio replay -file "$learning_dir/normal/report.json"
```

`report.json` 看全貌，`events.jsonl` 看时间线，`metrics.json` 看计数。`audit` 核验现有报告；`replay` 重跑配置，比较语义结果。重跑产生新随机密钥，文件内容不要求逐字一致。

复制 `scenarios/normal.json`，只把 Alice 的数量从 4 改为 5，另存后运行，观察剩余库存。接着只降低初始余额，看订单虽然登记成功，执行时仍可能因余额不足失败。这些是业务结果，不能据此指控节点。

## 按这个顺序读代码

1. **订单是什么**：`protocol/types.go` 的 `Order`。`struct` 是一组字段，`[]Order` 是订单切片，`map[string]int64` 是按账户名查余额。金额以分计，`owner:nonce` 标识命令。
2. **成交怎样计算**：`protocol/market.go` 的 `Execute`。初始库存 10 份，每份 60 分；跟随一次判断、扣款、加份额的过程。它由两种模式共用。
3. **用户命令从哪里进来**：`internal/live/cli.go`。先找 `submit`，再找 `SubmitPacket`，理解参数如何变成密文请求和收据。
4. **订单怎样加密**：`internal/live/types.go` 的 `NewPacket`、`OpenPacket`。内层签名授权订单，AES-GCM 隐藏正文，门限加密保护 AES 密钥，外层签名授权密文包。
5. **节点承诺了什么**：`internal/live/node.go` 的 `accept`、`seal`、`work`。观察节点为什么先保存承诺再回复，为什么等锁序的共识状态提交后才生成自己的解密份额。
6. **所有节点怎样得到相同结果**：`internal/live/state.go` 的 `Apply`。按 `open → list → register → lock → shares → execute` 阅读；`evidence` 是另一种可提交的交易。
7. **共识与密码库**：最后再读 `internal/consensus/` 和 `threshold/`。先掌握它们接受什么输入、返回什么结果，暂不修改底层数学。

读到 `if err != nil`，先理解“失败就返回”。沿“输入 → 判断 → 状态变化 → 输出”画流程，不必一次吃透所有语法。不要凭直觉修改签名上下文、随机数、密钥处理和阈值约束。

## 想改什么，先看哪里？

| 想改的部分 | 入口 |
|---|---|
| 模拟中的买家、数量、余额、延迟 | 复制 `scenarios/normal.json`，使用 `run -config 新文件 -out 新目录` |
| 真实网络的节点数、窗口、队列和服务容量 | `network init -h`，对应 `internal/live/bootstrap.go`；每次初始化新网络 |
| 节点拒收、遗漏、扣住份额 | `network node -h` 与 `internal/live/node.go` 的故障选项 |
| 撮合、限价、撤单规则 | `protocol/market.go`，同步检查独立市场审计及相关测试 |
| 登记、排队、锁序和执行规则 | `internal/live/state.go` |
| 命令与输出 | `cmd/pinocchio/main.go`、`internal/live/cli.go` |

`-delay-ms` 延迟的是节点的接单接口，不是整个 CometBFT 网络。模拟中的虚拟延迟也不能直接当成真实网络测量。

## 修改后怎样检查？

先运行现有单元测试和静态检查：

```sh
./scripts/go.sh test ./...
./scripts/go.sh vet ./...
```

改动共识状态、持久化或门限释放时，再运行真实进程集成测试：

```sh
PINOCCHIO_LIVE_INTEGRATION=1 ./scripts/go.sh test ./internal/live -run '^TestLiveNetworkProcessesRestartAndOmission$' -count=1 -timeout=150s -v
```

该测试会监听本机端口并启动子进程。测试通过说明列明的场景成立，不代表完成性能实验或安全证明。优先给实际要改变的行为补测试，保留原始结果便于比较。

最后记住部署边界：初始化器虽然运行真实的逐成员 DKG，却能接触所有输出份额；各进程也在同一 OS 用户下运行。目前适合研究本地协议行为，不能等同于生产环境的相互隔离节点。
