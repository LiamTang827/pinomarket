# pinomarket

## 新增：中位数实验排序与分阶段测量

运行 `./scripts/ordering-experiment.sh runs/ordering-normal-01 normal 1`，可用真实本地节点比较原 identity 排序和新的 median-receipts 模式，导出实际采样指标和链审计结果。新模式采用签名接单序号与中位数，观察不足时明确回退，不宣称实现完整 AOAB 或继承其公平性保证。详见[实验指南](docs/ORDERING_EXPERIMENTS.zh-CN.md)。

[English](README.md) | **简体中文**

**Make promises checkable. Make markets replayable.**

让节点的承诺可检查，让订单的处理过程可重放。

pinomarket 是研究加密订单准入、处理与节点问责的 Go 原型。**v0.3 已能在本机多个独立进程之间运行完整流程**，接入 CometBFT 共识和真实 Shutter 门限加密。原来的单进程模拟保留，用于控制变量和重放场景。

## 名字与匹诺曹节点

项目名由来自 Pinocchio（匹诺曹）的 **Pino** 和 **market（市场）** 组成。节点仍叫匹诺曹，它们可以诚实履约，也可能留下可核验的签名矛盾。

网络延迟会让不同节点看到不同的交易接收顺序。这本身不能证明说谎；但一个节点签了承诺，后来又签署遗漏该订单的完整清单，就可能留下违反规则的证据。

我们希望这些矛盾像匹诺曹的鼻子一样可见。检查器核对声明与规则，不猜测节点动机，也不能证明节点在现实中第一次收到订单的时间。

## 现在能运行什么？

| 模式 | 已实现部分 | 用途 |
|---|---|---|
| **v0.3 `network`** | 独立节点进程与持久化状态；CometBFT v0.38.26；Shutter shlib v0.1.19 门限加密；承诺、登记、队首锁序、份额发布、执行和遗漏证据 | 用真实共识和密码操作运行协议 |
| **v0.2 模拟** | 虚拟消息调度；真实签名和 AES-GCM；理想最终确认和密钥保管器；报告审计与语义重放 | 重复观察延迟、损坏、重复消息和遗漏场景 |

默认网络有五个等权验证节点，在共识假设下容忍一个拜占庭节点；取得承诺需要四个不同节点签名，解密需要三个不同成员的有效份额。运行时，每个节点持有自己的签名私钥与门限私钥份额。

### 一笔订单怎样走完？

```mermaid
flowchart LR
    A[钱包签名并加密] --> B[节点持久化收录承诺]
    B --> C[完整清单经共识确认]
    C --> D[合并登记到队列]
    D --> E[最终确认队首名单与顺序]
    E --> F[节点发布可验证解密份额]
    F --> G[解密并按固定顺序执行]
    B -. 承诺与矛盾的完整清单 .-> H[核验遗漏证据]
```

Alice 在现场得知赛果后提交 YES 买单。加密使订单内容在服务顺序锁定前保持隐藏，收录承诺则让节点承担明确、可检查的收录义务。这不保证成交、获利，也不保证她一定排在所有后来得知赛果的人前面。

## 运行真实本地协议

需要 Go >=1.23，以及密码依赖所需的 C 编译器。首次构建会下载 Go 依赖。在仓库根目录执行：

```sh
./scripts/network-demo.sh runs/my-v03-test offline
```

脚本会构建程序、初始化新网络、启动五个节点进程，再停止第五个验证节点，并提交三笔买单。其余四个节点继续完成登记、锁序、解密与处理。审计器检查真实共识提交签名、重放已提交区块、验证门限解密结果，并独立重算市场账本。脚本退出时会停止自己启动的节点。

每次使用**尚不存在的输出目录**。完成后查看 `runs/my-v03-test/audit.json`、三个 `*-receipt.json` 和 `node*.log`。网络目录还包含本地演示私钥，需保留在 Git 忽略目录中。

脚本也支持 `normal`、`omission`、`withhold`。手动启动节点和各故障的具体含义见[中文协议与操作说明](docs/LIVE_PROTOCOL.zh-CN.md)或 [English guide](docs/LIVE_PROTOCOL.md)。

## 已验证什么，边界在哪里？

真实进程集成测试已经通过：签了承诺的节点重启后仍返回同一份持久化承诺；一个节点离线时其余四个继续处理；离线节点回来后追上状态，不重复执行；恶意节点遗漏已承诺订单时能形成证据，订单仍被处理。单元测试和 `go vet` 也已通过。这些是功能检查，**不是性能基准或安全证明**。

当前部署边界：

- 初始化器通过本地消息转发运行真实的逐成员 DKG 计算，但配置期间可接触全部输出份额。这还不是独立部署、经过认证的分布式 DKG 仪式。
- 所有进程在同一台电脑、同一个 OS 用户下运行。它们是独立协议参与者，不是相互隔离的安全域；接口只绑定本机回环地址。
- 同轮内部使用确定排序占位规则，尚不保证按实际到达时间公平排序，也未实现孔多塞排序。
- 目前记录证据；尚未实现 gas、押金、经济惩罚或买方资金预留。
- 足够多的份额持有者串谋仍可提前解密；共识票数或解密份额不足时会停滞。
- 尚无外部资金结算、生产预测市场设施、已确认的新颖性结论或完整 MEV 防护。

## 保留模拟作为基线

```sh
./scripts/go.sh test ./...
./scripts/go.sh run ./cmd/pinocchio run -scenario normal -out runs/sim-normal-01
./scripts/go.sh run ./cmd/pinocchio run -scenario omission -out runs/sim-omission-01
./scripts/go.sh run ./cmd/pinocchio audit -file runs/sim-omission-01/report.json
```

`run`、`audit`、`replay` 模拟命令见 [v0.2 原型说明](docs/PROTOTYPE.zh-CN.md)，它们不会启动真实网络。

## 文档入口

- [完整本地协议与命令](docs/LIVE_PROTOCOL.zh-CN.md) · [English](docs/LIVE_PROTOCOL.md)
- [设计范围](docs/SCOPE.md) · [路线图](ROADMAP.md)
- [完整开发报告](docs/DEVELOPMENT_REPORT.zh-CN.md)
- [Go 入门与维护指南](docs/LEARNING.zh-CN.md)
- [GitHub 使用入门](docs/GITHUB_GUIDE.zh-CN.md)
- [v0.3 验证记录](docs/validation-v03.json) · [v0.2 验证记录](docs/validation-v02.json)

## 相关工作与依赖

已有机制会标注来源；组合已有机制本身不代表已证明原创性。

- [Shutter＋Primev 公开设计](https://ethresear.ch/t/threshold-encrypted-mempools-with-mev-commit-preconfirmations/23588)与 [primev-sequencer](https://github.com/shutter-network/primev-sequencer)：加密交易与收录承诺。
- [Shutter shlib](https://github.com/shutter-network/shutter/tree/main/shlib) 与 [Rolling Shutter](https://github.com/shutter-network/rolling-shutter)：门限加密组件和基础设施。
- [CometBFT](https://github.com/cometbft/cometbft)：真实网络模式使用的共识引擎。
- [AOAB](https://gramoli.github.io/pubs/DSN24_AOAB_preprint.pdf)：排序、共同输出与纳入保证。
- [PeerReview](https://www.sigops.org/s/conferences/sosp/2007/papers/sosp118-haeberlen.pdf)：签名日志与可问责系统。
- [ABIDES](https://github.com/abides-sim/abides)：市场与消息延迟仿真。

## 名称与兼容性

项目和 GitHub 仓库名称统一为 `pinomarket`。现有 `pinocchio` 命令、Python harness 文件名及密码域标识保留，以兼容已保存的实验。

## 许可

项目自身代码的许可证尚未选定。第三方依赖保留各自许可证，见[归属说明](THIRD_PARTY.md)和[门限组件说明](threshold/THIRD_PARTY.md)。

## Python harness / 模型接入

`python3 harness/pinocchio_harness.py --binary bin/pinocchio --run-dir runs/model-session-01`

Control local validators, faults, measurements and audits through validated JSONL tools or a Python model adapter. 详见[Python 节点控制与模型接入](docs/PYTHON_HARNESS.zh-CN.md)。
