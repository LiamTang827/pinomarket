# Pinocchio · 匹诺曹

[English](README.md) | **简体中文**

**Make promises checkable. Make markets replayable.**

让节点的承诺可检查，让订单的处理过程可重放。

Pinocchio 是一个正在设计中的市场攻防研究项目。我们希望构建一个可交互的预测市场环境，让用户观察订单如何传播、获得承诺、排队、解密和执行，并检查节点是否违反自己签署的声明。

## 为什么叫匹诺曹？

节点可以因为网络延迟而看到不同的交易顺序；不同视图本身不是说谎。但如果它对同一轮签署互相冲突的声明，或发布与自己承诺不一致的完整清单，就可能留下可验证的证据。

我们希望让这些矛盾像匹诺曹的鼻子一样可见。这里的“说谎”指违反明确规则的可验证声明，不是对节点动机的猜测。

## 一个场景

Alice 在现场先知道比赛结果，提交买入 YES 的订单。与此同时：

- 监听机器人可能观察公开订单并提交竞争订单；
- 卖家可能撤回尚未成交的库存；
- 不同节点可能以不同顺序收到消息；
- 有限接单额度和处理容量可能让订单继续等待。

项目计划允许用户重放同一场景，更换交易可见性、准入和处理规则，比较订单结果与系统开销。

## 计划提供什么？

| 部分 | 用途 |
|---|---|
| 市场模拟引擎 | 处理买入、撤单、余额和库存，记录确定的状态变化 |
| 消息与节点模型 | 表达传播延迟、签名承诺和节点故障 |
| 协议适配层 | 比较公开订单、加密订单及候选准入规则 |
| 证据检查器 | 检查冲突声明、承诺遗漏等明确定义的违规 |
| 交互与重放界面 | 展示订单时间线、节点视图和可核验的证据 |

## 当前进度

**v0.2 已有可运行的 Go 协议模型。** 使用真实签名和 AES-GCM；网络、共同最终确认与门限释放条件使用模拟组件。**尚未实现真实门限加密或拜占庭共识。**

v0.2 新增：离线报告审计、独立市场核算、重复／损坏／丢包案例和指标输出。

阅读 [中文运行与协议说明](docs/PROTOTYPE.zh-CN.md) 或 [English prototype guide](docs/PROTOTYPE.md)。

- [x] 建立项目定位、范围说明和路线图。
- [x] 定义 v0.2 消息、状态转换和签名证据格式。
- [x] 实现最小市场与可重放事件引擎。
- [x] 实现承诺与清单一致性检查，并加入攻击案例。
- [ ] 增加真实多进程节点和密码组件。
- [ ] 增加交互界面与可重复的对比实验。

既有研究目录中的排序与 AMM 实验尚未迁入本仓库；它们不是当前加密准入协议的完整实现。目前没有新的性能结果、形式化安全证明或已确认的原创性结论。

## 开发记录

- [完整开发报告](docs/DEVELOPMENT_REPORT.zh-CN.md)
- [Go 入门与维护指南](docs/LEARNING.zh-CN.md)
- [v0.2 验证记录](docs/validation-v02.json)

## 从哪里开始？

1. 阅读 [设计范围](docs/SCOPE.md)，理解各阶段保护什么。
2. 阅读 [路线图](ROADMAP.md)，了解第一版要完成的工作。
3. 阅读 [GitHub 使用入门](docs/GITHUB_GUIDE.zh-CN.md)。
4. 运行 Go 原型（需要 Go >=1.23，无第三方 Go 依赖）：

```sh
./scripts/go.sh test ./...
./scripts/go.sh run ./cmd/pinocchio run -scenario normal -out runs/normal-01
./scripts/go.sh run ./cmd/pinocchio run -scenario omission -out runs/omission-01
./scripts/go.sh run ./cmd/pinocchio verify -file runs/omission-01/evidence.json
```

每次运行使用新的输出目录。这些是功能性案例，不是测得的安全性或性能实验结果。

## 研究边界

- 加密隐藏内容，不自动保证公平接入或最先成交。
- 签名证明节点说过什么，不自动证明真实接收时间。
- 超时或不同接收顺序不能单独作为说谎证据。
- 在节点留下第一份记录之前发生的隐瞒，仍是需要研究的边界。
- 模拟中的理想密码操作与真实密码实现将明确区分。

## 相关工作与参考项目

本项目参考已有加密交易、收录保证、可问责系统和市场仿真研究。采用已有机制时会明确标注来源。

- [Shutter＋Primev 公开设计](https://ethresear.ch/t/threshold-encrypted-mempools-with-mev-commit-preconfirmations/23588)与 [primev-sequencer 原型](https://github.com/shutter-network/primev-sequencer)：加密交易与收录承诺。
- [Rolling Shutter](https://github.com/shutter-network/rolling-shutter)：门限加密基础设施。
- [AOAB](https://gramoli.github.io/pubs/DSN24_AOAB_preprint.pdf)：交易排序、共同输出与纳入保证。
- [PeerReview](https://www.sigops.org/s/conferences/sosp/2007/papers/sosp118-haeberlen.pdf)：签名日志与分布式系统问责。
- [ABIDES](https://github.com/abides-sim/abides)：多智能体市场与消息延迟仿真。

## 许可

开源许可证尚未选定。复用第三方代码前，需要核对相应许可证并保留归属说明。
