# 通信、计算与延迟开销：统计说明

**理论公式见[协议复杂度分析](COMPLEXITY.zh-CN.md)。** 本文说明实测统计口径；逐阶段公式、假设和条件上界在该独立文档中。

这套工具用于检查当前实现处理有限负载所需的资源。参考 AOAB 逐阶段记账的思路，但不会直接套用 AOAB 的复杂度结论。协议安全假设、收录规则、队列规则和密码算法保持原样。

## 1. 一次运行统计什么

| 类别 | 指标与来源 | 解释 |
|---|---|---|
| 应用通信 | 节点 `/metrics`，按 `/submit`、`/gossip`、`/open` 分组的请求/响应正文字节 | 同一条 HTTP 交互只在服务器侧记一次；包含重复、失败请求 |
| 共识通信 | CometBFT `/net_info` 的每连接 `SendMonitor.Bytes` 差值 | 只累计发送侧，不再加接收侧，避免重复 |
| 观察通信 | `/state`、`/health` 正文字节，单独列出 | 不加到协议通信合计；读取 `/metrics` 自身不增加计数 |
| 计算操作 | `network benchmark`，逐 API 的串行耗时样本 | 完整 API 保留实际配置、签名和份额验证；详细依赖见输出 `includes` |
| 节点资源 | 各自 PID 的累计 CPU 时间差、RSS 采样 | CPU 为全部节点进程总和；RSS 是采到的最大合计，不是精确内存峰值 |
| 阶段延迟 | 同一控制器单调时钟，轮询各节点状态、客户端回执 | 记录提交、登记、锁序、足够份额和处理；首次观察不等于事件发生的精确时刻 |
| 有限负载处理速率 | 处理订单数 / 整段测量秒数 | 包含开窗、等待和收尾，不是系统吞吐上限 |

这里的 `benchmark` 是独立本地调用。初始实验不调用 AI；若以后把统计用于在线 agent，应把模型请求数、tokens、推理等待和流量另行记录，不混入协议密码运算。

## 2. 通信量如何记账

设测量区间为 $[t_0,t_1]$，`Δ` 为两次累计计数之差：

$$
C_{\mathrm{HTTP}}=\sum_{v}\sum_{r\in\{\mathrm{submit,gossip,open}\}}
\left(\Delta B^{\mathrm{request}}_{v,r}+\Delta B^{\mathrm{response}}_{v,r}\right).
$$

$$
C_{\mathrm{P2P}}=\sum_v\sum_{p\in\mathrm{peers}(v)}
\Delta\mathrm{SendMonitor.Bytes}_{v,p}.
$$

二者属于不同连接，可以列出 `measured_layered_protocol_bytes = C_HTTP + C_P2P` 作为**已观测部分的合计**，但不能称为完整线上字节：HTTP 不含头部和 TCP/IP；P2P 计数位于 CometBFT 的 MConnection 数据包层，不含全部 SecretConnection/TCP/IP 开销。本地 Comet RPC、观察接口与模型通道也不在合计中。

其他注意事项：

- Comet 发送监控存在约 100ms 的采样边界误差，且缓冲写入与实际发送并非完全同时。
- HTTP 在处理器完成或异常退出时记账，跨边界请求会整体落入完成的一侧。计数不是抓包。
- 节点快照不是同一瞬间取得；输出保留采集起止时间。
- 连接集、连接起始时间、累计值或节点进程身份变化时，该区间不能按连续计数器相减。工具将该样本标为无效并保留记录。
- 空块共识、重试和重复传播仍消耗资源。当前没有扣除同长度空闲对照。

对于已处理订单数 $N_{\mathrm{processed}}>0$，可以计算：

$$
\overline C_{\mathrm{observed}}=
\frac{C_{\mathrm{HTTP}}+C_{\mathrm{P2P}}}{N_{\mathrm{processed}}}.
$$

这只是指定区间的归一化结果。尚未完成的订单也保留在提交数和未完成数中，不能把它当作对任意运行都成立的单笔通信上界。

## 3. 理论分析应该怎样继续

当前可以按实际消息结构列账：

1. 一笔密文包发送给 `r` 个入口，约产生 `r` 份密文请求及对应承诺响应。
2. 节点把自己签署的收据向其他节点传播；应累计实际发送次数与收据大小。
3. 完整名单、登记、锁序、份额与执行命令进入 CometBFT，计入该共识引擎的传播与投票成本。
4. 漏报证据也进入共识；异常场景需要单列证据数量与大小。

特别是 `receiptForTick` / `sendReceipt` 每 250ms 尝试轮转自己签过的收据，当前在订单处理后仍可能继续传播。因而，未经重试时长、负载和终止条件的约束，不能给整个实现直接写一个有限的“每笔总通信量”复杂度定理。

在一个有限窗口内，若节点 `i` 实际执行了 `K_i(T)` 次收据传播，每次至多发给 `n−1` 个其他节点，则发送尝试数可按 `(n−1) × Σ K_i(T)` 记账；每个传播包的大小再单独乘入。实际 HTTP 完成计数还受连接失败和窗口边界影响。这里显式保留了运行时长及重试次数，避免把持续后台流量错误归成一次性交易成本。AOAB 的 `O(nℓ+λn²)` 也不能套用到采用 CometBFT 的本项目。

## 4. 计算耗时与 CPU 的区别

`network benchmark` 覆盖签名订单的创建与验证、AES-GCM、随机密钥的门限加密、承诺签验、四订单名单的签验、解密份额生成/验证、三份额解密、完整订单打开，以及一个新内存市场的单次处理。

- 每项先运行 3 次预热，再记录指定次数；保留每次样本和均值、最小值、p50、p95、最大值。
- 离线微基准为构造合法输入会读取本地演示配置及所需的多个秘密份额；只输出公共上下文、大小与耗时。它是测试夹具，不代表运行中的节点可以读取其他节点的份额。
- 使用真实库和成功的密码校验，不用占位加密。
- 初始化、磁盘、网络、共识和 AI 不在单项 API 计时里。实验控制器先停止节点，再执行这些微基准，避免与本次共识负载争抢 CPU。
- `CreateDecryptionShare` 内部会验证份额，`Decrypt` 又会验证所有输入份额；`OpenPacket` 包含整个门限解密。因此各行有包含关系，**不能相加当作一笔交易的总耗时**。
- 微基准是 API 的墙钟耗时，不是 CPU 周期。节点 CPU 差值则来自真实进程，在负载期间仍包含共识、序列化、统计插桩、观察请求和后台工作。
- `/metrics` 的 `handler_ms_total` 包含等待与 IO，不能称作密码计算时间。

## 5. 运行方法

先编译；无需模型账号：

```sh
./scripts/go.sh build -o bin/pinocchio ./cmd/pinocchio
python3 harness/performance_experiment.py \
  --binary "$PWD/bin/pinocchio" \
  --out "$PWD/runs/performance-new" \
  --nodes 5,8 --orders 6 --repeats 2 \
  --compute-samples 30 \
  --window-blocks 20 --block-interval-ms 300 --timeout 90
```

要求 Python 3.9 或以上，系统提供 `ps`，本机允许创建网络连接。输出目录必须不存在。基础密码依赖还需要 C 编译器。

两种节点数都固定解密门槛为 3、服务容量为 2；队列容量设为 `节点数 × 订单数`，让每节点本轮额度同为 6。容错参数与共识门槛随节点数按现有协议计算。默认 `normal`；可用 `--modes normal,omission` 增加一个节点漏报场景，不能把未运行的场景当作已有结果。

独立计算测试也可读取已经初始化的演示配置：

```sh
bin/pinocchio network benchmark \
  -dir runs/your-network/network -samples 30 \
  -out runs/compute-new.json -timeout 120s
```

网络测量流程为：初始化和启动 → 全连接就绪 → 基线快照 → 开窗和提交 → 等待各节点处理 → 结束快照 → 审计 → 停止节点 → 本地计算微基准。初始化/DKG与启动不在负载区间，微基准不会再次操作共识。

## 6. 保存什么，如何核对

- `provenance.json`：源码/二进制摘要、参数、运行环境与统计限制。
- `results.json`、各组 `result.json`：包括失败与未完成的结果，不自动丢弃。
- `network-samples.json`、`resource-samples.json`：通信计数和资源的原始样本。
- `state-observations.json`：各次轮询的实际状态，用于重算阶段观察时间。
- `receipt-*.json`：承诺回执；`audit.json`：独立核验共识与执行。
- `compute.json`：真实 API 操作的逐次耗时。

原始网络目录含演示私钥，保持在 Git 忽略的 `runs/` 下。公开/整理后的报告只放统计、公共证据和摘要，不复制私钥配置。

[本轮样本报告](experiments/2026-10-25/performance/REPORT.zh-CN.md)

## 参考

- [AOAB，§V-C 与 §VI](https://gramoli.github.io/pubs/DSN24_AOAB_preprint.pdf#page=10)：逐阶段通信复杂度分析。
- [CometBFT v0.38.26 MConnection](https://github.com/cometbft/cometbft/blob/v0.38.26/p2p/conn/connection.go)：发送监控所在层次。
