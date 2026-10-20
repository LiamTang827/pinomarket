# 匹诺曹：中位数参考排序与真实流程测量

2026-10-20。本扩展参考 AOAB 的签名逻辑序号、中位数，以及 Isotaxis 实验材料的分阶段测量和普通/故障对照。代码由本项目实现，没有复制外部 Rust 源码或新增密码依赖。

## 排序模式

`network init -ordering identity` 保留原来的同轮 `(owner, nonce, id)` 排序。

`network init -ordering median-receipts` 启用实验模式：

1. 节点成功接单时分配本轮序号 1、2、3……，写入签名承诺并落盘。重发不占新序号，重启后继续计数。它表示节点声明的接单顺序，不是可证明的物理到达时间。
2. 共识仍选择前 q 份有效完整清单并求并集。对每单收集所选清单内不同成员的签名序号。
3. 至少有 `2f+1` 份观察时，按成员 ID 固定选择前 `2f+1` 份，以其中位数排序；平局沿用身份规则。
4. 观察不足的订单仍登记，但排在足量观察订单之后，沿用身份排序，公开标记 `qualified=false`。该回退保留收录语义，也可能影响成交机会，需要单独评价。
5. 跨轮追加、精确队首锁定、真实门限解密、按序执行及遗漏证据沿用原流程。

**这是 AOAB-inspired reference ordering，不是完整 AOAB 或 Isotaxis。** 本扩展没有实现 AOAB 的中位数门限签名证明、PRBC/MVBA/ADD，仍使用 CometBFT 和现有清单。样本选择与回退也属于本项目规则，不能继承原论文的公平性、异步活性或最优通信结论。签名证明成员作出了声明，不证明其诚实记录了真实时间。

模式绑定在 manifest 的网络上下文里。更换模式必须初始化新网络，不能修改旧 manifest 后续跑。旧网络未启用该字段时仍可使用。

## 一条命令运行对照

在项目根目录：

```sh
./scripts/ordering-experiment.sh runs/ordering-normal-01 normal 1
```

脚本分别启动两套五进程网络，比较 identity 和 median-receipts。每组提交三笔真实钱包加密订单，完成后核验共识签名、区块重放、门限打开及市场账本，并停止自己启动的进程。

第二个参数支持 `normal`、`offline`、`omission`、`withhold`、`delay`。delay 仅给第一个节点的接单 API 增加 500ms，不模拟洲际 P2P 网络。omission 同时停止第五节点，让第一节点的空清单有机会进入选中集合；本脚本不保证遗漏证据在完成采样前已提交，证据路径由专用进程回归验证。

第三个参数取 1–5，表示每种模式的重复次数，偶数次交换运行顺序。每次密钥和共识调度独立，因此只是成对本地功能测量，不是相同随机网络轨迹上的严格因果比较，更不能直接证明性能优势。

默认端口：P2P/RPC 为 `38656+10i`、`38657+10i`，API 为 `39600+i`。可通过 `PINOCCHIO_BASE_PORT`、`PINOCCHIO_API_PORT` 调整。输出目录必须是新目录。脚本不启动云资源。

## 测量已运行的网络

```sh
bin/pinocchio network init -dir runs/manual-median -ordering median-receipts
# 按 LIVE_PROTOCOL 文档分别启动节点，再执行：
bin/pinocchio network measure -dir runs/manual-median -out runs/manual-measure-01 -count 3 -quantity 1 -nonce 0 -timeout 90s
```

measure 打开或沿用未登记的窗口，等待至少 q 个节点看到该窗口后再提交。钱包轮流使用 alice、bob、carol，同一钱包的编号从 `-nonce` 开始递增。重复实验使用新网络或未使用的命令编号。

每次最多 80 笔；超过接单额度可能无法完成。超时会返回失败并保留指标。库存耗尽是业务结果，不能当成协议崩溃。

## 输出与解释

- `network/`：运行配置和私钥材料，不能整个公开上传。
- `measurement/receipt-*.json`：密文、签名回执、各节点响应耗时和收齐 q 份有效回执的耗时。
- `measurement/metrics.json`：提交、获证、登记、处理、成交、未完成数量；加密时间、各阶段观察时间、完成样本 p50/p95/p99、有限工作负载处理速率。
- `measurement/audit.json`：真实链审计通过后的结果。
- `summary.json`：从本次实际 metrics.json 汇总结果和源代码哈希，没有内置论文性能数据。

`admission_quorum_ms` 从客户端开始提交，到收齐第 q 份有效签名为止；其他节点稍后失败不会抹去该值。登记、锁序、足量解密份额和处理时间，是同一个客户端约每 50ms 轮询首次看到相应已提交状态的时间上界，不是内部事件的精确时间或全球物理时间证明。同一次轮询可能看到多个阶段已经完成。

`completion_ms` 从每单开始提交计算，只对完成订单统计，未完成数量另列。`processed_tps` 是开轮至采样完成的有限工作负载速率，包含窗口等待、不含最终审计，不是饱和吞吐。正式性能评价还需要预热、负载、重复次数及硬件/网络配置。

没收齐 q 份回执的订单仍可能被清单带入登记。因此获证数、登记数、处理数和成交数分别统计。旧 owner/nonce 对应另一份密文的结果，不能冒充本次提交完成。

## 验证

登记记录保存中位数样本及回退标记。离线审计独立从签名清单重算完整并集、冲突排除、样本、中位数及顺序，不信任状态机自己写的资格标记。真实网络审计选择响应节点中提交高度最高的快照，再验证真实提交签名和区块重放。

```sh
./scripts/go.sh test ./...
./scripts/go.sh vet ./...
PINOCCHIO_LIVE_INTEGRATION=1 PINOCCHIO_TEST_ORDERING=median-receipts ./scripts/go.sh test ./internal/live -run '^TestLiveNetworkProcessesRestartAndOmission$' -count=1 -timeout=150s -v
```

最后一条在中位数模式检查五进程、承诺后重启、一个验证者离线、恢复追赶、第二轮遗漏证据和最终账本；不设置 PINOCCHIO_TEST_ORDERING 时运行原模式。功能测试不替代协议证明。

## 来源与后续

- [AOAB，DSN 2024，Section V–VI](https://gramoli.github.io/pubs/DSN24_AOAB_preprint.pdf)：签名逻辑序号、中位数及密文有序输出后的解密。
- [Isotaxis 配套实验材料](https://github.com/xrxrxrxrxr/Isotaxis-ArtifactEvaluation)：测量拆分与对照组织参考，不是 AOAB 原版实现。

下一步先与作者核对原生实现版本和排序定义，再决定是否引入原后端。目前可检验不同排序对有限库存成交的影响、稀疏观察回退的影响，以及有限接单额度的受阻。钱包端加密原本已经存在，不能把全部隐私收益归给本次中位数模块。
