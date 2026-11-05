# pinomarket

[English](README.md) · **简体中文** · [协议说明](docs/LIVE_PROTOCOL.zh-CN.md)

pinomarket 是一个 Go 研究原型。多个节点给密文交易提供可验证的时间依据，通过共识确定服务顺序，锁定之后才开放交易内容。简化市场只用于演示执行结果。

1. **加密提交。** 用户在钱包里签名并加密交易，再提交给入口节点。
2. **受理与排序。** 其他节点用校准后的时间验证入口声明。客户端取得时间证书后，将证书和密文发给多个节点受理。共识登记后，同轮按证书时间排序。
3. **锁定与揭示。** CometBFT 先确认本批交易及其精确顺序。解密节点再提交可验证的份额，达到门限后按锁定顺序处理交易。

受理和计时目前由本机软件模拟。签名可以核验记录来源与绑定关系。真实 TEE／TNIC、硬件可信时钟和远程证明需要在硬件环境中接入和验证。

## 本地运行

需要 Go 和 C 编译器。首次构建会下载固定版本的依赖。

```sh
bash scripts/network-demo.sh runs/first-demo
./scripts/go.sh test ./...
```

演示目录会生成密钥，提交到 GitHub 前只挑选需要分享的公开回执和审计结果。每次演示使用新的目录。

## 从哪里看代码

| 位置 | 内容 |
| --- | --- |
| [internal/live](internal/live) | 节点、受理记录、时间证据、共识状态与执行审计 |
| [threshold](threshold) | 使用 Shutter shlib 的门限加密和解密份额 |
| [scripts/network-demo.sh](scripts/network-demo.sh) | 从启动本地节点到审计执行结果的一键入口 |

[路线图](ROADMAP.md) · [GitHub 使用入门](docs/GITHUB_GUIDE.zh-CN.md) · [第三方依赖](THIRD_PARTY.md)
