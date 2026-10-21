# Python 节点控制与模型接入

harness 把现有 Go CLI 包成有状态的 Python 工具。Python 管进程、故障和实验；共识、加密、排序和审计仍由 Go 实现。只依赖 Python 3.10+ 标准库。

## 启动

在项目根目录编译，然后选择一个不存在的运行目录：

```sh
./scripts/go.sh build -o bin/pinocchio ./cmd/pinocchio
python3 harness/pinocchio_harness.py --binary bin/pinocchio --run-dir runs/model-session-01
```

进程从 stdin 接收 JSON Lines，每行输出一个 JSON 结果。第一行输出可供模型使用的工具定义。一次会话固定控制五个本地验证者；进程退出或 stdin 关闭时会停止并回收它启动的节点。

```json
{"tool":"initialize","arguments":{"ordering":"median-receipts"}}
{"tool":"start_node","arguments":{"node":0}}
{"tool":"start_node","arguments":{"node":1}}
{"tool":"start_node","arguments":{"node":2}}
{"tool":"start_node","arguments":{"node":3}}
{"tool":"start_node","arguments":{"node":4}}
{"tool":"ready","arguments":{}}
{"tool":"set_fault","arguments":{"node":0,"fault":"delay","delay_ms":500}}
{"tool":"ready","arguments":{}}
{"tool":"stop_node","arguments":{"node":4}}
{"tool":"measure","arguments":{"count":3,"nonce":0}}
{"tool":"audit","arguments":{}}
```

`start_node` 返回进程观察，`ready` 才检查五个节点是否已经提交区块。故障参数在节点启动时读取，所以给运行节点调用 `set_fault` 会先停止再启动该节点，保留日志和 admission journal。这种重启本身会影响测量；应在工作负载前设置故障。停止第五节点后不要调用要求全员在线的 `ready`。

工具包括初始化、单节点启动/停止、故障配置、就绪检查、状态、开轮、提交、测量和审计。故障有 normal/refuse/omission/withhold/delay；离线用 stop_node 表示。故障不叠加。`submit` 要先 `open_round`，参数固定为 owner、nonce、quantity、limit；owner 为 alice/bob/carol。`measure` 会自行开轮，返回真实 metrics，包括超时留下的未完成数量。nonce 必须由调用者避免重用；新实验优先开新会话。

## 接入模型

`TOOLS` 是提供商无关的函数定义；适配器把它转换成模型 SDK 的 tool schema，再把 SDK 返回的调用转换成下面的格式。API 地址、模型名和密钥由外部适配器管理，不接受模型工具动态修改。

```python
from harness.pinocchio_harness import Harness, run_agent

# 将你使用的模型 SDK 封装成这个函数：
def model(messages, tools):
    # 1. 把 messages 中的 assistant.calls / tool.content 转成 SDK 对话格式，
    #    并在 SDK 需要时保留 tool_call_id。
    # 2. 调用模型，提供 tools 的 name/description/parameters。
    # 3. 将 arguments 的 JSON 字符串解码成 dict，返回：
    # {"calls": [{"name": "status", "arguments": {}}]}
    # 模型结束时返回 {"text": "实验结论", "calls": []}。
    return your_model_adapter(messages, tools)

with Harness("bin/pinocchio", "runs/model-session-02") as h:
    result = run_agent(h, model,
        "初始化中位数排序网络，启动五节点，确认就绪；"
        "让第五节点离线，测量三笔订单并审计。根据实际指标说明结果。",
        max_steps=20)
```

`run_agent` 将每个执行结果交回模型，让它决定下一步；最多 20 轮、每轮最多 10 次串行调用，宿主可调整轮数（上限 100）。工具参数按枚举、整数范围和必填键重新校验。没有任意 shell、任意文件读写、修改节点私钥或模型指定二进制路径的工具。`ok=false` 是执行失败，不会伪装成成功。`finished=true` 只表示模型结束对话；实验是否成功应核对 metrics 和审计结果。

也可以跳过 `run_agent`，在自己的 agent 框架中把 `h.call(name, arguments)` 注册为工具执行器；会话结束用 `with` 或 `finally: h.close()` 回收节点。

## 记录与验证

`actions.jsonl` 保存有效工具参数、执行成功与否及耗时；`nodeN.log` 保留节点日志，测量目录保存实际指标，回执单独落盘。非法输入不原样记入日志。网络目录包含演示私钥，不能整体上传。正常关闭会清理进程；强制 SIGKILL 无法执行 Python 清理逻辑。

宿主固定二进制、新运行目录、端口和单次命令超时（默认 120 秒，最长 180 秒）。默认 P2P/RPC 40656+10i / 40657+10i，API 41600+i。并行会话必须使用不同端口。

```sh
python3 -m unittest discover -s harness -v
# 以下实际启动五个节点；需要端口空闲，目录必须不存在：
python3 harness/smoke_harness.py --binary bin/pinocchio --run-dir runs/harness-smoke-01
```

smoke 检查中位数网络、节点故障重启、一个节点离线、三笔订单完成、真实链审计及退出清理。单元测试另外覆盖非法模型参数、工具执行失败时保留指标、模型反馈循环和步数上限。它不要求模型账户，也不把模拟模型回复当作真实模型服务测试。
