# 直接连接 ChatGPT 计划额度

日期：2026-10-23。我们自己管理 Python harness，通过官方 Sign in with ChatGPT 登录和 Responses API 调用模型。此路径不启动 Codex，也不读取 Codex 的登录文件。

## 先理解这一个循环

```text
harness 准备观察 → 模型返回动作 → harness 检查并执行 → 把结果交回模型
```

连接器是 `harness/chatgpt_model.py`。这里负责登录、模型调用和返回动作；原来的 Go 节点继续负责实际协议。它是实验控制器的模型适配器，尚未自动构成 Bob 与各节点独立信息隔离的多角色系统。

## 1. 安装可选依赖

在仓库根目录执行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r harness/requirements-chatgpt.txt
```

基础 harness 仍只用标准库。直接登录需要 PyJWT 和 cryptography 来验证官方 ID token 签名；该连接器目前支持 macOS/Linux（使用文件锁防止刷新令牌竞争）。

## 2. 登录并授权

```bash
.venv/bin/python harness/chatgpt_model.py login
```

程序先启动 `127.0.0.1` 上的本地连接页。只有你点击 **Continue with ChatGPT** 才跳到官方授权页；它不会自动跳转或反复重试。核对名称为 **pinomarket**，由你选择账户、工作区并确认是否允许使用计划额度。首次使用时按官方动态注册流程取得本应用的独立 client ID。

程序校验回调 state、PKCE、官方签名、issuer、audience、过期时间、nonce 和计划调用权限。返回账户身份不匹配时拒绝覆盖旧账户。新授权完成且全部检查通过后才切换活动账户。本地页面随后才显示“已连接并保存”；收到回调本身不算连接成功。

本版允许官方示例中的 5 秒时钟偏差，同时仍检查签名、身份、有效期和 nonce。首次实测曾因本机慢约 3 秒而拒绝令牌，现已加入对应回归测试。注册编号与验证通过的凭据分开保存：验证失败后保留原注册编号，重试不会重新创建应用。

已有有效连接时，`login` 会直接复用或刷新它，不打开浏览器。明确需要重新授权时才使用 `login --reauthorize`。若没有任何有效令牌，程序无法仅凭注册编号恢复账号权限，需要你完成一次新的登录回调。

```bash
.venv/bin/python harness/chatgpt_model.py status
.venv/bin/python harness/chatgpt_model.py models
```

`models` 从当前账户取得可见模型列表。选择服务器实际返回的 slug，不能假设所有 GPT 型号都可调用。账户额度、应用授权和工作区策略决定能否使用；遇到拒绝或额度不足时停止，不切换到 API Key 计费。

默认凭据保存在 Git 忽略的 `.local/chatgpt/`。目录权限 0700，凭据文件 0600，按账户及 issued client ID 分开保存。不要共享这个目录，不要把令牌贴进聊天。账号选择参数为 `--account PROFILE`，放在子命令前；添加另一账户可用 `login --new-account`。`--state-dir PATH` 可以由宿主指定其他私有存储位置。

## 3. 先测试连接

把下面的 `MODEL_SLUG` 换成 `models` 返回的一个实际 slug：

```bash
.venv/bin/python harness/chatgpt_model.py test --model MODEL_SLUG
```

这会消耗一次真实模型请求，要求模型返回一个 `status` 动作。**此命令没有创建 Harness，不会启动节点或执行动作。** 只有收到 `response.completed` 且动作 JSON 合法才算成功；部分文本、流中断和额度错误都不执行。

每次请求使用官方公开端点 `https://api.openai.com/v1/responses`，设置 `store=false`、`stream=true`。不使用 ChatGPT 的 backend-api，不传不支持的 temperature、max_output_tokens 或 previous_response_id；不自动重试推理请求。

`runs/chatgpt-connection/model_calls.jsonl` 只记录请求耗时、请求/返回模型、完成状态及服务器提供的 token usage。不记录观察内容或凭据。它不是美元费用估计，也不代表剩余订阅额度。实际用量和本应用权限请到 [ChatGPT Usage](https://chatgpt.com/settings/usage) 查看。

## 4. 接入我们自己的 harness

```python
from harness.pinocchio_harness import Harness, run_agent
from harness.chatgpt_model import ChatGPTModel

model = ChatGPTModel(
    '.local/chatgpt',
    'MODEL_SLUG',  # 使用 models 返回的值
    max_calls=5,
    telemetry='runs/my-model-experiment/model_calls.jsonl',
)
with Harness('bin/pinocchio', 'runs/my-model-experiment') as h:
    result = run_agent(h, model,
        '只初始化网络，然后读取状态并结束。',
        max_steps=5)
```

这是主动执行实验的例子，和上面的无执行连接测试不同。模型只返回 `text` 与 `calls`；工具名称和参数由程序再次验证。当前用本地 JSON 约定解析动作，没有声称使用服务端严格结构化输出保证。模型超出允许工具、回复损坏或达到调用上限时停止；普通文本不当作成功执行的证据。

模型名、凭据目录和请求预算由宿主指定，模型不能修改。调用次数上限不是精确 token 上限。实际角色实验还需要分别构建允许的信息和工具集合，不能把控制器全部权限直接交给 Bob。

## 5. 退出和测试

```bash
.venv/bin/python harness/chatgpt_model.py logout
.venv/bin/python -m unittest discover -s harness -v
```

退出会尝试撤销当前可续期会话并清除本地令牌，保留账户注册与稳定主机编号。远程撤销未获确认时会明确提示，你也可以在 ChatGPT Settings 断开 pinomarket。

自动测试不需要真实账户：检查伪造/过期/错误身份令牌、回调串改、缺失额度权限、刷新替换、凭据权限、流失败、动作限制、调用预算及遥测脱敏。真实登录授权和模型请求是否成功，以当次实际运行结果为准，不能由模拟测试替代。

## 官方依据

- [注册与登录](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- [模型列表与推理](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- [账户、刷新及退出](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
- [预览限制](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
