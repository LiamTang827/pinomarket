# GitHub 使用入门

[返回中文首页](../README.zh-CN.md) · [English README](../README.md)

## 中英文切换

仓库首页默认展示英文 README，点击顶部 **简体中文** 即可打开中文版。在中文版顶部点击 **English** 可返回英文版。这是两个相互链接的 Markdown 文件，不需要安装插件。

## 先认识这几个入口

| 入口 | 可以做什么 |
|---|---|
| Code | 浏览项目文件；README 会显示在文件列表下方 |
| Commits | 查看每次保存到 Git 的版本及改动 |
| Issues | 记录问题、研究想法和待办事项 |
| Pull requests | 提出一组改动，检查差异后再合并到主分支 |
| Settings | 管理仓库权限、协作者、可见性等设置 |

## 本地修改后怎么上传

在 Terminal 中进入项目目录：

```sh
cd /Users/tangliam/Projects/pinocchio-market
```

检查改了哪些文件：

```sh
git status
git diff
```

例如修改两份 README 后：

```sh
git add README.md README.zh-CN.md
git commit -m "docs: update project introduction"
git push
```

`git add` 选择要保存的文件，`git commit` 在本地记录一个版本，`git push` 才把本地提交发送到 GitHub。先检查差异，再选择文件，避免误传个人资料、密钥或无关报告。上传需要有效的 GitHub 登录。

## 也可以在网页改小地方

打开文件，点击铅笔按钮编辑，然后提交改动。网页改完后，在本地继续工作前先运行 `git pull`，把远程改动同步回来。

## 私有与公开

私有仓库仅对你和授权协作者可见。准备公开时，可在 Settings 中调整仓库可见性；公开前检查文件内容和历史提交，并决定许可证。仓库公开并不自动授予他人开源许可证。

## 目前从哪里看起

先看 README、[设计范围](SCOPE.md) 和[路线图](../ROADMAP.md)。目前已有 Go 协议模拟原型，请按 [中文运行说明](PROTOTYPE.zh-CN.md) 启动；真实门限加密和分布式共识尚未实现。
