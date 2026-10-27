# Gatelock MVP 需求

## Problem
agent 执行部分命令（deploy、migrate、调第三方 API 等）需要敏感凭证。现在凭证一般放在项目的 `.env` 里，agent 能直接读到，凭证会进入模型上下文、对话记录和日志。需要一个本地应用统一管理这些凭证：凭证不出现在项目目录里，也不明文落盘。agent 通过 Gatelock 的命令行工具执行命令，由 Gatelock 注入环境变量，并把输出中的凭证脱敏后再输出。目标是防止意外泄露，不防 agent 主动绕过。

## Scenarios
- 用户在 app 里创建 namespace（如 `prod-api`），录入一组 env（手动录入，或导入现有 `.env`；导入后可以在 app 里确认删除原文件），设置 passphrase，并选择是否把 passphrase 存进 Keychain。
- 用户告诉 agent "用 `prod-api` 跑 `npm run deploy`"。agent 在自己的 shell 里执行 `gatelock run prod-api -- npm run deploy`。Gatelock 按授权策略要求授权（Touch ID 或手动输入 passphrase），注入 env 执行命令，把脱敏后的输出打印出来，并返回命令的退出码。
- agent 用自己的后台运行能力启动 `gatelock run <ns> -- npm run dev` 这类长时间运行的命令，用 agent 自己的方式读取输出、停止命令。
- 用户打开看板，查看执行记录（命令、namespace、时间、退出码、输出），以及正在运行的命令，可以手动停止。
- 用户解锁 namespace 后，复制某个 env 的值去别处用；或者把整个 namespace 导出成 `.env.<namespace>` 文件，交给不走 Gatelock 的工具。
- 用户后来不想用 Keychain 了，就把某个 namespace 切换成"不存 Keychain"，之后解锁需要手动输入 passphrase；之后也可以再切换回来。

## Scope
In:
- namespace 增删改；每个 namespace 下 env 的增删改、导入 `.env`，导入后提示删除原文件
- 每个 namespace 一对 age 密钥：公钥加密 env 数据，私钥用该 namespace 的 passphrase 加密；磁盘上只有密文
- passphrase 可以选择存 Keychain（默认存），之后可以随时切换
- 授权方式：存 Keychain 的走 Touch ID / 系统密码，不存的手动输入 passphrase
- 授权频率：每次授权 / 授权后 N 分钟内有效 / 本次启动内有效
- 命令行工具 `gatelock run <namespace> -- <command...>`：注入 env、执行命令、透传 stdin 和退出码
- 对 stdout/stderr 做流式脱敏：匹配原值和常见编码（base64、hex、URL 编码等）；支持把某个 env 标记为不敏感，不参与脱敏
- 看板：执行记录 + 正在运行的命令 + 手动停止
- 解锁后复制单个 env 的值（一分钟后清空剪贴板，前提是剪贴板内容没被换掉）；把整个 namespace 导出成 `.env.<namespace>`（明文，权限 0600）

Out:
- 防 agent 主动绕过（变换编码输出、外发、读进程环境等）：不在目标内，不做命令白名单和逐次确认
- MCP 接入：改用 CLI，以后有需要再补
- 列出 namespace、查看 env 值的命令：用户会直接告诉 agent 用哪个 namespace
- agent sandbox 拦截 Unix socket 或网络的情况：用户不开 sandbox，或者自行放行
- Windows / Linux、签名公证、自动更新：MVP 只做 macOS 自用
- 交互式命令（需要 TTY 的）

## Constraints
- 加解密用 age（filippo.io/age），不自己实现加密
- passphrase 存 macOS Keychain
- GUI 参考 MyGo（纯 Go）；核心逻辑和 GUI 解耦，方便以后换框架
- 视觉风格参考 `../mux`：MyGo native UI（Go 绘制，不用 webview），主题沿用它的 Vellum 配色（`cmd/mux/theme.go`，暖色调，支持亮色和暗色）
- agent 通过自己的 shell 调用 CLI

## Success Criteria
- 磁盘上找不到任何敏感 env 的明文值或 passphrase 明文（Keychain 和用户主动导出的文件除外）。标记为不敏感的 env 在 vault 里同样加密存储，但可能以明文出现在执行记录的输出里
- 从 `.env` 导入后，app 会提示删除原文件，用户确认后删除
- agent 在 Claude Code 里用 `gatelock run` 指定 namespace 执行命令，子进程能读到注入的 env，退出码和 stdin 都正常透传
- 命令输出里出现的敏感 env 原值（不论长短），以及它的 base64、hex、URL 编码形式，输出时都被替换成 `[REDACTED:ns/KEY]`
- 三种授权频率表现符合预期；app 重启后"本次启动内有效"的授权会失效
- agent 在后台运行 `gatelock run` 时，读输出和停止都正常，停止时子进程也会一起停掉（子进程忽略 SIGTERM 时也一样）；看板上能看到这个命令，也能手动停止
- 正在运行的命令一定能在看板上看到。app 退出或崩溃时，这些命令会被停止；有命令在运行时，退出 app 前会先弹窗确认
- 切换 Keychain 开关后，解锁方式随之改变，数据不丢失
- 导出前要先授权；导出的文件只有本人可读写，再导入回来时每个值都和原来一样（包括 `0042` 这类数字串、引号、`$` 和换行）

## 已确认
- 授权频率按 namespace 单独设置
- 执行记录持久化保存，只保存脱敏后的输出
- 授权在命令启动时做一次；长时间运行的命令在运行期间不再要求授权
