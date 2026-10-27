# Gatelock MVP 设计

## Problem
agent 执行命令要用凭证，但凭证不应出现在项目目录里，也不应明文落盘。Gatelock 是一个常驻的 macOS 应用，负责管理这些凭证，并提供 CLI `gatelock run`。agent 用这个 CLI 执行命令：它向 app 申请凭证，作为环境变量注入子进程，再把输出里的凭证脱敏后打印出来。
需求：`../requirement/2026-10-27-gatelock-mvp.md`

## Scope
In：需求文档 Scope 中的全部内容。
Out：MCP；防 agent 主动绕过；需要 TTY 的交互式命令；agent sandbox；锁屏或睡眠时自动上锁；Windows/Linux；签名、公证和自动更新。

## Assumptions
- 单用户、单机，app 只运行一个实例（MyGo 的 `RequestSingleInstanceLock`）。数据目录只有 app 自己写。
- 规模很小：namespace < 50 个，每个 namespace 的 env < 100 个，单个 value ≤ 64KB。
- agent 的 shell 没有开 sandbox，或者已经放行 Gatelock 的 socket。
- CLI 和 app 是同一个二进制，并且一起升级，所以 IPC 协议不需要考虑新旧版本兼容。
- 不会出现的情况：多个 macOS 用户共用一份数据；从网络访问 vault；两个 app 实例同时写数据。
- env key 名不算敏感信息，可以明文落盘。如果这条不成立，存储格式需要重新设计。

## Validation Findings
- **纯 Go 能否调用 Touch ID？** 在 `.scratchpad/lacontext/` 里用 purego v0.11.1（不用 cgo）调用 `LAContext canEvaluatePolicy` 和 `evaluatePolicy:localizedReason:reply:`，命令行进程也能弹出系统授权框，回调 block 能正常拿到结果。授权通过时返回 success；用户点取消时返回 NSError `code=-2`（`LAErrorUserCancel`）。→ `ConfirmUser` 把 `-2` 映射成 `vault.ErrDenied`，其他错误码原样包装后返回。
- **age 解锁要多久？** 在 `.scratchpad/agecost/` 里测试：scrypt logN=18 解开 hybrid identity 约 0.49s；用它解密 30 个 env 文件共约 3ms；64B 的 value 加密后文件约 1.7KB。→ "每次授权"模式每次多 0.5s，可以接受。每个 env 单独存一个文件，开销也不大。
- **MyGo 的能力：** 读了源码，有以下结论。
  - `mygo.Secrets` 是 login keychain 里的普通 generic password，没有访问控制，单条上限 2560B，用来存 passphrase 够用。
  - 有 `ActivationPolicyAccessory`（不显示 Dock 图标）、tray、`OnWindowAllClosed`（关掉窗口后 app 不退出）。
  - text input 支持 `.Password()`，可以做密码输入框。
  - 包级 `init` 只有 `LockOSThread` 和注册函数这类无害操作，所以同一个二进制可以在 `mygo.App.Run` 之前分流到 `run` 子命令。

## Alternatives Considered
1. **agent 接入：CLI（采用） vs MCP（初版）。**
   MCP 要自己实现前台和后台执行、超时、分页读输出、停止，还要用一个 shim 把 agent 的 cwd 和 PATH 传过去。CLI 跑在 agent 自己的 shell 里，这些能力 agent 本来就有，同时也方便用户在终端里自己用。CLI 的代价是会受 agent sandbox 限制，用户确认不开 sandbox。
2. **谁启动子进程：CLI（采用） vs app 启动，CLI 只转发输出。**
   如果由 app 启动，CLI 就得代理 stdin、转发信号、回传退出码，TCC 权限也要单独授权给 Gatelock。由 CLI 启动的话，进程关系和平时在终端执行一样，app 只负责授权和记录。代价是 env 值会进入 CLI 进程；按"防意外泄露"的定位，可以接受。
3. **命令形式：argv（采用） vs 交给 `/bin/sh -c` 的字符串。**
   CLI 收到的参数已经被 agent 的 shell 解析过，直接 exec 最符合直觉，`sudo`、`env` 和 `op run` 也都是这么做的。需要在参数里引用凭证变量时，显式写成 `sh -c '...'`（见 Risks）。
4. **存储粒度：每个 env 一个密文文件（采用） vs 每个 namespace 一个密文文件。**
   单文件方案要先解锁才能增删改 env，而且每次都要重写整个文件。分文件后，新增或修改 env 只需要公钥，不用授权。代价是 key 名会出现在文件名和 meta 里，按上面的假设可以接受。
5. **缓存什么：解开后的 age identity（采用） vs 解密后的 env 值 vs passphrase。**
   缓存 env 值的话，修改 env 时还得同步更新缓存，而且明文在内存里停留的时间更长。缓存 passphrase 的话，每次都要再跑一遍 scrypt。缓存 identity 能让授权状态最简单：缓存有效就等于已授权。
6. **授权方式：app 内调用 LAContext，passphrase 存成普通 keychain 条目（采用） vs data protection keychain + `SecAccessControl(.userPresence)`。**
   后者由系统强制要求授权，更安全，但需要 `keychain-access-groups` entitlement 和 provisioning profile，MyGo 的打包流程不支持。自用场景用前者就够了。
7. **脱敏暂存：精确前缀暂存，结束时遮盖（采用） vs 暂存最长模式长度减 1 个字节，空闲后放行。**
   后者在密钥分两次输出、中间又有停顿时，会漏出前半段。精确前缀暂存只扣住"可能是密钥开头"的字节，绝大多数输出不受影响，所以不需要定时放行。
8. **执行记录存储：每次执行一个目录，输出只留最近一段（采用） vs SQLite / 完整保留可续读的输出。**
   读取实时输出由 agent 自己负责，执行记录只给人回看，所以不需要 offset 续读。文件实现最简单。
9. **CLI 和 app 断开连接：CLI 停止子进程（采用） vs CLI 继续运行，并重连 app、重新登记。**
   后者在 app 崩溃或重启时不会打断 agent 的命令，但要实现重连、恢复记录、断线期间的输出补传，状态也多了一种。自用场景下，运行中重启 app 的情况很少见。前者保证"在运行的命令一定能在看板上看到、能停止"，代价是 app 崩溃会连带停掉命令。

## Components
- `internal/vault`：管理 namespace 和 env 的存储、age 加解密、passphrase 与 Keychain、授权策略、解锁缓存。
- `internal/redact`：流式脱敏 writer，匹配密钥原值和常见编码形式。
- `internal/launch`（CLI 侧）：启动子进程，透传 stdin，脱敏 stdout/stderr，转发信号，处理停止请求，算出退出码。
- `internal/history`（app 侧）：执行记录的存储、运行中命令的状态、停止请求、变更通知。
- `internal/ipc`：CLI 和 app 之间的协议。app 侧的 `Serve` 是信任边界，负责校验请求，调用 vault 和 history；CLI 侧的 `Client` 负责连接，app 没运行时把它拉起来。
- `internal/macauth`：用 purego 调用 LAContext，实现 `ConfirmUser`。
- `cmd/gatelock`：入口。`gatelock run` 是 CLI，不带参数时启动 GUI（MyGo native UI + mux 的 Vellum 主题）。还负责组装各组件，实现 `vault.Authorizer`（Touch ID 和 passphrase 弹窗）。

## Interfaces
```go
// ---- vault ----
func Open(dir string, kc Keychain, auth Authorizer) (*Vault, error)

// 只读元数据，不需要授权。
func (v *Vault) Namespaces() []Namespace
func (v *Vault) Namespace(name string) (Namespace, error)       // ErrNotFound

// passphrase 由调用方提供（用户输入，或 UI 生成后展示给用户）。ErrExists、ErrInvalidName
func (v *Vault) Create(name string, passphrase []byte, useKeychain bool, p Policy) (Namespace, error)
func (v *Vault) Rename(old, new string) error
func (v *Vault) Delete(name string) error                        // 同时删除 Keychain 条目
func (v *Vault) SetPolicy(name string, p Policy) error           // 会清掉该 namespace 的解锁缓存

// 写 env 只用公钥，不需要授权。key 不合法时返回 ErrInvalidKey。
func (v *Vault) SetEnv(name, key string, value []byte) error
func (v *Vault) SetSensitive(name, key string, sensitive bool) error
func (v *Vault) DeleteEnv(name, key string) error
// 只负责写入，同名 key 会被覆盖。原 .env 文件的清理由 UI 负责：
// 导入成功后列出导入的 key，经用户确认后删除原文件。
func (v *Vault) Import(name string, dotenv []byte) (keys []string, err error)

// 按策略授权（可能阻塞，等 Touch ID 或 passphrase 输入），返回该 namespace 的全部 env。
// TTL/Session 策略下，同一 namespace 的并发请求共用一次授权；Every 策略下每个请求单独授权。
// 授权弹窗全局排队，同一时间只弹一个。ErrNotFound、ErrDenied；ctx 取消会关掉弹窗或退出排队。
func (v *Vault) Resolve(ctx context.Context, name, reason string) ([]Secret, error)
// 打开时会通过 Authorizer 要求输入一次 passphrase，并校验；关闭时删除 Keychain 条目。
func (v *Vault) SetKeychain(ctx context.Context, name string, on bool) error
// 先授权。顺序：新私钥密文写临时文件 → rename 覆盖 identity.age → 更新 Keychain。
// 最后一步失败时返回 ErrKeychainStale：密文已经换好，下次解锁会提示手动输入一次并自动修复 Keychain。
func (v *Vault) ChangePassphrase(ctx context.Context, name string, newPass []byte) error
func (v *Vault) Lock(name string)
func (v *Vault) LockAll()

type Secret struct { Key string; Value []byte; Sensitive bool }
type Policy struct { Mode PolicyMode; TTL time.Duration }    // Every | TTL | Session

// 由 app 层实现。
type Authorizer interface {
	ConfirmUser(ctx context.Context, reason string) error                             // Touch ID / 登录密码；返回 nil 表示通过
	AskPassphrase(ctx context.Context, ns, reason string, retry bool) ([]byte, error) // passphrase 错了会以 retry=true 再调用
}
type Keychain interface { Get(account string) ([]byte, error); Set(account string, v []byte) error; Delete(account string) error }

// ---- redact ----
type Secret struct { Label string; Value []byte }                // Label 例如 "prod-api/STRIPE_KEY"
// 把脱敏后的内容写进 dst，匹配会跨 Write 调用。只暂存"可能是某个模式开头"的末尾字节，
// 等后续数据到来再判断，不会按时间放行；Close 时仍在暂存的字节一律遮盖成 [REDACTED:...]。
// 所有传入的值都参与脱敏，不论长短。可以并发调用。
func NewWriter(dst io.Writer, secrets []Secret) *Writer

// ---- launch（CLI 侧）----
type Spec struct {
	Argv           []string
	Cwd            string
	Env            []string            // 完整的子进程环境变量
	Redact         []redact.Secret
	Stdin          io.Reader
	Stdout, Stderr io.Writer           // 收到的是脱敏后的内容
	Record         io.Writer           // 脱敏后的 stdout+stderr 按顺序交错再写一份，用于执行记录；写慢了不会阻塞子进程
}
// 在独立进程组里启动子进程并等它结束。started 在子进程启动后调用，参数是进程组 id。
// 停止规则：收到 SIGINT/SIGTERM/SIGHUP 时，把同样的信号转发给进程组；stop 被关闭时发 SIGTERM。
// 两种情况都会在 5s 后检查进程组，还在就 SIGKILL；期间再收到一次信号，立即 SIGKILL。
// 返回值按 shell 惯例：正常退出返回退出码，被信号杀死返回 128+信号值，启动失败返回 127 和 error。
func Run(s Spec, started func(pgid int), stop <-chan struct{}) (exitCode int, err error)

// ---- ipc ----
type RunRequest struct { Namespace string; Argv []string; Cwd string }

// CLI 侧。连不上时拉起 app，最多重试 10s：先对 os.Executable() 做 filepath.EvalSymlinks，
// 再往上找 `.app` 目录，用 `open <path>` 拉起；找不到 .app 时退回 `open -b <bundle id>`。
func Dial(socketPath string) (*Client, error)
// 阻塞到授权完成，返回 env 和本次执行的会话。ErrNotFound（错误信息里附上已有的 namespace 名）、ErrDenied。
func (c *Client) Run(req RunRequest) (*Session, []vault.Secret, error)
func (s *Session) Started(pgid int)
func (s *Session) Record() io.Writer                  // 把输出同步给 app；app 处理慢时丢弃并标记 truncated，不阻塞
func (s *Session) Stop() <-chan struct{}              // app 要求停止，或者和 app 的连接断开时关闭
func (s *Session) Lost() bool                         // Stop 是否因为连接断开而关闭；CLI 据此用 125 退出并在 stderr 说明
func (s *Session) Exit(code int)                      // 上报退出码并关闭连接

// app 侧。拒绝 uid 和自己不同的连接。每个连接对应一次执行：校验请求 → history 登记（authorizing）
// → vault.Resolve（被拒时记录标成 denied，然后断开）→ 发送 env → 收输出 → 收退出码。
// 如果连接在 Exit 之前断开，就 kill 已登记的进程组，并把记录标成 lost。
func Serve(l net.Listener, v *vault.Vault, h *history.Store) error

// ---- history（app 侧）----
func Open(dir string, onChange func()) (*Store, error)          // 启动时把残留的未结束记录（authorizing、running）都标成 lost；只保留最近 200 条
func (s *Store) Begin(r Run, stop func()) *Record                // 状态为 authorizing；stop 用来通知对应的 CLI 停止
func (r *Record) Authorized()                                    // authorizing → running
func (r *Record) Started(pgid int)
func (r *Record) Write(p []byte) (int, error)                    // 追加脱敏后的输出
func (r *Record) End(status Status, exitCode int)
func (s *Store) List() []Run                                     // 运行中的在前，然后按开始时间倒序
func (s *Store) Output(id string) ([]byte, error)
func (s *Store) Stop(id string) error                            // 看板上的停止按钮；已结束时直接返回

// ---- macauth ----
func ConfirmUser(ctx context.Context, reason string) error       // ctx 取消时调用 LAContext invalidate
```

**信任边界**
- `ipc.Serve`：对端 uid 必须和自己相同。请求必须满足：namespace 存在，argv 非空，cwd 是存在的绝对路径。每个输出帧不超过 64KB。下游的 vault 和 history 可以直接信任这些参数，不再重复校验。CLI 侧信任 app，因为两端是同一用户、同一个二进制。
- `vault` 的 UI 入口：name 必须匹配 `[a-z0-9][a-z0-9._-]{0,63}`，key 必须匹配 `[A-Za-z_][A-Za-z0-9_]*`。vault 内部会再校验一次，因为文件路径是用它们拼出来的。

**CLI 契约**（这是对 agent 的公开接口）
- 用法：`gatelock run <namespace> [--] <command> [args...]`。直接 exec，不经过 shell。
- env：继承调用方的全部环境变量，再叠加 namespace 的 env，同名时 namespace 的值覆盖原值。
- stdin 原样透传；stdout 和 stderr 分开输出，各自脱敏。
- 退出码：子进程的退出码；子进程被信号杀死时为 128+信号值；namespace 不存在、授权被拒、连不上 app，或者运行中和 app 断开连接时为 125，错误信息写到 stderr；命令找不到或无法执行时为 127。
- 停止：agent 发来的 SIGINT/SIGTERM/SIGHUP 会转发给子进程，子进程 5s 内没退出就 SIGKILL。
- app 退出时，正在运行的命令会被停止。所以如果还有命令在运行，退出 app 前会先弹窗确认。
- UI 提供一段可以粘贴到 `CLAUDE.md` / `AGENTS.md` 的说明，命令路径用 `gatelock`；如果 `~/.local/bin` 不在 PATH 里，改用绝对路径。内容包括：用法；参数里要引用凭证变量时，用 `gatelock run ns -- sh -c 'curl -H "Authorization: Bearer $API_KEY" ...'` 的写法。

## Data Model
数据目录：`~/Library/Application Support/Gatelock/`（来自 MyGo 的 `PathUserData`）。目录权限 0700，文件权限 0600。

```
gatelock.sock
namespaces/<nsid>/                  # nsid 随机生成，不随改名变化
  meta.json        {version:1, name, recipient, policy:{mode,ttl}, keychain:bool,
                    envs:[{key, sensitive, updated_at}]}
  identity.age     # hybrid identity，用 scrypt（passphrase）加密，logN=18
  env/<KEY>.age    # 一个 value 一个文件，用 recipient 加密
runs/<runid>/
  meta.json        {version:1, namespace, argv, cwd, pgid, started_at, ended_at, status, exit_code, truncated}
  output.log       # 脱敏后的 stdout+stderr 按顺序交错。超过 4MB 时只留最后 2MB，并把 truncated 设为 true
```
- Keychain 条目：service 是 app identifier，account 是 `nsid`，value 是 passphrase。
- 执行记录只保留最近 200 条，app 启动时清理。
- 状态枚举：`authorizing | running | exited | stopped | denied | failed | lost`。请求通过校验后先登记为 `authorizing`，看板上能看到"等待授权"；授权被拒后改成 `denied`。namespace 不存在这类校验失败不登记。
- **共享可变状态**：
  - vault 的 meta 和解锁缓存：只归 `Vault` 所有，用 mutex 保护。TTL/Session 策略下，同一 namespace 的授权用 singleflight 合并；授权弹窗全局串行。
  - 运行中命令的状态：只归 `history.Store` 所有。
  - UI 只读这两份状态，变更通过 `onChange` 通知后重新拉取。
  - 写 meta 一律先写临时文件再 rename。

**执行流程**（`gatelock run prod-api -- npm run deploy`）
1. CLI 调用 `ipc.Dial`，连不上就拉起 app。然后发送 `RunRequest`，cwd 取 CLI 自己的当前目录。
2. app 的 `Serve` 校验请求，在 history 里登记为 `authorizing`，然后调用 `vault.Resolve(ctx, ns, "运行: npm run deploy")`。连接断开时 ctx 会被取消，弹窗随之关闭。授权被拒时，记录标成 `denied`，CLI 以 125 退出。
3. vault 检查解锁缓存。缓存无效时：
   - 如果开了 Keychain，先 `ConfirmUser`，再从 Keychain 读 passphrase。如果条目不见了，或者里面的 passphrase 解不开私钥（比如改 passphrase 时最后一步没完成），就退回到手动输入；输入正确后，用它覆盖 Keychain 条目。
   - 如果没开 Keychain，调用 `AskPassphrase`。
   - 然后解开 identity，按策略写入缓存（Every 不缓存）。
4. vault 用 identity 解密 `env/*.age`。`Serve` 把记录改成 `running`，然后把 env 发给 CLI。
5. CLI 合并 env，从 `Sensitive` 的 env 生成脱敏列表，调用 `launch.Run`。输出脱敏后打印出来，同时通过 `Session.Record` 同步给 app。
6. 子进程退出后，CLI 上报退出码，然后以同样的退出码退出。看板上点停止时：app 关闭 `Session.Stop()` 对应的 channel，CLI 停掉进程组。CLI 被强制杀掉时：app 发现连接断开，kill 已登记的进程组。app 退出或崩溃时：CLI 发现连接断开，按停止规则停掉进程组，以 125 退出。所以不会出现"命令还在跑，看板上却看不到"的情况。

**脱敏规则**：对每个敏感值生成以下模式，替换成 `[REDACTED:<ns>/<KEY>]`。
- 原值
- base64（std 和 url 两种字母表，各取 3 种对齐偏移下稳定不变的那段）
- hex（大写和小写）
- `url.QueryEscape` 和 `url.PathEscape`
- JSON 转义

原值和对整个值编码后的完整结果（base64 带和不带 padding、hex、URL 编码、JSON 转义）都加入，不论长短。例如 `abc` 对应 `YWJj`、`616263`。base64 在另外两种对齐偏移下的稳定片段，长度 ≥ 8 时才加入，因为片段太短误伤太多。只有标记为敏感的 env 参与脱敏；不敏感的 env 是用户声明的"非秘密"，可以出现在输出和执行记录里。匹配取最左、最长。实现先用简单的逐模式扫描，性能不够再换 Aho-Corasick，接口不变。

## Load-Bearing Decisions
- **磁盘格式**：每个 env 一个 age 文件；identity 用 scrypt 加密；`meta.json` 带 `version`。以后改格式需要写迁移逻辑。
- **CLI 契约**：`gatelock run <ns> -- argv`、env 的覆盖规则、退出码约定。这是 agent 侧的说明和用户脚本依赖的接口。IPC 协议两端一起升级，不算在内。
- **子进程由 CLI 启动**：app 只负责授权和记录。看板上的停止要经过 CLI，CLI 不在了才由 app 兜底 kill。
- **解锁缓存的是 identity**："授权"的定义就是"手里有 identity"，三种策略都只是这份缓存的有效期不同。

## Risks / Open Questions
- **agent 在参数里直接写 `$API_KEY`**：agent 的 shell 会在 Gatelock 注入 env 之前展开变量，得到空值。这个问题靠 UI 提供的说明里写清楚 `sh -c` 的用法来避免。路线图第 1 步顺便看看 agent 实际会怎么写。
- **agent 停止后台命令的方式**：要确认 Claude Code 停止后台命令时，发给 `gatelock` 的是可以转发的信号，还是 SIGKILL。前者走停止规则，后者靠 app 兜底 kill，两种情况都能停掉子进程。路线图第 1 步实测具体走的是哪条路径。
- **PATH**：agent 的 PATH 里不一定有 `~/.local/bin`。安装命令行工具后，UI 用 `$SHELL -lic` 读一次登录 shell 的 PATH 来检查；没有的话，提示要加到 rc 文件里的那一行，并让给 agent 的说明片段改用绝对路径。
- **开发期的 Keychain 弹窗**：没签名的构建每次重新编译，读 Keychain 都会弹"允许访问"。开发时用自签证书签名，或者先接受这个弹窗。用 `mygo dev` 运行时没有 .app，CLI 拉不起 app，要先手动启动；socket 路径可以用环境变量 `GATELOCK_SOCKET` 覆盖。
- **MyGo 版本差异**：mux 用的是 v0.6.3，最新是 v0.7.1，`ui.Theme` 的字段可能有变化，做 UI 那一步时确认。另外 MyGo 还没到 1.0，所以核心包都不依赖 mygo。
- **脱敏的已知缺口**：变换过的输出（反转、分段打印、其他编码）匹配不到，符合"防意外泄露"的定位。
- **短值误伤**：很短的敏感值（如 `abc`）也照常脱敏，正常输出里出现同样的内容也会被遮住。值短于 4 字节时 UI 会提示，用户可以改成"不敏感"。
- **暂存带来的延迟**：输出末尾如果恰好像某个密钥的开头，这几个字节要等后续数据到来或命令结束才会出现。只影响很少的字节，可以接受。
- **非 TTY**：子进程的输出接的是管道，部分工具会关掉颜色和进度条。可以接受。
- **兜底 kill**：app 发现连接断开后 kill 进程组，进程组 id 理论上可能已被复用，概率很低，可以接受。app 和 CLI 同时被强制杀掉时，子进程会成为孤儿进程，也可以接受。

## Implementation Roadmap
- [x] [risk validation] 最小可用的 `gatelock run`：和 MyGo app 用同一个二进制，env 先写死，加上最简的 ipc 和 launch
      Purpose：验证同一个二进制按子命令分流、通过软链接调用的 CLI 能拉起 app、Claude Code 前台和后台运行、Claude Code 停止后台命令时收到的信号、退出码和 stdin 透传，并观察 agent 怎么写引用变量的命令
      Verification：在 Claude Code 里分别执行前台命令、后台的 `sleep` 循环再停止、`echo x | gatelock run ns -- cat`，以及 `exit 3`，检查行为和退出码
- [x] [core logic] `redact`：生成模式、精确前缀暂存、跨 Write 匹配、Close 时遮盖、并发写
      Purpose：这是核心能力，可以单独测试
      Verification：单测覆盖密钥被切在两次 Write 之间（中间停顿很久也不漏）、各种编码、重叠的密钥、短值的原值和完整编码（如 `abc` → `YWJj`、`616263`）都被脱敏、Close 时暂存的前缀被遮盖
- [x] [core logic] `vault`：存储格式、加解密、策略缓存、singleflight、Keychain 开关切换、改 passphrase（Authorizer 和 Keychain 用 fake）
      Purpose：把存储和授权的行为固定下来
      Verification：单测覆盖三种策略（包括 Every 下并发请求各自授权、TTL 下并发请求只授权一次）、passphrase 错误后重试、Keychain 条目缺失或 passphrase 过期时退回手动输入并修复条目、改 passphrase 时 Keychain 写入失败返回 ErrKeychainStale 且之后能恢复、改名后数据不丢；磁盘上 grep 不到任何敏感值的明文
- [x] [platform] `macauth.ConfirmUser`（从 spike 改过来）+ 基于 `mygo.Secrets` 的 Keychain 实现
      Purpose：接上真实的系统能力
      Verification：手动测试 Touch ID 通过和取消、Keychain 读写删
- [x] [core logic] `launch`：进程组、信号转发、stop、退出码、stdout/stderr 分开脱敏、Record 写慢时不阻塞
      Purpose：保证 CLI 的行为符合契约
      Verification：单测覆盖退出码（正常、被信号杀、命令找不到）、stop 能杀掉子进程树、SIGTERM 转发、忽略 SIGTERM 的子进程在 5s 后被 SIGKILL（agent 发信号和 stop 两条路径都测）、第二次信号立即 SIGKILL、Record 阻塞时子进程照常运行
- [x] [integration] 完整的 `ipc` 和 `history`：请求校验、授权、登记、输出同步、看板停止、连接异常断开时兜底 kill、denied 记录、输出 4MB 截断、200 条清理
      Purpose：把 CLI 和 app 完整连起来
      Verification：在临时目录里起真实的 socket，配合 fake Authorizer 写集成测试，跑通以下场景
        - 正常执行
        - 授权中状态为 authorizing，被拒后为 denied
        - namespace 不存在时不登记
        - 看板停止
        - kill -9 掉 CLI 后，子进程被清理
        - 运行中关掉 app server 后，CLI 停掉子进程并以 125 退出，重启后记录为 lost
        - 授权中关掉 app server 后，CLI 以 125 退出，重启后记录为 lost，不会一直显示"等待授权"
- [x] [ui] MyGo native UI：Vellum 主题、namespace/env 管理（导入 .env 后列出导入的 key，确认后删除原文件；查看值时要授权；敏感开关）、namespace 设置（策略、Keychain、改 passphrase、上锁、删除）、passphrase 弹窗、执行看板、tray（运行中的数量 / 全部上锁 / 退出）、"安装命令行工具"（在 `~/.local/bin` 创建 `gatelock` 软链接，并检查登录 shell 的 PATH）、给 agent 用的说明片段，以及有命令在运行时退出前弹窗确认
      Purpose：满足需求里的管理和看板场景
      Verification：按需求文档的 Scenarios 逐条手动走一遍
- [x] [e2e] 对照需求文档的 Success Criteria 逐条验收

## Deviations from Design
- 实现顺序：先写了各个核心包，最后才用真实二进制验证路线图第 1 步。第 1 步要验证的点都已实测通过。实测发现：Claude Code 停止后台任务时，先发 SIGTERM（gatelock 会转发给子进程），随后强杀整棵进程树，所以这条记录显示为 `lost`，子进程也已停止。
- env 文件名改成 `env/<hex(KEY)>.age`：macOS 默认文件系统不区分大小写，`TOKEN` 和 `token` 会落到同一个文件。
- vault 合并并发授权时没有用 singleflight，而是先查一次缓存，拿到授权锁后再查一次。Every 策略不写缓存，所以天然每个请求单独授权。这套机制同时实现了"授权弹窗全局排队"。
- history：`Begin(namespace, argv, cwd, stop)` 直接返回 Record；状态变化拆成 `Authorized()`、`Exited(code)` 和 `End(status)` 三个方法。`Exited` 根据看板是否要求过停止，自己判断记为 stopped 还是 exited。另外加了 `Running()`，供 tray 和退出确认使用。
- ipc：`Dial(socketPath, start)` 的 `start` 由 cmd 传入，负责拉起 app；`Run` 改为普通函数；`Session` 本身实现 `io.Writer`，用来同步输出，并且保证不阻塞；新增 `Session.Failed`，用于上报"命令启动失败"。原先写在 launch 里的"Record 不阻塞"测试，移到了 ipc。
- 数据目录和 socket 统一用 `GATELOCK_HOME` 覆盖，取代原来的 `GATELOCK_SOCKET`。
- CLI 用 `open -g <app> --args --background` 拉起 app，所以由 CLI 拉起时不打开主窗口。app 平时处于 Accessory 模式（不显示 Dock 图标），主窗口打开期间切换为 Regular。
- 窗口风格参考 Mux：隐藏标题栏，红绿灯放在侧边栏上，页面顶部是一行紧凑的标题。只有标题部分可以拖动窗口，操作按钮放在拖动区域之外，否则点击会被拖动区域吞掉（实测过）。
- 看板的执行记录做成手风琴：每条记录是一节，点开后输出显示在这条记录下面，可以同时展开多条，只读取展开中的记录的输出。输出区最高 280，超过就在框里滚动，并跟随最新输出，用户往上翻时停止跟随。停止按钮在每节的标题行上，不用展开就能点。状态用 Mux 那样的圆点表示：运行中呼吸，等待授权时向外扩散，结束后不动；绿色是退出码 0，红色是非 0 或启动失败，灰色是被停止、拒绝或丢失，运行中和等待授权都是琥珀色，靠动画区分（主题色太接近红色，圆点小的时候分不出来）。文字只补充圆点表达不了的：非 0 的退出码（`exit 1`），或 waiting、stopped、denied、failed、lost。退出码 0 和运行中不写字。圆点的 tooltip 是完整说明。输出框用页面底色加边框，和 hover 的标题行区分开。
- 设置对话框里，TTL 下拉框放到了单独一行，避免超出对话框宽度。
- `cmd/gatelock/main_test.go` 用 MyGo 的 Tester 在内存里渲染界面，覆盖亮色和暗色下的各个页面、添加 env、在看板上停止命令。
- 授权完成前在看板上点停止（按钮此时显示为 Cancel）：关掉授权弹窗，记录标为 `stopped`，CLI 以 125 退出，并提示 "stopped in Gatelock before it was authorized"。授权完成后点停止，仍然走原来的流程，由 CLI 停止子进程。
- 开关 Keychain 时，以 meta 为准：打开时先写 Keychain 条目，再保存 meta，保存失败就删掉刚写的条目；关闭时先保存 meta，再删除条目，删除失败就把 meta 改回原值。任何 `update` 保存失败，内存里的 meta 都会回滚。开关 Keychain（两个方向）、删除 namespace，都和解锁共用授权锁，并且从头持有到结束。这样，停在确认窗口里的解锁请求，就不会在用户关掉 Keychain 或删掉 namespace 之后，又把 passphrase 写回 Keychain。为此 `Delete` 改为 `Delete(ctx, name)`；UI 在后台调用它，因为 passphrase 弹窗要靠主线程绘制，主线程不能等这把锁。
- 控件尺寸：主题 Spacing 设为 3（MyGo 的紧凑模式），所有控件统一高约 26：输入框、次要按钮、下拉框、分段控件本来就是这个高度；主按钮没有边框，所以上下内边距各加 1pt 补齐（`primaryButton`）；图标按钮是 26×26；switch 固定为 32×18；侧边栏每一项高 32。新增 env 不再用对话框，而是在列表末尾插入一行可编辑的行：值是一个会随内容长高的多行输入框（1 到 6 行），Enter 确认，Shift+Enter 换行，Esc 取消；输入时值以明文显示（TextArea 没有密码模式）。编辑也在行内进行，用同一个表单行：key 不可改，值已展开时预先填入原值，Mask 开关随保存一起生效。设置和新建 namespace 的对话框按 macOS 系统设置的样式分组；删除 namespace 放在侧边栏，鼠标悬停时出现。
- 侧边栏可以收起，参考 Mux：红绿灯右侧有一个固定位置的切换按钮，Cmd+B 也能切换；侧边栏带动画向左滑出，页面标题随之右移，给红绿灯和按钮留出位置。收起状态不保存，app 重启后恢复展开。
- 托盘的 Lock All、每个 namespace 的 Lock Now、修改策略，都会清空界面上已显示的值；还在进行中的查看请求返回后，也不会再把值显示出来。
- MVP 之后加了复制和导出（需求文档已同步）。复制：值显示出来后，每行多一个复制按钮；一分钟后，如果剪贴板里还是这个值，就清空。导出：namespace 页顶部的导出按钮，先选保存位置（默认文件名 `.env.<ns>`），再走一次 `Resolve` 授权，然后写文件。文件权限是 0600，覆盖已有文件时也会改成 0600。编码用自己写的 `vault.Dotenv`：每个值都加双引号，转义 `\`、`"`、`$` 和换行。没用 `godotenv.Marshal`，因为它会把 `0123` 写成 `123`。导出的文件是明文，这是用户主动要的，不受"磁盘上没有明文"的限制。

## Acceptance (2026-10-27)
在真实 app 上（`GATELOCK_HOME=/tmp/gl-dev`）用模拟点击走完了需求文档的 Success Criteria：
- 磁盘上 grep 不到任何敏感值的明文；导入 `.env` 后，确认删除原文件
- 前台执行：注入的 env、原值和 base64、hex 的脱敏、stdout 和 stderr 分开输出、退出码（命令自己的、125、127）、stdin 透传
- 授权策略：Every 每次都问（手动输入 passphrase，输错后会提示重试，取消后 CLI 以 125 退出）；TTL 时效内不再询问；Session 在 app 重启后失效
- 后台执行：Claude Code 停止后台任务后，忽略 SIGTERM 的子进程也被停止；看板上的停止按钮能用（记为 stopped，CLI 以 143 退出）
- 有命令运行时退出 app 会弹窗确认；确认后命令被停止，记录为 stopped
- Keychain 开关：关闭方向在 UI 上实测过；打开方向只有单测覆盖
- 用打包后的 `.app` 实测：CLI 能在后台拉起 app，且不会打开主窗口
- 复制和导出（`GATELOCK_HOME=/tmp/gl-e2e`）：复制后 `pbpaste` 拿到的是原值；导出时，macOS 会对点开头的文件名再确认一次，确认后得到 `.env.e2e`，权限 0600，`PIN="0042"`，DSN 里的 `$` 和 `"` 都已转义
