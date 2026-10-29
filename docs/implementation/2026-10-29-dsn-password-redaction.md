# DSN 只对密码脱敏：设计

## Problem
敏感 env 是连接串时，输出里匹配到整个值后只替换其中的密码，host、port、user、库名照常显示，方便排查连接问题。需求见 `../requirement/2026-10-29-dsn-password-redaction.md`。

## Scope
In：`internal/redact` 在 `NewWriter` 里识别 DSN、找出密码在值里的位置，并据此生成匹配规则的替换内容；对应的测试；AGENTS.md 中 `internal/redact` 一节。
Out：`redact.Secret`、`cli.go`、vault、IPC、UI 都不改；密码单独出现时的脱敏、key=value 格式、Go MySQL driver 格式、密码以外的凭证类 query 参数（见需求文档）。

## Assumptions
- 只看 env 的整个值：值本身就是一个 DSN 才识别。值前后有空白、DSN 嵌在更长的文本里（比如一段 JSON 配置），都按非 DSN 处理，整串脱敏。
- 识别失败的代价只是退回整串脱敏，不会少遮。所以解析可以保守，拿不准就当作没找到密码。
- 不需要知道具体协议：scheme 合法就行，不维护协议白名单。
- 不需要解码密码：匹配的是整个值原样写的文本，替换时只要知道密码在这段文本里的起止位置。

## Validation Findings
- 问题：能不能直接用 `net/url` 找密码？方法：`.scratchpad/dsn-parse/` 跑了 15 种常见写法。结果：
  - `postgresql+asyncpg://`、`redis://:pw@`、IPv6 host、mongodb 多 host 都能取到密码。
  - `jdbc:mysql://u:p@h/db` 被当成 opaque URL，取不到 userinfo。
  - 密码里有未转义的 `/`、`?`、`#` 或者坏的 `%` 转义时，直接报错。
  - `net/url` 只给出解码后的密码，不给出它在原文里的位置。
- 结论：自己写一个小解析器，直接返回位置。见下面的 Alternatives。

## Alternatives Considered
- **用 `net/url.Parse` 取密码，再回原文里找位置**：`net/url` 只返回解码后的值，要在原文里找回位置，得先把它重新编码，而重新编码的写法未必和用户写的一样（比如用户把 `~` 写成 `%7E`）。另外，同一段文本可能出现好几次（比如 `postgres://postgres:postgres@...`），找到的不一定是密码那一处。自己写的解析器大约 40 行，扫描时就能记下位置，这两个问题都不存在，`jdbc:mysql://` 这种多段 scheme 也能处理。
- **生成"密码"这个字符串本身的匹配规则**（最初的方案）：密码单独出现时也能抓到。缺点是短密码或常见密码（`postgres`、`guest`）会把输出里所有相同的字符串都替换掉，包括 scheme、库名和普通日志。另外，它比现在的整串匹配多做了一层保护，超出了这次需求的范围。用户确认这次只做整串匹配，见需求文档的 Out。

## Components
- `redact.NewWriter`（已有）：对每个 `Secret`，先找出它的值里密码的位置，再为每种编码形式生成匹配内容和对应的替换内容。
- `passwordSpans`（新增，`internal/redact/dsn.go`）：找出一个值里 DSN 密码的位置。

## Interfaces
```go
// passwordSpans returns where the passwords sit in v, as [start, end)
// byte offsets in order, if v is a URL-style DSN: the password in its
// userinfo and the values of password query parameters. It returns nil if
// v is not a DSN or holds no non-empty password; v is then masked whole.
func passwordSpans(v string) [][2]int
```
对外接口不变：`NewWriter(dst, []Secret)`。调用方不需要知道有 DSN 这回事。

识别规则：
- **DSN**：值以 `scheme:` 开头，可以有多段，比如 `jdbc:postgresql:`；每段 scheme 字母开头，后面可以跟字母、数字和 `+`、`-`、`.`。最后一段后面必须紧跟 `//`。
- **authority**：`//` 之后，到第一个 `/`、`?` 或 `#` 为止。
- **userinfo 里的密码**：authority 中最后一个 `@` 之前是 userinfo，userinfo 中第一个 `:` 之后是密码。
- **query 里的密码**：`?` 之后、`#` 之前，按 `&` 拆分。参数名不区分大小写，等于下面某一个时才当作密码：`password`、`pwd`、`pass`、`passwd`、`sslpassword`、`trustStorePassword`、`keyStorePassword`。只认明确列出的名字，不用"以 password 结尾"这类通用规则，否则 `?showPassword=false&token=secret` 这种没有密码的 URL 会只遮住 `false`，把 `token` 露出来。参数名按原样比较，不做解码。
- **空密码**：不算，比如 `app:@host`、`password=&`。
- **先确认整个值可信，再给出任何位置**：
  - 值里有空白或控制字符，就返回 nil，整串脱敏。
  - userinfo 的密码按三种常见解析器的规则各算一次，三者结果一致才使用，否则返回 nil，整串脱敏。三种规则是：
    - **RFC 3986**（Go `net/url`、Python `urlsplit`、WHATWG URL）：取第一个 `/`、`?` 或 `#` 之前的最后一个 `@`。
    - **libpq**：取第一个 `/` 之前的第一个 `@`。
    - **SQLAlchemy**：取第一个 `@`，不管前面有没有分隔符，而且用户名里不能有 `/`。

    三者的结果只在密码里含有未转义的 `@`、`/`、`?` 或 `#` 时才会不同。比如 `postgres://app:pa/ss@db/x?password=other`，RFC 认为没有 userinfo 密码，SQLAlchemy 却认为密码是 `pa/ss`。这时如果只遮 query 里的 `other`，`pa/ss` 就会露出来。三者一致时，密码里不含这几个字符，authority 的边界也就是准的，query 可以照常解析，`?options=a@b` 这种合法的 `@` 不受影响。
  - 代价：`postgres://db:5432?user=a@corp&password=p` 这种没有路径、query 里又有 `@` 的值，libpq 会把 `5432?user=a` 当成密码，三者不一致，于是整串脱敏。

## Load-Bearing Decisions
- **一个带密码的 DSN 怎么生成规则**：
  - 匹配内容和现在一样，仍然是整个值的各种形式。替换内容按形式分两类：
    - 原值、URL 转义（Query 和 Path）、JSON 转义：按密码位置把值切成几段，每段各自编码；密码段换成标签，其余段保留编码后的样子。这几种编码都是逐字节或逐字符转换的，而切分点前后都是 ASCII 字符（`:`、`@`、`=`、`&` 或值的末尾），所以各段编码后拼起来，正好等于整个值的编码，替换后的文本和输出里原来的样子对得上。
    - base64（4 种整串编码和 fragment）、hex：整串替换成标签，和现在一样。
  - 实现上，`forms` 返回的每种形式要带上它的替换内容。非 DSN 的值，替换内容都是标签，行为和现在完全一样。
  - 只有完整匹配时，才用"只替换密码"的替换内容。`Close` 收尾时，如果末尾是某条规则没凑齐的前缀（比如命令只输出了 `postgres://app:s3` 就结束），仍然整体换成标签，和现在一样。否则替换内容里的 host、库名会被补出来，而这些命令根本没有输出过。所以每条规则要同时带两种替换内容：完整匹配用的，和收尾时前缀用的标签。
  - 代价：hex 也是逐字节的，本来可以只替换密码，但 hex 文本本来就不可读，部分保留没有意义，所以和 base64 一样整串替换。
- **扩展点是 `passwordSpans`**：识别规则只作用在 env 的值上，每个值在 `NewWriter` 里跑一次，结果只有密码的位置。以后加格式（libpq 的 key=value、ADO.NET、Go MySQL driver）或者加 query 参数名，只改 `dsn.go`：新格式写一个返回位置的识别函数，在 `passwordSpans` 里依次尝试。生成编码形式、替换内容和流式匹配都不用动。前提是密码段的边界落在 ASCII 字符上，这几种格式都满足。现在只有一种格式，先不做规则列表，加第二种时再改。
- **标签不变**：每个密码段都换成 `[REDACTED:<vault>/<KEY>]`，与现有 CLI 输出保持一致。

## Risks / Open Questions
- **风险最大的地方**：解析器把不是密码的一段当成密码，真正的密码反而露出来。比如 query 里的密码含有未转义的 `&`，按 `&` 拆分后只能取到前半段，后半段会显示出来。不过驱动解析 URL 时也是这么拆的，所以这种情况下实际生效的密码就是前半段。测试里要覆盖未转义字符和坏的转义，确认结果要么是正确的位置，要么退回整串脱敏。
- **JSON 转义的切分**：JSON 编码按 rune 转换，值不是合法 UTF-8 时，坏字节会变成 `\ufffd`。因为切分点都在 ASCII 字符上，不会切开一个多字节字符，所以分段编码的结果和整体编码一致。要用测试确认，包括 `SetEscapeHTML(true)` 时 `&` 变成 `\u0026` 的情况。
- **三种解析器都读错的写法**：比如 `postgres://app:p@ss/w@db/x`，三种解析器都认为密码是 `p`、host 是 `ss`，所以只遮住 `p`，`ss/w` 会显示出来。按任何一个驱动的解析，这个连接串的密码都只是 `p`，实际上连不上数据库，用户会发现并改正。这种情况接受现状，测试里固定了这个行为。
- 参数名列表以后可能要扩充（比如 `secret`）。改动只在 `dsn.go` 里，代价很小。

## Implementation Roadmap
- [x] [risk validation] 实现 `passwordSpans`，并写表格测试
      Purpose：先确认解析规则在各种写法下要么返回正确的位置，要么返回 nil
      Verification：表格覆盖需求里的各个场景，以及 `postgresql+asyncpg://`、`jdbc:mysql://u:p@h`、`redis://:pw@`、IPv6、mongodb 多 host、`p%40ss`、未转义的 `@`、`/`、`?`、`#`、坏的 `%` 转义、空密码、query 里的 `sslpassword`、`?showPassword=false&token=secret`（不算密码，返回 nil）、userinfo 和 query 都有密码、Slack webhook、普通 token
- [x] [core logic] 让 `forms` 返回每种形式的替换内容，改 `NewWriter`
      Purpose：让需求里的输出行为成立
      Verification：新测试覆盖以下情况，现有测试全部通过
      - 场景输出：DSN 原样、`postgres://postgres:postgres@...`、`%7E` 这类不常见转义
      - DSN 的 URL 转义、JSON 转义形式（含 `&` 变成 `\u0026` 的情况）只替换密码；base64、hex 形式整串替换
      - 跨 write 的匹配
      - 输出只到 DSN 的一部分就结束（`postgres://app:s3`）时，`Close` 输出的是标签，不会补出 DSN 的其余部分
      - 非 DSN 的值和没有密码的 URL，输出与现在一致
- [x] [docs] 更新 AGENTS.md 的 `internal/redact` 一节
      Purpose：保持文档与实现一致
      Verification：文档里写明 DSN 匹配整串后只替换密码，以及 base64、hex 形式仍然整串替换
