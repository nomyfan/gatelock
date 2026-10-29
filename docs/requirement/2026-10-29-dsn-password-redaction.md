# DSN 只对密码脱敏

## Problem
现在标记为敏感的 env 会整串脱敏。`DATABASE_URL=postgres://app:s3cret@db.internal:5432/orders` 这类连接串在输出里整个变成 `[REDACTED:prod-api/DATABASE_URL]`，用户和 agent 都看不出命令连的是哪台主机、哪个端口、哪个库、用的哪个用户，排查连接问题很不方便。可是连接串里真正的秘密只有密码。

## Scenarios
- agent 执行 `gatelock run prod-api -- npm run migrate`，迁移工具打印 `connecting to postgres://app:s3cret@db.internal:5432/orders`。输出里显示为 `postgres://app:[REDACTED:prod-api/DATABASE_URL]@db.internal:5432/orders`，agent 能看出连错了库。
- JDBC 连接串 `jdbc:postgresql://db.internal/orders?user=app&password=s3cret` 出现在 Java 程序的日志里，只有 `password` 的值被替换。
- 本地开发的 `postgres://postgres:postgres@localhost/postgres` 显示为 `postgres://postgres:[REDACTED:dev/DATABASE_URL]@localhost/postgres`，scheme、用户名、库名不受影响。
- 一个敏感 env 的值是 Slack webhook 这种 URL，里面没有密码，就跟现在一样整串脱敏。

## Scope
In:
- 自动识别敏感 env 中的两种 DSN：URL 的 userinfo（`scheme://user:pass@host...`）和 URL query 里的密码参数（如 `password=`、`pwd=`，具体参数名在设计阶段确定）。两处都有密码时都替换。scheme 不限具体协议，只要符合 URL 的 scheme 规则（字母开头，后面可以跟字母、数字和 `+`、`-`、`.`），比如 SQLAlchemy 的 `postgresql+asyncpg://`、`mysql+pymysql://`
- 匹配方式和现在一样：整个值（或它的某种编码形式）出现在输出里才匹配。区别只在替换：识别出密码的 env，匹配到以后只把其中的密码换成标签，其余部分原样显示
- 原值、URL 转义、JSON 转义这几种形式只替换密码；base64、hex 形式看不出结构，仍然整串替换
- 识别不出密码的 env（不是 DSN，或者 DSN 里没有密码）保持整串脱敏
- 标签不变，仍然是 `[REDACTED:<vault>/<KEY>]`

Out:
- 密码单独出现、或者只出现 DSN 的一部分（如 `app:s3cret@db.internal`）时的脱敏：现在整串匹配也覆盖不到，这次保持现状，以后需要时单独作为需求
- key=value 格式（libpq 的 `password=...`、ADO.NET/ODBC 的 `Password=...;`）和 Go MySQL driver 的 `user:pass@tcp(host)/db`：这次不做
- 按 env 单独开关：全部自动识别，不加选项，也不改 UI
- query 里除密码以外的凭证类参数（`token=`、`api_key=` 等）：识别出密码后，这些参数照常显示

## Constraints
- 改动限于 `internal/redact`，vault 磁盘格式、IPC 协议、CLI contract 都不变
- 不能降低现有保护：现在能匹配到的地方，以后照样匹配，并且密码一定被遮住，包括跨 write 的匹配

## Success Criteria
- 上面几个场景的输出与描述一致：host、port、user、库名、其他 query 参数照常显示，只有密码被替换
- `postgresql+asyncpg://app:s3cret@db.internal/orders` 这种带 `+` 的 scheme 同样只替换密码
- 密码在 DSN 里是 percent-encoded 的（如 `p%40ss`）时，替换的是 DSN 里原样写的那一段
- 整个 DSN 以 URL 转义、JSON 转义形式出现时只替换密码；以 base64 或 hex 形式出现时整串替换
- 非 DSN 的敏感 env、没有密码的 URL，脱敏行为和现在完全一样
- 现有 `internal/redact` 测试全部通过，并新增覆盖上述情况的测试
