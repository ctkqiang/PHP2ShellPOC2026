# PHP2ShellPOC2026

[English](README.md) | 简体中文

面向 **PHP2Shell** 漏洞类别（CVE-2026-109618 与 CVE-2026-109619）的暴露面排查工具，
并附带一个仅限授权的实验环境 POC。最重要的答案是操作者需要的决策：

**该主机能否被 PHP2Shell 入侵：是、否或未知**

随后给出证据、限制条件以及下一步操作。把工具指向一个 Web 端点，它会在一份报告中回答四个问题：

1. **实际响应的是什么？** PHP 版本、SAPI、边缘、CDN、WAF、框架。
2. **解释器是否暴露？** 低于分支修复下限、已停止维护、已修复，或确实未验证。
3. **部署形态如何改变结论？** 暴露严重度与利用阻力分开报告。
4. **下一步做什么？** ATT&CK 映射、检测建议、修复建议和可复制的后续操作。

扫描器只发送普通 `GET` 请求。交互式文本扫描发现暴露主机后，只问一个问题：
是否运行授权实验 POC；只有明确回答 `y` 才会开始 POST/multipart 利用流程。
POC 没有命令行开关。

> **仅限授权使用。** 这是排查工具，不是授权书。指向任何目标前，请先确认项目范围、
> 交战规则和速率限制。`--scope` 与 `--require-scope` 让这条边界可执行，而不是装饰。
> POC 针对 bookworm PHP 8.4.26 实验构建校准，可能中断目标服务，且永远不能替代书面授权。
> 参见 [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md)。

---

## 为什么有 3.0

2.x 有一个危险的失败模式：对每个请求都返回 `403` 的主机，会被报告为
**不可被入侵**，证据比率为 `0.00`。`403` 不是这个意思。它意味着扫描器看不到应用。
当时把“没有证据”当成了“没有漏洞的证据”。

3.0 改变了工具提出的问题：

- 根路径之外会请求一个随机 **探针路径（canary）**。如果探针也被拒绝，结果是
  `BLOCKED` / `INCONCLUSIVE`，而不是“安全”。
- 全捕获路由会被识别为 **软 404**；路径状态码不再被信任。
- 登录重定向是 **认证墙**，不是已修复的解释器。
- `429` 是 **限速**，不是不存在。
- 版本证据与 **访问证据** 分离。泄露 `X-Powered-By` 的 `403` 页面仍会报告版本，
  但置信度低，并带有明确限制说明。
- **暴露严重度**（存在漏洞的解释器为 `9.8`）与 **利用阻力**（WAF、CDN、FPM
  工作进程亲和性、认证墙）分开。WAF 不会让未打补丁的解析器变成已打补丁。
- 当没有任何正向或负向证据时，证据比率为 `null`，而不是 `0.00`。
- 报告支持 text、JSON、Markdown、SARIF、CSV 和 NDJSON。
- 攻击性工具建议由 `--authorized` 控制。
- `--dry-run` 打印完整请求计划，不打开 socket。
- `--scope` / `--require-scope` 失败关闭，退出码 `4`。

---

## 安装

### RubyGems

```sh
gem install php2shell_poc2026
php2shell --version
```

### 从源码检出安装

```sh
git clone https://github.com/ctkqiang/PHP2ShellPOC2026.git
cd PHP2ShellPOC2026
./install.sh            # 系统 gem
./install.sh --user     # 用户 gem 目录
```

该 gem **没有运行时依赖**。只需要 Ruby `>= 2.7` 和 RubyGems。
POC 只使用 Ruby 标准库；不需要 Python 运行时，也没有外部利用脚本。

### Docker

```sh
docker build -t php2shell-poc2026 .
docker run --rm php2shell-poc2026 --version
docker run --rm php2shell-poc2026 --dry-run https://example.com/
```

镜像以非特权用户运行，只需要出站 HTTP(S)。

---

## 快速开始

```sh
# 被动：根路径 + 一个文本探针，不探测 .php
php2shell --profile passive https://example.com/

# 标准：根路径、文本/PHP 探针、/index.php；检测到框架时才探测框架路径
php2shell https://example.com/

# 深度：常见 PHP 路径、框架路径、robots.txt 和 sitemap.xml 发现
php2shell -d https://example.com/

# 深度 + 专家附录：技术细节、攻击者笔记和工具
php2shell -d -r -c -v https://example.com/

# 机器可读报告
php2shell --json https://example.com/ > report.json

# 先预演；不打开 socket
php2shell --dry-run --profile deep https://example.com/

# 中文文本报告；省略语言参数时跟随设备语言
php2shell --lang zh https://example.com/
php2shell -zh https://example.com/     # 同上，更短
php2shell -en https://example.com/     # 强制英文
```

默认文本报告刻意保持简短。结论行回答扫描器存在的意义——
*该主机能否被 PHP2Shell 入侵？*——以 `YES` / `UNKNOWN` / `NO` 给出，
并附上下一步操作。随后是带 `HACKABLE?` 列的发现表，以及每台主机的：
`DECISION` 决策卡、`WHAT THIS MEANS` 说明卡（结果、原因、置信度、证据、
PHP 版本和修复方式），以及最有用的两步操作。`-v` 增加技术细节、已检查页面、
攻击路径、防御检查、全部后续操作、完整修复列表和请求跟踪。`-c` 增加工具，
`--toolchain-full` 增加理由和低优先级条目，`-r` 增加攻击者笔记，
`--quiet` 只保留结论、发现表和运行摘要。

只有 stdout 是终端时才使用颜色；重定向输出、`--output`、`NO_COLOR` 和
`--no-color` 保持纯文本。

文本报告跟随设备语言：系统 locale 为 `zh*`（例如 `zh_CN.UTF-8` 或 macOS
`zh-Hans-CN`）时使用简体中文，否则使用英文。`--lang en`、`--lang zh`、`-en`
和 `-zh` 可覆盖检测结果，`PHP2SHELL_LANG` 也能在不加参数的情况下覆盖。
解析顺序为：语言参数、`PHP2SHELL_LANG`、`LC_ALL`、`LC_MESSAGES`、`LANGUAGE`、
`LANG`，最后是 macOS 用户 locale；不支持的语言回退到英文。宽度、换行和表格对齐
按 CJK 字符占两列计算，结束标点不会出现在行首。POC 的提示、警告、进度和结果
也跟随同一语言。机器格式（`json`、`markdown`、`sarif`、`csv`、`ndjson`）
始终保留英文消息以保持契约稳定，并且永远不会运行 POC。

---

## 工作原理

### 1. 范围和目标规范化

每个目标只解析一次，生成 `Target` 对象。裸主机名会变成 `https://…/`；
IDN 会转换为 Punycode 用于网络请求；IPv6 字面量会加方括号；URL 中的凭据会被拒绝
（请使用 `--basic-auth` 或 `--bearer`）。范围在打开第一个 socket **之前**检查。

### 2. 根路径 + 控制探针

扫描器先请求根路径，再请求一到两个随机探针路径，例如
`/php2shell-<8hex>.txt` 和 `/php2shell-<8hex>.php`。探针是方法上的关键变化：

| 根路径 | 探针 | 分类 |
|---|---|---|
| `403` | `403` | **拦截**——边缘拒绝了扫描器 |
| `403` | `404` | **受限**——路径级访问控制 |
| `200` | `200`，正文相同 | **软 404**——全捕获路由 |
| `302` 到登录页 | 任意 | **认证墙** |
| `429` | 任意 | **限速** |
| `5xx` | 任意 | **服务器错误** |
| error | error | **无法连接** |
| `200` | `404` | **开放**——路径状态码可用 |

对拦截、认证墙、限速、软 404、服务器错误和无法连接的结果，自适应模式在控制探针后停止。
当你确有理由时，`--no-adaptive` 强制完整探测。

### 2b. 拦截页面指纹

拒绝页面仍然是关于边缘的证据。扫描器能识别常见拦截页面——OVHcloud、Cloudflare、
Akamai、Sucuri、Imperva、AWS WAF、F5、Wordfence 和 ModSecurity——并报告厂商
以及页面显示的消息。如果拦截很可能与 User-Agent 有关，报告会说明，并提供显式重试：

```sh
php2shell --browser-ua https://example.com/
```

`--browser-ua` 永远不会自动启用。它发送浏览器兼容的 `User-Agent`，可能跨越机器人
控制边界，因此报告会标注该模式，操作者必须确认授权。默认仍使用可识别的
`php2shell-poc2026` User-Agent。

### 3. 版本证据

版本按以下顺序读取：

- `X-Powered-By`、`Server` 以及任何包含 `PHP/<version>` 的响应头。
- `phpinfo()` 页面，包括 `<title>phpinfo()</title>` 和 `PHP Version`。
- 框架元数据（WordPress/Drupal/Joomla）只记录为 **框架** 版本上下文，
  绝不当作 PHP 补丁级别。

仅分支级的值（例如 `8.2`）会报告为 `UNVERIFIED` / `branch_only`，
不会悄悄升级为补丁级结论。已停止维护分支（例如 `8.1`、`8.0`、`7.4`）上的
分支级值已经属于 `END-OF-LIFE`，因为该分支上不存在包含修复的补丁级别。
在拦截或错误响应中观察到的版本会以低置信度报告，并附带限制说明。

### 3b. 为什么主机可能是 `UNKNOWN`

大多数现代站点隐藏 `X-Powered-By`，不暴露 PHP 补丁级别。扫描器不会根据 CMS 名称、
Cookie 或营销页面猜测版本。如果存在 PHP 但版本被隐藏，报告会写
`UNKNOWN` / `PHP present, version hidden`——不是 `YES`，也不是 `NO`。

你可以在扫描前自行检查响应头：

```sh
curl -sSI https://example.com/ | grep -i 'x-powered-by\|^server'
```

如果响应包含 `X-Powered-By: PHP/x.y.z`，扫描器就能判断。如果没有，补丁级别
只能来自主机或你被授权读取的诊断页面。`NO` 会是谎言，因此工具不会打印 `NO`。

### 4. 结论

| 状态 | 含义 | 是否暴露 |
|---|---|---|
| `vulnerable` | 版本低于分支修复下限 | 是 |
| `eol` | 分支没有上游修复（5.x、7.x、8.0、8.1） | 是 |
| `patched` | 达到或高于分支修复下限 | 否 |
| `unknown` | 观察到 PHP，但版本未确定 | 未验证 |
| `no_php` | 可达路径上没有 PHP 标记；控制路径正常 | 否（有范围） |
| `inconclusive` | 被拦截、认证墙、软 404、限速、5xx 或无法连接 | 未验证 |

本版本使用的修复下限：

| 分支 | 首个修复版本 |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

`5.x`、`7.x`、`8.0` 和 `8.1` 分支在该漏洞类别上已停止维护。
比表格更新的分支会报告为 `unknown` / `newer_than_table`，不会猜测。

### 5. 暴露程度与阻力

`risk.score` 是 **暴露严重度**，形状类似 CVSS，但不是 CVSS 向量：

- `vulnerable` → `9.8`
- `eol` → `10.0`
- `patched` / `no_php` → `0.0`
- 未验证 → `null`（`UNKNOWN`）

`risk.friction` 是一个独立的、可累加的列表，描述攻击者需要克服什么：
WAF、CDN、FPM 工作进程亲和性、认证墙、限速、边缘拦截、软 404。
WAF 后面的存在漏洞解释器仍然是 `9.8` 暴露；WAF 改变的是利用可能性，不是补丁状态。

`hackability` 权衡观察到的信号。当正向 + 负向证据为零时，`ratio` 为 `null`，
评级为 `INCONCLUSIVE`——绝不是 `0.00` / `NOT EXPOSED`。每个结果还携带人类可以
据以行动的决策：`answer`（`yes` / `no` / `unknown`，其中 `LIKELY` 回答 `yes`，
因为举证责任在于证明未暴露）和 `action`（由该答案推出的一句建议）。
JSON 报告在 `results.<target>.hackability` 下暴露这两个字段，文本和 Markdown
报告将其打印为 `DECISION` 卡片。

### 6. ATT&CK 与增强信息

报告始终包含 **评估路径**（本次扫描做了什么，以及下一步低风险验证步骤）。
只有确认存在漏洞解释器时才打印 **杀伤链**；为未确认的发现打印杀伤链会训练人们忽略它。

增强模块是 verdict + environment 的纯函数：

- `Detections`——WAF 规则、PHP/FPM 日志、工作进程健康、EDR、源站暴露。
- `Remediation`——特定版本的升级路径、临时 WAF 控制、配置审计，
  以及修复与补偿之间的区别。
- `Tooling`——针对主机的建议；只有 `--authorized` 才包含攻击性条目。
- `NextActions`——只读命令（curl、openssl、dig）以及明确授权的后续操作。
- `RedTeam`——使用 `-r` 时的攻击者视角笔记。

### 7. 授权 POC

文本模式扫描发现 `vulnerable` 或 `eol` 时，工具只问一次：

```text
  授权渗透测试
  · 检测到 PHP 8.4.26。实验 POC 针对 PHP 8.4.26（bookworm）校准。
  ? 该主机存在暴露。是否继续执行授权渗透测试？[y/N]
```

回答 `n` 退出。回答 `y` 先打印授权使用警告，再运行 Ruby POC。
POC 没有命令行开关。它复现实验 POC 的网络行为——原始 HTTP/1.1、multipart
字段布局、堆/库泄露计算、偏移、重试、工作进程轮换和 `out/p1` 证明——
但使用 Ruby 编写，并隔离在 `lib/php2shell_poc2026/poc/` 下。

POC 针对 bookworm PHP 8.4.26 实验构建校准，会执行内存耗尽和工作进程轮换，
可能中断目标服务。机器可读格式、`--quiet` 和非交互会话无法回答问题，
因此永远不会运行它。每次运行结束时都会明确打印 `RESULT: SUCCESS` 或
`RESULT: FAILED`；`-v` 还会显示堆锚点、库基址、载体地址、`system()` 地址
和完整输出日志。完整契约见 [docs/POC.md](docs/POC.md)。

---

## 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 安全（已修复 / 无 PHP），或未验证且未指定 `--fail-on` |
| `1` | 用法、配置或内部错误 |
| `2` | 暴露：存在漏洞或已停止维护的解释器 |
| `3` | 无法判定，当 `--fail-on inconclusive` 或 `--fail-on any` 时 |
| `4` | 范围违规（`--require-scope`） |

`--fail-on` 取值：

- `exposed`（默认）：只有暴露才返回 `2`。
- `inconclusive`：暴露返回 `2`，任何未验证目标返回 `3`。
- `any`：本版本与 `inconclusive` 相同；两者都表示“不要让被拦截的结果静默通过”。
- `never`：除非内部错误，否则始终 `0`。

当你要求 CI 门禁时，被拦截的主机应该让 CI 失败。这正是重点。

POC 不改变退出码。如果主机暴露，无论用户回答 `n`、POC 失败，还是 POC 确认代码执行，
进程仍退出 `2`。扫描发现是契约；POC 是额外的证据步骤。

---

## 输出格式

| 格式 | 参数 | 用途 |
|---|---|---|
| Text | `-f text`（默认） | 人工排查；感知 `COLUMNS` |
| JSON | `-j`、`--json`、`-f json` | 完整信封，schema 版本 `3.0` |
| Markdown | `-f markdown` | 工单、漏洞赏金报告、文档 |
| SARIF | `-f sarif` | GitHub code scanning / 安全仪表盘 |
| CSV | `-f csv` | 电子表格和资产清单 |
| NDJSON | `-f ndjson` | 日志采集器、流式管道 |

`--output FILE` 写入文件；`--output -` 写入 stdout。`--compact` 让 JSON 单行。
`--evidence` 在 JSON/NDJSON 探针中增加简短正文摘录（目标控制的数据；请谨慎使用）。

JSON 信封记录在 [docs/JSON-SCHEMA.md](docs/JSON-SCHEMA.md)。每种格式使用相同的
计算摘要，因此 text、JSON 和 SARIF 不会对暴露目标数量产生分歧。

POC 有意不进入 JSON、Markdown、SARIF、CSV 和 NDJSON：这些格式没有终端来回答
y/N 问题。它只在交互式文本报告中运行。请在 TTY 上使用 `--format text` 查看。

---

## 命令行参考

```text
Usage: php2shell-poc2026 [options] URL [URL ...]
```

### 扫描

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-p`, `--profile passive\|standard\|deep` | `standard` | 探测深度 |
| `-d`, `--deep` | — | `--profile deep` 的别名 |
| `-t`, `--timeout SECS` | `10` | 读取超时 |
| `--connect-timeout SECS` | `5` | 连接/TLS 超时 |
| `--max-redirects N` | `5` | 每次探测的重定向次数 |
| `--max-body BYTES` | `512k` | 响应大小上限（`512k`、`1M`） |
| `--retries N` | `1` | 瞬时失败重试次数 |
| `--no-retry-after` | — | 忽略 `Retry-After` |
| `--delay MS` | `250` | 每主机最小延迟 |
| `--threads N` | `4` | 目标工作线程数 |
| `--max-requests N` | `25` | 每目标请求预算 |
| `--no-adaptive` | — | 全面拒绝后仍继续探测 |
| `--path PATH` | — | 额外路径（可重复） |

### HTTP

| 参数 | 说明 |
|---|---|
| `-H`, `--header "Name: value"` | 额外请求头（可重复） |
| `--cookie STRING` | Cookie 请求头 |
| `-A`, `--user-agent STRING` | 覆盖 User-Agent |
| `--browser-ua` | 用于机器人防护兼容的浏览器 User-Agent（仅授权） |
| `--proxy URL` | HTTP 代理 |
| `--no-proxy` | 忽略代理环境变量 |
| `--basic-auth USER:PASS` | 基本认证，仅同源 |
| `--bearer TOKEN` | Bearer token，仅同源 |
| `--ca-file PATH` | 自定义 CA 包 |
| `-k`, `--insecure` | 跳过 TLS 校验（仅授权自签名） |

### 范围与授权

| 参数 | 说明 |
|---|---|
| `--scope FILE` | 只扫描匹配范围文件的主机 |
| `--exclude FILE` | 跳过匹配排除文件的主机 |
| `--require-scope` | 目标超出范围时失败关闭（`4`） |
| `--authorized` | 包含攻击/后渗透工具条目 |

POC 不受参数控制。它只在暴露的文本模式扫描之后、且用户明确回答 `y` 后才提供。
参见 [docs/POC.md](docs/POC.md)。

### 报告

| 参数 | 说明 |
|---|---|
| `-f`, `--format FORMAT` | `text`、`json`、`markdown`、`sarif`、`csv`、`ndjson` |
| `-j`, `--json` | `--format json` 的别名 |
| `--lang LOCALE` | 文本报告语言：`auto`（设备语言，默认）、`en` 或 `zh` |
| `-en` / `-zh` | `--lang en` / `--lang zh` 的短形式 |
| `-o`, `--output FILE` | 写入文件；`-` 表示 stdout |
| `--compact` | 紧凑 JSON |
| `--no-banner` | 隐藏横幅 |
| `--no-color` | 禁用颜色（TTY 上自动启用；遵守 `NO_COLOR`） |
| `--evidence` | JSON/NDJSON 中的正文摘录 |
| `-q`, `--quiet` | 文本模式只保留结论、发现表和运行摘要 |
| `-r`, `--redteam` | 攻击者笔记 |
| `-c`, `--toolchain` | 相关工具 |
| `--toolchain-full` | 包含理由的全部工具 |
| `-v`, `--verbose` | 技术细节、攻击路径、防御检查、全部操作和请求跟踪 |
| `--fail-on MODE` | `exposed`、`inconclusive`、`any`、`never` |
| `--dry-run` | 打印请求计划；不打开 socket |
| `-C`, `--config FILE` | YAML 默认值 |
| `-V`, `--version` | 版本 |
| `-h`, `--help` | 帮助 |

---

## 配置档

| 配置档 | 典型请求数 | 做什么 |
|---|---|---|
| `passive` | 2 | 根路径 + 文本探针；不探测 `.php` |
| `standard` | 4 | 根路径 + 文本/PHP 探针 + `/index.php`；仅在检测到框架时探测框架路径 |
| `deep` | 最多 `--max-requests` | 常见 PHP 路径、框架路径、`robots.txt`/`sitemap.xml` 发现 |

深度模式仍受 `--max-requests` 限制，绝不做暴力破解。它只请求站点自己发布的少量路径。

---

## 范围文件

纯文本，每行一个模式：

```text
# 精确主机及其子域名
example.com
# 仅子域名
*.example.com
# 单个 IP、CIDR 或 URL
192.0.2.10
192.0.2.0/24
https://app.example.com
```

```sh
php2shell --scope scope.txt --require-scope https://app.example.com/
# 目标不在列表中时退出 4
```

没有 `--require-scope` 时，超出范围的目标会被跳过并给出警告，运行继续。
使用它时，第一个超出范围的目标会在任何网络流量之前中止。

---

## 配置文件

```yaml
# php2shell.yml
profile: deep
format: sarif
output: reports/php2shell.sarif
delay_ms: 500
threads: 2
max_requests: 40
no_proxy: true
scope: scope.txt
require_scope: true
headers:
  X-Assessment: authorized
paths:
  - /health.php
targets:
  - https://example.com/
```

```sh
php2shell --config php2shell.yml
php2shell --config php2shell.yml https://other.example.com/   # CLI 目标优先
```

相对路径 `scope`、`exclude`、`ca_file` 和 `output` 相对于配置文件解析。
未知键会失败关闭，而不是被忽略。

---

## CI 示例

```sh
# 仅在暴露时失败
php2shell --format sarif --output php2shell.sarif https://example.com/

# 在暴露或被拦截/未验证时失败
php2shell --fail-on inconclusive --format json https://example.com/
```

```yaml
- name: PHP2Shell triage
  run: |
    php2shell --scope scope.txt --require-scope \
      --fail-on inconclusive --format sarif \
      --output php2shell.sarif https://app.example.com/
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: php2shell.sarif
```

CI 永远不会运行 POC：提示需要交互式终端。发现暴露主机的 CI 运行仍会以退出码 `2`
失败并上传 SARIF 报告；它无法回答 POC 问题。

---

## 安全属性

- **扫描器只发送 GET。** 扫描本身不发送 POST、载荷、模糊测试或改变状态的请求方法。
- **POC 显式且隔离。** POST/multipart 流程位于
  `lib/php2shell_poc2026/poc/`，只在暴露主机的 y/N 提示后运行，
  并先打印授权使用警告。
- **扫描器有边界。** `--max-requests`、正文上限、重定向上限、重试和速率限制
  适用于扫描。POC 有自己的固定超时、重试和 12 MB 请求正文；它不是扫描探针，
  不受 `--max-requests` 约束。
- **同源凭据。** `--cookie`、`--basic-auth` 和 `--bearer` 不会跨重定向转发到不同源。
- **范围在 I/O 前强制执行。** `--require-scope` 在第一个 socket 前退出 `4`。
- **目标数据不可信。** 响应头、标题、正文和路径在到达终端或 Markdown/CSV 单元格前，
  都会清理 ANSI/OSC/控制字符/双向文本。
- **没有静默扫描。** 默认 User-Agent 标识工具和项目。
- **浏览器 UA 模式需显式启用。** `--browser-ua` 可能跨越机器人控制边界，
  因此绝不自动启用；报告会标注该模式，操作者必须先确认授权。
- **没有自动利用。** POC 绝不会由参数、CI 作业或机器可读报告启动。
  它需要交互式暴露主机 `y` 回答，并在运行前打印警告。

---

## 项目结构

```text
bin/                     php2shell
lib/php2shell_poc2026/
  cli.rb                 选项、配置、范围、线程、输出、退出码
  scanner.rb             自适应编排、发现、增强信息
  http_client.rb         Net::HTTP 传输：重定向、重试、代理、TLS
  probe.rb               一个响应 + PHP/访问证据
  access.rb              拦截 / 受限 / 软 404 / 认证墙 / 429
  verdict.rb             修复表和状态决策
  risk.rb                暴露评分 + 阻力
  hackability.rb         带符号的证据比率（无证据时为 nil）
  environment.rb         边缘 / CDN / WAF / 托管 / SAPI / 框架
  block_page.rb          OVHcloud/Cloudflare/Akamai/... 拦截页面指纹
  poc/                   y/N 提示后的授权原始 HTTP 实验 POC
  report/                text、JSON、Markdown、SARIF、CSV、NDJSON
  scope.rb, target.rb, idn.rb, sanitize.rb, options.rb
  attack.rb, detections.rb, remediation.rb, tooling.rb, next_actions.rb
docs/                    方法论、JSON schema、授权使用、安全
test/                    使用假传输和本地 TCP 的 Minitest 套件
```

---

## 开发

```sh
bundle install
bundle exec rake test
ruby -Ilib bin/php2shell --dry-run https://example.com/
gem build php2shell_poc2026.gemspec
```

测试套件使用假传输和本地 TCP 服务器；它不扫描互联网，也不对真实目标运行 POC。
POC 辅助测试覆盖 multipart 字节、Cookie 解码、堆/库计算、载体布局、偏移解析、
同意提示和结果展示，位于 `test/poc_test.rb`。

---

## 文档

- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) —— 为什么有控制探针、如何权衡证据、
  以及每个结论的含义。
- [docs/POC.md](docs/POC.md) —— 授权 POC 契约、默认值、证明机制和限制。
- [docs/JSON-SCHEMA.md](docs/JSON-SCHEMA.md) —— v3 JSON 信封。
- [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md) —— 范围、交战规则和法律边界。
- [docs/SECURITY.md](docs/SECURITY.md) —— 威胁模型和漏洞报告。
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) —— 代码和测试约定。
- [docs/UML.md](docs/UML.md) —— 类图、序列图和状态图。
- [CHANGELOG.md](CHANGELOG.md) —— 3.0 的变化。

---

## 许可证与免责声明

MIT。参见 [LICENSE](LICENSE)。

本工具给出的是 **迹象**，不是认证。`patched` 结论只覆盖它看到的版本证据；
`no_php` 结论只覆盖它测试过的路由；`inconclusive` 就是字面意思。
它不能替代主机侧配置审查、单独授权下的认证测试，或由理解资产面的真人做出的评估。

POC 也不是认证。它针对 bookworm PHP 8.4.26 实验构建校准，可能中断目标服务；
它的 `out/p1` 证明依赖共享的实验目录，或依赖命令写入你可读取的位置。
POC 失败不能证明主机安全；POC 成功也不授权你继续做更多事情。

只对你拥有或获得明确书面授权评估的系统使用。不要对军事、政府、关键基础设施
或任何授权范围之外的系统使用。作者与贡献者不对滥用、损害或法律后果承担责任。
