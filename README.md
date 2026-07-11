# ALL1n 3.3 - 通用 POC 验证工作台

ALL1n 是一个基于 **Go + Fyne GUI** 的本地漏洞 POC 验证与结果管理工具，面向授权安全测试、漏洞复现、内部验证和安全研究场景。

> 仅允许对已获得明确授权的目标进行验证。程序在执行前要求用户主动确认目标已获授权。

## 外观与主题

- 默认使用更适合中文界面的“现代等线”字体，并对标题、正文、状态与代码文本建立清晰层级
- 顶栏可即时切换 4 套产品主题：`深海蓝`、`极光青`、`石墨紫`、`云雾白`
- 可切换 `现代等线`、`清晰黑体`、`系统默认` 三种字体策略
- 主题和字体选择会自动保存，下次启动继续使用
- 字体从 Windows 系统字体目录安全加载，不在发布包中重新分发商业字体文件；缺失时自动回退到 Fyne 系统字体

## 产品能力

### POC 管理

- 文件夹 / POC 树形管理
- 名称快速筛选
- GET、HEAD、POST、PUT、DELETE、PATCH、OPTIONS 请求
- Path、Query、Body、Header 和匹配规则编辑
- 支持粘贴 Burp Suite、浏览器或代理工具中的原始 HTTP 请求包，自动填充方法、路径、参数、Headers、Body 和 Body 类型
- JSON 数据导入、导出和完整性校验
- 用户配置目录持久化和旧数据自动迁移

### 验证执行

- 多目标资产列表：每行一个目标，支持 `#` 注释、自动补全协议、校验与去重
- 支持导入 `.txt` / `.list` 目标文件，单次最多 1000 个目标
- “仅验证当前 POC”：对全部目标执行当前叶子 POC
- 选中产品或文件夹节点后，自动统计其全部子目录中的 POC，并显示明确的范围运行按钮
- “运行所选节点全部 POC”：按 `目标 × POC` 任务矩阵递归执行节点下所有 POC；单目标同样支持一次运行多个 POC
- 1–16 并发的统一任务调度
- 可随时停止正在运行的任务
- 每个请求独立超时控制
- TLS 证书校验开关，默认开启证书校验
- HTTP 连接池复用
- 4 MiB 响应分析上限和截断提示
- 请求发送前验证方法、Header 和匹配规则

### 结果与报告

- 总数、完成、命中、错误、取消统计
- 运行时自动进入结构化结果视图
- 卡片式结构化结果流，通过状态色、图标和信息层级区分命中、未命中、错误与取消
- 支持按结果状态筛选，并可搜索目标、POC、URL 和验证说明
- 每张结果卡片集中展示目标、POC、方法、URL、状态码、耗时、响应大小和验证说明
- 会话结果清理
- 结果行可打开独立证据中心，分为概览、原始请求、原始响应和匹配证据
- 请求与响应证据默认自动脱敏，单侧证据预览上限 256 KiB
- 可复制的只读证据视图，明确标记截断状态
- 独立、可离线查看的 HTML 验证报告
- CSV 报告导出
- JSON 报告导出（包含结构化证据）
- CSV 公式注入防护
- Excel 中文兼容



## 导入原始 HTTP 请求

选择一个 POC 节点，在“请求定义”中点击“粘贴 HTTP 请求”，可直接粘贴 HTTP/1.x 请求或 Burp Suite 风格的 `HTTP/2` 请求，例如：

```http
POST /api/login?debug=true HTTP/1.1
Host: app.example.com
Content-Type: application/json
Authorization: Bearer token

{"username":"admin","password":"demo"}
```

解析后会自动填充请求方法、路径、查询参数、Headers、Body 和 Body 类型。POC 名称与匹配规则不会被覆盖。为保证同一个 POC 可用于多个目标，`Host`、`Content-Length`、`Connection`、`Transfer-Encoding` 等由目标或 HTTP 客户端管理的 Header 不会固化到 POC 中。

## 多目标使用

在“目标资产”中每行输入一个目标，例如：

```text
https://app.example.com
192.168.1.10:8080
# 测试环境
http://test.internal:9000
```

未写协议时默认补全为 `http://`；重复目标会自动去重。选择一个叶子 POC 后点击“仅验证当前 POC”，会对列表中的全部目标执行该 POC；选择产品或文件夹节点后，运行配置区会显示该节点下递归收集到的 POC 数量，点击高亮的范围运行按钮即可生成 `目标数 × POC 数` 个任务。界面中的并发数限制作用于整个任务矩阵，而不是每个目标单独创建一组并发。

### 单目标运行产品节点全部 POC

例如目标资产中只有：

```text
https://u8.example.com
```

在左侧选择“用友 U8 Cloud”产品节点后，界面会显示类似：

```text
验证范围：用友 U8 Cloud
将对每个目标运行该节点下全部 12 个 POC
运行「用友 U8 Cloud」全部 POC（12）
```

执行后会生成 `1 × 12 = 12` 个任务；如果产品节点下还有 SQL 注入、文件读取等多级子目录，也会递归收集其中的全部 POC。选择节点本身不会自动发送请求，仍需授权确认并主动点击运行按钮，避免误操作。

> 目标列表仅用于当前会话，不会自动持久化；授权确认也不会被保存。

## 验证证据与 HTML 报告

验证完成后切换到“验证结果 → 结构化结果”，选择任意结果卡片并点击“查看证据”。证据中心采用独立对话框，不会挤压或覆盖请求定义工作区，包含：

- **概览**：结论、目标、POC、URL、状态码、响应大小、耗时与验证时间
- **原始请求**：请求行、请求头和请求体证据
- **原始响应**：状态行、响应头和响应体证据
- **匹配证据**：匹配 DSL 的实际判定原因

认证信息、Cookie、Token、密码、API Key、Session ID、私钥字段及敏感查询参数会在证据捕获时自动脱敏，并在 JSON / HTML / CSV 导出前再次执行防御性脱敏。超长请求或响应只保留前 256 KiB 证据预览，并显示截断标记；响应匹配分析仍保留独立的 4 MiB 上限。

点击“导出 HTML”可生成完全独立的离线报告，无需外部 CSS、JavaScript 或网络资源。报告提供任务摘要、逐项结果和可折叠的请求/响应证据，所有不可信文本均经过 HTML 转义。

## Windows 快速启动

### 直接双击

```text
start.bat
```

首次启动会下载 Go 依赖并编译。后续仅在源码或依赖文件变化时重新构建。

生成的程序位于：

```text
bin\ALL1n.exe
```

### PowerShell

启动：

```powershell
.\run.ps1
```

构建并运行测试：

```powershell
.\build.ps1
```

跳过测试快速构建：

```powershell
.\build.ps1 -SkipTests
```

调试构建：

```powershell
.\build.ps1 -DebugBuild
```

生成发布 ZIP 和 SHA256：

```powershell
.\package.ps1
```

发布产物位于：

```text
dist\ALL1n-3.5.0-windows-amd64.zip
dist\ALL1n-3.5.0-windows-amd64.zip.sha256
```

## 通用 Go 命令

```bash
go mod download
go test ./...
go run -buildvcs=false .
```

构建：

```bash
go build -buildvcs=false -o ALL1n .
```

启动脚本显式使用 `-buildvcs=false`，从 ZIP 解压、没有 Git 元数据或上级目录 Git 状态异常时也能正常构建。

## 数据文件

POC 数据默认保存在用户配置目录：

```text
Windows: %AppData%\ALL1n\poc_data.json
Linux:   $XDG_CONFIG_HOME/ALL1n/poc_data.json
macOS:   ~/Library/Application Support/ALL1n/poc_data.json
```

旧版本当前目录中的 `poc_data.json` 会在首次启动时自动迁移。保存过程使用临时文件、同步写入、备份替换和中断恢复，避免重复保存失败或数据损坏。

超时、并发数和 TLS 策略通过 Fyne Preferences 保存；授权确认不会跨会话保存。

## 匹配规则

### 正文文本

```text
Welcome Admin
body:SQL syntax
```

### HTTP 状态码

```text
status:200
status:200-299
status:2xx
```

状态码必须位于 `100-599`，范围起始值不能大于结束值。

### 响应头

```text
header:Server=nginx
```

### 正则表达式

```text
regex:uid=\d+
```

### 响应耗时与预期超时

时间型 SQL 注入等场景可以直接使用实际请求耗时判定：

```text
duration:>=5s
time:>3000ms
elapsed:<=10s
```

`duration:`、`time:`、`elapsed:` 含义相同，支持 `>`、`>=`、`<`、`<=`、`=`、`==`。不写比较符时默认使用 `>=`，例如 `duration:5s` 等价于 `duration:>=5s`。

如果漏洞表现为请求达到客户端超时而没有返回 HTTP 响应，可以把“预期超时”本身作为证据：

```text
timeout:true
timeout:true && duration:>=5s
```

`timeout:true` 只匹配由请求超时截止时间触发的超时，不会把手动取消或普通网络错误误判为漏洞。需要等待完整响应时，运行配置中的“请求超时”必须大于耗时阈值；需要以超时作为命中证据时，应让超时值与 POC 的预期延迟相匹配。

### AND / OR 组合条件

响应码、响应头、响应体、正则、响应耗时和预期超时条件可以自由组合：

```text
status:2xx && header:Server=nginx && body:Welcome
status:200 || status:302
status:500 OR header:Server=nginx
status:2xx 和 body:success
status:403 或 body:Access Denied
duration:>=5s && status:200
timeout:true && duration:>=5s
```

支持的逻辑运算符：

- AND：`&&`、`AND`、`and`、`和`
- OR：`||`、`OR`、`or`、`或`
- AND 的优先级高于 OR。例如 `status:200 || status:404 && body:missing` 等价于“状态码为 200，或者状态码为 404 且响应体包含 missing”。
- 推荐在运算符两侧留空格，规则更易读；旧版紧凑写法 `status:200&&body:ok` 继续兼容。

每个条件都会生成 `✓ / ✗` 匹配证据；OR 规则会展示各分支命中情况，而不是只给出一个模糊结论。正则、状态范围、Header 格式、耗时单位、timeout 布尔值和表达式完整性会在请求发送前检查，避免无效 POC 对目标产生无意义请求。

## 测试与质量检查

```bash
go test ./...
go test -race ./...
go test -tags ci ./...
go vet ./...
```

无桌面环境构建：

```bash
go build -tags ci .
```

当前测试覆盖：

- URL 构造和目标协议校验
- 匹配 DSL
- POC 配置校验
- 请求取消
- 大响应截断
- 产品节点递归 POC 收集、单目标多 POC 任务矩阵
- 批量并发和取消收敛
- 数据保存、重复替换和备份恢复
- JSON 导入尾随内容校验
- CSV / JSON / HTML 报告
- HTTP 请求与响应证据捕获、截断和敏感字段脱敏
- CSV 公式注入防护

## 项目结构

- `main.go`：GUI、交互状态和任务控制
- `model.go`：POC 数据模型和树结构
- `persistence.go`：数据存储、迁移、备份恢复、导入导出
- `runner.go`：HTTP 执行、取消、输入校验、证据捕获和匹配 DSL
- `batch.go`：目标 × POC 有界并发任务调度器
- `targets.go`：目标列表解析、规范化、校验与去重
- `raw_request.go`：原始 HTTP 请求包解析与字段映射
- `product_theme.go` / `surface_panel.go`：主题、字体和产品化面板系统
- `result_row.go`：卡片式验证结果组件和状态视觉映射
- `evidence.go` / `evidence_dialog.go`：证据模型、自动脱敏和证据中心界面
- `report.go` / `html_report.go`：CSV / JSON / HTML 报告生成
- `*_test.go`：自动化测试
- `build.ps1`：测试和 Windows 构建
- `run.ps1` / `start.bat`：增量构建与启动
- `package.ps1`：发布包和 SHA256 生成
- `CHANGELOG.md`：版本变更记录

## 开发环境

- Go `1.22.2+`
- Fyne `v2.7.4`
- 当前产品版本：`3.5.0`

## 后续路线

- 多请求链与变量提取
- Cookie Jar 和会话复用
- nuclei 模板导入
- 多次验证结果差异对比与趋势视图
- PDF 报告与报告签名
- POC 标签、风险等级和搜索索引
- 工作区加密与敏感字段保护
