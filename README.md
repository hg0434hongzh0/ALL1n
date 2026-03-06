# ALL1n - 通用 POC 验证工作台

一个基于 **Go + Fyne GUI** 的本地漏洞 POC 验证工具，面向安全研究、漏洞复现和内部验证场景。

## 当前版本亮点

- 更清晰的工作台式界面布局
- 树形管理 POC / 文件夹，支持快速筛选
- 支持 **链式多步骤 POC**
- 支持 **Nuclei YAML 模板导入**
- 单点验证与批量验证
- 批量验证支持可配置并发
- 支持变量提取、占位符替换和 Cookie 会话连续复用
- 日志区支持结果汇总与自动裁剪
- 更稳的数据导入 / 导出 / 本地持久化
- 更可靠的 URL 组装、Header 解析和响应匹配

## 主要优化内容

这次重构主要做了以下改进：

1. **结构拆分**
   - 将原本单文件实现拆分为：
     - `main.go`：GUI 与交互逻辑
     - `model.go`：数据模型与树结构操作
     - `persistence.go`：本地存储、导入导出
     - `runner.go`：HTTP 执行与匹配逻辑

2. **界面优化**
   - 新增顶部运行配置区
   - 编辑器、目录区、日志区分栏更清晰
   - 统一了节点选中时的字段启用/禁用逻辑
   - 单请求编辑器升级为多步骤链式编辑器
   - 新增运行状态、进度条、统计卡片
   - 新增 POC 名称筛选

3. **执行优化**
   - 请求客户端复用，减少重复创建开销
   - 使用更稳健的 URL 拼接方式
   - 支持步骤级变量提取与模板渲染
   - 支持链式请求中的 Cookie 会话复用
   - 批量执行改为并发 worker 模式
   - 支持配置请求超时和 TLS 证书校验策略

4. **稳定性增强**
   - 后台执行通过 Fyne UI 调度安全刷新界面
   - 本地数据保存改为临时文件 + 原子替换
   - 导入数据前进行结构校验
   - 内置基础测试，覆盖 URL、匹配规则、链式执行、Nuclei 导入和持久化逻辑

## 数据文件

本地数据默认保存为：

```text
poc_data.json
```

如需共享漏洞库，推荐直接使用 **导出 / 导入** 功能，而不是手动覆盖文件。

## 匹配规则语法

匹配规则支持以下格式：

- 纯文本：`Welcome Admin`
- 响应体包含：`body:SQL syntax`
- 全部响应头包含：`headers:Set-Cookie`
- 状态码：
  - `status:200`
  - `status:200-299`
  - `status:2xx`
- 响应头包含：`header:Server=nginx`
- 正则匹配：`regex:uid=\d+`
- 取反：`!body:forbidden`

多个条件可通过 `&&` 和 `||` 组合：

```text
status:2xx && header:Server=nginx && body:Welcome
```

```text
status:200 || status:302 && !body:forbidden
```

## 链式步骤与变量提取

每个 POC 现在都可以包含多个步骤，步骤会按顺序执行。

支持的能力：

- 前一个步骤提取变量供后续步骤使用
- 请求间自动复用 Cookie / Session
- 支持 `{{变量名}}` 占位符替换
- 支持 Nuclei 常见变量：
  - `{{BaseURL}}`
  - `{{RootURL}}`
  - `{{Hostname}}`
  - `{{Host}}`
  - `{{Port}}`
  - `{{Scheme}}`

支持的提取规则示例：

```text
token=body_regex:token=([a-z0-9]+)
sid=header:Set-Cookie
last=headers_regex:JSESSIONID=([^;]+)
code=status
```

## 运行方式

### 1. 本地 GUI 构建

需要安装 Fyne 桌面依赖（Linux 下一般需要 X11 / OpenGL 开发库）：

```bash
go build .
```

### 1.1 编译 Windows EXE

如果你想在 Linux / macOS 上交叉编译 Windows 可执行文件：

```bash
GOOS=windows GOARCH=amd64 go build -o ALL1n.exe .
```

如果你本机直接就是 Windows：

```powershell
go build -o ALL1n.exe .
```

> 注意：Fyne 桌面程序跨平台构建时，通常仍需要目标平台对应的 GUI 构建环境。  
> 如果只是做代码校验，建议优先使用 `-tags ci`。

### 2. CI / 无桌面环境校验

如果当前环境没有桌面库，可使用 Fyne 的 `ci` 构建标签做编译或测试：

```bash
go build -tags ci .
go test -tags ci ./...
```

## 开发环境

- Go `1.22.2`
- Fyne `v2.7.1`

## 后续可继续扩展的方向

- 更丰富的匹配 DSL
- 更完整的 Nuclei DSL / matcher / extractor 兼容
- 多模板批量导入与目录扫描
- 链式步骤级断言、条件分支和失败策略
- 验证结果导出报告
