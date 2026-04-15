# VulnDetectEngine (漏洞攻击检测引擎)

VulnDetectEngine 是一款基于 C/C++ 和 libpcap 开发的高性能漏洞攻击检测引擎。它以动态链接库 (DLL/SO) 的形式提供，可以轻松集成到各类安全产品（如 IDS/IPS、端点安全、微隔离系统）中。

本项目在全平台（Windows/Linux）统一使用工业级深度包检测引擎 **nDPI 4.x** 作为底层协议识别基础，在其之上实现了精细化的协议字段提取和基于 JSON 的动态漏洞特征匹配。

---

## 🌟 核心特性

- **跨平台多线程架构**：支持 Linux (SO) 和 Windows (DLL)，自动枚举所有网卡并启动独立捕获线程。
- **工业级协议解析**：集成 nDPI 4.x 引擎，支持 280+ 种应用层协议精准识别，辅以深度字段解析（SMB/HTTP/DNS/RDP/DCERPC/Kerberos 等）。
- **动态漏洞特征库**：基于 JSON 格式的规则库，支持正则表达式（POSIX regex/PCRE2）和多维条件匹配，支持**热重载**（无需重启引擎）。
- **三种检测模式**：
  - `STATELESS`（无状态）：单包特征匹配（如 HTTP XSS、路径遍历、Log4Shell）。
  - `STATEFUL`（有状态）：基于会话哈希表的上下文追踪（如 EternalBlue 协商与触发的两阶段检测）。
  - `THRESHOLD`（阈值）：基于时间滑动窗口的行为检测（如端口扫描、暴力破解）。
- **无锁高性能统计**：采用原子操作 (`__sync_fetch_and_add`) 实现每网卡维度的流量与告警统计，无锁争用。

---

## 📁 目录结构

```text
VulnDetectEngine/
├── DetectEngine/                 # 核心检测引擎 (DLL/SO)
│   ├── include/                  # 对外导出接口及内部头文件
│   ├── src/                      # 核心源码 (协议解析、规则引擎、多线程调度)
│   └── third_party/              # 第三方依赖 (cJSON)
├── AttackSimulator/              # 漏洞攻击模拟测试程序
├── TestApp/                      # 宿主程序调用示例 (命令行检测工具)
├── RuleDB/                       # 漏洞特征库 (vuln_rules.json)
├── docs/                         # 文档
├── scripts/                      # 测试 pcap 生成脚本
├── Makefile                      # Linux 构建系统
└── VulnDetectEngine.sln          # Windows VS2017 解决方案
```

---

## 🛠️ 编译指南 (Linux)

### 1. 安装依赖

在 Ubuntu/Debian 上：
```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev libndpi-dev
```

### 2. 编译项目

在项目根目录下执行：
```bash
make all
```

产物将生成在 `bin/` 目录下：
- `libVulnDetectEngine.so`：检测引擎共享库
- `TestApp`：检测引擎调用示例
- `AttackSimulator`：攻击模拟器

---

## 🛠️ 编译指南 (Windows)

在 Windows 下，引擎同样依赖 nDPI 进行协议解析。由于 nDPI 官方不提供 Windows 预编译库，需要先自行编译 nDPI。

### 1. 准备基础依赖

1. **Npcap SDK**
   - 安装 Npcap 运行时环境（勾选 "Install Npcap in WinPcap API-compatible Mode"）：https://npcap.com/#download
   - 下载 Npcap SDK，解压到项目根目录下的 `third_party\npcap-sdk\`

2. **pthreads-win32** (nDPI 内部线程依赖)
   - 在 Visual Studio 2017 中打开 `VulnDetectEngine.sln`
   - 通过 NuGet 包管理器安装：`工具` -> `NuGet 包管理器` -> `管理解决方案的 NuGet 包`
   - 搜索并安装 `pthreads.2.9.1.4`

### 2. 编译 nDPI (Windows)

nDPI 支持通过 MSYS2 或 Visual Studio 编译。这里推荐使用 VS2017 官方工程：

1. 克隆 nDPI 源码：
   ```cmd
   git clone https://github.com/ntop/nDPI.git
   cd nDPI
   ```
2. 生成 Windows 头文件：
   - 运行 `windows\win32_setup.bat` 脚本（它会复制 `ndpi_typedefs.h.in` 等文件）
3. 编译 nDPI：
   - 使用 VS2017 打开 `windows\nDPI.sln`
   - 选择 `Release` | `x64`，右键点击 `nDPI` 工程，选择"生成"
4. **融合到 VulnDetectEngine**：
   - 在本项目的 `third_party\` 下创建 `ndpi\` 目录
   - 复制头文件：将 nDPI 源码的 `src\include\` 目录复制到 `third_party\ndpi\include\`
   - 复制静态库：将编译生成的 `ndpi.lib` (位于 `windows\x64\Release\`) 复制到 `third_party\ndpi\lib\x64\`

*注：`DetectEngine.vcxproj` 已配置好相对路径，只需将 nDPI 产物放入 `third_party\ndpi\` 即可自动链接。*

### 3. 编译核心引擎

1. 使用 VS2017 打开 `VulnDetectEngine.sln`
2. 选择 `Release` | `x64`
3. 按 `Ctrl+Shift+B` 生成解决方案

产物将生成在 `bin\x64\Release\` 目录下。

---

## 🚀 引擎集成与使用

### 1. 引入头文件

宿主程序只需包含一个头文件：
```c
#include "VulnDetectEngine.h"
```

### 2. 核心 API 调用流程

```c
// 1. 定义告警回调函数
void VDE_CALLBACK my_alert_cb(const AlertInfo* alert, void* user_data) {
    printf("[ALERT] %s: %s (Severity: %d)\n", 
           alert->rule_id, alert->rule_name, alert->severity);
}

// 2. 初始化配置
VDE_Config config;
memset(&config, 0, sizeof(config));
config.mode = VDE_MODE_LIVE_ALL;           // 监听所有网卡
config.rule_file = "RuleDB/vuln_rules.json"; // 规则库路径
config.alert_cb = my_alert_cb;             // 注册回调

// 3. 创建引擎实例
VDE_Handle engine = VDE_Create(&config);
if (!engine) {
    printf("引擎创建失败\n");
    return;
}

// 4. 启动多线程捕获
if (VDE_Start(engine) != VDE_OK) {
    printf("启动失败\n");
}

// 5. 运行中可以获取统计信息或热重载规则
VDE_IfaceStat stats[10];
int count = 0;
VDE_GetIfaceStatistics(engine, stats, 10, &count);
// VDE_ReloadRules(engine);

// 6. 停止并清理资源
VDE_Stop(engine);
VDE_Destroy(engine);
```

---

## 🛡️ 漏洞特征库扩展

规则库位于 `RuleDB/vuln_rules.json`，修改后调用 `VDE_ReloadRules()` 即可热生效。

### 规则字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | 字符串 | 规则唯一标识，如 "VDE-001" |
| `name` | 字符串 | 规则名称 |
| `category` | 字符串 | 漏洞类别（SMB/HTTP/DNS 等） |
| `severity` | 整数 | 严重级别：1(INFO), 2(LOW), 3(MEDIUM), 4(HIGH), 5(CRITICAL) |
| `type` | 字符串 | 匹配模式："STATELESS" 或 "STATEFUL" 或 "THRESHOLD" |
| `conditions` | 数组 | 匹配条件列表（AND 逻辑） |

### 支持的操作符 (OP)

- `EQ`：精确匹配（数字或字符串）
- `CONTAINS`：子串包含（大小写不敏感）
- `REGEX`：正则表达式匹配（POSIX ERE 标准）

### 编写示例：检测 HTTP 路径遍历

```json
{
    "id": "VDE-039",
    "name": "HTTP Path Traversal (../../)",
    "category": "HTTP",
    "severity": 4,
    "type": "STATELESS",
    "conditions": [
        { "field": "app_proto", "op": "EQ", "value": "PROTO_HTTP" },
        { "field": "http_uri", "op": "CONTAINS", "value": "../.." }
    ]
}
```

---

## 🧪 攻击模拟与集成测试

项目内置了 `AttackSimulator` 用于验证检测引擎的准确性。

### 运行全量测试

1. 启动 TestApp 监听所有网卡：
   ```bash
   sudo ./bin/TestApp -i all -r RuleDB/vuln_rules.json
   ```
2. 运行攻击模拟器发送测试流量：
   ```bash
   ./bin/AttackSimulator 127.0.0.1 127.0.0.1 80 all
   ```
3. TestApp 将实时输出触发的漏洞告警。

*作者：Manus AI*
