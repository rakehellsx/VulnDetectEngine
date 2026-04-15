# Windows 漏洞攻击检测引擎 (VulnDetectEngine)

## 1. 简介

VulnDetectEngine 是一套基于 C/C++ (Visual Studio 2017) 和 libpcap (Npcap) 实现的轻量级 Windows 漏洞攻击检测引擎。系统以 DLL 动态链接库的形式提供核心能力，能够被各类安全审计平台、主机入侵检测系统 (HIDS) 以及流量分析产品无缝集成。

引擎的核心目标是通过对网络数据包的深度协议解析与多维度特征匹配，实时发现针对 Windows 系统的典型漏洞攻击行为（如永恒之蓝、BlueKeep 等）。系统内置了灵活的规则引擎与 JSON 格式的特征库，支持无状态单包匹配、有状态会话追踪以及基于时间窗口的阈值统计分析。

## 2. 核心架构与功能特性

### 2.1 模块划分

本系统在设计上充分考虑了可扩展性与集成便利性，主要包含以下核心模块：

*   **数据捕获层**：基于 libpcap 接口，支持网卡实时混杂模式抓包（LIVE 模式）与离线 PCAP 文件回放分析（OFFLINE 模式）。
*   **协议解析层**：实现了从链路层到应用层的逐级解包。当前支持的协议包括：Ethernet、IPv4、TCP、UDP、ICMP、DNS、HTTP、SMBv1/v2/v3、RDP(TPKT/X.224)、DCERPC 以及 NetBIOS Session Service。
*   **规则引擎层**：采用 cJSON 库解析外部特征库文件。支持正则表达式、十六进制字节序列匹配、数值比较等多种操作符。具备智能会话追踪能力，可对多步攻击流程进行关联分析。
*   **日志与告警层**：提供独立的文件日志记录与结构化 JSON 格式告警输出，便于对接第三方 SIEM/SOC 平台。

### 2.2 技术指标与价值体现

在系统价值与能力储备方面，本引擎展现了以下技术特性：

*   **灵活的策略编排能力**：支持将基础的检测算子（如载荷匹配、端口过滤、协议识别）进行人工编排，形成复杂的渗透测试检测策略。同时，引擎内部也支持基于状态机的智能策略调用，能够对完整的攻击路径进行推演与识别。
*   **丰富的特征库储备**：初始版本已内置 18 种高危攻击技法特征，涵盖缓冲区溢出、远程代码执行 (RCE)、凭证窃取、协议暴力破解等多个维度。
*   **高性能并发处理**：核心检测流程采用无锁设计（针对单包匹配），并配备了高效的哈希表用于会话追踪与频率统计，能够在千兆网络环境下保持较低的 CPU 占用率。

## 3. 术语阐述

为便于理解系统的检测逻辑，特对以下核心术语进行说明：

*   **算子 (Operator)**：指引擎内部执行的最基础的匹配动作。例如“等于(EQ)”、“包含(CONTAINS)”、“正则匹配(REGEX)”以及“十六进制序列匹配(HEX_MATCH)”。
*   **攻击技法 (Attack Technique)**：攻击者在漏洞利用过程中采用的具体手段。例如通过发送特定的 SMBv1 Negotiate 协议包来触发缓冲区溢出，或利用 JNDI 注入特性执行恶意代码。
*   **攻击流程 (Attack Flow)**：由多个攻击技法按特定顺序组合而成的完整利用链。例如，永恒之蓝攻击通常包含“协议协商”、“内存布局”、“触发溢出”以及“后门植入”等多个阶段。
*   **渗透测试策略 (Penetration Test Strategy)**：为检测特定攻击流程而制定的综合性规则集。本引擎通过 JSON 规则文件将这些策略固化，指导引擎进行数据包的过滤、状态追踪与告警生成。

## 4. 编译与运行指南

### 4.1 环境准备

1.  **操作系统**：Windows 10 / Windows Server 2016 或更高版本。
2.  **开发工具**：Visual Studio 2017 (平台工具集 v141)。
3.  **依赖库**：安装 Npcap 并下载 Npcap SDK。请将 SDK 解压至解决方案根目录下的 `third_party\npcap-sdk\` 文件夹中（需包含 `Include` 和 `Lib` 子目录）。

### 4.2 编译步骤

1.  使用 Visual Studio 2017 打开 `VulnDetectEngine.sln`。
2.  选择所需的构建配置（如 `Release | x64`）。
3.  右键点击解决方案，选择“生成解决方案”。
4.  编译完成后，`DetectEngine.dll`、`DetectEngine.lib` 以及测试程序 `TestApp.exe` 将生成在对应的输出目录中（例如 `x64\Release\`）。

### 4.3 运行测试程序

`TestApp.exe` 是一个命令行宿主程序示例，展示了如何加载 DLL 并启动检测引擎。

*   **列出可用网卡**：
    ```cmd
    TestApp.exe -l
    ```
*   **启动实时检测**（需替换为实际的网卡设备名）：
    ```cmd
    TestApp.exe -i "\Device\NPF_{...}" -d RuleDB\vuln_rules.json -o logs
    ```
*   **离线 PCAP 分析**：
    ```cmd
    TestApp.exe -r sample_attack.pcap -d RuleDB\vuln_rules.json
    ```

## 5. 漏洞特征库扩展指南

系统的核心检测能力由 `RuleDB/vuln_rules.json` 文件驱动。安全研究人员可以人工编排新的攻击技法规则，并动态加载到引擎中。

### 5.1 规则结构示例

以下为检测 MS08-067 漏洞的无状态规则示例：

```json
{
  "id": "VDE-006",
  "name": "MS08-067-NetAPI",
  "cve": "CVE-2008-4250",
  "description": "MS08-067 NetAPI缓冲区溢出漏洞检测",
  "severity": "CRITICAL",
  "protocol": "SMB",
  "match_type": "STATELESS",
  "conditions": [
    {
      "field": "dcerpc_uuid",
      "op": "EQ",
      "value": "4b324fc8-1670-01d3-1278-5a47bf6ee188"
    },
    {
      "field": "dcerpc_opnum",
      "op": "EQ",
      "value": "0x1F"
    },
    {
      "field": "payload_pattern",
      "op": "REGEX",
      "value": "(\\.\\./|\\.\\.\\\\){3,}"
    }
  ]
}
```

### 5.2 匹配类型 (match_type)

*   `STATELESS`：单包无状态匹配。只要当前数据包满足所有 `conditions` 算子，即触发告警。
*   `STATEFUL`：有状态匹配。适用于多步攻击流程推演。当首包满足 `conditions` 时，引擎会建立会话追踪状态机；如果在规定时间 (`max_interval_ms`) 内，后续数据包满足 `follow_up` 条件，则触发最终告警。
*   `THRESHOLD`：阈值匹配。用于检测暴力破解、端口扫描等行为。当特定分组键 (`group_by`) 在时间窗口 (`window_ms`) 内的事件计数达到 `count` 阈值时触发。

### 5.3 支持的匹配字段 (field)

引擎解析层支持提取丰富的协议字段用于策略编排，包括但不限于：

*   **通用网络层**：`src_ip`, `dst_ip`, `src_port`, `dst_port`, `tcp_flags`, `payload_length`。
*   **应用层协议**：
    *   **SMB**：`smb_command`, `smb_status`, `smb_version`, `smb_tree_path`, `smb_filename`。
    *   **DCERPC**：`dcerpc_uuid`, `dcerpc_opnum`。
    *   **HTTP**：`http_method`, `http_uri`, `http_header_any`。
    *   **RDP**：`rdp_pdu_type`, `rdp_channel`。
*   **原始载荷**：`payload_pattern`（配合 REGEX 或 HEX_MATCH 算子使用）。

## 6. DLL 接口集成指南

第三方系统可通过引入 `VulnDetectEngine.h` 并链接 `DetectEngine.lib` 来集成检测能力。

核心调用流程如下：

1.  **配置初始化**：填充 `VDE_Config` 结构体，设置工作模式、网卡名称、规则库路径以及告警回调函数 (`alert_callback`)。
2.  **创建引擎**：调用 `VDE_Create(&config, &handle)` 获取引擎实例句柄。
3.  **启动检测**：调用 `VDE_Start(handle)`，引擎将在后台线程中进行数据捕获与分析。
4.  **接收告警**：当检测到攻击时，引擎会在内部线程中触发用户注册的告警回调函数，传递结构化的 `VDE_Alert` 数据。
5.  **停止与销毁**：调用 `VDE_Stop(handle)` 停止捕获，调用 `VDE_Destroy(handle)` 释放资源。

*注意：告警回调函数应尽量保持轻量，避免执行耗时的 I/O 操作，以免阻塞底层数据包捕获队列。*
