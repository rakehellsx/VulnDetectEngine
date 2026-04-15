/**
 * @file    VulnDetectEngine.h
 * @brief   漏洞攻击检测引擎 - 公共导出接口
 *
 * 本头文件定义了 VulnDetectEngine.dll 对外暴露的全部 C 接口、
 * 数据结构、枚举类型及回调函数原型。
 * 宿主程序只需包含此头文件并链接对应的导入库（.lib）即可使用。
 *
 * 编译环境：Visual Studio 2017，Windows x86/x64
 * 依  赖：WinPcap / Npcap（libpcap for Windows）
 */

#ifndef VULN_DETECT_ENGINE_H
#define VULN_DETECT_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* =========================================================
 *  导出宏
 * ========================================================= */
#ifdef VULNDETECT_EXPORTS
#   define VDE_API __declspec(dllexport)
#else
#   define VDE_API __declspec(dllimport)
#endif

/* =========================================================
 *  版本信息
 * ========================================================= */
#define VDE_VERSION_MAJOR   1
#define VDE_VERSION_MINOR   0
#define VDE_VERSION_PATCH   0
#define VDE_VERSION_STR     "1.0.0"

/* =========================================================
 *  错误码
 * ========================================================= */
typedef enum VDE_ErrorCode {
    VDE_OK                  =  0,   /**< 成功 */
    VDE_ERR_INVALID_PARAM   = -1,   /**< 参数无效 */
    VDE_ERR_INIT_FAILED     = -2,   /**< 初始化失败 */
    VDE_ERR_PCAP_OPEN       = -3,   /**< 打开网络接口失败 */
    VDE_ERR_RULE_LOAD       = -4,   /**< 规则库加载失败 */
    VDE_ERR_RULE_PARSE      = -5,   /**< 规则解析错误 */
    VDE_ERR_NO_DEVICE       = -6,   /**< 未找到网络设备 */
    VDE_ERR_ALREADY_RUNNING = -7,   /**< 引擎已在运行 */
    VDE_ERR_NOT_RUNNING     = -8,   /**< 引擎未运行 */
    VDE_ERR_MEMORY          = -9,   /**< 内存分配失败 */
    VDE_ERR_FILE_IO         = -10,  /**< 文件读写失败 */
    VDE_ERR_UNKNOWN         = -99   /**< 未知错误 */
} VDE_ErrorCode;

/* =========================================================
 *  严重级别
 * ========================================================= */
typedef enum VDE_Severity {
    VDE_SEV_INFO     = 0,
    VDE_SEV_LOW      = 1,
    VDE_SEV_MEDIUM   = 2,
    VDE_SEV_HIGH     = 3,
    VDE_SEV_CRITICAL = 4
} VDE_Severity;

/* =========================================================
 *  引擎工作模式
 * ========================================================= */
typedef enum VDE_CaptureMode {
    VDE_MODE_LIVE    = 0,   /**< 实时抓包模式（监听网卡） */
    VDE_MODE_OFFLINE = 1    /**< 离线分析模式（读取pcap文件） */
} VDE_CaptureMode;

/* =========================================================
 *  告警信息结构体
 * ========================================================= */
#define VDE_MAX_RULE_ID_LEN     32
#define VDE_MAX_RULE_NAME_LEN   128
#define VDE_MAX_CVE_LEN         32
#define VDE_MAX_DESC_LEN        512
#define VDE_MAX_PROTO_LEN       16
#define VDE_MAX_IP_LEN          46   /**< 支持IPv6 */
#define VDE_MAX_PAYLOAD_DUMP    64   /**< 告警时附带的原始载荷字节数 */

typedef struct VDE_Alert {
    char        rule_id[VDE_MAX_RULE_ID_LEN];       /**< 规则ID，如 "VDE-001" */
    char        rule_name[VDE_MAX_RULE_NAME_LEN];   /**< 规则名称 */
    char        cve[VDE_MAX_CVE_LEN];               /**< CVE编号 */
    char        description[VDE_MAX_DESC_LEN];      /**< 漏洞描述 */
    VDE_Severity severity;                          /**< 严重级别 */
    char        protocol[VDE_MAX_PROTO_LEN];        /**< 协议名称 */
    char        src_ip[VDE_MAX_IP_LEN];             /**< 源IP地址 */
    char        dst_ip[VDE_MAX_IP_LEN];             /**< 目的IP地址 */
    uint16_t    src_port;                           /**< 源端口 */
    uint16_t    dst_port;                           /**< 目的端口 */
    uint64_t    timestamp_us;                       /**< 告警时间戳（微秒，Unix epoch） */
    uint32_t    pkt_len;                            /**< 触发告警的数据包长度 */
    uint8_t     payload_dump[VDE_MAX_PAYLOAD_DUMP]; /**< 载荷前N字节 */
    uint32_t    payload_dump_len;                   /**< 实际载荷转储字节数 */
    uint64_t    session_id;                         /**< 关联会话ID（0=无状态规则） */
} VDE_Alert;

/* =========================================================
 *  告警回调函数原型
 *  当检测到攻击时，引擎在内部线程中调用此回调。
 *  注意：回调函数应尽快返回，不要在其中执行耗时操作。
 * ========================================================= */
typedef void (__cdecl *VDE_AlertCallback)(
    const VDE_Alert* alert,     /**< 告警详情（仅在回调期间有效） */
    void*            user_ctx   /**< 用户自定义上下文指针 */
);

/* =========================================================
 *  引擎配置结构体
 * ========================================================= */
#define VDE_MAX_PATH_LEN    260
#define VDE_MAX_FILTER_LEN  512
#define VDE_MAX_DEV_LEN     128

typedef struct VDE_Config {
    VDE_CaptureMode mode;                       /**< 工作模式 */
    char    device_name[VDE_MAX_DEV_LEN];       /**< 网卡名称（LIVE模式）或pcap文件路径（OFFLINE模式） */
    char    rule_db_path[VDE_MAX_PATH_LEN];     /**< 规则库JSON文件路径 */
    char    log_dir[VDE_MAX_PATH_LEN];          /**< 日志输出目录（空串=不写文件日志） */
    char    bpf_filter[VDE_MAX_FILTER_LEN];     /**< 可选BPF过滤表达式，如 "tcp port 445" */
    int     snaplen;                            /**< 抓包截断长度，0=使用默认65535 */
    int     promiscuous;                        /**< 混杂模式：1=开启，0=关闭 */
    int     read_timeout_ms;                    /**< 读超时（毫秒），0=使用默认500ms */
    int     log_level;                          /**< 日志级别：0=OFF 1=ERROR 2=WARN 3=INFO 4=DEBUG */
    VDE_AlertCallback alert_callback;           /**< 告警回调函数指针（不可为NULL） */
    void*   alert_callback_ctx;                 /**< 传递给回调的用户上下文 */
} VDE_Config;

/* =========================================================
 *  规则信息结构体（用于规则查询）
 * ========================================================= */
typedef struct VDE_RuleInfo {
    char        rule_id[VDE_MAX_RULE_ID_LEN];
    char        rule_name[VDE_MAX_RULE_NAME_LEN];
    char        cve[VDE_MAX_CVE_LEN];
    char        description[VDE_MAX_DESC_LEN];
    VDE_Severity severity;
    char        protocol[VDE_MAX_PROTO_LEN];
    uint16_t    dst_port;
    int         enabled;
} VDE_RuleInfo;

/* =========================================================
 *  统计信息结构体
 * ========================================================= */
typedef struct VDE_Statistics {
    uint64_t    packets_captured;   /**< 捕获数据包总数 */
    uint64_t    packets_analyzed;   /**< 实际分析数据包数 */
    uint64_t    packets_dropped;    /**< 驱动层丢包数 */
    uint64_t    alerts_generated;   /**< 产生告警总数 */
    uint64_t    sessions_tracked;   /**< 当前追踪会话数 */
    uint64_t    rules_loaded;       /**< 已加载规则数 */
    uint64_t    rules_enabled;      /**< 已启用规则数 */
    double      packets_per_sec;    /**< 当前处理速率（包/秒） */
} VDE_Statistics;

/* =========================================================
 *  网络设备列表（用于枚举可用网卡）
 * ========================================================= */
#define VDE_MAX_DEVICES         32
#define VDE_MAX_DEV_DESC_LEN    256

typedef struct VDE_DeviceInfo {
    char    name[VDE_MAX_DEV_LEN];          /**< 设备内部名称（传给 Config.device_name） */
    char    description[VDE_MAX_DEV_DESC_LEN]; /**< 设备友好描述 */
    char    ip_addr[VDE_MAX_IP_LEN];        /**< 设备IP地址 */
} VDE_DeviceInfo;

typedef struct VDE_DeviceList {
    VDE_DeviceInfo  devices[VDE_MAX_DEVICES];
    int             count;
} VDE_DeviceList;

/* =========================================================
 *  引擎句柄（不透明指针）
 * ========================================================= */
typedef void* VDE_Handle;

/* =========================================================
 *  导出函数声明
 * ========================================================= */

/**
 * @brief  获取引擎版本字符串
 * @return 版本字符串指针，如 "1.0.0"
 */
VDE_API const char* VDE_GetVersion(void);

/**
 * @brief  枚举系统上所有可用的网络接口
 * @param  out_list  [out] 设备列表结构体，由调用方分配
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_EnumDevices(VDE_DeviceList* out_list);

/**
 * @brief  创建检测引擎实例
 * @param  config    引擎配置（必须提供有效的 alert_callback）
 * @param  out_handle [out] 成功时返回引擎句柄
 * @return VDE_OK 或错误码
 * @note   每个进程可创建多个实例，监听不同网卡
 */
VDE_API VDE_ErrorCode VDE_Create(
    const VDE_Config*   config,
    VDE_Handle*         out_handle
);

/**
 * @brief  销毁引擎实例，释放所有资源
 * @param  handle  由 VDE_Create 返回的句柄
 */
VDE_API void VDE_Destroy(VDE_Handle handle);

/**
 * @brief  启动检测引擎（非阻塞，内部创建捕获线程）
 * @param  handle  引擎句柄
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_Start(VDE_Handle handle);

/**
 * @brief  停止检测引擎
 * @param  handle  引擎句柄
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_Stop(VDE_Handle handle);

/**
 * @brief  查询引擎是否正在运行
 * @param  handle  引擎句柄
 * @return 1=运行中，0=已停止
 */
VDE_API int VDE_IsRunning(VDE_Handle handle);

/**
 * @brief  热加载/重载规则库（无需停止引擎）
 * @param  handle       引擎句柄
 * @param  rule_db_path 新规则库JSON文件路径（NULL=重载当前路径）
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_ReloadRules(
    VDE_Handle  handle,
    const char* rule_db_path
);

/**
 * @brief  启用或禁用单条规则
 * @param  handle   引擎句柄
 * @param  rule_id  规则ID字符串，如 "VDE-001"
 * @param  enable   1=启用，0=禁用
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_SetRuleEnabled(
    VDE_Handle  handle,
    const char* rule_id,
    int         enable
);

/**
 * @brief  获取所有已加载规则的信息
 * @param  handle       引擎句柄
 * @param  out_rules    [out] 规则信息数组，由调用方分配
 * @param  max_count    数组最大容量
 * @param  out_count    [out] 实际规则数量
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_GetRules(
    VDE_Handle      handle,
    VDE_RuleInfo*   out_rules,
    int             max_count,
    int*            out_count
);

/**
 * @brief  获取引擎运行统计信息
 * @param  handle   引擎句柄
 * @param  out_stat [out] 统计信息结构体
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_GetStatistics(
    VDE_Handle      handle,
    VDE_Statistics* out_stat
);

/**
 * @brief  重置统计计数器
 * @param  handle  引擎句柄
 * @return VDE_OK 或错误码
 */
VDE_API VDE_ErrorCode VDE_ResetStatistics(VDE_Handle handle);

/**
 * @brief  获取最近一次错误的详细描述字符串
 * @param  handle  引擎句柄（可为NULL，返回全局错误）
 * @return 错误描述字符串
 */
VDE_API const char* VDE_GetLastError(VDE_Handle handle);

/**
 * @brief  将错误码转换为可读字符串
 * @param  code  错误码
 * @return 错误描述字符串
 */
VDE_API const char* VDE_ErrorString(VDE_ErrorCode code);

/**
 * @brief  将严重级别枚举转换为字符串
 * @param  sev  严重级别
 * @return 字符串，如 "CRITICAL"
 */
VDE_API const char* VDE_SeverityString(VDE_Severity sev);

#ifdef __cplusplus
}
#endif

#endif /* VULN_DETECT_ENGINE_H */
