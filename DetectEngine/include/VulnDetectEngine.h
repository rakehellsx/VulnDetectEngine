/**
 * @file    VulnDetectEngine.h
 * @brief   漏洞攻击检测引擎 v3.0 — 公共导出接口
 *
 * 多线程多网卡架构：
 *   - VDE_Start() 自动枚举所有非 127.0.0.1 接口，每个接口独立捕获线程
 *   - 所有线程共享规则引擎（读写锁保护），共享告警回调
 *   - VDE_GetStatistics()     返回全局聚合统计
 *   - VDE_GetIfaceStatistics() 返回每个接口的独立统计
 *
 * 跨平台：Windows VS2017 + Npcap SDK / Linux GCC + libpcap + nDPI
 */

#ifndef VULN_DETECT_ENGINE_H
#define VULN_DETECT_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* =========================================================
 *  平台导出宏
 * ========================================================= */
#ifdef _WIN32
#   ifdef VULNDETECT_EXPORTS
#       define VDE_API __declspec(dllexport)
#   else
#       define VDE_API __declspec(dllimport)
#   endif
#   define VDE_CALLBACK __cdecl
#else
#   ifdef VULNDETECT_EXPORTS
#       define VDE_API __attribute__((visibility("default")))
#   else
#       define VDE_API
#   endif
#   define VDE_CALLBACK
#   ifndef __cdecl
#       define __cdecl
#   endif
#endif

/* =========================================================
 *  版本
 * ========================================================= */
#define VDE_VERSION_MAJOR   3
#define VDE_VERSION_MINOR   0
#define VDE_VERSION_PATCH   0
#define VDE_VERSION_STR     "3.0.0"

/* =========================================================
 *  常量
 * ========================================================= */
#define VDE_MAX_RULE_ID_LEN     32
#define VDE_MAX_RULE_NAME_LEN   128
#define VDE_MAX_CVE_LEN         32
#define VDE_MAX_DESC_LEN        512
#define VDE_MAX_PROTO_LEN       16
#define VDE_MAX_IP_LEN          46
#define VDE_MAX_PAYLOAD_DUMP    64
#define VDE_MAX_PATH_LEN        260
#define VDE_MAX_FILTER_LEN      512
#define VDE_MAX_DEV_LEN         128
#define VDE_MAX_DEV_DESC_LEN    256
#define VDE_MAX_DEVICES         32

/* =========================================================
 *  错误码
 * ========================================================= */
typedef enum VDE_ErrorCode {
    VDE_OK                  =  0,
    VDE_ERR_INVALID_PARAM   = -1,
    VDE_ERR_INIT_FAILED     = -2,
    VDE_ERR_PCAP_OPEN       = -3,
    VDE_ERR_RULE_LOAD       = -4,
    VDE_ERR_RULE_PARSE      = -5,
    VDE_ERR_NO_DEVICE       = -6,
    VDE_ERR_ALREADY_RUNNING = -7,
    VDE_ERR_NOT_RUNNING     = -8,
    VDE_ERR_MEMORY          = -9,
    VDE_ERR_FILE_IO         = -10,
    VDE_ERR_NO_INTERFACES   = -11,  /**< 未找到任何可用非 loopback 接口 */
    VDE_ERR_PARTIAL         = -12,  /**< 部分接口启动成功（至少一个失败） */
    VDE_ERR_UNKNOWN         = -99
} VDE_ErrorCode;

/* =========================================================
 *  工作模式
 * ========================================================= */
typedef enum VDE_CaptureMode {
    VDE_MODE_LIVE    = 0,   /**< 实时抓包：自动枚举所有非 loopback 接口，每卡一线程 */
    VDE_MODE_OFFLINE = 1    /**< 离线分析：读取单个 pcap 文件，单线程 */
} VDE_CaptureMode;

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
 *  告警结构体
 * ========================================================= */
typedef struct VDE_Alert {
    char        rule_id[VDE_MAX_RULE_ID_LEN];
    char        rule_name[VDE_MAX_RULE_NAME_LEN];
    char        cve[VDE_MAX_CVE_LEN];
    char        description[VDE_MAX_DESC_LEN];
    VDE_Severity severity;
    char        protocol[VDE_MAX_PROTO_LEN];
    char        src_ip[VDE_MAX_IP_LEN];
    char        dst_ip[VDE_MAX_IP_LEN];
    uint16_t    src_port;
    uint16_t    dst_port;
    uint64_t    timestamp_us;
    uint32_t    pkt_len;
    uint8_t     payload_dump[VDE_MAX_PAYLOAD_DUMP];
    uint32_t    payload_dump_len;
    uint64_t    session_id;
    char        iface_name[VDE_MAX_DEV_LEN];  /**< 触发告警的网卡名 */
} VDE_Alert;

/* =========================================================
 *  告警回调
 * ========================================================= */
typedef void (VDE_CALLBACK *VDE_AlertCallback)(
    const VDE_Alert* alert,
    void*            user_ctx
);

/* =========================================================
 *  引擎配置
 * ========================================================= */
typedef struct VDE_Config {
    VDE_CaptureMode mode;
    char    pcap_file[VDE_MAX_PATH_LEN];        /**< OFFLINE 模式：pcap 文件路径 */
    char    rule_db_path[VDE_MAX_PATH_LEN];     /**< 规则库 JSON 路径 */
    char    log_dir[VDE_MAX_PATH_LEN];          /**< 日志目录（空=不写文件） */
    char    bpf_filter[VDE_MAX_FILTER_LEN];     /**< BPF 过滤（所有接口共用） */
    int     snaplen;                            /**< 截断长度，0=65535 */
    int     promiscuous;                        /**< 混杂模式 1=开 */
    int     read_timeout_ms;                    /**< 读超时 ms，0=500 */
    int     log_level;                          /**< 0=OFF 1=ERR 2=WARN 3=INFO 4=DEBUG */
    VDE_AlertCallback alert_callback;
    void*   alert_callback_ctx;
} VDE_Config;

/* =========================================================
 *  单网卡统计
 * ========================================================= */
typedef struct VDE_IfaceStatistics {
    char        iface_name[VDE_MAX_DEV_LEN];
    char        ip_addr[VDE_MAX_IP_LEN];
    int         running;                /**< 1=线程运行中 */
    uint64_t    packets_captured;
    uint64_t    packets_analyzed;
    uint64_t    packets_dropped;
    uint64_t    alerts_generated;
    double      packets_per_sec;
} VDE_IfaceStatistics;

/* =========================================================
 *  全局聚合统计
 * ========================================================= */
typedef struct VDE_Statistics {
    uint64_t    packets_captured;
    uint64_t    packets_analyzed;
    uint64_t    packets_dropped;
    uint64_t    alerts_generated;
    uint64_t    sessions_tracked;
    uint64_t    rules_loaded;
    uint64_t    rules_enabled;
    double      packets_per_sec;
    int         iface_count;        /**< 已启动的接口数 */
    int         iface_running;      /**< 当前活跃线程数 */
} VDE_Statistics;

/* =========================================================
 *  网络设备信息
 * ========================================================= */
typedef struct VDE_DeviceInfo {
    char    name[VDE_MAX_DEV_LEN];
    char    description[VDE_MAX_DEV_DESC_LEN];
    char    ip_addr[VDE_MAX_IP_LEN];
    int     is_loopback;
} VDE_DeviceInfo;

typedef struct VDE_DeviceList {
    VDE_DeviceInfo  devices[VDE_MAX_DEVICES];
    int             count;
} VDE_DeviceList;

/* =========================================================
 *  规则信息（VDE_GetRules 输出）
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
 *  引擎句柄（不透明指针）
 * ========================================================= */
typedef void* VDE_Handle;

/* =========================================================
 *  导出函数
 * ========================================================= */

VDE_API const char*     VDE_GetVersion(void);
VDE_API VDE_ErrorCode   VDE_EnumDevices(VDE_DeviceList* out_list);

/**
 * @brief 创建引擎实例
 * LIVE 模式下 config->pcap_file 忽略；
 * OFFLINE 模式下 config->pcap_file 为 pcap 文件路径。
 */
VDE_API VDE_ErrorCode   VDE_Create(const VDE_Config* config, VDE_Handle* out_handle);
VDE_API void            VDE_Destroy(VDE_Handle handle);

/**
 * @brief 启动引擎
 * LIVE 模式：自动枚举所有非 127.0.0.1 接口，每个接口启动独立捕获线程。
 *            至少一个接口成功则返回 VDE_OK；全部失败返回 VDE_ERR_NO_INTERFACES。
 *            部分失败返回 VDE_ERR_PARTIAL。
 * OFFLINE 模式：对 pcap_file 启动单个分析线程。
 */
VDE_API VDE_ErrorCode   VDE_Start(VDE_Handle handle);
VDE_API VDE_ErrorCode   VDE_Stop(VDE_Handle handle);
VDE_API int             VDE_IsRunning(VDE_Handle handle);

VDE_API VDE_ErrorCode   VDE_ReloadRules(VDE_Handle handle, const char* rule_db_path);
VDE_API VDE_ErrorCode   VDE_SetRuleEnabled(VDE_Handle handle, const char* rule_id, int enable);
VDE_API VDE_ErrorCode   VDE_GetRules(VDE_Handle handle, VDE_RuleInfo* out_rules,
                                     int max_count, int* out_count);

VDE_API VDE_ErrorCode   VDE_GetStatistics(VDE_Handle handle, VDE_Statistics* out_stat);

/**
 * @brief 获取每个接口的独立统计
 * @param out_stats  调用方分配的数组，长度 >= VDE_MAX_DEVICES
 * @param out_count  实际返回的接口数
 */
VDE_API VDE_ErrorCode   VDE_GetIfaceStatistics(VDE_Handle handle,
                                               VDE_IfaceStatistics* out_stats,
                                               int max_count, int* out_count);

VDE_API VDE_ErrorCode   VDE_ResetStatistics(VDE_Handle handle);
VDE_API const char*     VDE_GetLastError(VDE_Handle handle);
VDE_API const char*     VDE_ErrorString(VDE_ErrorCode code);
VDE_API const char*     VDE_SeverityString(VDE_Severity sev);

#ifdef __cplusplus
}
#endif

#endif /* VULN_DETECT_ENGINE_H */
