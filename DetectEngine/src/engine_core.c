/**
 * @file    engine_core.c
 * @brief   DLL 核心引擎实现
 *          - 管理 pcap 句柄与捕获线程
 *          - 实现全部 VDE_API 导出函数
 *          - 内部使用 RuleEngine + ProtoParser + Logger
 */

#define VULNDETECT_EXPORTS
#include "../include/VulnDetectEngine.h"
#include "../include/proto_parser.h"
#include "../include/rule_engine.h"
#include "../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* WinPcap / Npcap */
#ifdef _WIN32
#  include <winsock2.h>
#  include <windows.h>
   /* Npcap 安装在 System32\Npcap，需在项目属性中配置附加包含目录 */
#  include <pcap/pcap.h>
#  pragma comment(lib, "wpcap.lib")
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <pcap/pcap.h>
#  include <pthread.h>
#  include <unistd.h>
#endif

/* =========================================================
 *  引擎实例结构体（不透明句柄的真实类型）
 * ========================================================= */
#define VDE_MAX_ERROR_LEN   512

typedef struct VDE_Instance {
    VDE_Config      config;
    RuleEngine      rule_engine;
    Logger          logger;

    pcap_t*         pcap_handle;
    char            pcap_errbuf[PCAP_ERRBUF_SIZE];

    /* 统计 */
    volatile uint64_t stat_captured;
    volatile uint64_t stat_analyzed;
    volatile uint64_t stat_alerts;
    volatile uint64_t stat_dropped;

    /* 运行状态 */
    volatile int    running;
    volatile int    stop_requested;

    /* 捕获线程 */
#ifdef _WIN32
    HANDLE          capture_thread;
    CRITICAL_SECTION stat_lock;
#else
    pthread_t       capture_thread;
    pthread_mutex_t stat_lock;
#endif

    /* 错误信息 */
    char            last_error[VDE_MAX_ERROR_LEN];

    /* 速率统计 */
    uint64_t        rate_pkt_count;
    uint64_t        rate_last_time_us;
    double          packets_per_sec;

} VDE_Instance;

/* =========================================================
 *  内部辅助
 * ========================================================= */
static void set_error(VDE_Instance* inst, const char* fmt, ...)
{
    if (!inst) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(inst->last_error, sizeof(inst->last_error), fmt, args);
    va_end(args);
}

static uint64_t now_us(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= 116444736000000000ULL;
    return t / 10;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
#endif
}

/* =========================================================
 *  pcap 数据包回调
 * ========================================================= */
static void pcap_packet_handler(
    u_char*                 user,
    const struct pcap_pkthdr* pkthdr,
    const u_char*           packet)
{
    VDE_Instance* inst = (VDE_Instance*)user;
    if (!inst || inst->stop_requested) return;

    uint64_t ts = (uint64_t)pkthdr->ts.tv_sec * 1000000ULL
                + (uint64_t)pkthdr->ts.tv_usec;

#ifdef _WIN32
    InterlockedIncrement64((LONGLONG*)&inst->stat_captured);
#else
    __sync_fetch_and_add(&inst->stat_captured, 1);
#endif

    /* 协议解析 */
    ParsedPacket pkt;
    if (!PP_ParsePacket(packet, pkthdr->caplen, ts, &pkt)) return;

#ifdef _WIN32
    InterlockedIncrement64((LONGLONG*)&inst->stat_analyzed);
#else
    __sync_fetch_and_add(&inst->stat_analyzed, 1);
#endif

    /* 规则匹配 */
    VDE_Alert alert;
    if (RE_MatchPacket(&inst->rule_engine, &pkt, &alert)) {
#ifdef _WIN32
        InterlockedIncrement64((LONGLONG*)&inst->stat_alerts);
#else
        __sync_fetch_and_add(&inst->stat_alerts, 1);
#endif
        /* 写日志 */
        Logger_WriteAlert(&inst->logger, &alert);

        /* 调用用户回调 */
        if (inst->config.alert_callback) {
            inst->config.alert_callback(&alert, inst->config.alert_callback_ctx);
        }
    }

    /* 速率统计（每 1000 包更新一次） */
    inst->rate_pkt_count++;
    if (inst->rate_pkt_count % 1000 == 0) {
        uint64_t cur_us = now_us();
        uint64_t elapsed = cur_us - inst->rate_last_time_us;
        if (elapsed > 0) {
            inst->packets_per_sec = 1000.0 * 1e6 / (double)elapsed;
            inst->rate_last_time_us = cur_us;
        }
    }

    /* 定期清理过期会话（每 10000 包） */
    if (inst->stat_captured % 10000 == 0) {
        RE_PurgeExpiredSessions(&inst->rule_engine, ts);
    }
}

/* =========================================================
 *  捕获线程函数
 * ========================================================= */
#ifdef _WIN32
static DWORD WINAPI capture_thread_func(LPVOID param)
#else
static void* capture_thread_func(void* param)
#endif
{
    VDE_Instance* inst = (VDE_Instance*)param;

    LOG_I(&inst->logger, "捕获线程启动，设备: %s", inst->config.device_name);

    /* pcap_loop 阻塞直到 stop_requested */
    int ret = pcap_loop(inst->pcap_handle, -1,
                        pcap_packet_handler, (u_char*)inst);

    if (ret == -1 && !inst->stop_requested) {
        LOG_E(&inst->logger, "pcap_loop 错误: %s",
              pcap_geterr(inst->pcap_handle));
    }

    LOG_I(&inst->logger, "捕获线程退出");
    inst->running = 0;

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* =========================================================
 *  VDE_GetVersion
 * ========================================================= */
VDE_API const char* VDE_GetVersion(void)
{
    return VDE_VERSION_STR;
}

/* =========================================================
 *  VDE_ErrorString
 * ========================================================= */
VDE_API const char* VDE_ErrorString(VDE_ErrorCode code)
{
    switch (code) {
        case VDE_OK:                  return "Success";
        case VDE_ERR_INVALID_PARAM:   return "Invalid parameter";
        case VDE_ERR_INIT_FAILED:     return "Initialization failed";
        case VDE_ERR_PCAP_OPEN:       return "Failed to open pcap device";
        case VDE_ERR_RULE_LOAD:       return "Failed to load rule database";
        case VDE_ERR_RULE_PARSE:      return "Rule parsing error";
        case VDE_ERR_NO_DEVICE:       return "No network device found";
        case VDE_ERR_ALREADY_RUNNING: return "Engine is already running";
        case VDE_ERR_NOT_RUNNING:     return "Engine is not running";
        case VDE_ERR_MEMORY:          return "Memory allocation failed";
        case VDE_ERR_FILE_IO:         return "File I/O error";
        default:                      return "Unknown error";
    }
}

/* =========================================================
 *  VDE_SeverityString
 * ========================================================= */
VDE_API const char* VDE_SeverityString(VDE_Severity sev)
{
    switch (sev) {
        case VDE_SEV_INFO:     return "INFO";
        case VDE_SEV_LOW:      return "LOW";
        case VDE_SEV_MEDIUM:   return "MEDIUM";
        case VDE_SEV_HIGH:     return "HIGH";
        case VDE_SEV_CRITICAL: return "CRITICAL";
        default:               return "UNKNOWN";
    }
}

/* =========================================================
 *  VDE_EnumDevices
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_EnumDevices(VDE_DeviceList* out_list)
{
    if (!out_list) return VDE_ERR_INVALID_PARAM;
    memset(out_list, 0, sizeof(VDE_DeviceList));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs)
        return VDE_ERR_NO_DEVICE;

    int count = 0;
    for (pcap_if_t* d = alldevs;
         d && count < VDE_MAX_DEVICES;
         d = d->next, count++)
    {
        VDE_DeviceInfo* di = &out_list->devices[count];
        strncpy(di->name, d->name, sizeof(di->name) - 1);
        if (d->description)
            strncpy(di->description, d->description, sizeof(di->description) - 1);
        /* 获取第一个 IPv4 地址 */
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, di->ip_addr, sizeof(di->ip_addr));
                break;
            }
        }
    }
    out_list->count = count;
    pcap_freealldevs(alldevs);
    return VDE_OK;
}

/* =========================================================
 *  VDE_Create
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_Create(
    const VDE_Config*   config,
    VDE_Handle*         out_handle)
{
    if (!config || !out_handle) return VDE_ERR_INVALID_PARAM;
    if (!config->alert_callback)  return VDE_ERR_INVALID_PARAM;

    VDE_Instance* inst = (VDE_Instance*)calloc(1, sizeof(VDE_Instance));
    if (!inst) return VDE_ERR_MEMORY;

    /* 复制配置 */
    memcpy(&inst->config, config, sizeof(VDE_Config));

    /* 初始化日志 */
    LogLevel ll = (LogLevel)(config->log_level < 0 ? 0 :
                             config->log_level > 4 ? 4 : config->log_level);
    if (!Logger_Init(&inst->logger, config->log_dir, ll)) {
        free(inst);
        return VDE_ERR_INIT_FAILED;
    }

    /* 初始化规则引擎 */
    if (!RE_Init(&inst->rule_engine)) {
        Logger_Destroy(&inst->logger);
        free(inst);
        return VDE_ERR_INIT_FAILED;
    }

    /* 加载规则库 */
    if (config->rule_db_path[0]) {
        int loaded = RE_LoadRules(&inst->rule_engine, config->rule_db_path);
        if (loaded < 0) {
            set_error(inst, "规则库加载失败: %s", config->rule_db_path);
            LOG_E(&inst->logger, "%s", inst->last_error);
            RE_Destroy(&inst->rule_engine);
            Logger_Destroy(&inst->logger);
            free(inst);
            return VDE_ERR_RULE_LOAD;
        }
        LOG_I(&inst->logger, "规则库加载成功，共 %d 条规则 (版本 %s)",
              loaded, inst->rule_engine.ruleset.version);
    }

    /* 初始化统计锁 */
#ifdef _WIN32
    InitializeCriticalSection(&inst->stat_lock);
#else
    pthread_mutex_init(&inst->stat_lock, NULL);
#endif

    inst->rate_last_time_us = now_us();

    LOG_I(&inst->logger, "引擎实例创建成功，版本 %s", VDE_VERSION_STR);
    *out_handle = (VDE_Handle)inst;
    return VDE_OK;
}

/* =========================================================
 *  VDE_Destroy
 * ========================================================= */
VDE_API void VDE_Destroy(VDE_Handle handle)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst) return;

    if (inst->running) VDE_Stop(handle);

    RE_Destroy(&inst->rule_engine);
    Logger_Destroy(&inst->logger);

    if (inst->pcap_handle) {
        pcap_close(inst->pcap_handle);
        inst->pcap_handle = NULL;
    }

#ifdef _WIN32
    DeleteCriticalSection(&inst->stat_lock);
#else
    pthread_mutex_destroy(&inst->stat_lock);
#endif

    free(inst);
}

/* =========================================================
 *  VDE_Start
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_Start(VDE_Handle handle)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst) return VDE_ERR_INVALID_PARAM;
    if (inst->running) return VDE_ERR_ALREADY_RUNNING;

    inst->stop_requested = 0;

    int snaplen  = inst->config.snaplen > 0 ? inst->config.snaplen : 65535;
    int promisc  = inst->config.promiscuous;
    int timeout  = inst->config.read_timeout_ms > 0
                   ? inst->config.read_timeout_ms : 500;

    if (inst->config.mode == VDE_MODE_LIVE) {
        /* 实时抓包 */
        inst->pcap_handle = pcap_open_live(
            inst->config.device_name,
            snaplen, promisc, timeout,
            inst->pcap_errbuf);
    } else {
        /* 离线 pcap 文件分析 */
        inst->pcap_handle = pcap_open_offline(
            inst->config.device_name,
            inst->pcap_errbuf);
    }

    if (!inst->pcap_handle) {
        set_error(inst, "pcap 打开失败: %s", inst->pcap_errbuf);
        LOG_E(&inst->logger, "%s", inst->last_error);
        return VDE_ERR_PCAP_OPEN;
    }

    /* 设置 BPF 过滤器 */
    if (inst->config.bpf_filter[0]) {
        struct bpf_program fp;
        if (pcap_compile(inst->pcap_handle, &fp,
                         inst->config.bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(inst->pcap_handle, &fp);
            pcap_freecode(&fp);
            LOG_I(&inst->logger, "BPF 过滤器已设置: %s", inst->config.bpf_filter);
        } else {
            LOG_W(&inst->logger, "BPF 过滤器编译失败: %s",
                  pcap_geterr(inst->pcap_handle));
        }
    }

    inst->running = 1;

    /* 启动捕获线程 */
#ifdef _WIN32
    inst->capture_thread = CreateThread(
        NULL, 0, capture_thread_func, inst, 0, NULL);
    if (!inst->capture_thread) {
        inst->running = 0;
        pcap_close(inst->pcap_handle);
        inst->pcap_handle = NULL;
        set_error(inst, "创建捕获线程失败，错误码: %lu", GetLastError());
        return VDE_ERR_INIT_FAILED;
    }
#else
    if (pthread_create(&inst->capture_thread, NULL,
                       capture_thread_func, inst) != 0) {
        inst->running = 0;
        pcap_close(inst->pcap_handle);
        inst->pcap_handle = NULL;
        set_error(inst, "创建捕获线程失败");
        return VDE_ERR_INIT_FAILED;
    }
#endif

    LOG_I(&inst->logger, "引擎启动，模式: %s，设备/文件: %s",
          inst->config.mode == VDE_MODE_LIVE ? "LIVE" : "OFFLINE",
          inst->config.device_name);
    return VDE_OK;
}

/* =========================================================
 *  VDE_Stop
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_Stop(VDE_Handle handle)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst) return VDE_ERR_INVALID_PARAM;
    if (!inst->running) return VDE_ERR_NOT_RUNNING;

    inst->stop_requested = 1;

    if (inst->pcap_handle) {
        pcap_breakloop(inst->pcap_handle);
    }

    /* 等待线程退出（最多 5 秒） */
#ifdef _WIN32
    if (inst->capture_thread) {
        WaitForSingleObject(inst->capture_thread, 5000);
        CloseHandle(inst->capture_thread);
        inst->capture_thread = NULL;
    }
#else
    pthread_join(inst->capture_thread, NULL);
#endif

    if (inst->pcap_handle) {
        /* 获取 pcap 统计 */
        struct pcap_stat ps;
        if (pcap_stats(inst->pcap_handle, &ps) == 0) {
            inst->stat_dropped = ps.ps_drop;
        }
        pcap_close(inst->pcap_handle);
        inst->pcap_handle = NULL;
    }

    inst->running = 0;
    LOG_I(&inst->logger,
          "引擎已停止。捕获: %llu 包，分析: %llu 包，告警: %llu 次，丢包: %llu",
          (unsigned long long)inst->stat_captured,
          (unsigned long long)inst->stat_analyzed,
          (unsigned long long)inst->stat_alerts,
          (unsigned long long)inst->stat_dropped);
    return VDE_OK;
}

/* =========================================================
 *  VDE_IsRunning
 * ========================================================= */
VDE_API int VDE_IsRunning(VDE_Handle handle)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    return inst ? inst->running : 0;
}

/* =========================================================
 *  VDE_ReloadRules
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_ReloadRules(VDE_Handle handle, const char* rule_db_path)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst) return VDE_ERR_INVALID_PARAM;

    const char* path = (rule_db_path && rule_db_path[0])
                       ? rule_db_path
                       : inst->config.rule_db_path;

    int loaded = RE_LoadRules(&inst->rule_engine, path);
    if (loaded < 0) {
        set_error(inst, "规则库重载失败: %s", path);
        LOG_E(&inst->logger, "%s", inst->last_error);
        return VDE_ERR_RULE_LOAD;
    }

    if (rule_db_path && rule_db_path[0]) {
        strncpy(inst->config.rule_db_path, rule_db_path,
                sizeof(inst->config.rule_db_path) - 1);
    }

    LOG_I(&inst->logger, "规则库已热重载，共 %d 条规则", loaded);
    return VDE_OK;
}

/* =========================================================
 *  VDE_SetRuleEnabled
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_SetRuleEnabled(
    VDE_Handle handle, const char* rule_id, int enable)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst || !rule_id) return VDE_ERR_INVALID_PARAM;

    if (!RE_SetRuleEnabled(&inst->rule_engine, rule_id, enable)) {
        set_error(inst, "规则 %s 未找到", rule_id);
        return VDE_ERR_INVALID_PARAM;
    }
    LOG_I(&inst->logger, "规则 %s 已%s", rule_id, enable ? "启用" : "禁用");
    return VDE_OK;
}

/* =========================================================
 *  VDE_GetRules
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_GetRules(
    VDE_Handle      handle,
    VDE_RuleInfo*   out_rules,
    int             max_count,
    int*            out_count)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst || !out_rules || !out_count) return VDE_ERR_INVALID_PARAM;

    int n = inst->rule_engine.ruleset.count;
    if (n > max_count) n = max_count;

    for (int i = 0; i < n; i++) {
        const Rule* r = &inst->rule_engine.ruleset.rules[i];
        VDE_RuleInfo* ri = &out_rules[i];
        strncpy(ri->rule_id,     r->rule_id,     sizeof(ri->rule_id) - 1);
        strncpy(ri->rule_name,   r->name,         sizeof(ri->rule_name) - 1);
        strncpy(ri->cve,         r->cve,          sizeof(ri->cve) - 1);
        strncpy(ri->description, r->description,  sizeof(ri->description) - 1);
        strncpy(ri->protocol,    r->protocol,     sizeof(ri->protocol) - 1);
        ri->severity = r->severity;
        ri->dst_port = r->dst_port;
        ri->enabled  = r->enabled;
    }
    *out_count = n;
    return VDE_OK;
}

/* =========================================================
 *  VDE_GetStatistics
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_GetStatistics(
    VDE_Handle      handle,
    VDE_Statistics* out_stat)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst || !out_stat) return VDE_ERR_INVALID_PARAM;

    memset(out_stat, 0, sizeof(VDE_Statistics));
    out_stat->packets_captured  = inst->stat_captured;
    out_stat->packets_analyzed  = inst->stat_analyzed;
    out_stat->packets_dropped   = inst->stat_dropped;
    out_stat->alerts_generated  = inst->stat_alerts;
    out_stat->sessions_tracked  = RE_GetSessionCount(&inst->rule_engine);
    out_stat->rules_loaded      = (uint64_t)inst->rule_engine.ruleset.count;
    out_stat->packets_per_sec   = inst->packets_per_sec;

    /* 统计已启用规则数 */
    uint64_t enabled = 0;
    for (int i = 0; i < inst->rule_engine.ruleset.count; i++) {
        if (inst->rule_engine.ruleset.rules[i].enabled) enabled++;
    }
    out_stat->rules_enabled = enabled;

    return VDE_OK;
}

/* =========================================================
 *  VDE_ResetStatistics
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_ResetStatistics(VDE_Handle handle)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst) return VDE_ERR_INVALID_PARAM;

    inst->stat_captured = 0;
    inst->stat_analyzed = 0;
    inst->stat_alerts   = 0;
    inst->stat_dropped  = 0;
    inst->rate_pkt_count = 0;
    inst->packets_per_sec = 0.0;
    inst->rate_last_time_us = now_us();
    return VDE_OK;
}

/* =========================================================
 *  VDE_GetLastError
 * ========================================================= */
VDE_API const char* VDE_GetLastError(VDE_Handle handle)
{
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (!inst) return "Invalid handle";
    return inst->last_error;
}
