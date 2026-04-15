/**
 * @file  engine_core.c
 * @brief 漏洞检测引擎核心 v3.0 — 多线程多网卡
 *
 * 架构：
 *   VDE_Instance
 *     ├── RuleEngine re          (共享，pthread_rwlock 保护)
 *     ├── IfaceWorker workers[N] (每非loopback网卡一个)
 *     │     ├── pcap_t*          (独立 pcap 句柄)
 *     │     ├── pthread_t        (独立捕获线程)
 *     │     ├── 原子统计计数器   (无锁)
 *     │     └── NdpiContext      (Linux，每线程独立)
 *     ├── alert_mutex            (串行化告警回调)
 *     └── 全局告警回调 + 用户上下文
 */

#define _GNU_SOURCE
#define VULNDETECT_EXPORTS

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "wpcap.lib")
#else
#  include <pthread.h>
#  include <unistd.h>
#  include <arpa/inet.h>
#  include <sys/time.h>
#  include <strings.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pcap.h>

#include "../include/VulnDetectEngine.h"
#include "../include/proto_parser.h"
#include "../include/rule_engine.h"
#include "../include/logger.h"

/* =========================================================
 *  平台抽象层
 * ========================================================= */
#ifdef _WIN32
typedef HANDLE           vde_thread_t;
typedef SRWLOCK          vde_rwlock_t;
typedef CRITICAL_SECTION vde_mutex_t;
typedef volatile LONG    vde_atomic_t;

#define VDE_RWLOCK_INIT(l)      InitializeSRWLock(l)
#define VDE_RWLOCK_RDLOCK(l)    AcquireSRWLockShared(l)
#define VDE_RWLOCK_RDUNLOCK(l)  ReleaseSRWLockShared(l)
#define VDE_RWLOCK_WRLOCK(l)    AcquireSRWLockExclusive(l)
#define VDE_RWLOCK_WRUNLOCK(l)  ReleaseSRWLockExclusive(l)
#define VDE_RWLOCK_DESTROY(l)   /* SRW 无需销毁 */

#define VDE_MUTEX_INIT(m)       InitializeCriticalSection(m)
#define VDE_MUTEX_LOCK(m)       EnterCriticalSection(m)
#define VDE_MUTEX_UNLOCK(m)     LeaveCriticalSection(m)
#define VDE_MUTEX_DESTROY(m)    DeleteCriticalSection(m)

#define VDE_ATOMIC_INC(p)       InterlockedIncrement(p)
#define VDE_ATOMIC_ADD(p,v)     InterlockedAdd((LONG*)(p), (LONG)(v))
#define VDE_ATOMIC_LOAD(p)      (*(volatile LONG*)(p))
#define VDE_ATOMIC_STORE(p,v)   InterlockedExchange((LONG*)(p),(LONG)(v))

static uint64_t vde_now_us(void) {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ui; ui.LowPart=ft.dwLowDateTime; ui.HighPart=ft.dwHighDateTime;
    return ui.QuadPart/10ULL - 11644473600000000ULL;
}
static DWORD WINAPI thread_entry(LPVOID arg);
#define VDE_THREAD_CREATE(t,arg) (*(t)=CreateThread(NULL,0,thread_entry,(arg),0,NULL), *(t)?0:-1)
#define VDE_THREAD_JOIN(t)       do{WaitForSingleObject(t,10000);CloseHandle(t);}while(0)

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

#else /* Linux */
typedef pthread_t        vde_thread_t;
typedef pthread_rwlock_t vde_rwlock_t;
typedef pthread_mutex_t  vde_mutex_t;
typedef volatile long    vde_atomic_t;

#define VDE_RWLOCK_INIT(l)      pthread_rwlock_init(l,NULL)
#define VDE_RWLOCK_RDLOCK(l)    pthread_rwlock_rdlock(l)
#define VDE_RWLOCK_RDUNLOCK(l)  pthread_rwlock_unlock(l)
#define VDE_RWLOCK_WRLOCK(l)    pthread_rwlock_wrlock(l)
#define VDE_RWLOCK_WRUNLOCK(l)  pthread_rwlock_unlock(l)
#define VDE_RWLOCK_DESTROY(l)   pthread_rwlock_destroy(l)

#define VDE_MUTEX_INIT(m)       pthread_mutex_init(m,NULL)
#define VDE_MUTEX_LOCK(m)       pthread_mutex_lock(m)
#define VDE_MUTEX_UNLOCK(m)     pthread_mutex_unlock(m)
#define VDE_MUTEX_DESTROY(m)    pthread_mutex_destroy(m)

#define VDE_ATOMIC_INC(p)       __sync_fetch_and_add(p,1)
#define VDE_ATOMIC_ADD(p,v)     __sync_fetch_and_add(p,(long)(v))
#define VDE_ATOMIC_LOAD(p)      __sync_fetch_and_add(p,0)
#define VDE_ATOMIC_STORE(p,v)   __atomic_store_n(p,(long)(v),__ATOMIC_SEQ_CST)

static uint64_t vde_now_us(void) {
    struct timeval tv; gettimeofday(&tv,NULL);
    return (uint64_t)tv.tv_sec*1000000ULL+(uint64_t)tv.tv_usec;
}
static void* thread_entry(void* arg);
#define VDE_THREAD_CREATE(t,arg) pthread_create(t,NULL,thread_entry,(arg))
#define VDE_THREAD_JOIN(t)       pthread_join(t,NULL)
#endif

/* =========================================================
 *  每网卡工作单元
 * ========================================================= */
struct VDE_Instance;  /* 前向声明 */

typedef struct IfaceWorker {
    char            iface_name[VDE_MAX_DEV_LEN];
    char            ip_addr[VDE_MAX_IP_LEN];
    pcap_t*         pcap_handle;
    vde_thread_t    thread;
    volatile int    running;
    volatile int    thread_started;

    /* 独立原子统计 */
    vde_atomic_t    pkt_captured;
    vde_atomic_t    pkt_analyzed;
    vde_atomic_t    pkt_dropped;
    vde_atomic_t    alerts;

    /* 速率 */
    uint64_t        last_ts_us;
    uint64_t        last_pkt_snap;
    double          pps;

#ifndef _WIN32
    NdpiContext     ndpi_ctx;   /* 每线程独立 nDPI 上下文 */
#endif

    struct VDE_Instance* inst;
} IfaceWorker;

/* =========================================================
 *  引擎实例
 * ========================================================= */
typedef struct VDE_Instance {
    VDE_Config      config;
    char            last_error[512];

    /* 规则引擎（共享，读写锁保护） */
    RuleEngine      re;
    vde_rwlock_t    re_rwlock;

    /* 告警回调串行化 */
    vde_mutex_t     alert_mutex;

    /* 网卡工作线程 */
    IfaceWorker     workers[VDE_MAX_DEVICES];
    int             worker_count;

    /* 全局会话计数（原子） */
    vde_atomic_t    sessions_tracked;

    uint64_t        start_ts_us;
} VDE_Instance;

/* =========================================================
 *  全局 Logger 实例（进程级）
 * ========================================================= */
static Logger g_logger;
static int    g_logger_inited = 0;

/* 兼容宏：将旧式 LOG_Info/LOG_Error 等映射到 Logger 实例宏 */
#define LOG_Info(fmt, ...)   do { if(g_logger_inited) LOG_I(&g_logger, fmt, ##__VA_ARGS__); } while(0)
#define LOG_Error(fmt, ...)  do { if(g_logger_inited) LOG_E(&g_logger, fmt, ##__VA_ARGS__); } while(0)
#define LOG_Warn(fmt, ...)   do { if(g_logger_inited) LOG_W(&g_logger, fmt, ##__VA_ARGS__); } while(0)
#define LOG_Debug(fmt, ...)  do { if(g_logger_inited) LOG_D(&g_logger, fmt, ##__VA_ARGS__); } while(0)
#define LOG_Alert(a)         do { if(g_logger_inited) Logger_WriteAlert(&g_logger, (a)); } while(0)
#define LOG_Init(lvl, dir)   do { Logger_Init(&g_logger, (dir), (LogLevel)(lvl)); g_logger_inited=1; } while(0)
#define LOG_Destroy()        do { if(g_logger_inited){ Logger_Destroy(&g_logger); g_logger_inited=0; } } while(0)
#define LOG_LEVEL_INFO       LOG_INFO

/* =========================================================
 *  内部辅助
 * ========================================================= */
static void set_error(VDE_Instance* inst, const char* fmt, ...) {
    va_list ap; va_start(ap,fmt);
    vsnprintf(inst->last_error, sizeof(inst->last_error), fmt, ap);
    va_end(ap);
}

/* =========================================================
 *  数据包回调（每个 IfaceWorker 独立）
 * ========================================================= */
static void packet_handler(u_char* user,
                            const struct pcap_pkthdr* hdr,
                            const u_char* pkt)
{
    IfaceWorker* w = (IfaceWorker*)user;
    VDE_Instance* inst = w->inst;

    VDE_ATOMIC_INC(&w->pkt_captured);

    /* 协议解析 */
    ParsedPacket pp;
    memset(&pp, 0, sizeof(pp));

    uint64_t ts_us = (uint64_t)hdr->ts.tv_sec * 1000000ULL + (uint64_t)hdr->ts.tv_usec;
#ifndef _WIN32
    if (!PP_ParsePacket(&w->ndpi_ctx, NULL, pkt, hdr->caplen, ts_us, &pp)) return;
#else
    if (!PP_ParsePacket(NULL, NULL, pkt, hdr->caplen, ts_us, &pp)) return;
#endif
    VDE_ATOMIC_INC(&w->pkt_analyzed);

    /* 规则匹配（读锁，允许多线程并发匹配） */
    VDE_RWLOCK_RDLOCK(&inst->re_rwlock);
    VDE_Alert alert;
    memset(&alert, 0, sizeof(alert));
    int hit = RE_MatchPacket(&inst->re, &pp, &alert);
    VDE_RWLOCK_RDUNLOCK(&inst->re_rwlock);

    if (!hit) return;

    VDE_ATOMIC_INC(&w->alerts);

    /* 填充附加字段 */
    alert.timestamp_us = (uint64_t)hdr->ts.tv_sec*1000000ULL + hdr->ts.tv_usec;
    alert.pkt_len      = hdr->len;
    strncpy(alert.iface_name, w->iface_name, VDE_MAX_DEV_LEN-1);

    uint32_t dlen = hdr->caplen < VDE_MAX_PAYLOAD_DUMP ? hdr->caplen : VDE_MAX_PAYLOAD_DUMP;
    memcpy(alert.payload_dump, pkt, dlen);
    alert.payload_dump_len = dlen;

    /* 写日志 */
    LOG_Alert(&alert);

    /* 串行回调（加锁防止并发乱序） */
    VDE_MUTEX_LOCK(&inst->alert_mutex);
    if (inst->config.alert_callback)
        inst->config.alert_callback(&alert, inst->config.alert_callback_ctx);
    VDE_MUTEX_UNLOCK(&inst->alert_mutex);

    /* 定期清理过期会话（每 5000 包） */
    long cap = VDE_ATOMIC_LOAD(&w->pkt_captured);
    if (cap % 5000 == 0) {
        VDE_RWLOCK_WRLOCK(&inst->re_rwlock);
        RE_PurgeExpiredSessions(&inst->re, alert.timestamp_us);
        VDE_RWLOCK_WRUNLOCK(&inst->re_rwlock);
    }
}

/* =========================================================
 *  捕获线程主函数
 * ========================================================= */
#ifdef _WIN32
static DWORD WINAPI thread_entry(LPVOID arg)
#else
static void* thread_entry(void* arg)
#endif
{
    IfaceWorker* w = (IfaceWorker*)arg;
    w->thread_started = 1;
    w->last_ts_us    = vde_now_us();
    w->last_pkt_snap = 0;

    LOG_Info("[%s] 捕获线程启动 (IP: %s)", w->iface_name, w->ip_addr);

    pcap_loop(w->pcap_handle, -1, packet_handler, (u_char*)w);

    /* 更新驱动丢包统计 */
    struct pcap_stat ps;
    if (pcap_stats(w->pcap_handle, &ps) == 0)
        VDE_ATOMIC_ADD(&w->pkt_dropped, (long)ps.ps_drop);

    w->running = 0;
    LOG_Info("[%s] 捕获线程退出", w->iface_name);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* =========================================================
 *  判断是否为 loopback 地址
 * ========================================================= */
static int is_loopback_addr(const char* ip) {
    if (!ip || !ip[0]) return 1;
    if (strncmp(ip,"127.",4)==0) return 1;
    if (strcmp(ip,"::1")==0)     return 1;
    return 0;
}

/* =========================================================
 *  枚举所有非 loopback 接口
 * ========================================================= */
static int enum_non_loopback(VDE_Instance* inst) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = NULL;
    int count = 0;

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        set_error(inst, "pcap_findalldevs: %s", errbuf);
        return -1;
    }

    for (pcap_if_t* d = alldevs; d && count < VDE_MAX_DEVICES; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;

        char ip[VDE_MAX_IP_LEN] = {0};
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in* s = (struct sockaddr_in*)a->addr;
                inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
                break;
            }
        }
        if (ip[0]=='\0' || is_loopback_addr(ip)) continue;

        IfaceWorker* w = &inst->workers[count];
        memset(w, 0, sizeof(IfaceWorker));
        strncpy(w->iface_name, d->name, VDE_MAX_DEV_LEN-1);
        strncpy(w->ip_addr,    ip,      VDE_MAX_IP_LEN-1);
        w->inst = inst;
        count++;
        LOG_Info("发现接口: %-20s  IP: %s", d->name, ip);
    }

    pcap_freealldevs(alldevs);
    return count;
}

/* =========================================================
 *  启动单个网卡工作线程
 * ========================================================= */
static int start_worker(VDE_Instance* inst, IfaceWorker* w, int offline) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const VDE_Config* cfg = &inst->config;
    int snaplen = cfg->snaplen > 0 ? cfg->snaplen : 65535;
    int promisc = cfg->promiscuous;
    int timeout = cfg->read_timeout_ms > 0 ? cfg->read_timeout_ms : 500;

    if (offline)
        w->pcap_handle = pcap_open_offline(cfg->pcap_file, errbuf);
    else
        w->pcap_handle = pcap_open_live(w->iface_name, snaplen, promisc, timeout, errbuf);

    if (!w->pcap_handle) {
        LOG_Error("[%s] pcap 打开失败: %s", w->iface_name, errbuf);
        return -1;
    }

    /* BPF 过滤 */
    if (cfg->bpf_filter[0]) {
        struct bpf_program fp;
        if (pcap_compile(w->pcap_handle, &fp, cfg->bpf_filter, 1,
                         PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(w->pcap_handle, &fp);
            pcap_freecode(&fp);
        } else {
            LOG_Warn("[%s] BPF 编译失败: %s", w->iface_name,
                     pcap_geterr(w->pcap_handle));
        }
    }

#ifndef _WIN32
    /* Linux: 每线程独立 nDPI 上下文 */
    if (PP_Init(&w->ndpi_ctx) != 0)
        LOG_Warn("[%s] nDPI 上下文初始化失败", w->iface_name);
#endif

    w->running = 1;
    if (VDE_THREAD_CREATE(&w->thread, w) != 0) {
        LOG_Error("[%s] 创建捕获线程失败", w->iface_name);
        w->running = 0;
        pcap_close(w->pcap_handle);
        w->pcap_handle = NULL;
#ifndef _WIN32
        PP_Destroy(&w->ndpi_ctx);
#endif
        return -1;
    }
    return 0;
}

/* =========================================================
 *  VDE_GetVersion
 * ========================================================= */
VDE_API const char* VDE_GetVersion(void) {
    return VDE_VERSION_STR " (multi-thread/multi-iface)";
}

/* =========================================================
 *  VDE_ErrorString / VDE_SeverityString
 * ========================================================= */
VDE_API const char* VDE_ErrorString(VDE_ErrorCode code) {
    switch(code) {
        case VDE_OK:                  return "Success";
        case VDE_ERR_INVALID_PARAM:   return "Invalid parameter";
        case VDE_ERR_INIT_FAILED:     return "Initialization failed";
        case VDE_ERR_PCAP_OPEN:       return "Failed to open pcap device/file";
        case VDE_ERR_RULE_LOAD:       return "Failed to load rule database";
        case VDE_ERR_RULE_PARSE:      return "Rule parse error";
        case VDE_ERR_NO_DEVICE:       return "No network device found";
        case VDE_ERR_ALREADY_RUNNING: return "Engine already running";
        case VDE_ERR_NOT_RUNNING:     return "Engine not running";
        case VDE_ERR_MEMORY:          return "Memory allocation failed";
        case VDE_ERR_FILE_IO:         return "File I/O error";
        case VDE_ERR_NO_INTERFACES:   return "No non-loopback interfaces found";
        case VDE_ERR_PARTIAL:         return "Partial start: some interfaces failed";
        default:                      return "Unknown error";
    }
}

VDE_API const char* VDE_SeverityString(VDE_Severity sev) {
    switch(sev) {
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
VDE_API VDE_ErrorCode VDE_EnumDevices(VDE_DeviceList* out_list) {
    if (!out_list) return VDE_ERR_INVALID_PARAM;
    memset(out_list, 0, sizeof(*out_list));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = NULL;
    if (pcap_findalldevs(&alldevs, errbuf) != 0) return VDE_ERR_NO_DEVICE;

    int cnt = 0;
    for (pcap_if_t* d = alldevs; d && cnt < VDE_MAX_DEVICES; d = d->next) {
        VDE_DeviceInfo* di = &out_list->devices[cnt++];
        strncpy(di->name, d->name, VDE_MAX_DEV_LEN-1);
        if (d->description)
            strncpy(di->description, d->description, VDE_MAX_DEV_DESC_LEN-1);
        di->is_loopback = (d->flags & PCAP_IF_LOOPBACK) ? 1 : 0;
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in* s = (struct sockaddr_in*)a->addr;
                inet_ntop(AF_INET, &s->sin_addr, di->ip_addr, sizeof(di->ip_addr));
                break;
            }
        }
    }
    out_list->count = cnt;
    pcap_freealldevs(alldevs);
    return VDE_OK;
}

/* =========================================================
 *  VDE_Create
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_Create(const VDE_Config* config, VDE_Handle* out_handle) {
    if (!config || !out_handle || !config->alert_callback)
        return VDE_ERR_INVALID_PARAM;

    VDE_Instance* inst = (VDE_Instance*)calloc(1, sizeof(VDE_Instance));
    if (!inst) return VDE_ERR_MEMORY;

    memcpy(&inst->config, config, sizeof(VDE_Config));

    VDE_RWLOCK_INIT(&inst->re_rwlock);
    VDE_MUTEX_INIT(&inst->alert_mutex);

    int ll = config->log_level > 0 ? config->log_level : LOG_LEVEL_INFO;
    LOG_Init(ll, config->log_dir[0] ? config->log_dir : NULL);

    const char* rdb = config->rule_db_path[0] ? config->rule_db_path
                                               : "RuleDB/vuln_rules.json";
    if (RE_Init(&inst->re) == 0 || RE_LoadRules(&inst->re, rdb) < 0) {
        set_error(inst, "规则库加载失败: %s", rdb);
        free(inst);
        return VDE_ERR_RULE_LOAD;
    }
    LOG_Info("规则库加载完成: %d 条规则", inst->re.ruleset.count);

    inst->start_ts_us = vde_now_us();
    *out_handle = inst;
    return VDE_OK;
}

/* =========================================================
 *  VDE_Destroy
 * ========================================================= */
VDE_API void VDE_Destroy(VDE_Handle handle) {
    if (!handle) return;
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (VDE_IsRunning(handle)) VDE_Stop(handle);
    RE_Destroy(&inst->re);
    VDE_RWLOCK_DESTROY(&inst->re_rwlock);
    VDE_MUTEX_DESTROY(&inst->alert_mutex);
    LOG_Destroy();
    free(inst);
}

/* =========================================================
 *  VDE_Start
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_Start(VDE_Handle handle) {
    if (!handle) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;
    if (VDE_IsRunning(handle)) return VDE_ERR_ALREADY_RUNNING;

    if (inst->config.mode == VDE_MODE_OFFLINE) {
        /* OFFLINE：单线程分析 pcap 文件 */
        if (!inst->config.pcap_file[0]) {
            set_error(inst, "OFFLINE 模式需要指定 pcap_file");
            return VDE_ERR_INVALID_PARAM;
        }
        IfaceWorker* w = &inst->workers[0];
        memset(w, 0, sizeof(IfaceWorker));
        strncpy(w->iface_name, inst->config.pcap_file, VDE_MAX_DEV_LEN-1);
        strncpy(w->ip_addr, "offline", VDE_MAX_IP_LEN-1);
        w->inst = inst;
        inst->worker_count = 1;
        if (start_worker(inst, w, 1) != 0) {
            set_error(inst, "无法打开 pcap 文件: %s", inst->config.pcap_file);
            return VDE_ERR_PCAP_OPEN;
        }
        return VDE_OK;
    }

    /* LIVE：枚举所有非 loopback 接口，每卡一线程 */
    int found = enum_non_loopback(inst);
    if (found <= 0) {
        set_error(inst, "未找到任何非 loopback 网络接口");
        return VDE_ERR_NO_INTERFACES;
    }
    inst->worker_count = found;

    int ok = 0, fail = 0;
    for (int i = 0; i < inst->worker_count; i++) {
        if (start_worker(inst, &inst->workers[i], 0) == 0) ok++;
        else fail++;
    }

    if (ok == 0) {
        set_error(inst, "所有 %d 个接口均启动失败", fail);
        return VDE_ERR_NO_INTERFACES;
    }
    if (fail > 0) {
        LOG_Warn("%d 个接口启动成功，%d 个失败", ok, fail);
        return VDE_ERR_PARTIAL;
    }
    LOG_Info("引擎启动完成，共监听 %d 个接口", ok);
    return VDE_OK;
}

/* =========================================================
 *  VDE_Stop
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_Stop(VDE_Handle handle) {
    if (!handle) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;

    int any = 0;
    for (int i = 0; i < inst->worker_count; i++) {
        IfaceWorker* w = &inst->workers[i];
        if (!w->running && !w->thread_started) continue;
        any = 1;
        w->running = 0;
        if (w->pcap_handle) pcap_breakloop(w->pcap_handle);
    }
    if (!any) return VDE_ERR_NOT_RUNNING;

    for (int i = 0; i < inst->worker_count; i++) {
        IfaceWorker* w = &inst->workers[i];
        if (!w->thread_started) continue;
        VDE_THREAD_JOIN(w->thread);
        w->thread_started = 0;
        if (w->pcap_handle) { pcap_close(w->pcap_handle); w->pcap_handle=NULL; }
#ifndef _WIN32
        PP_Destroy(&w->ndpi_ctx);
#endif
    }
    inst->worker_count = 0;
    LOG_Info("引擎已停止");
    return VDE_OK;
}

/* =========================================================
 *  VDE_IsRunning
 * ========================================================= */
VDE_API int VDE_IsRunning(VDE_Handle handle) {
    if (!handle) return 0;
    VDE_Instance* inst = (VDE_Instance*)handle;
    for (int i = 0; i < inst->worker_count; i++)
        if (inst->workers[i].running) return 1;
    return 0;
}

/* =========================================================
 *  VDE_ReloadRules（热重载，写锁）
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_ReloadRules(VDE_Handle handle, const char* path) {
    if (!handle || !path) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;

    RuleEngine new_re;
    if (RE_Init(&new_re) == 0 || RE_LoadRules(&new_re, path) < 0) {
        RE_Destroy(&new_re);
        return VDE_ERR_RULE_LOAD;
    }
    VDE_RWLOCK_WRLOCK(&inst->re_rwlock);
    RE_Destroy(&inst->re);
    memcpy(&inst->re, &new_re, sizeof(RuleEngine));
    VDE_RWLOCK_WRUNLOCK(&inst->re_rwlock);

    LOG_Info("规则库热重载完成: %d 条规则", inst->re.ruleset.count);
    return VDE_OK;
}

/* =========================================================
 *  VDE_SetRuleEnabled
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_SetRuleEnabled(VDE_Handle handle,
                                          const char* rule_id, int enable) {
    if (!handle || !rule_id) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;

    VDE_RWLOCK_WRLOCK(&inst->re_rwlock);
    VDE_ErrorCode ret = VDE_ERR_NO_DEVICE;
    for (int i = 0; i < inst->re.ruleset.count; i++) {
        if (strcasecmp(inst->re.ruleset.rules[i].rule_id, rule_id) == 0) {
            inst->re.ruleset.rules[i].enabled = enable ? 1 : 0;
            ret = VDE_OK;
            break;
        }
    }
    VDE_RWLOCK_WRUNLOCK(&inst->re_rwlock);
    return ret;
}

/* =========================================================
 *  VDE_GetRules
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_GetRules(VDE_Handle handle, VDE_RuleInfo* out,
                                    int max, int* cnt) {
    if (!handle || !out || !cnt) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;

    VDE_RWLOCK_RDLOCK(&inst->re_rwlock);
    int n = inst->re.ruleset.count < max ? inst->re.ruleset.count : max;
    for (int i = 0; i < n; i++) {
        Rule* r = &inst->re.ruleset.rules[i];
        VDE_RuleInfo* ri = &out[i];
        strncpy(ri->rule_id,     r->rule_id,     VDE_MAX_RULE_ID_LEN-1);
        strncpy(ri->rule_name,   r->name,   VDE_MAX_RULE_NAME_LEN-1);
        strncpy(ri->cve,         r->cve,         VDE_MAX_CVE_LEN-1);
        strncpy(ri->description, r->description, VDE_MAX_DESC_LEN-1);
        ri->severity = (VDE_Severity)r->severity;
        strncpy(ri->protocol, r->protocol, VDE_MAX_PROTO_LEN-1);
        ri->dst_port = r->dst_port;
        ri->enabled  = r->enabled;
    }
    *cnt = n;
    VDE_RWLOCK_RDUNLOCK(&inst->re_rwlock);
    return VDE_OK;
}

/* =========================================================
 *  VDE_GetStatistics（聚合所有接口）
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_GetStatistics(VDE_Handle handle, VDE_Statistics* s) {
    if (!handle || !s) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;
    memset(s, 0, sizeof(*s));

    VDE_RWLOCK_RDLOCK(&inst->re_rwlock);
    s->rules_loaded = inst->re.ruleset.count;
    for (int i = 0; i < inst->re.ruleset.count; i++)
        if (inst->re.ruleset.rules[i].enabled) s->rules_enabled++;
    s->sessions_tracked = (uint64_t)VDE_ATOMIC_LOAD(&inst->sessions_tracked);
    VDE_RWLOCK_RDUNLOCK(&inst->re_rwlock);

    int running = 0;
    double total_pps = 0.0;
    uint64_t now = vde_now_us();

    for (int i = 0; i < inst->worker_count; i++) {
        IfaceWorker* w = &inst->workers[i];
        s->packets_captured += (uint64_t)VDE_ATOMIC_LOAD(&w->pkt_captured);
        s->packets_analyzed += (uint64_t)VDE_ATOMIC_LOAD(&w->pkt_analyzed);
        s->packets_dropped  += (uint64_t)VDE_ATOMIC_LOAD(&w->pkt_dropped);
        s->alerts_generated += (uint64_t)VDE_ATOMIC_LOAD(&w->alerts);

        uint64_t dt = now - w->last_ts_us;
        if (dt > 500000ULL) {
            uint64_t cur = (uint64_t)VDE_ATOMIC_LOAD(&w->pkt_captured);
            w->pps = (double)(cur - w->last_pkt_snap) / (dt / 1e6);
            w->last_pkt_snap = cur;
            w->last_ts_us    = now;
        }
        total_pps += w->pps;
        if (w->running) running++;
    }
    s->packets_per_sec = total_pps;
    s->iface_count     = inst->worker_count;
    s->iface_running   = running;
    return VDE_OK;
}

/* =========================================================
 *  VDE_GetIfaceStatistics
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_GetIfaceStatistics(VDE_Handle handle,
                                              VDE_IfaceStatistics* out,
                                              int max, int* cnt) {
    if (!handle || !out || !cnt) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;

    int n = inst->worker_count < max ? inst->worker_count : max;
    for (int i = 0; i < n; i++) {
        IfaceWorker* w = &inst->workers[i];
        VDE_IfaceStatistics* s = &out[i];
        strncpy(s->iface_name, w->iface_name, VDE_MAX_DEV_LEN-1);
        strncpy(s->ip_addr,    w->ip_addr,    VDE_MAX_IP_LEN-1);
        s->running          = w->running;
        s->packets_captured = (uint64_t)VDE_ATOMIC_LOAD(&w->pkt_captured);
        s->packets_analyzed = (uint64_t)VDE_ATOMIC_LOAD(&w->pkt_analyzed);
        s->packets_dropped  = (uint64_t)VDE_ATOMIC_LOAD(&w->pkt_dropped);
        s->alerts_generated = (uint64_t)VDE_ATOMIC_LOAD(&w->alerts);
        s->packets_per_sec  = w->pps;
    }
    *cnt = n;
    return VDE_OK;
}

/* =========================================================
 *  VDE_ResetStatistics
 * ========================================================= */
VDE_API VDE_ErrorCode VDE_ResetStatistics(VDE_Handle handle) {
    if (!handle) return VDE_ERR_INVALID_PARAM;
    VDE_Instance* inst = (VDE_Instance*)handle;
    for (int i = 0; i < inst->worker_count; i++) {
        IfaceWorker* w = &inst->workers[i];
        VDE_ATOMIC_STORE(&w->pkt_captured, 0);
        VDE_ATOMIC_STORE(&w->pkt_analyzed, 0);
        VDE_ATOMIC_STORE(&w->pkt_dropped,  0);
        VDE_ATOMIC_STORE(&w->alerts,       0);
        w->pps = 0.0;
    }
    return VDE_OK;
}

/* =========================================================
 *  VDE_GetLastError
 * ========================================================= */
VDE_API const char* VDE_GetLastError(VDE_Handle handle) {
    if (!handle) return "Invalid handle";
    return ((VDE_Instance*)handle)->last_error;
}
