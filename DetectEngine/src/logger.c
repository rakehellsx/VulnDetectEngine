/**
 * @file    logger.c
 * @brief   日志与告警输出模块实现
 *          - 支持文件日志（按日滚动）
 *          - 告警以 JSON 格式写入独立告警日志
 *          - 线程安全（CRITICAL_SECTION）
 */

#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
#  include <direct.h>
#  define MKDIR(p) _mkdir(p)
#  define PATH_SEP "\\"
#else
#  include <sys/stat.h>
#  include <pthread.h>
#  define MKDIR(p) mkdir(p, 0755)
#  define PATH_SEP "/"
#endif

/* =========================================================
 *  内部辅助
 * ========================================================= */
static const char* level_str(LogLevel level)
{
    switch (level) {
        case LOG_ERROR: return "ERROR";
        case LOG_WARN:  return "WARN ";
        case LOG_INFO:  return "INFO ";
        case LOG_DEBUG: return "DEBUG";
        default:        return "?????";
    }
}

/* 获取当前时间字符串 "YYYY-MM-DD HH:MM:SS.mmm" */
void Logger_GetTimestamp(char* buf, size_t buf_len)
{
#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);
    snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
             (int)(ts.tv_nsec / 1000000));
#endif
}

/* 构建日志文件路径（按日命名） */
static void build_log_path(const char* log_dir, char* out_path, size_t out_sz,
                            const char* prefix)
{
#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(out_path, out_sz, "%s%s%s_%04d%02d%02d.log",
             log_dir, PATH_SEP, prefix,
             st.wYear, st.wMonth, st.wDay);
#else
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    snprintf(out_path, out_sz, "%s%s%s_%04d%02d%02d.log",
             log_dir, PATH_SEP, prefix,
             tm_info->tm_year + 1900,
             tm_info->tm_mon + 1,
             tm_info->tm_mday);
#endif
}

/* =========================================================
 *  初始化
 * ========================================================= */
int Logger_Init(Logger* logger, const char* log_dir, LogLevel level)
{
    if (!logger) return 0;
    memset(logger, 0, sizeof(Logger));
    logger->level           = level;
    logger->console_output  = 1;

    /* 初始化互斥锁 */
#ifdef _WIN32
    CRITICAL_SECTION* cs = (CRITICAL_SECTION*)malloc(sizeof(CRITICAL_SECTION));
    if (!cs) return 0;
    InitializeCriticalSection(cs);
    logger->mutex = cs;
#else
    pthread_mutex_t* mtx = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    if (!mtx) return 0;
    pthread_mutex_init(mtx, NULL);
    logger->mutex = mtx;
#endif

    if (!log_dir || log_dir[0] == '\0') {
        logger->file_handle = NULL;
        return 1;
    }

    /* 创建日志目录 */
    strncpy(logger->log_dir, log_dir, sizeof(logger->log_dir) - 1);
    MKDIR(log_dir);

    /* 打开日志文件 */
    build_log_path(log_dir, logger->log_file_path,
                   sizeof(logger->log_file_path), "vde_engine");
    FILE* fp = fopen(logger->log_file_path, "a");
    logger->file_handle = fp;

    return 1;
}

/* =========================================================
 *  销毁
 * ========================================================= */
void Logger_Destroy(Logger* logger)
{
    if (!logger) return;

    if (logger->file_handle) {
        fclose((FILE*)logger->file_handle);
        logger->file_handle = NULL;
    }

#ifdef _WIN32
    if (logger->mutex) {
        DeleteCriticalSection((CRITICAL_SECTION*)logger->mutex);
        free(logger->mutex);
        logger->mutex = NULL;
    }
#else
    if (logger->mutex) {
        pthread_mutex_destroy((pthread_mutex_t*)logger->mutex);
        free(logger->mutex);
        logger->mutex = NULL;
    }
#endif
}

/* =========================================================
 *  写入日志
 * ========================================================= */
void Logger_Write(Logger* logger, LogLevel level, const char* fmt, ...)
{
    if (!logger || level > logger->level || level == LOG_OFF) return;

    char ts[32];
    Logger_GetTimestamp(ts, sizeof(ts));

    char msg[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    char line[2200];
    snprintf(line, sizeof(line), "[%s][%s] %s\n", ts, level_str(level), msg);

#ifdef _WIN32
    if (logger->mutex) EnterCriticalSection((CRITICAL_SECTION*)logger->mutex);
#else
    if (logger->mutex) pthread_mutex_lock((pthread_mutex_t*)logger->mutex);
#endif

    if (logger->console_output) {
        if (level == LOG_ERROR) fputs(line, stderr);
        else                    fputs(line, stdout);
    }

    if (logger->file_handle) {
        fputs(line, (FILE*)logger->file_handle);
        fflush((FILE*)logger->file_handle);
    }

#ifdef _WIN32
    if (logger->mutex) LeaveCriticalSection((CRITICAL_SECTION*)logger->mutex);
#else
    if (logger->mutex) pthread_mutex_unlock((pthread_mutex_t*)logger->mutex);
#endif
}

/* =========================================================
 *  写入告警（JSON 格式）
 * ========================================================= */
void Logger_WriteAlert(Logger* logger, const VDE_Alert* alert)
{
    if (!logger || !alert) return;
    if (logger->level == LOG_OFF) return;

    /* 构建告警日志文件路径 */
    char alert_path[300];
    if (logger->log_dir[0]) {
        build_log_path(logger->log_dir, alert_path, sizeof(alert_path), "vde_alerts");
    } else {
        return; /* 无日志目录则不写文件 */
    }

    /* 时间戳字符串 */
    char ts[32];
    Logger_GetTimestamp(ts, sizeof(ts));

    /* 载荷十六进制转储 */
    char hex_dump[VDE_MAX_PAYLOAD_DUMP * 3 + 4] = "";
    for (uint32_t i = 0; i < alert->payload_dump_len; i++) {
        char byte_str[4];
        snprintf(byte_str, sizeof(byte_str), "%02X ", alert->payload_dump[i]);
        strcat(hex_dump, byte_str);
    }

    /* 严重级别字符串 */
    const char* sev_str[] = { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };
    const char* sev = (alert->severity <= VDE_SEV_CRITICAL)
                      ? sev_str[alert->severity] : "UNKNOWN";

    /* 构建 JSON 行 */
    char json_line[4096];
    snprintf(json_line, sizeof(json_line),
        "{\"timestamp\":\"%s\","
        "\"rule_id\":\"%s\","
        "\"rule_name\":\"%s\","
        "\"cve\":\"%s\","
        "\"severity\":\"%s\","
        "\"protocol\":\"%s\","
        "\"src_ip\":\"%s\","
        "\"src_port\":%u,"
        "\"dst_ip\":\"%s\","
        "\"dst_port\":%u,"
        "\"pkt_len\":%u,"
        "\"session_id\":%llu,"
        "\"payload_hex\":\"%s\","
        "\"description\":\"%s\"}\n",
        ts,
        alert->rule_id,
        alert->rule_name,
        alert->cve,
        sev,
        alert->protocol,
        alert->src_ip,
        (unsigned)alert->src_port,
        alert->dst_ip,
        (unsigned)alert->dst_port,
        (unsigned)alert->pkt_len,
        (unsigned long long)alert->session_id,
        hex_dump,
        alert->description);

#ifdef _WIN32
    if (logger->mutex) EnterCriticalSection((CRITICAL_SECTION*)logger->mutex);
#else
    if (logger->mutex) pthread_mutex_lock((pthread_mutex_t*)logger->mutex);
#endif

    /* 控制台输出（红色高亮） */
    if (logger->console_output) {
#ifdef _WIN32
        HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("[ALERT][%s] %s | %s | %s:%u -> %s:%u\n",
               ts, alert->rule_id, sev,
               alert->src_ip, alert->src_port,
               alert->dst_ip, alert->dst_port);
        SetConsoleTextAttribute(hCon,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
        printf("\033[1;31m[ALERT][%s] %s | %s | %s:%u -> %s:%u\033[0m\n",
               ts, alert->rule_id, sev,
               alert->src_ip, alert->src_port,
               alert->dst_ip, alert->dst_port);
#endif
    }

    /* 写入告警日志文件 */
    FILE* afp = fopen(alert_path, "a");
    if (afp) {
        fputs(json_line, afp);
        fclose(afp);
    }

#ifdef _WIN32
    if (logger->mutex) LeaveCriticalSection((CRITICAL_SECTION*)logger->mutex);
#else
    if (logger->mutex) pthread_mutex_unlock((pthread_mutex_t*)logger->mutex);
#endif
}
