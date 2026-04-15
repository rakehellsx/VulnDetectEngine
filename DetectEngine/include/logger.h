/**
 * @file    logger.h
 * @brief   日志与告警输出模块
 */

#ifndef LOGGER_H
#define LOGGER_H

#include "VulnDetectEngine.h"
#include <stdarg.h>

/* =========================================================
 *  日志级别
 * ========================================================= */
typedef enum LogLevel {
    LOG_OFF   = 0,
    LOG_ERROR = 1,
    LOG_WARN  = 2,
    LOG_INFO  = 3,
    LOG_DEBUG = 4
} LogLevel;

/* =========================================================
 *  日志上下文
 * ========================================================= */
typedef struct Logger {
    LogLevel    level;
    char        log_dir[260];
    char        log_file_path[300];
    void*       file_handle;        /**< FILE* 指针 */
    int         console_output;     /**< 是否同时输出到控制台 */
    void*       mutex;              /**< CRITICAL_SECTION 指针 */
} Logger;

/* =========================================================
 *  函数声明
 * ========================================================= */

/**
 * @brief  初始化日志模块
 * @param  logger    日志上下文
 * @param  log_dir   日志目录（空串=不写文件）
 * @param  level     日志级别
 * @return 1=成功，0=失败
 */
int Logger_Init(Logger* logger, const char* log_dir, LogLevel level);

/**
 * @brief  销毁日志模块
 */
void Logger_Destroy(Logger* logger);

/**
 * @brief  写入日志（格式化字符串）
 */
void Logger_Write(Logger* logger, LogLevel level, const char* fmt, ...);

/**
 * @brief  记录告警信息到日志文件（JSON格式）
 */
void Logger_WriteAlert(Logger* logger, const VDE_Alert* alert);

/**
 * @brief  获取当前时间戳字符串（线程安全）
 */
void Logger_GetTimestamp(char* buf, size_t buf_len);

/* 便捷宏 */
#define LOG_E(lg, fmt, ...) Logger_Write((lg), LOG_ERROR, "[ERROR] " fmt, ##__VA_ARGS__)
#define LOG_W(lg, fmt, ...) Logger_Write((lg), LOG_WARN,  "[WARN ] " fmt, ##__VA_ARGS__)
#define LOG_I(lg, fmt, ...) Logger_Write((lg), LOG_INFO,  "[INFO ] " fmt, ##__VA_ARGS__)
#define LOG_D(lg, fmt, ...) Logger_Write((lg), LOG_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)

#endif /* LOGGER_H */
