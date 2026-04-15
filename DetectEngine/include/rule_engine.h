/**
 * @file    rule_engine.h
 * @brief   规则引擎 - 规则加载、特征匹配、会话追踪、阈值检测
 */

#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include "VulnDetectEngine.h"
#include "proto_parser.h"
#include <stdint.h>

/* =========================================================
 *  规则匹配类型
 * ========================================================= */
typedef enum MatchType {
    MATCH_STATELESS  = 0,   /**< 无状态单包匹配 */
    MATCH_STATEFUL   = 1,   /**< 有状态多包匹配（会话追踪） */
    MATCH_THRESHOLD  = 2    /**< 阈值检测（频率统计） */
} MatchType;

/* =========================================================
 *  条件操作符
 * ========================================================= */
typedef enum CondOp {
    OP_EQ       = 0,    /**< 等于 */
    OP_NEQ      = 1,    /**< 不等于 */
    OP_GT       = 2,    /**< 大于 */
    OP_LT       = 3,    /**< 小于 */
    OP_GTE      = 4,    /**< 大于等于 */
    OP_LTE      = 5,    /**< 小于等于 */
    OP_CONTAINS = 6,    /**< 包含子串 */
    OP_REGEX    = 7,    /**< 正则匹配 */
    OP_HEX_MATCH= 8     /**< 十六进制字节序列匹配 */
} CondOp;

/* =========================================================
 *  单条匹配条件
 * ========================================================= */
#define RE_MAX_FIELD_LEN    64
#define RE_MAX_VALUE_LEN    512
#define RE_MAX_COMMENT_LEN  128

typedef struct RuleCondition {
    char    field[RE_MAX_FIELD_LEN];    /**< 字段名，对应 ParsedPacket 成员 */
    CondOp  op;                         /**< 操作符 */
    char    value[RE_MAX_VALUE_LEN];    /**< 匹配值（字符串形式） */
    char    comment[RE_MAX_COMMENT_LEN];

    /* 预编译的正则（仅 OP_REGEX 时有效） */
    void*   compiled_regex;

    /* 预解析的十六进制字节序列（仅 OP_HEX_MATCH 时有效） */
    uint8_t hex_bytes[256];
    int     hex_len;
} RuleCondition;

/* =========================================================
 *  有状态规则的后续包条件
 * ========================================================= */
typedef struct FollowUpCondition {
    char        smb_command[16];
    char        payload_pattern[RE_MAX_VALUE_LEN];
    uint32_t    max_interval_ms;
    void*       compiled_regex;
} FollowUpCondition;

/* =========================================================
 *  阈值配置
 * ========================================================= */
typedef struct ThresholdConfig {
    uint32_t    count;          /**< 触发阈值 */
    uint32_t    window_ms;      /**< 时间窗口（毫秒） */
    char        group_by[32];   /**< 分组字段，如 "src_ip" */
    char        unique_field[32]; /**< 唯一计数字段，如 "dst_port" */
} ThresholdConfig;

/* =========================================================
 *  规则结构体
 * ========================================================= */
#define RE_MAX_CONDITIONS   16
#define RE_MAX_RULE_ID_LEN  32
#define RE_MAX_NAME_LEN     128
#define RE_MAX_CVE_LEN      32
#define RE_MAX_DESC_LEN     512
#define RE_MAX_PROTO_LEN    16

typedef struct Rule {
    char            rule_id[RE_MAX_RULE_ID_LEN];
    char            name[RE_MAX_NAME_LEN];
    char            cve[RE_MAX_CVE_LEN];
    char            description[RE_MAX_DESC_LEN];
    VDE_Severity    severity;
    char            protocol[RE_MAX_PROTO_LEN];
    char            transport[RE_MAX_PROTO_LEN];
    uint16_t        dst_port;           /**< 0=任意端口 */
    int             enabled;

    MatchType       match_type;

    /* 主条件列表 */
    RuleCondition   conditions[RE_MAX_CONDITIONS];
    int             condition_count;

    /* 有状态规则的后续条件 */
    FollowUpCondition follow_up;
    int             has_follow_up;

    /* 阈值规则配置 */
    ThresholdConfig threshold;
} Rule;

/* =========================================================
 *  规则库
 * ========================================================= */
#define RE_MAX_RULES    256

typedef struct RuleSet {
    Rule    rules[RE_MAX_RULES];
    int     count;
    char    version[32];
    char    db_path[260];
} RuleSet;

/* =========================================================
 *  会话追踪表
 * ========================================================= */
#define SESSION_TABLE_SIZE  65536   /**< 哈希桶数量 */
#define SESSION_MAX_ENTRIES 32768   /**< 最大会话数 */
#define SESSION_TIMEOUT_MS  60000   /**< 会话超时（毫秒） */

typedef struct SessionEntry {
    uint64_t    session_id;
    uint32_t    src_ip;
    uint32_t    dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     ip_proto;

    /* 关联规则 */
    char        rule_id[RE_MAX_RULE_ID_LEN];
    int         stage;          /**< 当前匹配阶段（0=初始，1=等待后续包） */

    uint64_t    first_seen_us;
    uint64_t    last_seen_us;

    struct SessionEntry* next;  /**< 链表（哈希冲突） */
} SessionEntry;

typedef struct SessionTable {
    SessionEntry*   buckets[SESSION_TABLE_SIZE];
    uint32_t        entry_count;
    uint64_t        next_session_id;
} SessionTable;

/* =========================================================
 *  阈值追踪表（用于频率检测）
 * ========================================================= */
#define THRESH_TABLE_SIZE   4096
#define THRESH_MAX_ENTRIES  2048

typedef struct ThreshEntry {
    char        key[64];        /**< 分组键，如 "src_ip:192.168.1.1" */
    char        rule_id[RE_MAX_RULE_ID_LEN];
    uint32_t    count;
    uint32_t    unique_count;   /**< 唯一字段计数 */
    uint64_t    window_start_us;

    /* 用于 unique_field 去重的简单位图（最多64个唯一值） */
    uint64_t    unique_bitmap;
    uint32_t    unique_vals[64];

    struct ThreshEntry* next;
} ThreshEntry;

typedef struct ThreshTable {
    ThreshEntry*    buckets[THRESH_TABLE_SIZE];
    uint32_t        entry_count;
} ThreshTable;

/* =========================================================
 *  规则引擎上下文
 * ========================================================= */
typedef struct RuleEngine {
    RuleSet         ruleset;
    SessionTable    sessions;
    ThreshTable     thresholds;
} RuleEngine;

/* =========================================================
 *  函数声明
 * ========================================================= */

/**
 * @brief  初始化规则引擎
 */
int RE_Init(RuleEngine* engine);

/**
 * @brief  从 JSON 文件加载规则库
 * @return 加载的规则数量，<0 表示失败
 */
int RE_LoadRules(RuleEngine* engine, const char* json_path);

/**
 * @brief  卸载规则库，释放编译的正则等资源
 */
void RE_UnloadRules(RuleEngine* engine);

/**
 * @brief  销毁规则引擎，释放所有资源
 */
void RE_Destroy(RuleEngine* engine);

/**
 * @brief  对单个数据包执行规则匹配
 * @param  engine   规则引擎上下文
 * @param  pkt      已解析的数据包
 * @param  out_alert [out] 若匹配成功则填充告警信息
 * @return 1=产生告警，0=无告警
 */
int RE_MatchPacket(
    RuleEngine*     engine,
    const ParsedPacket* pkt,
    VDE_Alert*      out_alert
);

/**
 * @brief  启用或禁用规则
 */
int RE_SetRuleEnabled(RuleEngine* engine, const char* rule_id, int enable);

/**
 * @brief  清理过期会话
 */
void RE_PurgeExpiredSessions(RuleEngine* engine, uint64_t now_us);

/**
 * @brief  获取当前活跃会话数
 */
uint32_t RE_GetSessionCount(const RuleEngine* engine);

#endif /* RULE_ENGINE_H */
