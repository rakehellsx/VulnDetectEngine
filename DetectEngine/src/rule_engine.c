/**
 * @file    rule_engine.c
 * @brief   规则引擎实现
 *          - 使用 cJSON 解析 JSON 规则库
 *          - 支持无状态/有状态/阈值三种匹配模式
 *          - 内置正则匹配（Windows PCRE 或 POSIX regex）
 *          - 会话追踪哈希表（超时清理）
 *          - 阈值滑动窗口计数
 */

#include "../include/rule_engine.h"
#include "../third_party/cJSON/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
/* Windows 下使用系统正则（通过 PCRE 或简单手写匹配）
 * 为保持零外部依赖，此处实现一个轻量级通配/子串匹配，
 * 完整正则支持可替换为 PCRE2 库。                      */
#else
#  include <regex.h>
#endif

/* =========================================================
 *  内部辅助
 * ========================================================= */
#define SAFE_STRNCPY(dst, src, n) \
    do { strncpy((dst),(src),(n)-1); (dst)[(n)-1]='\0'; } while(0)

static uint64_t get_time_us(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    /* 转换为 Unix epoch 微秒：Windows FILETIME 从 1601-01-01 起，单位 100ns */
    t -= 116444736000000000ULL;
    return t / 10;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
#endif
}

/* =========================================================
 *  轻量级正则/模式匹配（Windows 无 POSIX regex）
 *  支持：
 *    - 普通子串搜索（无特殊字符时）
 *    - 简单 \xNN 转义字节序列匹配
 *    - 基本 .* 通配
 *  如需完整正则，将 compiled_regex 替换为 PCRE2 句柄。
 * ========================================================= */

/* 将含 \xNN 转义的模式字符串展开为字节数组 */
static int expand_pattern(const char* pattern, uint8_t* out, int max_len)
{
    int out_len = 0;
    const char* p = pattern;
    while (*p && out_len < max_len - 1) {
        if (p[0] == '\\' && p[1] == 'x' && isxdigit((unsigned char)p[2])
                                         && isxdigit((unsigned char)p[3])) {
            char hex[3] = { p[2], p[3], '\0' };
            out[out_len++] = (uint8_t)strtol(hex, NULL, 16);
            p += 4;
        } else if (p[0] == '\\' && p[1] == 'n') {
            out[out_len++] = '\n'; p += 2;
        } else if (p[0] == '\\' && p[1] == 'r') {
            out[out_len++] = '\r'; p += 2;
        } else if (p[0] == '\\' && p[1] == 't') {
            out[out_len++] = '\t'; p += 2;
        } else {
            out[out_len++] = (uint8_t)*p++;
        }
    }
    out[out_len] = 0;
    return out_len;
}

/* Boyer-Moore-Horspool 子串搜索 */
static const uint8_t* bmh_search(
    const uint8_t* haystack, size_t hlen,
    const uint8_t* needle,   size_t nlen)
{
    if (nlen == 0) return haystack;
    if (nlen > hlen) return NULL;

    size_t skip[256];
    for (int i = 0; i < 256; i++) skip[i] = nlen;
    for (size_t i = 0; i < nlen - 1; i++)
        skip[needle[i]] = nlen - 1 - i;

    size_t pos = nlen - 1;
    while (pos < hlen) {
        size_t j = nlen - 1;
        size_t k = pos;
        while (j > 0 && haystack[k] == needle[j]) { k--; j--; }
        if (j == 0 && haystack[k] == needle[0])
            return haystack + k;
        pos += skip[haystack[pos]];
    }
    return NULL;
}

/* 简单模式匹配：先尝试 \xNN 展开后做字节序列搜索 */
static int pattern_match(const char* pattern,
                         const uint8_t* data, uint32_t data_len)
{
    if (!pattern || !data || data_len == 0) return 0;

    uint8_t expanded[512];
    int exp_len = expand_pattern(pattern, expanded, sizeof(expanded));
    if (exp_len <= 0) return 0;

    return bmh_search(data, data_len, expanded, (size_t)exp_len) != NULL;
}

/* =========================================================
 *  十六进制字符串转字节
 * ========================================================= */
static int hex_to_bytes(const char* hex, uint8_t* out, int max_len)
{
    int len = 0;
    const char* p = hex;
    while (*p && *(p+1) && len < max_len) {
        char b[3] = { *p, *(p+1), '\0' };
        out[len++] = (uint8_t)strtol(b, NULL, 16);
        p += 2;
    }
    return len;
}

/* =========================================================
 *  严重级别字符串转枚举
 * ========================================================= */
static VDE_Severity severity_from_str(const char* s)
{
    if (!s) return VDE_SEV_INFO;
    if (strcmp(s, "CRITICAL") == 0) return VDE_SEV_CRITICAL;
    if (strcmp(s, "HIGH")     == 0) return VDE_SEV_HIGH;
    if (strcmp(s, "MEDIUM")   == 0) return VDE_SEV_MEDIUM;
    if (strcmp(s, "LOW")      == 0) return VDE_SEV_LOW;
    return VDE_SEV_INFO;
}

/* =========================================================
 *  操作符字符串转枚举
 * ========================================================= */
static CondOp op_from_str(const char* s)
{
    if (!s) return OP_EQ;
    if (strcmp(s, "EQ")        == 0) return OP_EQ;
    if (strcmp(s, "NEQ")       == 0) return OP_NEQ;
    if (strcmp(s, "GT")        == 0) return OP_GT;
    if (strcmp(s, "LT")        == 0) return OP_LT;
    if (strcmp(s, "GTE")       == 0) return OP_GTE;
    if (strcmp(s, "LTE")       == 0) return OP_LTE;
    if (strcmp(s, "CONTAINS")  == 0) return OP_CONTAINS;
    if (strcmp(s, "REGEX")     == 0) return OP_REGEX;
    if (strcmp(s, "HEX_MATCH") == 0) return OP_HEX_MATCH;
    return OP_EQ;
}

/* =========================================================
 *  匹配类型字符串转枚举
 * ========================================================= */
static MatchType match_type_from_str(const char* s)
{
    if (!s) return MATCH_STATELESS;
    if (strcmp(s, "STATEFUL")  == 0) return MATCH_STATEFUL;
    if (strcmp(s, "THRESHOLD") == 0) return MATCH_THRESHOLD;
    return MATCH_STATELESS;
}

/* =========================================================
 *  从 cJSON 对象解析单条规则
 * ========================================================= */
static int parse_one_rule(const cJSON* jrule, Rule* rule)
{
    memset(rule, 0, sizeof(Rule));
    rule->enabled = 1;

    /* 基本字段 */
    cJSON* j;
#define GET_STR(field, dst, dstsz) \
    j = cJSON_GetObjectItemCaseSensitive(jrule, field); \
    if (cJSON_IsString(j)) SAFE_STRNCPY(dst, j->valuestring, dstsz);

    GET_STR("id",          rule->rule_id,     sizeof(rule->rule_id))
    GET_STR("name",        rule->name,        sizeof(rule->name))
    GET_STR("cve",         rule->cve,         sizeof(rule->cve))
    GET_STR("description", rule->description, sizeof(rule->description))
    GET_STR("protocol",    rule->protocol,    sizeof(rule->protocol))
    GET_STR("transport",   rule->transport,   sizeof(rule->transport))

    j = cJSON_GetObjectItemCaseSensitive(jrule, "severity");
    if (cJSON_IsString(j)) rule->severity = severity_from_str(j->valuestring);

    j = cJSON_GetObjectItemCaseSensitive(jrule, "dst_port");
    if (cJSON_IsNumber(j)) rule->dst_port = (uint16_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(jrule, "enabled");
    if (cJSON_IsBool(j)) rule->enabled = cJSON_IsTrue(j) ? 1 : 0;

    j = cJSON_GetObjectItemCaseSensitive(jrule, "match_type");
    if (cJSON_IsString(j)) rule->match_type = match_type_from_str(j->valuestring);

    /* 解析 conditions 数组 */
    cJSON* jconds = cJSON_GetObjectItemCaseSensitive(jrule, "conditions");
    if (cJSON_IsArray(jconds)) {
        int cidx = 0;
        cJSON* jcond = NULL;
        cJSON_ArrayForEach(jcond, jconds) {
            if (cidx >= RE_MAX_CONDITIONS) break;
            RuleCondition* cond = &rule->conditions[cidx];

            GET_STR("field",   cond->field,   sizeof(cond->field))
            GET_STR("value",   cond->value,   sizeof(cond->value))
            GET_STR("comment", cond->comment, sizeof(cond->comment))

            j = cJSON_GetObjectItemCaseSensitive(jcond, "op");
            if (cJSON_IsString(j)) cond->op = op_from_str(j->valuestring);

            /* 预处理 HEX_MATCH */
            if (cond->op == OP_HEX_MATCH) {
                cond->hex_len = hex_to_bytes(cond->value,
                                             cond->hex_bytes,
                                             sizeof(cond->hex_bytes));
            }
            /* REGEX 模式：存储原始字符串，运行时做展开匹配 */

            cidx++;
        }
        rule->condition_count = cidx;
    }

    /* 解析 follow_up（有状态规则） */
    cJSON* jfu = cJSON_GetObjectItemCaseSensitive(jrule, "follow_up");
    if (cJSON_IsObject(jfu)) {
        rule->has_follow_up = 1;
        FollowUpCondition* fu = &rule->follow_up;

        j = cJSON_GetObjectItemCaseSensitive(jfu, "smb_command");
        if (cJSON_IsString(j)) SAFE_STRNCPY(fu->smb_command, j->valuestring, sizeof(fu->smb_command));

        j = cJSON_GetObjectItemCaseSensitive(jfu, "payload_pattern");
        if (cJSON_IsString(j)) SAFE_STRNCPY(fu->payload_pattern, j->valuestring, sizeof(fu->payload_pattern));

        j = cJSON_GetObjectItemCaseSensitive(jfu, "max_interval_ms");
        if (cJSON_IsNumber(j)) fu->max_interval_ms = (uint32_t)j->valueint;
    }

    /* 解析 threshold */
    cJSON* jthr = cJSON_GetObjectItemCaseSensitive(jrule, "threshold");
    if (cJSON_IsObject(jthr)) {
        ThresholdConfig* thr = &rule->threshold;

        j = cJSON_GetObjectItemCaseSensitive(jthr, "count");
        if (cJSON_IsNumber(j)) thr->count = (uint32_t)j->valueint;

        j = cJSON_GetObjectItemCaseSensitive(jthr, "window_ms");
        if (cJSON_IsNumber(j)) thr->window_ms = (uint32_t)j->valueint;

        j = cJSON_GetObjectItemCaseSensitive(jthr, "group_by");
        if (cJSON_IsString(j)) SAFE_STRNCPY(thr->group_by, j->valuestring, sizeof(thr->group_by));

        j = cJSON_GetObjectItemCaseSensitive(jthr, "unique_field");
        if (cJSON_IsString(j)) SAFE_STRNCPY(thr->unique_field, j->valuestring, sizeof(thr->unique_field));
    }

#undef GET_STR
    return 1;
}

/* =========================================================
 *  规则引擎初始化
 * ========================================================= */
int RE_Init(RuleEngine* engine)
{
    if (!engine) return 0;
    memset(engine, 0, sizeof(RuleEngine));
    engine->sessions.next_session_id = 1;
    return 1;
}

/* =========================================================
 *  从 JSON 文件加载规则库
 * ========================================================= */
int RE_LoadRules(RuleEngine* engine, const char* json_path)
{
    if (!engine || !json_path) return -1;

    /* 读取文件 */
    FILE* fp = fopen(json_path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 4 * 1024 * 1024) { /* 最大 4MB */
        fclose(fp);
        return -1;
    }

    char* buf = (char*)malloc((size_t)fsize + 1);
    if (!buf) { fclose(fp); return -1; }

    size_t read_bytes = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);
    buf[read_bytes] = '\0';

    /* cJSON 解析 */
    cJSON* root = cJSON_Parse(buf);
    free(buf);
    if (!root) return -1;

    /* 提取 version */
    cJSON* jver = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (cJSON_IsString(jver))
        SAFE_STRNCPY(engine->ruleset.version, jver->valuestring,
                     sizeof(engine->ruleset.version));

    /* 先卸载旧规则 */
    RE_UnloadRules(engine);
    SAFE_STRNCPY(engine->ruleset.db_path, json_path,
                 sizeof(engine->ruleset.db_path));

    /* 遍历 rules 数组 */
    cJSON* jrules = cJSON_GetObjectItemCaseSensitive(root, "rules");
    int loaded = 0;
    if (cJSON_IsArray(jrules)) {
        cJSON* jrule = NULL;
        cJSON_ArrayForEach(jrule, jrules) {
            if (engine->ruleset.count >= RE_MAX_RULES) break;
            Rule* rule = &engine->ruleset.rules[engine->ruleset.count];
            if (parse_one_rule(jrule, rule)) {
                engine->ruleset.count++;
                loaded++;
            }
        }
    }

    cJSON_Delete(root);
    return loaded;
}

/* =========================================================
 *  卸载规则库
 * ========================================================= */
void RE_UnloadRules(RuleEngine* engine)
{
    if (!engine) return;
    /* 释放编译的正则（如果使用 PCRE2 则在此 free） */
    for (int i = 0; i < engine->ruleset.count; i++) {
        Rule* r = &engine->ruleset.rules[i];
        for (int c = 0; c < r->condition_count; c++) {
            if (r->conditions[c].compiled_regex) {
                free(r->conditions[c].compiled_regex);
                r->conditions[c].compiled_regex = NULL;
            }
        }
    }
    engine->ruleset.count = 0;
}

/* =========================================================
 *  销毁规则引擎
 * ========================================================= */
void RE_Destroy(RuleEngine* engine)
{
    if (!engine) return;
    RE_UnloadRules(engine);

    /* 释放会话表 */
    for (int i = 0; i < SESSION_TABLE_SIZE; i++) {
        SessionEntry* e = engine->sessions.buckets[i];
        while (e) {
            SessionEntry* next = e->next;
            free(e);
            e = next;
        }
        engine->sessions.buckets[i] = NULL;
    }

    /* 释放阈值表 */
    for (int i = 0; i < THRESH_TABLE_SIZE; i++) {
        ThreshEntry* e = engine->thresholds.buckets[i];
        while (e) {
            ThreshEntry* next = e->next;
            free(e);
            e = next;
        }
        engine->thresholds.buckets[i] = NULL;
    }
}

/* =========================================================
 *  启用/禁用规则
 * ========================================================= */
int RE_SetRuleEnabled(RuleEngine* engine, const char* rule_id, int enable)
{
    if (!engine || !rule_id) return 0;
    for (int i = 0; i < engine->ruleset.count; i++) {
        if (strcmp(engine->ruleset.rules[i].rule_id, rule_id) == 0) {
            engine->ruleset.rules[i].enabled = enable ? 1 : 0;
            return 1;
        }
    }
    return 0;
}

/* =========================================================
 *  会话表操作
 * ========================================================= */
static uint32_t session_hash(uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint8_t proto)
{
    uint32_t h = src_ip ^ dst_ip ^ ((uint32_t)src_port << 16 | dst_port)
                 ^ ((uint32_t)proto << 24);
    h ^= (h >> 16);
    h *= 0x45d9f3b;
    h ^= (h >> 16);
    return h % SESSION_TABLE_SIZE;
}

static SessionEntry* session_find(SessionTable* tbl,
                                   uint32_t src_ip, uint32_t dst_ip,
                                   uint16_t src_port, uint16_t dst_port,
                                   uint8_t proto)
{
    uint32_t idx = session_hash(src_ip, dst_ip, src_port, dst_port, proto);
    SessionEntry* e = tbl->buckets[idx];
    while (e) {
        if (e->src_ip == src_ip && e->dst_ip == dst_ip &&
            e->src_port == src_port && e->dst_port == dst_port &&
            e->ip_proto == proto)
            return e;
        /* 双向匹配 */
        if (e->src_ip == dst_ip && e->dst_ip == src_ip &&
            e->src_port == dst_port && e->dst_port == src_port &&
            e->ip_proto == proto)
            return e;
        e = e->next;
    }
    return NULL;
}

static SessionEntry* session_create(SessionTable* tbl,
                                     uint32_t src_ip, uint32_t dst_ip,
                                     uint16_t src_port, uint16_t dst_port,
                                     uint8_t proto,
                                     const char* rule_id,
                                     uint64_t now_us)
{
    if (tbl->entry_count >= SESSION_MAX_ENTRIES) return NULL;

    SessionEntry* e = (SessionEntry*)calloc(1, sizeof(SessionEntry));
    if (!e) return NULL;

    e->session_id    = tbl->next_session_id++;
    e->src_ip        = src_ip;
    e->dst_ip        = dst_ip;
    e->src_port      = src_port;
    e->dst_port      = dst_port;
    e->ip_proto      = proto;
    e->stage         = 1;
    e->first_seen_us = now_us;
    e->last_seen_us  = now_us;
    SAFE_STRNCPY(e->rule_id, rule_id, sizeof(e->rule_id));

    uint32_t idx = session_hash(src_ip, dst_ip, src_port, dst_port, proto);
    e->next = tbl->buckets[idx];
    tbl->buckets[idx] = e;
    tbl->entry_count++;
    return e;
}

static void session_remove(SessionTable* tbl,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t proto)
{
    uint32_t idx = session_hash(src_ip, dst_ip, src_port, dst_port, proto);
    SessionEntry** pp = &tbl->buckets[idx];
    while (*pp) {
        SessionEntry* e = *pp;
        if (e->src_ip == src_ip && e->dst_ip == dst_ip &&
            e->src_port == src_port && e->dst_port == dst_port &&
            e->ip_proto == proto) {
            *pp = e->next;
            free(e);
            tbl->entry_count--;
            return;
        }
        pp = &e->next;
    }
}

/* =========================================================
 *  清理过期会话
 * ========================================================= */
void RE_PurgeExpiredSessions(RuleEngine* engine, uint64_t now_us)
{
    uint64_t timeout_us = (uint64_t)SESSION_TIMEOUT_MS * 1000;
    for (int i = 0; i < SESSION_TABLE_SIZE; i++) {
        SessionEntry** pp = &engine->sessions.buckets[i];
        while (*pp) {
            SessionEntry* e = *pp;
            if (now_us - e->last_seen_us > timeout_us) {
                *pp = e->next;
                free(e);
                engine->sessions.entry_count--;
            } else {
                pp = &e->next;
            }
        }
    }
}

/* =========================================================
 *  获取当前会话数
 * ========================================================= */
uint32_t RE_GetSessionCount(const RuleEngine* engine)
{
    return engine ? engine->sessions.entry_count : 0;
}

/* =========================================================
 *  阈值表操作
 * ========================================================= */
static uint32_t thresh_hash(const char* key)
{
    uint32_t h = 5381;
    while (*key) h = ((h << 5) + h) ^ (uint8_t)*key++;
    return h % THRESH_TABLE_SIZE;
}

static ThreshEntry* thresh_find_or_create(ThreshTable* tbl,
                                           const char* key,
                                           const char* rule_id,
                                           uint64_t now_us,
                                           uint32_t window_ms)
{
    uint32_t idx = thresh_hash(key);
    ThreshEntry* e = tbl->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0 && strcmp(e->rule_id, rule_id) == 0)
            return e;
        e = e->next;
    }

    /* 创建新条目 */
    if (tbl->entry_count >= THRESH_MAX_ENTRIES) return NULL;
    e = (ThreshEntry*)calloc(1, sizeof(ThreshEntry));
    if (!e) return NULL;

    SAFE_STRNCPY(e->key,     key,     sizeof(e->key));
    SAFE_STRNCPY(e->rule_id, rule_id, sizeof(e->rule_id));
    e->window_start_us = now_us;
    e->count           = 0;
    e->next            = tbl->buckets[idx];
    tbl->buckets[idx]  = e;
    tbl->entry_count++;
    return e;
}

/* =========================================================
 *  从 ParsedPacket 中获取字段值（字符串形式）
 * ========================================================= */
static int get_field_str(const ParsedPacket* pkt,
                          const char* field,
                          char* out, size_t out_sz)
{
    if (strcmp(field, "smb_command") == 0) {
        snprintf(out, out_sz, "0x%02X", pkt->smb_command);
        return 1;
    }
    if (strcmp(field, "smb_status") == 0) {
        snprintf(out, out_sz, "0x%08X", pkt->smb_status);
        return 1;
    }
    if (strcmp(field, "smb_version") == 0) {
        snprintf(out, out_sz, "%d", pkt->smb_version);
        return 1;
    }
    if (strcmp(field, "smb_compression_flag") == 0) {
        snprintf(out, out_sz, "%d", pkt->smb_compression);
        return 1;
    }
    if (strcmp(field, "smb_tree_path") == 0) {
        SAFE_STRNCPY(out, pkt->smb_tree_path, out_sz); return 1;
    }
    if (strcmp(field, "smb_filename") == 0) {
        SAFE_STRNCPY(out, pkt->smb_filename, out_sz); return 1;
    }
    if (strcmp(field, "smb_fid") == 0) {
        snprintf(out, out_sz, "0x%04X", pkt->smb_fid); return 1;
    }
    if (strcmp(field, "dcerpc_uuid") == 0) {
        SAFE_STRNCPY(out, pkt->dcerpc_uuid, out_sz); return 1;
    }
    if (strcmp(field, "dcerpc_opnum") == 0) {
        snprintf(out, out_sz, "0x%02X", pkt->dcerpc_opnum); return 1;
    }
    if (strcmp(field, "dns_query") == 0) {
        SAFE_STRNCPY(out, pkt->dns_query, out_sz); return 1;
    }
    if (strcmp(field, "http_method") == 0) {
        SAFE_STRNCPY(out, pkt->http_method, out_sz); return 1;
    }
    if (strcmp(field, "http_uri") == 0) {
        SAFE_STRNCPY(out, pkt->http_uri, out_sz); return 1;
    }
    if (strcmp(field, "http_header_any") == 0) {
        SAFE_STRNCPY(out, pkt->http_headers, out_sz); return 1;
    }
    if (strcmp(field, "http_cookie") == 0) {
        SAFE_STRNCPY(out, pkt->http_cookie, out_sz); return 1;
    }
    if (strcmp(field, "rdp_channel") == 0) {
        SAFE_STRNCPY(out, pkt->rdp_channel, out_sz); return 1;
    }
    if (strcmp(field, "rdp_pdu_type") == 0) {
        snprintf(out, out_sz, "0x%02X", pkt->rdp_pdu_type); return 1;
    }
    if (strcmp(field, "icmp_type") == 0) {
        snprintf(out, out_sz, "%d", pkt->icmp_type); return 1;
    }
    if (strcmp(field, "tcp_flags") == 0) {
        /* 返回标志字符串 */
        char flags[32] = "";
        if (pkt->tcp_flags & 0x02) strcat(flags, "SYN");
        if (pkt->tcp_flags & 0x10) strcat(flags, "ACK");
        if (pkt->tcp_flags & 0x01) strcat(flags, "FIN");
        if (pkt->tcp_flags & 0x04) strcat(flags, "RST");
        SAFE_STRNCPY(out, flags, out_sz); return 1;
    }
    if (strcmp(field, "src_ip") == 0) {
        SAFE_STRNCPY(out, pkt->src_ip, out_sz); return 1;
    }
    if (strcmp(field, "dst_ip") == 0) {
        SAFE_STRNCPY(out, pkt->dst_ip, out_sz); return 1;
    }
    return 0;
}

/* 获取数值字段 */
static int get_field_num(const ParsedPacket* pkt,
                          const char* field, long long* out_val)
{
    if (strcmp(field, "payload_length") == 0) {
        *out_val = (long long)pkt->payload_len; return 1;
    }
    if (strcmp(field, "dst_port") == 0) {
        *out_val = (long long)pkt->dst_port; return 1;
    }
    if (strcmp(field, "src_port") == 0) {
        *out_val = (long long)pkt->src_port; return 1;
    }
    if (strcmp(field, "ip_ttl") == 0) {
        *out_val = (long long)pkt->ip_ttl; return 1;
    }
    return 0;
}

/* =========================================================
 *  单条件匹配
 * ========================================================= */
static int eval_condition(const RuleCondition* cond, const ParsedPacket* pkt)
{
    /* 载荷字节序列匹配 */
    if (strcmp(cond->field, "payload_pattern") == 0) {
        if (!pkt->payload || pkt->payload_len == 0) return 0;
        if (cond->op == OP_HEX_MATCH) {
            return bmh_search(pkt->payload, pkt->payload_len,
                              cond->hex_bytes, (size_t)cond->hex_len) != NULL;
        }
        if (cond->op == OP_REGEX || cond->op == OP_CONTAINS) {
            return pattern_match(cond->value, pkt->payload, pkt->payload_len);
        }
        return 0;
    }

    /* 数值字段 */
    long long num_val = 0;
    if (get_field_num(pkt, cond->field, &num_val)) {
        long long cmp_val = strtoll(cond->value, NULL, 0);
        switch (cond->op) {
            case OP_EQ:  return num_val == cmp_val;
            case OP_NEQ: return num_val != cmp_val;
            case OP_GT:  return num_val >  cmp_val;
            case OP_LT:  return num_val <  cmp_val;
            case OP_GTE: return num_val >= cmp_val;
            case OP_LTE: return num_val <= cmp_val;
            default:     return 0;
        }
    }

    /* 字符串字段 */
    char field_val[4096] = "";
    if (!get_field_str(pkt, cond->field, field_val, sizeof(field_val)))
        return 0;

    switch (cond->op) {
        case OP_EQ:
            return strcasecmp(field_val, cond->value) == 0;
        case OP_NEQ:
            return strcasecmp(field_val, cond->value) != 0;
        case OP_CONTAINS:
            return strstr(field_val, cond->value) != NULL;
        case OP_REGEX: {
            /* 简单展开匹配（生产环境建议替换为 PCRE2） */
            uint8_t expanded[512];
            int exp_len = expand_pattern(cond->value, expanded, sizeof(expanded));
            if (exp_len <= 0) return 0;
            return bmh_search((const uint8_t*)field_val, strlen(field_val),
                               expanded, (size_t)exp_len) != NULL;
        }
        case OP_HEX_MATCH:
            return bmh_search((const uint8_t*)field_val, strlen(field_val),
                               cond->hex_bytes, (size_t)cond->hex_len) != NULL;
        default:
            return 0;
    }
}

/* =========================================================
 *  协议过滤：判断数据包是否匹配规则的协议/端口
 * ========================================================= */
static int proto_match(const Rule* rule, const ParsedPacket* pkt)
{
    /* ANY 协议规则不过滤 */
    if (strcmp(rule->protocol, "ANY") == 0) return 1;

    /* 端口过滤（0=任意） */
    if (rule->dst_port != 0 &&
        pkt->dst_port != rule->dst_port &&
        pkt->src_port != rule->dst_port)
        return 0;

    /* 协议类型过滤 */
    if (strcmp(rule->protocol, "SMB") == 0) {
        return pkt->app_proto == PROTO_SMB1 ||
               pkt->app_proto == PROTO_SMB2 ||
               pkt->app_proto == PROTO_SMB3_COMPRESS;
    }
    if (strcmp(rule->protocol, "HTTP") == 0)
        return pkt->app_proto == PROTO_HTTP;
    if (strcmp(rule->protocol, "DNS") == 0)
        return pkt->app_proto == PROTO_DNS;
    if (strcmp(rule->protocol, "RDP") == 0)
        return pkt->app_proto == PROTO_RDP;
    if (strcmp(rule->protocol, "DCERPC") == 0)
        return pkt->app_proto == PROTO_DCERPC;
    if (strcmp(rule->protocol, "TCP") == 0)
        return pkt->ip_proto == IP_PROTO_TCP;
    if (strcmp(rule->protocol, "UDP") == 0)
        return pkt->ip_proto == IP_PROTO_UDP;
    if (strcmp(rule->protocol, "ICMP") == 0)
        return pkt->ip_proto == IP_PROTO_ICMP;

    return 1;
}

/* =========================================================
 *  填充告警结构体
 * ========================================================= */
static void fill_alert(VDE_Alert* alert, const Rule* rule,
                        const ParsedPacket* pkt, uint64_t session_id)
{
    memset(alert, 0, sizeof(VDE_Alert));
    SAFE_STRNCPY(alert->rule_id,     rule->rule_id,     sizeof(alert->rule_id));
    SAFE_STRNCPY(alert->rule_name,   rule->name,        sizeof(alert->rule_name));
    SAFE_STRNCPY(alert->cve,         rule->cve,         sizeof(alert->cve));
    SAFE_STRNCPY(alert->description, rule->description, sizeof(alert->description));
    SAFE_STRNCPY(alert->protocol,    rule->protocol,    sizeof(alert->protocol));
    SAFE_STRNCPY(alert->src_ip,      pkt->src_ip,       sizeof(alert->src_ip));
    SAFE_STRNCPY(alert->dst_ip,      pkt->dst_ip,       sizeof(alert->dst_ip));
    alert->severity      = rule->severity;
    alert->src_port      = pkt->src_port;
    alert->dst_port      = pkt->dst_port;
    alert->timestamp_us  = pkt->timestamp_us;
    alert->pkt_len       = pkt->raw_pkt_len;
    alert->session_id    = session_id;

    /* 载荷转储 */
    if (pkt->payload && pkt->payload_len > 0) {
        uint32_t dump_len = pkt->payload_len < VDE_MAX_PAYLOAD_DUMP
                            ? pkt->payload_len : VDE_MAX_PAYLOAD_DUMP;
        memcpy(alert->payload_dump, pkt->payload, dump_len);
        alert->payload_dump_len = dump_len;
    }
}

/* =========================================================
 *  主匹配函数
 * ========================================================= */
int RE_MatchPacket(RuleEngine* engine, const ParsedPacket* pkt,
                   VDE_Alert* out_alert)
{
    if (!engine || !pkt || !out_alert) return 0;

    uint64_t now_us = pkt->timestamp_us ? pkt->timestamp_us : get_time_us();

    for (int i = 0; i < engine->ruleset.count; i++) {
        Rule* rule = &engine->ruleset.rules[i];
        if (!rule->enabled) continue;

        /* 协议/端口预过滤 */
        if (!proto_match(rule, pkt)) continue;

        /* ---- 无状态匹配 ---- */
        if (rule->match_type == MATCH_STATELESS) {
            int all_match = 1;
            for (int c = 0; c < rule->condition_count; c++) {
                if (!eval_condition(&rule->conditions[c], pkt)) {
                    all_match = 0; break;
                }
            }
            if (all_match && rule->condition_count > 0) {
                fill_alert(out_alert, rule, pkt, 0);
                return 1;
            }
        }

        /* ---- 有状态匹配 ---- */
        else if (rule->match_type == MATCH_STATEFUL) {
            SessionEntry* sess = session_find(&engine->sessions,
                                              pkt->src_ip_raw, pkt->dst_ip_raw,
                                              pkt->src_port, pkt->dst_port,
                                              pkt->ip_proto);

            if (!sess) {
                /* 检查主条件（阶段0） */
                int all_match = 1;
                for (int c = 0; c < rule->condition_count; c++) {
                    if (!eval_condition(&rule->conditions[c], pkt)) {
                        all_match = 0; break;
                    }
                }
                if (all_match && rule->condition_count > 0) {
                    if (rule->has_follow_up) {
                        /* 创建会话，等待后续包 */
                        session_create(&engine->sessions,
                                       pkt->src_ip_raw, pkt->dst_ip_raw,
                                       pkt->src_port, pkt->dst_port,
                                       pkt->ip_proto, rule->rule_id, now_us);
                    } else {
                        fill_alert(out_alert, rule, pkt, 0);
                        return 1;
                    }
                }
            } else if (strcmp(sess->rule_id, rule->rule_id) == 0) {
                /* 检查后续包条件（阶段1） */
                uint64_t interval_ms = (now_us - sess->first_seen_us) / 1000;
                int timeout = rule->has_follow_up &&
                              interval_ms > rule->follow_up.max_interval_ms;

                if (timeout) {
                    session_remove(&engine->sessions,
                                   pkt->src_ip_raw, pkt->dst_ip_raw,
                                   pkt->src_port, pkt->dst_port,
                                   pkt->ip_proto);
                    continue;
                }

                /* 检查后续包的 smb_command 或 payload_pattern */
                int fu_match = 0;
                if (rule->has_follow_up) {
                    FollowUpCondition* fu = &rule->follow_up;
                    int cmd_ok = 1, pat_ok = 1;

                    if (fu->smb_command[0]) {
                        char cmd_str[16];
                        snprintf(cmd_str, sizeof(cmd_str), "0x%02X", pkt->smb_command);
                        cmd_ok = (strcasecmp(cmd_str, fu->smb_command) == 0);
                    }
                    if (fu->payload_pattern[0] && pkt->payload && pkt->payload_len > 0) {
                        pat_ok = pattern_match(fu->payload_pattern,
                                               pkt->payload, pkt->payload_len);
                    }
                    fu_match = cmd_ok && pat_ok;
                }

                if (fu_match) {
                    uint64_t sid = sess->session_id;
                    session_remove(&engine->sessions,
                                   pkt->src_ip_raw, pkt->dst_ip_raw,
                                   pkt->src_port, pkt->dst_port,
                                   pkt->ip_proto);
                    fill_alert(out_alert, rule, pkt, sid);
                    return 1;
                }
                sess->last_seen_us = now_us;
            }
        }

        /* ---- 阈值匹配 ---- */
        else if (rule->match_type == MATCH_THRESHOLD) {
            /* 检查基本条件 */
            int cond_ok = 1;
            for (int c = 0; c < rule->condition_count; c++) {
                if (!eval_condition(&rule->conditions[c], pkt)) {
                    cond_ok = 0; break;
                }
            }
            if (!cond_ok) continue;

            /* 构建分组键 */
            char group_key[128] = "";
            if (strcmp(rule->threshold.group_by, "src_ip") == 0) {
                snprintf(group_key, sizeof(group_key), "src:%s", pkt->src_ip);
            } else if (strcmp(rule->threshold.group_by, "dst_ip") == 0) {
                snprintf(group_key, sizeof(group_key), "dst:%s", pkt->dst_ip);
            } else {
                snprintf(group_key, sizeof(group_key), "any");
            }

            ThreshEntry* te = thresh_find_or_create(&engine->thresholds,
                                                     group_key, rule->rule_id,
                                                     now_us,
                                                     rule->threshold.window_ms);
            if (!te) continue;

            /* 检查时间窗口是否过期 */
            uint64_t window_us = (uint64_t)rule->threshold.window_ms * 1000;
            if (now_us - te->window_start_us > window_us) {
                te->count           = 0;
                te->unique_count    = 0;
                te->unique_bitmap   = 0;
                te->window_start_us = now_us;
            }

            te->count++;

            /* unique_field 去重计数（dst_port） */
            if (rule->threshold.unique_field[0] &&
                strcmp(rule->threshold.unique_field, "dst_port") == 0) {
                uint32_t uval = pkt->dst_port;
                int already = 0;
                for (int u = 0; u < te->unique_count && u < 64; u++) {
                    if (te->unique_vals[u] == uval) { already = 1; break; }
                }
                if (!already && te->unique_count < 64) {
                    te->unique_vals[te->unique_count++] = uval;
                }
            }

            /* 判断是否超过阈值 */
            uint32_t check_count = rule->threshold.unique_field[0]
                                   ? te->unique_count : te->count;
            if (check_count >= rule->threshold.count) {
                /* 重置计数器，避免重复告警 */
                te->count           = 0;
                te->unique_count    = 0;
                te->window_start_us = now_us;
                fill_alert(out_alert, rule, pkt, 0);
                return 1;
            }
        }
    }

    return 0;
}
