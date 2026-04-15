/**
 * @file  main.c
 * @brief VulnDetectEngine 宿主程序示例
 *        - LIVE 模式：自动监听所有非 loopback 接口（每卡独立线程）
 *        - OFFLINE 模式：分析指定 pcap 文件
 *        - 定期打印每个接口的独立统计
 */

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  define sleep(s) Sleep((s)*1000)
#  define VDE_CALLBACK __cdecl
#else
#  include <unistd.h>
#  include <signal.h>
#  define VDE_CALLBACK
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "VulnDetectEngine.h"

/* =========================================================
 *  全局句柄（信号处理用）
 * ========================================================= */
static VDE_Handle g_engine = NULL;
static volatile int g_stop = 0;

#ifndef _WIN32
static void sig_handler(int sig) { (void)sig; g_stop = 1; }
#endif

/* =========================================================
 *  告警回调
 * ========================================================= */
static void VDE_CALLBACK on_alert(const VDE_Alert* alert, void* ctx) {
    (void)ctx;

    time_t t = (time_t)(alert->timestamp_us / 1000000ULL);
    struct tm* tm_info = localtime(&t);
    char ts_buf[32] = {0};
    if (tm_info) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  [ALERT] %-52s║\n", alert->rule_name);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  规则ID  : %-50s║\n", alert->rule_id);
    printf("║  CVE     : %-50s║\n", alert->cve[0] ? alert->cve : "N/A");
    printf("║  严重级别: %-50s║\n", VDE_SeverityString(alert->severity));
    printf("║  时间    : %-50s║\n", ts_buf);
    printf("║  接口    : %-50s║\n", alert->iface_name);
    printf("║  源地址  : %-15s:%-4u → %-15s:%-4u        ║\n",
           alert->src_ip, alert->src_port,
           alert->dst_ip, alert->dst_port);
    printf("║  协议    : %-50s║\n", alert->protocol);
    printf("║  描述    : %-50s║\n", alert->description);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    fflush(stdout);
}

/* =========================================================
 *  打印多网卡统计
 * ========================================================= */
static void print_iface_stats(VDE_Handle engine) {
    VDE_IfaceStatistics iface_stats[VDE_MAX_DEVICES];
    int iface_cnt = 0;
    VDE_GetIfaceStatistics(engine, iface_stats, VDE_MAX_DEVICES, &iface_cnt);

    VDE_Statistics global;
    VDE_GetStatistics(engine, &global);

    printf("\n┌─────────────────────────────────────────────────────────────────────────┐\n");
    printf("│  VulnDetectEngine 运行统计  [规则: %d/%d]                              │\n",
           (int)global.rules_enabled, (int)global.rules_loaded);
    printf("├──────────────────────┬──────────┬──────────┬──────────┬──────────┬──────┤\n");
    printf("│ 接口 (IP)            │  捕获包  │  分析包  │  丢包    │  告警    │ pps  │\n");
    printf("├──────────────────────┼──────────┼──────────┼──────────┼──────────┼──────┤\n");

    for (int i = 0; i < iface_cnt; i++) {
        VDE_IfaceStatistics* s = &iface_stats[i];
        char iface_ip[48];
        snprintf(iface_ip, sizeof(iface_ip), "%s (%s)", s->iface_name, s->ip_addr);
        printf("│ %-20.20s │ %8llu │ %8llu │ %8llu │ %8llu │ %4.0f │ %s\n",
               iface_ip,
               (unsigned long long)s->packets_captured,
               (unsigned long long)s->packets_analyzed,
               (unsigned long long)s->packets_dropped,
               (unsigned long long)s->alerts_generated,
               s->packets_per_sec,
               s->running ? "[运行中]" : "[已停止]");
    }

    printf("├──────────────────────┼──────────┼──────────┼──────────┼──────────┼──────┤\n");
    printf("│ %-20s │ %8llu │ %8llu │ %8llu │ %8llu │ %4.0f │\n",
           "合计",
           (unsigned long long)global.packets_captured,
           (unsigned long long)global.packets_analyzed,
           (unsigned long long)global.packets_dropped,
           (unsigned long long)global.alerts_generated,
           global.packets_per_sec);
    printf("└──────────────────────┴──────────┴──────────┴──────────┴──────────┴──────┘\n");
    fflush(stdout);
}

/* =========================================================
 *  打印帮助
 * ========================================================= */
static void print_help(const char* prog) {
    printf("用法: %s [选项]\n\n", prog);
    printf("选项:\n");
    printf("  -i <网卡名>      指定单个网卡（LIVE 模式，不指定则自动监听所有非 loopback 接口）\n");
    printf("  -p <pcap文件>    OFFLINE 模式：分析 pcap 文件\n");
    printf("  -r <规则库路径>  规则库 JSON 文件（默认: RuleDB/vuln_rules.json）\n");
    printf("  -f <BPF表达式>   BPF 过滤（所有接口共用）\n");
    printf("  -l               列出所有网卡并退出\n");
    printf("  -s               每 5 秒打印一次统计（LIVE 模式）\n");
    printf("  -v               DEBUG 详细日志\n");
    printf("  -h               显示帮助\n\n");
    printf("示例:\n");
    printf("  %s                              # 自动监听所有非 loopback 接口\n", prog);
    printf("  %s -p capture.pcap              # 分析 pcap 文件\n", prog);
    printf("  %s -r /etc/vde/rules.json -s    # 指定规则库 + 定期统计\n", prog);
    printf("  %s -f \"tcp port 445 or port 80\" # BPF 过滤\n", prog);
}

/* =========================================================
 *  main
 * ========================================================= */
int main(int argc, char* argv[]) {
    char pcap_file[512]    = {0};
    char rule_db[512]      = "RuleDB/vuln_rules.json";
    char bpf_filter[256]   = {0};
    char device[256]       = {0};
    int  show_stats        = 0;
    int  verbose           = 0;
    int  list_devs         = 0;

    /* 解析命令行 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            strncpy(pcap_file, argv[++i], sizeof(pcap_file)-1);
        } else if (strcmp(argv[i], "-r") == 0 && i+1 < argc) {
            strncpy(rule_db, argv[++i], sizeof(rule_db)-1);
        } else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) {
            strncpy(bpf_filter, argv[++i], sizeof(bpf_filter)-1);
        } else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
            strncpy(device, argv[++i], sizeof(device)-1);
        } else if (strcmp(argv[i], "-s") == 0) {
            show_stats = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-l") == 0) {
            list_devs = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        }
    }

    /* 列出网卡 */
    if (list_devs) {
        VDE_DeviceList devlist;
        if (VDE_EnumDevices(&devlist) == VDE_OK) {
            printf("可用网络接口 (%d 个):\n", devlist.count);
            for (int i = 0; i < devlist.count; i++) {
                VDE_DeviceInfo* d = &devlist.devices[i];
                printf("  [%d] %-30s  IP: %-16s  %s%s\n",
                       i+1, d->name, d->ip_addr[0] ? d->ip_addr : "N/A",
                       d->is_loopback ? "[loopback]" : "",
                       d->description[0] ? d->description : "");
            }
        }
        return 0;
    }

    printf("VulnDetectEngine v%s\n", VDE_GetVersion());
    printf("规则库: %s\n\n", rule_db);

    /* 配置引擎 */
    VDE_Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (pcap_file[0]) {
        cfg.mode = VDE_MODE_OFFLINE;
        strncpy(cfg.pcap_file, pcap_file, VDE_MAX_PATH_LEN-1);
        printf("模式: OFFLINE  文件: %s\n", pcap_file);
    } else {
        cfg.mode = VDE_MODE_LIVE;
        /* device 指定时写入 bpf_filter 备用；多网卡模式忽略 device 字段 */
        if (device[0]) {
            printf("模式: LIVE  指定接口: %s\n", device);
            /* 将指定接口名附加到 BPF 过滤（引擎内部会枚举，此处仅提示） */
        } else {
            printf("模式: LIVE  自动监听所有非 loopback 接口\n");
        }
    }

    strncpy(cfg.rule_db_path, rule_db, VDE_MAX_PATH_LEN-1);
    strncpy(cfg.bpf_filter,   bpf_filter, VDE_MAX_FILTER_LEN-1);
    cfg.snaplen        = 65535;
    cfg.promiscuous    = 1;
    cfg.read_timeout_ms= 500;
    cfg.log_level      = verbose ? 4 : 3;  /* DEBUG : INFO */
    cfg.alert_callback = on_alert;
    cfg.alert_callback_ctx = NULL;

    /* 创建引擎 */
    VDE_Handle engine = NULL;
    VDE_ErrorCode rc = VDE_Create(&cfg, &engine);
    if (rc != VDE_OK) {
        fprintf(stderr, "VDE_Create 失败: %s\n", VDE_ErrorString(rc));
        return 1;
    }
    g_engine = engine;

    /* 打印已加载规则 */
    VDE_RuleInfo rules[256];
    int rule_cnt = 0;
    VDE_GetRules(engine, rules, 256, &rule_cnt);
    printf("已加载 %d 条规则:\n", rule_cnt);
    for (int i = 0; i < rule_cnt && i < 10; i++) {
        printf("  [%s] %-30s  %s  %s\n",
               rules[i].rule_id, rules[i].rule_name,
               VDE_SeverityString(rules[i].severity),
               rules[i].cve[0] ? rules[i].cve : "");
    }
    if (rule_cnt > 10) printf("  ... 共 %d 条（仅显示前10条）\n", rule_cnt);
    printf("\n");

    /* 启动引擎 */
    rc = VDE_Start(engine);
    if (rc != VDE_OK && rc != VDE_ERR_PARTIAL) {
        fprintf(stderr, "VDE_Start 失败: %s\n  %s\n",
                VDE_ErrorString(rc), VDE_GetLastError(engine));
        VDE_Destroy(engine);
        return 1;
    }
    if (rc == VDE_ERR_PARTIAL) {
        printf("[警告] 部分接口启动失败，继续运行已成功的接口\n");
    }

    /* 打印初始接口状态 */
    print_iface_stats(engine);

    /* 注册信号 */
#ifndef _WIN32
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
#endif

    if (pcap_file[0]) {
        /* OFFLINE：等待分析完成 */
        printf("正在分析 pcap 文件，请稍候...\n");
        while (VDE_IsRunning(engine) && !g_stop) {
            sleep(1);
        }
        /* 等待线程完全退出 */
        sleep(1);
        print_iface_stats(engine);
    } else {
        /* LIVE：循环等待，定期打印统计 */
        printf("按 Ctrl+C 停止监听...\n\n");
        int tick = 0;
        while (!g_stop) {
            sleep(1);
            tick++;
            if (show_stats && tick % 5 == 0) {
                print_iface_stats(engine);
            }
        }
        printf("\n正在停止...\n");
        VDE_Stop(engine);
        print_iface_stats(engine);
    }

    VDE_Destroy(engine);
    printf("引擎已退出。\n");
    return 0;
}
