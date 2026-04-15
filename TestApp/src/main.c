/**
 * @file    main.c
 * @brief   VulnDetectEngine DLL 宿主程序示例
 *
 * 用法：
 *   TestApp.exe [选项]
 *
 * 选项：
 *   -l               列出所有网络接口
 *   -i <接口名>      指定监听网卡（LIVE模式）
 *   -r <pcap文件>    读取离线pcap文件（OFFLINE模式）
 *   -d <规则库路径>  指定规则库JSON文件（默认 ./RuleDB/vuln_rules.json）
 *   -o <日志目录>    指定日志输出目录（默认 ./logs）
 *   -f <BPF过滤>     设置BPF过滤表达式
 *   -v               详细输出（DEBUG日志级别）
 *   -s               每5秒打印一次统计信息
 *   -h               显示帮助
 *
 * 示例：
 *   TestApp.exe -l
 *   TestApp.exe -i "\Device\NPF_{GUID}" -d ./RuleDB/vuln_rules.json -o ./logs
 *   TestApp.exe -r capture.pcap -d ./RuleDB/vuln_rules.json
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#  include <windows.h>
#  include <conio.h>
#  define SLEEP_MS(ms) Sleep(ms)
#else
#  include <unistd.h>
#  define SLEEP_MS(ms) usleep((ms)*1000)
#endif

#include "../../DetectEngine/include/VulnDetectEngine.h"

/* =========================================================
 *  全局变量
 * ========================================================= */
static volatile int g_running = 1;
static VDE_Handle   g_handle  = NULL;

/* =========================================================
 *  信号处理
 * ========================================================= */
static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
    if (g_handle && VDE_IsRunning(g_handle)) {
        VDE_Stop(g_handle);
    }
}

/* =========================================================
 *  告警回调函数
 * ========================================================= */
static void __cdecl on_alert(const VDE_Alert* alert, void* ctx)
{
    (void)ctx;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  [!] 漏洞攻击告警                                    ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  规则ID   : %-40s  ║\n", alert->rule_id);
    printf("║  规则名称 : %-40s  ║\n", alert->rule_name);
    printf("║  CVE      : %-40s  ║\n", alert->cve);
    printf("║  严重级别 : %-40s  ║\n", VDE_SeverityString(alert->severity));
    printf("║  协议     : %-40s  ║\n", alert->protocol);
    printf("║  源地址   : %-20s:%-5u                    ║\n",
           alert->src_ip, alert->src_port);
    printf("║  目的地址 : %-20s:%-5u                    ║\n",
           alert->dst_ip, alert->dst_port);
    printf("║  数据包长 : %-6u 字节                                ║\n",
           alert->pkt_len);
    if (alert->session_id)
        printf("║  会话ID   : %-20llu                        ║\n",
               (unsigned long long)alert->session_id);

    /* 载荷十六进制 */
    if (alert->payload_dump_len > 0) {
        printf("║  载荷(HEX): ");
        for (uint32_t i = 0; i < alert->payload_dump_len && i < 16; i++)
            printf("%02X ", alert->payload_dump[i]);
        printf("%-*s  ║\n",
               (int)(16 - (alert->payload_dump_len < 16
                           ? alert->payload_dump_len : 16)) * 3, "");
    }
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("  描述: %s\n\n", alert->description);
}

/* =========================================================
 *  打印统计信息
 * ========================================================= */
static void print_stats(VDE_Handle handle)
{
    VDE_Statistics stat;
    if (VDE_GetStatistics(handle, &stat) == VDE_OK) {
        printf("\n[统计] 捕获: %llu | 分析: %llu | 告警: %llu"
               " | 丢包: %llu | 会话: %llu | 速率: %.1f pps\n",
               (unsigned long long)stat.packets_captured,
               (unsigned long long)stat.packets_analyzed,
               (unsigned long long)stat.alerts_generated,
               (unsigned long long)stat.packets_dropped,
               (unsigned long long)stat.sessions_tracked,
               stat.packets_per_sec);
    }
}

/* =========================================================
 *  列出网络接口
 * ========================================================= */
static void list_devices(void)
{
    VDE_DeviceList devlist;
    VDE_ErrorCode ret = VDE_EnumDevices(&devlist);
    if (ret != VDE_OK) {
        fprintf(stderr, "枚举网络接口失败: %s\n", VDE_ErrorString(ret));
        return;
    }
    printf("\n可用网络接口（共 %d 个）：\n", devlist.count);
    printf("%-4s  %-50s  %-16s  %s\n", "序号", "设备名称", "IP地址", "描述");
    printf("%-4s  %-50s  %-16s  %s\n",
           "----", "--------------------------------------------------",
           "----------------", "----");
    for (int i = 0; i < devlist.count; i++) {
        printf("%-4d  %-50s  %-16s  %s\n",
               i + 1,
               devlist.devices[i].name,
               devlist.devices[i].ip_addr[0] ? devlist.devices[i].ip_addr : "-",
               devlist.devices[i].description);
    }
    printf("\n");
}

/* =========================================================
 *  打印帮助
 * ========================================================= */
static void print_help(const char* prog)
{
    printf("用法: %s [选项]\n\n", prog);
    printf("  -l               列出所有网络接口\n");
    printf("  -i <接口名>      指定监听网卡（LIVE模式）\n");
    printf("  -r <pcap文件>    读取离线pcap文件（OFFLINE模式）\n");
    printf("  -d <规则库路径>  规则库JSON文件（默认 ./RuleDB/vuln_rules.json）\n");
    printf("  -o <日志目录>    日志输出目录（默认 ./logs）\n");
    printf("  -f <BPF过滤>     BPF过滤表达式，如 \"tcp port 445\"\n");
    printf("  -v               详细输出（DEBUG级别）\n");
    printf("  -s               每5秒打印统计信息\n");
    printf("  -h               显示本帮助\n\n");
    printf("示例：\n");
    printf("  %s -l\n", prog);
    printf("  %s -i \"\\Device\\NPF_{GUID}\" -d RuleDB/vuln_rules.json -o logs\n", prog);
    printf("  %s -r capture.pcap -d RuleDB/vuln_rules.json\n\n", prog);
}

/* =========================================================
 *  主函数
 * ========================================================= */
int main(int argc, char* argv[])
{
    /* 默认参数 */
    char device[VDE_MAX_DEV_LEN]      = "";
    char rule_db[VDE_MAX_PATH_LEN]    = ".\\RuleDB\\vuln_rules.json";
    char log_dir[VDE_MAX_PATH_LEN]    = ".\\logs";
    char bpf_filter[VDE_MAX_FILTER_LEN] = "";
    VDE_CaptureMode mode = VDE_MODE_LIVE;
    int verbose      = 0;
    int show_stats   = 0;
    int list_dev     = 0;

    /* 解析命令行 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-l") == 0) {
            list_dev = 1;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(device, argv[++i], sizeof(device) - 1);
            mode = VDE_MODE_LIVE;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            strncpy(device, argv[++i], sizeof(device) - 1);
            mode = VDE_MODE_OFFLINE;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            strncpy(rule_db, argv[++i], sizeof(rule_db) - 1);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(log_dir, argv[++i], sizeof(log_dir) - 1);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            strncpy(bpf_filter, argv[++i], sizeof(bpf_filter) - 1);
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            show_stats = 1;
        }
    }

    printf("VulnDetectEngine v%s - 漏洞攻击检测引擎\n", VDE_GetVersion());
    printf("==========================================\n\n");

    /* 列出设备 */
    if (list_dev) {
        list_devices();
        if (device[0] == '\0') return 0;
    }

    if (device[0] == '\0') {
        fprintf(stderr, "错误：未指定网络接口或pcap文件。使用 -l 查看可用接口，-h 查看帮助。\n");
        return 1;
    }

    /* 注册信号处理 */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* 构建配置 */
    VDE_Config config;
    memset(&config, 0, sizeof(config));
    config.mode              = mode;
    config.promiscuous       = 1;
    config.snaplen           = 65535;
    config.read_timeout_ms   = 500;
    config.log_level         = verbose ? 4 : 3; /* DEBUG or INFO */
    config.alert_callback    = on_alert;
    config.alert_callback_ctx = NULL;

    strncpy(config.device_name, device,     sizeof(config.device_name) - 1);
    strncpy(config.rule_db_path, rule_db,   sizeof(config.rule_db_path) - 1);
    strncpy(config.log_dir,      log_dir,   sizeof(config.log_dir) - 1);
    strncpy(config.bpf_filter,   bpf_filter, sizeof(config.bpf_filter) - 1);

    /* 创建引擎实例 */
    VDE_ErrorCode ret = VDE_Create(&config, &g_handle);
    if (ret != VDE_OK) {
        fprintf(stderr, "引擎创建失败: %s\n", VDE_ErrorString(ret));
        return 1;
    }

    /* 打印已加载规则 */
    VDE_RuleInfo rules[RE_MAX_RULES];
    int rule_count = 0;
    VDE_GetRules(g_handle, rules, RE_MAX_RULES, &rule_count);
    printf("已加载规则 %d 条：\n", rule_count);
    printf("%-10s  %-32s  %-16s  %-8s  %s\n",
           "规则ID", "规则名称", "CVE", "严重级别", "协议");
    printf("%-10s  %-32s  %-16s  %-8s  %s\n",
           "----------", "--------------------------------",
           "----------------", "--------", "--------");
    for (int i = 0; i < rule_count; i++) {
        printf("%-10s  %-32s  %-16s  %-8s  %s\n",
               rules[i].rule_id,
               rules[i].rule_name,
               rules[i].cve,
               VDE_SeverityString(rules[i].severity),
               rules[i].protocol);
    }
    printf("\n");

    /* 启动引擎 */
    ret = VDE_Start(g_handle);
    if (ret != VDE_OK) {
        fprintf(stderr, "引擎启动失败: %s\n  详情: %s\n",
                VDE_ErrorString(ret), VDE_GetLastError(g_handle));
        VDE_Destroy(g_handle);
        return 1;
    }

    printf("引擎已启动，按 Ctrl+C 停止...\n\n");

    /* 主循环 */
    int stat_counter = 0;
    while (g_running && VDE_IsRunning(g_handle)) {
        SLEEP_MS(1000);
        stat_counter++;
        if (show_stats && stat_counter % 5 == 0) {
            print_stats(g_handle);
        }
    }

    /* 停止并打印最终统计 */
    if (VDE_IsRunning(g_handle)) VDE_Stop(g_handle);
    print_stats(g_handle);

    VDE_Destroy(g_handle);
    g_handle = NULL;

    printf("\n引擎已关闭。\n");
    return 0;
}
