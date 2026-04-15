/**
 * @file    main.c
 * @brief   VulnDetectEngine 攻击模拟测试程序主入口
 *
 * 使用方法:
 *   AttackSimulator.exe [目标IP] [DNS服务器IP] [HTTP端口] [测试类别]
 *
 * 参数说明:
 *   目标IP       - 目标主机 IP（默认 127.0.0.1）
 *   DNS服务器IP  - DNS 服务器 IP（默认 8.8.8.8）
 *   HTTP端口     - HTTP 服务端口（默认 80）
 *   测试类别     - all/smb/rdp/http/network/shellcode（默认 all）
 *
 * 示例:
 *   AttackSimulator.exe 192.168.1.100 192.168.1.1 8080 all
 *   AttackSimulator.exe 10.0.0.1 8.8.8.8 80 smb
 *   AttackSimulator.exe 172.16.0.1 172.16.0.1 443 http
 *
 * !! 警告 !!
 * 本程序仅供安全研究与检测引擎验证使用，严禁在未经授权的网络或
 * 主机上运行。所有发送的数据包均为漏洞特征模拟，不会实际利用漏洞。
 */

#include "../include/attack_common.h"

/* 各模块测试函数声明 */
extern void run_smb_attacks(const char* target_ip, TestStats* stats);
extern void run_rdp_attacks(const char* target_ip, TestStats* stats);
extern void run_http_attacks(const char* target_ip, uint16_t port, TestStats* stats);
extern void run_network_attacks(const char* target_ip, const char* dns_server, TestStats* stats);
extern void run_shellcode_attacks(const char* target_ip, TestStats* stats);

/* =========================================================
 *  打印 Banner
 * ========================================================= */
static void print_banner(void) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);  /* UTF-8 */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║        VulnDetectEngine 攻击模拟测试程序 v2.0            ║\n");
    printf("║        覆盖 60 条漏洞检测规则的完整测试套件              ║\n");
    printf("║                                                          ║\n");
    printf("║  !! 仅供安全研究与检测引擎验证使用 !!                    ║\n");
    printf("║  !! 严禁在未经授权的网络或主机上运行 !!                  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* =========================================================
 *  打印使用说明
 * ========================================================= */
static void print_usage(const char* prog) {
    printf("用法: %s [目标IP] [DNS服务器IP] [HTTP端口] [测试类别]\n\n", prog);
    printf("测试类别:\n");
    printf("  all       - 运行全部测试（默认）\n");
    printf("  smb       - SMB 协议攻击（VDE-001~022, VDE-060）\n");
    printf("  rdp       - RDP 协议攻击（VDE-003~004, VDE-013, VDE-058）\n");
    printf("  http      - HTTP 应用层攻击（VDE-008~009, VDE-033~042, VDE-046~048, VDE-053~054）\n");
    printf("  network   - 网络层/DNS/Kerberos/DCERPC（VDE-005~006, VDE-010~011, VDE-014~015, VDE-024~032, VDE-043~047, VDE-052, VDE-055~056, VDE-059）\n");
    printf("  shellcode - Shellcode/供应链/横向移动（VDE-018, VDE-030~031, VDE-049~051, VDE-057）\n");
    printf("\n");
    printf("示例:\n");
    printf("  %s 192.168.1.100 192.168.1.1 8080 all\n", prog);
    printf("  %s 10.0.0.1 8.8.8.8 80 smb\n", prog);
    printf("  %s 172.16.0.1 172.16.0.1 443 http\n", prog);
    printf("\n");
}

/* =========================================================
 *  规则覆盖率报告
 * ========================================================= */
static void print_rule_coverage(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                   规则覆盖率报告                        ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ 类别          │ 规则ID                    │ 数量        ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ SMB漏洞       │ 001-002,007,012,016-017   │ 13条        ║\n");
    printf("║               │ 019-023,049,060           │             ║\n");
    printf("║ RDP漏洞       │ 003-004,013,058           │ 4条         ║\n");
    printf("║ HTTP应用层    │ 008-009,033-042,046-048   │ 16条        ║\n");
    printf("║               │ 053-054                   │             ║\n");
    printf("║ DNS攻击       │ 011,043-045,047,059       │ 6条         ║\n");
    printf("║ DCERPC/RPC    │ 005-006,010,024,029-030   │ 8条         ║\n");
    printf("║               │ 052,057                   │             ║\n");
    printf("║ Kerberos/AD   │ 025-028,031-032           │ 6条         ║\n");
    printf("║ 扫描/泛洪     │ 014-015,055-056           │ 4条         ║\n");
    printf("║ Shellcode     │ 018,050-051               │ 3条         ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ 合计                                      │ 60条        ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* =========================================================
 *  主函数
 * ========================================================= */
int main(int argc, char* argv[]) {
    print_banner();

    /* 解析参数 */
    const char* target_ip  = "127.0.0.1";
    const char* dns_server = "8.8.8.8";
    uint16_t    http_port  = 80;
    const char* category   = "all";

    if (argc >= 2) target_ip  = argv[1];
    if (argc >= 3) dns_server = argv[2];
    if (argc >= 4) http_port  = (uint16_t)atoi(argv[3]);
    if (argc >= 5) category   = argv[4];

    if (strcmp(target_ip, "-h") == 0 || strcmp(target_ip, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    printf("配置信息:\n");
    printf("  目标 IP    : %s\n", target_ip);
    printf("  DNS 服务器 : %s\n", dns_server);
    printf("  HTTP 端口  : %d\n", http_port);
    printf("  测试类别   : %s\n", category);
    printf("\n");

    print_rule_coverage();

    /* 初始化网络 */
    if (net_init() != 0) {
        PRINT_FAIL("网络初始化失败");
        return 1;
    }

    PRINT_INFO("网络初始化成功，开始测试...");
    PRINT_INFO("请确保 VulnDetectEngine.dll 已在目标网卡上运行并监听！");
    printf("\n");

    /* 等待用户确认 */
    printf("按 Enter 键开始发送攻击模拟流量...");
    getchar();

    TestStats stats = {0, 0, 0};
    time_t start_time = time(NULL);

    /* 执行测试 */
    if (strcmp(category, "all") == 0 || strcmp(category, "smb") == 0) {
        run_smb_attacks(target_ip, &stats);
    }

    if (strcmp(category, "all") == 0 || strcmp(category, "rdp") == 0) {
        run_rdp_attacks(target_ip, &stats);
    }

    if (strcmp(category, "all") == 0 || strcmp(category, "http") == 0) {
        run_http_attacks(target_ip, http_port, &stats);
    }

    if (strcmp(category, "all") == 0 || strcmp(category, "network") == 0) {
        run_network_attacks(target_ip, dns_server, &stats);
    }

    if (strcmp(category, "all") == 0 || strcmp(category, "shellcode") == 0) {
        run_shellcode_attacks(target_ip, &stats);
    }

    /* 输出统计 */
    time_t elapsed = time(NULL) - start_time;
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                     测试完成汇总                        ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  总测试项目 : %-3d                                       ║\n", stats.total);
    printf("║  成功发送   : %-3d                                       ║\n", stats.sent);
    printf("║  发送失败   : %-3d                                       ║\n", stats.failed);
    printf("║  耗时       : %ld 秒                                     ║\n", (long)elapsed);
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  请检查 VulnDetectEngine 的告警日志确认检测结果          ║\n");
    printf("║  日志路径: logs\\vuln_detect_YYYYMMDD.log                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");

    net_cleanup();
    return 0;
}
