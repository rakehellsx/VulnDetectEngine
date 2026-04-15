/**
 * @file    attack_shellcode.c
 * @brief   Shellcode / 供应链 / 横向移动攻击模拟测试
 *
 * 覆盖规则:
 *   VDE-018  Shellcode NOP Sled
 *   VDE-023  Pass-The-Hash NTLM (NTLM Relay)
 *   VDE-028  MS14-068 PAC 伪造
 *   VDE-030  DCOM ShellWindows 横向移动
 *   VDE-031  NTLM 中继攻击
 *   VDE-045  SolarWinds SUNBURST（已在 network 中）
 *   VDE-049  Ryuk 勒索软件 SMB 传播
 *   VDE-050  Metasploit Stager
 *   VDE-051  堆喷射攻击
 *   VDE-057  PrintNightmare LPE CVE-2021-1675
 */

#include "../include/attack_common.h"

/* =========================================================
 *  Shellcode 特征包构造
 * ========================================================= */

/** NOP Sled (24 字节 0x90) + 随机填充 */
static uint8_t nop_sled_payload[256];
static int build_nop_sled(void) {
    /* NetBIOS + SMB 头 */
    static const uint8_t hdr[] = {
        0x00, 0x00, 0x01, 0x00,
        0xFF, 0x53, 0x4D, 0x42,
        0x2F, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(nop_sled_payload, hdr, sizeof(hdr));
    /* 24 字节 NOP sled */
    memset(nop_sled_payload + sizeof(hdr), 0x90, 24);
    /* 随机 shellcode 填充 */
    for (int i = (int)sizeof(hdr) + 24; i < 200; i++) {
        nop_sled_payload[i] = (uint8_t)(i & 0xFF);
    }
    return 200;
}

/** Metasploit Meterpreter stager 头特征 */
static const uint8_t METERPRETER_STAGER[] = {
    /* 包装在 TCP 载荷中 */
    0x00, 0x00, 0x00, 0x40,
    0xFF, 0x53, 0x4D, 0x42,
    0x2F,
    0x00, 0x00, 0x00, 0x00,
    /* Meterpreter stager 特征 */
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
    0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
    0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
    0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7,
    0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0
};

/** 堆喷射模式 0x0C0C0C0C */
static uint8_t heap_spray_payload[2048];
static int build_heap_spray(void) {
    static const uint8_t hdr[] = {
        0x00, 0x00, 0x08, 0x00,
        0xFF, 0x53, 0x4D, 0x42,
        0x2F, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(heap_spray_payload, hdr, sizeof(hdr));
    /* 堆喷射填充 0x0C0C0C0C */
    for (int i = (int)sizeof(hdr); i < 2040; i += 4) {
        heap_spray_payload[i]   = 0x0C;
        heap_spray_payload[i+1] = 0x0C;
        heap_spray_payload[i+2] = 0x0C;
        heap_spray_payload[i+3] = 0x0C;
    }
    return 2040;
}

/* =========================================================
 *  测试函数
 * ========================================================= */

static void test_nop_sled(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-018 Shellcode NOP Sled ===");
    stats->total++;

    int len = build_nop_sled();
    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, nop_sled_payload, len);
        CLOSE_SOCK(u);
        PRINT_SEND("NOP Sled (24x 0x90) 载荷已发送 (%d bytes)", len);
        stats->sent++;
        PRINT_OK("VDE-018 流量已发送");
    }
}

static void test_metasploit_stager(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-050 Metasploit Meterpreter Stager ===");
    stats->total++;

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 4444, METERPRETER_STAGER, sizeof(METERPRETER_STAGER));
        CLOSE_SOCK(u);
        PRINT_SEND("Meterpreter stager 特征头已发送 (%d bytes)", (int)sizeof(METERPRETER_STAGER));
        stats->sent++;
        PRINT_OK("VDE-050 流量已发送");
    }
}

static void test_heap_spray(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-051 堆喷射攻击 (0x0C0C0C0C) ===");
    stats->total++;

    int len = build_heap_spray();
    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, heap_spray_payload, len);
        CLOSE_SOCK(u);
        PRINT_SEND("堆喷射载荷 (0x0C0C0C0C 填充 %d bytes) 已发送", len);
        stats->sent++;
        PRINT_OK("VDE-051 流量已发送");
    }
}

static void test_ntlm_relay(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-031 NTLM 中继攻击 ===");
    stats->total++;

    /* NTLMSSP Negotiate 包（中间人转发特征） */
    static const uint8_t NTLM_RELAY[] = {
        0x00, 0x00, 0x00, 0x50,
        0xFF, 0x53, 0x4D, 0x42,
        0x73,
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        /* NTLMSSP Negotiate */
        0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x07, 0x82, 0x08, 0xA2,  /* NegotiateFlags */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F  /* Version */
    };

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, NTLM_RELAY, sizeof(NTLM_RELAY));
        CLOSE_SOCK(u);
        PRINT_SEND("NTLM 中继 Negotiate 包已发送");
        stats->sent++;
        PRINT_OK("VDE-031 流量已发送");
    }
}

static void test_dcom_shellwindows(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-030 DCOM ShellWindows 横向移动 ===");
    stats->total++;

    /* ShellWindows CLSID: 9BA05972-F6D1-11D2-8F32-00C04F8EF57F */
    static const uint8_t DCOM_SHELLWINDOWS[] = {
        0x05, 0x00, 0x0B, 0x03,  /* DCERPC Bind */
        0x10, 0x00, 0x00, 0x00,
        0x48, 0x00,              /* frag_length */
        0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,  /* call_id */
        0x00, 0x10, 0x00, 0x00,  /* max_xmit_frag */
        0x00, 0x10, 0x00, 0x00,  /* max_recv_frag */
        0x00, 0x00, 0x00, 0x00,  /* assoc_group_id */
        0x01, 0x00, 0x00, 0x00,  /* num_ctx_items */
        0x00, 0x00,              /* context_id */
        0x01, 0x00,              /* num_trans_items */
        /* ShellWindows CLSID (bytes) */
        0x72, 0x59, 0xA0, 0x9B, 0xD1, 0xF6, 0xD2, 0x11,
        0x8F, 0x32, 0x00, 0xC0, 0x4F, 0x8E, 0xF5, 0x7F,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 135, DCOM_SHELLWINDOWS, sizeof(DCOM_SHELLWINDOWS));
        CLOSE_SOCK(u);
        PRINT_SEND("DCOM ShellWindows CLSID Bind 请求已发送");
        stats->sent++;
        PRINT_OK("VDE-030 流量已发送");
    }
}

static void test_printnightmare_lpe(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-057 PrintNightmare LPE CVE-2021-1675 ===");
    stats->total++;

    /* Spooler UUID + AddPrinterDriver (opnum 0x09) */
    static const uint8_t SPOOLER_UUID[] = {
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
        0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab
    };

    /* 含 .dll 路径的载荷 */
    static const uint8_t LPE_PAYLOAD[] = {
        /* DriverInfo level 3 */
        0x03, 0x00, 0x00, 0x00,
        /* pName: evil_driver */
        0x65, 0x76, 0x69, 0x6C, 0x5F, 0x64, 0x72, 0x69,
        0x76, 0x65, 0x72, 0x00,
        /* pDriverPath: C:\Windows\Temp\evil.dll */
        0x43, 0x3A, 0x5C, 0x57, 0x69, 0x6E, 0x64, 0x6F,
        0x77, 0x73, 0x5C, 0x54, 0x65, 0x6D, 0x70, 0x5C,
        0x65, 0x76, 0x69, 0x6C, 0x2E, 0x64, 0x6C, 0x6C, 0x00
    };

    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x05; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x03;
    buf[4] = 0x10; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00;
    uint16_t flen = (uint16_t)(24 + 16 + sizeof(LPE_PAYLOAD));
    buf[8] = (uint8_t)(flen & 0xFF); buf[9] = (uint8_t)(flen >> 8);
    buf[12] = 0x01;
    buf[20] = 0x09; buf[21] = 0x00;  /* opnum: AddPrinterDriver */
    memcpy(buf + 24, SPOOLER_UUID, 16);
    memcpy(buf + 40, LPE_PAYLOAD, sizeof(LPE_PAYLOAD));
    int len = 40 + (int)sizeof(LPE_PAYLOAD);

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, buf, len);
        CLOSE_SOCK(u);
        PRINT_SEND("PrintNightmare LPE AddPrinterDriver (.dll) 已发送 (%d bytes)", len);
        stats->sent++;
        PRINT_OK("VDE-057 流量已发送");
    }
}

static void test_ryuk_spread(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-049 Ryuk 勒索软件 SMB 传播 (THRESHOLD) ===");
    stats->total++;

    /* 模拟 Ryuk 大量 NT Create 操作 */
    static const uint8_t SMB_NT_CREATE[] = {
        0x00, 0x00, 0x00, 0x40,
        0xFF, 0x53, 0x4D, 0x42,
        0xA2,                    /* NT Create AndX */
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Filename: encrypted file */
        0x72, 0x79, 0x75, 0x6B, 0x2E, 0x72, 0x79, 0x75, 0x6B, 0x00
    };

    int sent = 0;
    for (int i = 0; i < 60; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 445, SMB_NT_CREATE, sizeof(SMB_NT_CREATE));
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(50);
    }

    PRINT_SEND("已发送 %d 次 SMB NT Create（模拟 Ryuk 传播）", sent);
    stats->sent++;
    PRINT_OK("VDE-049 阈值触发流量已发送");
}

/* =========================================================
 *  Shellcode/供应链测试入口
 * ========================================================= */
void run_shellcode_attacks(const char* target_ip, TestStats* stats) {
    printf("\n");
    PRINT_INFO("########################################");
    PRINT_INFO("  Shellcode / 供应链 / 横向移动攻击模拟测试");
    PRINT_INFO("  目标: %s", target_ip);
    PRINT_INFO("########################################");

    test_nop_sled(target_ip, stats);            SLEEP_MS(300);
    test_metasploit_stager(target_ip, stats);   SLEEP_MS(300);
    test_heap_spray(target_ip, stats);          SLEEP_MS(300);
    test_ntlm_relay(target_ip, stats);          SLEEP_MS(300);
    test_dcom_shellwindows(target_ip, stats);   SLEEP_MS(300);
    test_printnightmare_lpe(target_ip, stats);  SLEEP_MS(300);
    test_ryuk_spread(target_ip, stats);         SLEEP_MS(300);
}
