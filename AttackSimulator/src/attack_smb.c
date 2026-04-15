/**
 * @file    attack_smb.c
 * @brief   SMB 协议攻击模拟测试
 *
 * 覆盖规则:
 *   VDE-001  EternalBlue MS17-010 (SMBv1 Negotiate + Trans2)
 *   VDE-002  DoublePulsar 后门心跳
 *   VDE-007  SMBGhost CVE-2020-0796 (SMBv3 压缩头)
 *   VDE-012  SMB 暴力破解 (THRESHOLD)
 *   VDE-016  Mimikatz LSASS SMB 访问
 *   VDE-017  EternalRomance MS17-010 WriteAndX
 *   VDE-019  EternalChampion MS17-010 Trans2
 *   VDE-020  SMB 空会话枚举
 *   VDE-021  PsExec 横向移动
 *   VDE-022  勒索软件大量写操作
 *   VDE-023  Pass-The-Hash NTLM
 *   VDE-049  Ryuk 勒索软件 SMB 传播
 *   VDE-060  EternalSynergy CVE-2017-0143
 */

#include "../include/attack_common.h"

/* =========================================================
 *  SMB 数据包构造工具
 * ========================================================= */

/* SMBv1 Negotiate Request (含 NT LM 0.12 方言) */
static const uint8_t SMB1_NEGOTIATE[] = {
    /* NetBIOS Session */
    0x00, 0x00, 0x00, 0x54,
    /* SMB Header */
    0xFF, 0x53, 0x4D, 0x42,  /* Magic: \xFFSMB */
    0x72,                    /* Command: Negotiate */
    0x00, 0x00, 0x00, 0x00,  /* Status: SUCCESS */
    0x18,                    /* Flags */
    0x01, 0x28,              /* Flags2 */
    0x00, 0x00,              /* PID High */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Signature */
    0x00, 0x00,              /* Reserved */
    0xFF, 0xFF,              /* TID */
    0xFE, 0xFF,              /* PID */
    0xFF, 0xFF,              /* UID */
    0x00, 0x00,              /* MID */
    /* Negotiate */
    0x00,                    /* WordCount */
    0x31, 0x00,              /* ByteCount */
    /* Dialects */
    0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00,  /* LANMAN1.0 */
    0x02, 0x4C, 0x4D, 0x31, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,          /* LM1.2X002 */
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00, /* NT LANMAN 1.0 */
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00  /* NT LM 0.12 */
};

/* SMBv1 Trans2 (EternalBlue 触发载荷) */
static const uint8_t SMB1_TRANS2_ETERNAL[] = {
    0x00, 0x00, 0x00, 0x5F,
    0xFF, 0x53, 0x4D, 0x42,  /* Magic */
    0x25,                    /* Command: Trans2 */
    0x00, 0x00, 0x00, 0x00,
    0x18, 0x07, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    /* Trans2 parameters */
    0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
};

/* DoublePulsar Ping */
static const uint8_t DOUBLEPULSAR_PING[] = {
    0x00, 0x00, 0x00, 0x54,
    0xFF, 0x53, 0x4D, 0x42,  /* Magic */
    0x72,                    /* Negotiate */
    0x00, 0x00, 0x00, 0x00,
    0x98, 0x53, 0x43, 0x00,  /* DoublePulsar 特征标志 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x31, 0x00, 0x02, 0x4E, 0x54, 0x20, 0x4C,
    0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
};

/* SMBv3 压缩头 (SMBGhost CVE-2020-0796) */
static const uint8_t SMBGHOST_COMPRESS[] = {
    0x00, 0x00, 0x00, 0x20,
    0xFC, 0x53, 0x4D, 0x42,  /* SMBv3 压缩魔数 */
    0x10, 0x00, 0x00, 0x00,  /* OriginalCompressedSegmentSize */
    0x02, 0x00,              /* CompressionAlgorithm: LZ77 */
    0x00, 0x00,              /* Flags */
    0xFF, 0xFF, 0xFF, 0xFF,  /* Offset (触发整数溢出) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

/* NTLMSSP Negotiate (Pass-The-Hash / NTLM Relay) */
static const uint8_t NTLMSSP_NEGOTIATE[] = {
    0x00, 0x00, 0x00, 0x50,
    0xFF, 0x53, 0x4D, 0x42,
    0x73,                    /* Session Setup AndX */
    0x00, 0x00, 0x00, 0x00,
    0x18, 0x07, 0xC0, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    /* NTLMSSP */
    0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00,  /* NTLMSSP\0 */
    0x01, 0x00, 0x00, 0x00,  /* MessageType: Negotiate */
    0x00, 0x00, 0x00, 0x00,  /* NegotiateFlags (空) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* SMBv1 WriteAndX (EternalRomance 大载荷) */
static uint8_t smb1_write_andx[128];
static void build_smb1_write_andx(void) {
    memset(smb1_write_andx, 0, sizeof(smb1_write_andx));
    smb1_write_andx[0] = 0x00; smb1_write_andx[1] = 0x00;
    smb1_write_andx[2] = 0x00; smb1_write_andx[3] = 0x7C;
    smb1_write_andx[4] = 0xFF; smb1_write_andx[5] = 0x53;
    smb1_write_andx[6] = 0x4D; smb1_write_andx[7] = 0x42;
    smb1_write_andx[8] = 0x2F;  /* Write AndX */
    /* FID = 0x0000 (无效) */
    smb1_write_andx[32] = 0x00; smb1_write_andx[33] = 0x00;
    /* DataLength = 0xFFFF (超长) */
    smb1_write_andx[40] = 0xFF; smb1_write_andx[41] = 0xFF;
    /* 填充 NOP sled */
    memset(smb1_write_andx + 60, 0x90, 68);
}

/* =========================================================
 *  测试函数
 * ========================================================= */

static void test_eternal_blue(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-001 EternalBlue MS17-010 ===");
    stats->total++;

    sock_t s = tcp_connect(target_ip, 445, 3000);
    if (s == INVALID_SOCK) {
        PRINT_FAIL("无法连接 %s:445（目标不可达，仅测试流量特征）", target_ip);
        /* 即使连接失败，仍通过 UDP 发送特征包让检测引擎捕获 */
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 445, SMB1_NEGOTIATE, sizeof(SMB1_NEGOTIATE));
            SLEEP_MS(200);
            udp_send(u, target_ip, 445, SMB1_TRANS2_ETERNAL, sizeof(SMB1_TRANS2_ETERNAL));
            CLOSE_SOCK(u);
            PRINT_SEND("已发送 SMBv1 Negotiate + Trans2 特征包（UDP）");
            stats->sent++;
        }
        return;
    }

    /* 发送 SMBv1 Negotiate */
    if (tcp_send_all(s, SMB1_NEGOTIATE, sizeof(SMB1_NEGOTIATE)) > 0) {
        PRINT_SEND("SMBv1 Negotiate 已发送 (%d bytes)", (int)sizeof(SMB1_NEGOTIATE));
        SLEEP_MS(300);
        uint8_t resp[256];
        tcp_recv(s, resp, sizeof(resp), 1000);
    }

    /* 发送 Trans2 触发载荷 */
    if (tcp_send_all(s, SMB1_TRANS2_ETERNAL, sizeof(SMB1_TRANS2_ETERNAL)) > 0) {
        PRINT_SEND("SMBv1 Trans2 (EternalBlue) 已发送 (%d bytes)", (int)sizeof(SMB1_TRANS2_ETERNAL));
        stats->sent++;
        PRINT_OK("VDE-001 流量已发送，等待检测引擎告警");
    }

    CLOSE_SOCK(s);
}

static void test_doublepulsar(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-002 DoublePulsar 后门心跳 ===");
    stats->total++;

    sock_t s = tcp_connect(target_ip, 445, 3000);
    if (s == INVALID_SOCK) {
        /* 降级为 UDP 发送 */
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 445, DOUBLEPULSAR_PING, sizeof(DOUBLEPULSAR_PING));
            CLOSE_SOCK(u);
            PRINT_SEND("DoublePulsar ping 已发送（UDP）");
            stats->sent++;
        }
        return;
    }

    if (tcp_send_all(s, DOUBLEPULSAR_PING, sizeof(DOUBLEPULSAR_PING)) > 0) {
        PRINT_SEND("DoublePulsar ping 已发送 (%d bytes)", (int)sizeof(DOUBLEPULSAR_PING));
        SLEEP_MS(500);
        uint8_t resp[64];
        int n = tcp_recv(s, resp, sizeof(resp), 1000);
        if (n > 0 && resp[8] == 0x72) {
            PRINT_OK("VDE-002 收到响应，疑似 DoublePulsar 已植入！");
        } else {
            PRINT_OK("VDE-002 流量已发送，等待检测引擎告警");
        }
        stats->sent++;
    }
    CLOSE_SOCK(s);
}

static void test_smbghost(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-007 SMBGhost CVE-2020-0796 ===");
    stats->total++;

    sock_t s = tcp_connect(target_ip, 445, 3000);
    if (s == INVALID_SOCK) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 445, SMBGHOST_COMPRESS, sizeof(SMBGHOST_COMPRESS));
            CLOSE_SOCK(u);
            PRINT_SEND("SMBGhost 压缩头已发送（UDP）");
            stats->sent++;
        }
        return;
    }

    if (tcp_send_all(s, SMBGHOST_COMPRESS, sizeof(SMBGHOST_COMPRESS)) > 0) {
        PRINT_SEND("SMBGhost CVE-2020-0796 压缩头已发送 (%d bytes)", (int)sizeof(SMBGHOST_COMPRESS));
        stats->sent++;
        PRINT_OK("VDE-007 流量已发送，等待检测引擎告警");
    }
    CLOSE_SOCK(s);
}

static void test_smb_brute_force(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-012 SMB 暴力破解 (THRESHOLD) ===");
    stats->total++;

    /* 发送 15 次 Session Setup 失败模拟（超过阈值10次/5s） */
    static const uint8_t SMB_SESSION_FAIL[] = {
        0x00, 0x00, 0x00, 0x30,
        0xFF, 0x53, 0x4D, 0x42,
        0x73,                    /* Session Setup */
        0x6D, 0x00, 0x00, 0xC0,  /* STATUS_LOGON_FAILURE = 0xC000006D */
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int sent_count = 0;
    for (int i = 0; i < 15; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 445, SMB_SESSION_FAIL, sizeof(SMB_SESSION_FAIL));
            CLOSE_SOCK(u);
            sent_count++;
        }
        SLEEP_MS(100);
    }

    if (sent_count > 0) {
        PRINT_SEND("已发送 %d 次 SMB Session Setup 失败包（模拟暴力破解）", sent_count);
        stats->sent++;
        PRINT_OK("VDE-012 阈值触发流量已发送");
    }
}

static void test_mimikatz_lsass(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-016 Mimikatz LSASS SMB 访问 ===");
    stats->total++;

    /* NT Create AndX 请求访问 lsass.dmp */
    static const uint8_t SMB_NTCREATE_LSASS[] = {
        0x00, 0x00, 0x00, 0x60,
        0xFF, 0x53, 0x4D, 0x42,
        0xA2,                    /* NT Create AndX */
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Filename: \lsass.dmp */
        0x5C, 0x00, 0x6C, 0x00, 0x73, 0x00, 0x61, 0x00,
        0x73, 0x00, 0x73, 0x00, 0x2E, 0x00, 0x64, 0x00,
        0x6D, 0x00, 0x70, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, SMB_NTCREATE_LSASS, sizeof(SMB_NTCREATE_LSASS));
        CLOSE_SOCK(u);
        PRINT_SEND("SMB NT Create lsass.dmp 已发送");
        stats->sent++;
        PRINT_OK("VDE-016 流量已发送，等待检测引擎告警");
    }
}

static void test_eternal_romance(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-017 EternalRomance MS17-010 WriteAndX ===");
    stats->total++;
    build_smb1_write_andx();

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, smb1_write_andx, sizeof(smb1_write_andx));
        CLOSE_SOCK(u);
        PRINT_SEND("SMBv1 WriteAndX (EternalRomance) 已发送 (%d bytes)", (int)sizeof(smb1_write_andx));
        stats->sent++;
        PRINT_OK("VDE-017 流量已发送");
    }
}

static void test_eternal_champion(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-019 EternalChampion MS17-010 Trans2 ===");
    stats->total++;

    static const uint8_t ETERNAL_CHAMPION[] = {
        0x00, 0x00, 0x00, 0x40,
        0xFF, 0x53, 0x4D, 0x42,
        0x25,                    /* Trans2 */
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0x10, 0x00,  /* EternalChampion 特征标志 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, ETERNAL_CHAMPION, sizeof(ETERNAL_CHAMPION));
        CLOSE_SOCK(u);
        PRINT_SEND("EternalChampion Trans2 已发送");
        stats->sent++;
        PRINT_OK("VDE-019 流量已发送");
    }
}

static void test_smb_null_session(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-020 SMB 空会话枚举 ===");
    stats->total++;

    static const uint8_t SMB_NULL_SESSION[] = {
        0x00, 0x00, 0x00, 0x50,
        0xFF, 0x53, 0x4D, 0x42,
        0x73,                    /* Session Setup */
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        /* NTLMSSP Negotiate (空用户) */
        0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  /* NegotiateFlags */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, SMB_NULL_SESSION, sizeof(SMB_NULL_SESSION));
        CLOSE_SOCK(u);
        PRINT_SEND("SMB 空会话 Negotiate 已发送");
        stats->sent++;
        PRINT_OK("VDE-020 流量已发送");
    }
}

static void test_pass_the_hash(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-023 Pass-The-Hash NTLM ===");
    stats->total++;

    /* NTLMSSP Authenticate 包（含哈希字段） */
    static const uint8_t NTLMSSP_AUTH[] = {
        0x00, 0x00, 0x00, 0x60,
        0xFF, 0x53, 0x4D, 0x42,
        0x73,
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        /* NTLMSSP Authenticate */
        0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00,
        0x03, 0x00, 0x00, 0x00,  /* MessageType: Authenticate */
        0x28, 0x00, 0x00, 0x00,  /* LmChallengeResponseFields */
        0x00, 0x00, 0x00, 0x00,
        0x28, 0x00, 0x00, 0x00,  /* NtChallengeResponseFields */
        0x00, 0x00, 0x00, 0x00,
        /* 模拟 NT Hash (32字节) */
        0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
        0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
        0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
        0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE
    };

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, NTLMSSP_AUTH, sizeof(NTLMSSP_AUTH));
        CLOSE_SOCK(u);
        PRINT_SEND("NTLMSSP Authenticate (PTH) 已发送");
        stats->sent++;
        PRINT_OK("VDE-023 流量已发送");
    }
}

static void test_ransomware_mass_write(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-022 勒索软件大量 SMB 写操作 (THRESHOLD) ===");
    stats->total++;

    static const uint8_t SMB_WRITE[] = {
        0x00, 0x00, 0x00, 0x30,
        0xFF, 0x53, 0x4D, 0x42,
        0x2F,                    /* Write AndX */
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int count = 0;
    for (int i = 0; i < 25; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 445, SMB_WRITE, sizeof(SMB_WRITE));
            CLOSE_SOCK(u);
            count++;
        }
        SLEEP_MS(30);
    }

    PRINT_SEND("已发送 %d 次 SMB WriteAndX（模拟勒索软件加密行为）", count);
    stats->sent++;
    PRINT_OK("VDE-022 阈值触发流量已发送");
}

static void test_eternal_synergy(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-060 EternalSynergy CVE-2017-0143 ===");
    stats->total++;

    static const uint8_t ETERNAL_SYNERGY[] = {
        0x00, 0x00, 0x00, 0x40,
        0xFF, 0x53, 0x4D, 0x42,
        0x25,                    /* Trans2 */
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x07, 0x10, 0x07,  /* EternalSynergy 特征 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, ETERNAL_SYNERGY, sizeof(ETERNAL_SYNERGY));
        CLOSE_SOCK(u);
        PRINT_SEND("EternalSynergy Trans2 已发送");
        stats->sent++;
        PRINT_OK("VDE-060 流量已发送");
    }
}

/* =========================================================
 *  SMB 测试入口
 * ========================================================= */
void run_smb_attacks(const char* target_ip, TestStats* stats) {
    printf("\n");
    PRINT_INFO("########################################");
    PRINT_INFO("  SMB 协议攻击模拟测试");
    PRINT_INFO("  目标: %s:445", target_ip);
    PRINT_INFO("########################################");

    test_eternal_blue(target_ip, stats);       SLEEP_MS(500);
    test_doublepulsar(target_ip, stats);       SLEEP_MS(500);
    test_smbghost(target_ip, stats);           SLEEP_MS(500);
    test_smb_brute_force(target_ip, stats);    SLEEP_MS(500);
    test_mimikatz_lsass(target_ip, stats);     SLEEP_MS(500);
    test_eternal_romance(target_ip, stats);    SLEEP_MS(500);
    test_eternal_champion(target_ip, stats);   SLEEP_MS(500);
    test_smb_null_session(target_ip, stats);   SLEEP_MS(500);
    test_pass_the_hash(target_ip, stats);      SLEEP_MS(500);
    test_ransomware_mass_write(target_ip, stats); SLEEP_MS(500);
    test_eternal_synergy(target_ip, stats);    SLEEP_MS(500);
}
