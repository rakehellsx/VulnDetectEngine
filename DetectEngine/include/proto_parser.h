/**
 * @file    proto_parser.h
 * @brief   协议解析层 —— 基于 nDPI 的深度包检测
 *
 * 使用 nDPI 4.x 作为协议识别引擎（200+ 协议精准分类）；
 * 在 nDPI 识别结果之上，对 SMB/HTTP/DNS/RDP/DCERPC 等关键协议
 * 进行字段级细粒度解析，填充 ParsedPacket 结构体供规则引擎使用。
 *
 * 跨平台：Windows (MSVC/MinGW) + Linux (GCC)
 */

#ifndef PROTO_PARSER_H
#define PROTO_PARSER_H

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* nDPI 头文件 */
#ifdef _WIN32
#  include "ndpi/ndpi_api.h"
#  include "ndpi/ndpi_protocol_ids.h"
#  include "ndpi/ndpi_typedefs.h"
#else
#  include <ndpi/ndpi_api.h>
#  include <ndpi/ndpi_protocol_ids.h>
#  include <ndpi/ndpi_typedefs.h>
#endif

/* =========================================================
 *  底层网络头结构（跨平台 packed）
 * ========================================================= */
#pragma pack(push, 1)

typedef struct EthHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
} EthHeader;

typedef struct IPv4Header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IPv4Header;

typedef struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TcpHeader;

typedef struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UdpHeader;

typedef struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} IcmpHeader;

typedef struct Smb1Header {
    uint8_t  protocol[4];
    uint8_t  command;
    uint32_t status;
    uint8_t  flags;
    uint16_t flags2;
    uint16_t pid_high;
    uint8_t  security_sig[8];
    uint16_t reserved;
    uint16_t tid;
    uint16_t pid;
    uint16_t uid;
    uint16_t mid;
} Smb1Header;

typedef struct Smb2Header {
    uint8_t  protocol[4];
    uint16_t structure_size;
    uint16_t credit_charge;
    uint32_t status;
    uint16_t command;
    uint16_t credit_req_resp;
    uint32_t flags;
    uint32_t next_command;
    uint64_t message_id;
    uint32_t process_id;
    uint32_t tree_id;
    uint64_t session_id;
    uint8_t  signature[16];
} Smb2Header;

typedef struct NbssHeader {
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;
} NbssHeader;

#pragma pack(pop)

/* =========================================================
 *  常量定义
 * ========================================================= */
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20

#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD
#define ETHERTYPE_VLAN  0x8100

#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

#define SMB1_MAGIC      0xFF534D42u
#define SMB2_MAGIC      0xFE534D42u
#define SMB3_COMPRESS   0xFC534D42u

/* =========================================================
 *  应用层协议枚举
 * ========================================================= */
#define PP_MAX_IP_STR   46
#define PP_MAX_HTTP_HDR 4096
#define PP_MAX_DNS_NAME 256

typedef enum ProtoType {
    PROTO_UNKNOWN        = 0,
    PROTO_ETH,
    PROTO_IP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_DNS,
    PROTO_HTTP,
    PROTO_SMB1,
    PROTO_SMB2,
    PROTO_SMB3_COMPRESS,
    PROTO_RDP,
    PROTO_DCERPC,
    PROTO_NBSS,
    PROTO_KERBEROS,
    PROTO_TLS
} ProtoType;

/* =========================================================
 *  解析后的数据包上下文（传递给规则引擎）
 * ========================================================= */
typedef struct ParsedPacket {
    /* 时间戳 */
    uint64_t    timestamp_us;

    /* 以太网层 */
    uint8_t     src_mac[6];
    uint8_t     dst_mac[6];
    uint16_t    ether_type;

    /* IP层 */
    char        src_ip[PP_MAX_IP_STR];
    char        dst_ip[PP_MAX_IP_STR];
    uint32_t    src_ip_raw;     /* 网络字节序 */
    uint32_t    dst_ip_raw;
    uint8_t     ip_proto;
    uint8_t     ip_ttl;
    uint16_t    ip_total_len;

    /* 传输层 */
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     tcp_flags;
    uint32_t    tcp_seq;
    uint32_t    tcp_ack;

    /* ICMP */
    uint8_t     icmp_type;
    uint8_t     icmp_code;

    /* 应用层协议类型（nDPI 识别结果映射） */
    ProtoType   app_proto;

    /* nDPI 原始协议 ID */
    uint16_t    ndpi_master_proto;
    uint16_t    ndpi_sub_proto;
    char        ndpi_proto_name[64];

    /* 应用层载荷（指向原始包内部） */
    const uint8_t*  payload;
    uint32_t        payload_len;

    /* 原始数据包 */
    const uint8_t*  raw_pkt;
    uint32_t        raw_pkt_len;

    /* SMB 解析字段（nDPI + 自研补充） */
    uint8_t     smb_version;
    uint8_t     smb_command;
    uint32_t    smb_status;
    uint16_t    smb_flags2;
    uint8_t     smb_compression;
    char        smb_tree_path[256];
    char        smb_filename[256];
    uint16_t    smb_fid;

    /* DCERPC 解析字段 */
    char        dcerpc_uuid[64];
    uint16_t    dcerpc_opnum;

    /* DNS 解析字段（nDPI 提供） */
    char        dns_query[PP_MAX_DNS_NAME];
    uint16_t    dns_qtype;

    /* HTTP 解析字段（nDPI 提供） */
    char        http_method[16];
    char        http_uri[1024];
    char        http_host[256];
    char        http_headers[PP_MAX_HTTP_HDR];
    char        http_cookie[1024];
    char        http_user_agent[512];

    /* RDP 解析字段 */
    uint8_t     rdp_pdu_type;
    char        rdp_channel[64];

    /* Kerberos 解析字段（nDPI 提供） */
    char        kerb_hostname[64];
    char        kerb_domain[64];
    char        kerb_username[64];
} ParsedPacket;

/* =========================================================
 *  nDPI 引擎上下文（每个 VDE 实例持有一个）
 * ========================================================= */
typedef struct NdpiContext {
    struct ndpi_detection_module_struct* ndpi_struct;
} NdpiContext;

/* =========================================================
 *  nDPI 单流上下文（每条 TCP/UDP 流持有一个）
 * ========================================================= */
typedef struct NdpiFlowCtx {
    struct ndpi_flow_struct* flow;
    uint8_t                  detection_completed;
    ndpi_protocol            detected_proto;
} NdpiFlowCtx;

/* =========================================================
 *  公共 API
 * ========================================================= */

/** 初始化 nDPI 检测模块（引擎启动时调用一次） */
int  PP_Init(NdpiContext* ctx);

/** 释放 nDPI 检测模块 */
void PP_Destroy(NdpiContext* ctx);

/** 创建一个新的 nDPI 流上下文 */
NdpiFlowCtx* PP_FlowCreate(void);

/** 释放 nDPI 流上下文 */
void PP_FlowDestroy(NdpiFlowCtx* fctx);

/**
 * @brief  解析原始数据包，填充 ParsedPacket 结构
 *
 * @param  ctx       nDPI 上下文（由 PP_Init 初始化）
 * @param  fctx      当前流的 nDPI 流上下文（可为 NULL）
 * @param  raw_data  原始数据包（以太网帧起始）
 * @param  raw_len   数据包长度
 * @param  ts_us     时间戳（微秒）
 * @param  out_pkt   [out] 解析结果
 * @return 1=成功，0=失败
 */
int PP_ParsePacket(
    NdpiContext*    ctx,
    NdpiFlowCtx*    fctx,
    const uint8_t*  raw_data,
    uint32_t        raw_len,
    uint64_t        ts_us,
    ParsedPacket*   out_pkt
);

/** 将 IPv4 地址（网络字节序）转换为字符串 */
void PP_IpToStr(uint32_t ip_net, char* buf, size_t buf_len);

#endif /* PROTO_PARSER_H */
