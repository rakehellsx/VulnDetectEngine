/**
 * @file    proto_parser.h
 * @brief   协议解析层 - 以太网/IP/TCP/UDP/ICMP/DNS/SMB/HTTP/RDP/DCERPC 结构定义与解析接口
 */

#ifndef PROTO_PARSER_H
#define PROTO_PARSER_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  include <winsock2.h>
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <arpa/inet.h>
#endif

/* =========================================================
 *  基础网络结构（按字节对齐）
 * ========================================================= */
#pragma pack(push, 1)

/* 以太网帧头 */
typedef struct EthHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;    /* 网络字节序 */
} EthHeader;

/* IPv4 头 */
typedef struct IPv4Header {
    uint8_t  ver_ihl;       /* 版本(4) + 首部长度(4) */
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

/* TCP 头 */
typedef struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;   /* 高4位=偏移，低4位=保留 */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TcpHeader;

/* UDP 头 */
typedef struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UdpHeader;

/* ICMP 头 */
typedef struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} IcmpHeader;

/* SMB1 头（NetBIOS Session Service 之后） */
typedef struct Smb1Header {
    uint8_t  protocol[4];   /* 0xFF 'S' 'M' 'B' */
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

/* SMB2/3 头 */
typedef struct Smb2Header {
    uint8_t  protocol[4];   /* 0xFE 'S' 'M' 'B' */
    uint16_t structure_size;/* 固定 0x0040 */
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

/* NetBIOS Session Service 头 */
typedef struct NbssHeader {
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;        /* 网络字节序 */
} NbssHeader;

#pragma pack(pop)

/* =========================================================
 *  TCP 标志位定义
 * ========================================================= */
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20

/* =========================================================
 *  EtherType 定义
 * ========================================================= */
#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD
#define ETHERTYPE_VLAN  0x8100

/* =========================================================
 *  IP 协议号定义
 * ========================================================= */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

/* =========================================================
 *  SMB 魔数
 * ========================================================= */
#define SMB1_MAGIC      0xFF534D42  /* \xFF SMB */
#define SMB2_MAGIC      0xFE534D42  /* \xFE SMB */
#define SMB3_COMPRESS   0xFC534D42  /* \xFC SMB - SMBv3压缩包 */

/* =========================================================
 *  解析后的数据包上下文（传递给匹配引擎）
 * ========================================================= */
#define PP_MAX_IP_STR   46
#define PP_MAX_HTTP_HDR 4096
#define PP_MAX_DNS_NAME 256

typedef enum ProtoType {
    PROTO_UNKNOWN = 0,
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
    PROTO_NBSS
} ProtoType;

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
    uint32_t    src_ip_raw;     /* 主机字节序 */
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

    /* 应用层协议类型 */
    ProtoType   app_proto;

    /* 应用层载荷 */
    const uint8_t*  payload;
    uint32_t        payload_len;

    /* 原始数据包 */
    const uint8_t*  raw_pkt;
    uint32_t        raw_pkt_len;

    /* SMB 解析字段 */
    uint8_t     smb_version;        /* 1 or 2 or 3 */
    uint8_t     smb_command;
    uint32_t    smb_status;
    uint16_t    smb_flags2;
    uint8_t     smb_compression;    /* SMBv3压缩标志 */
    char        smb_tree_path[256];
    char        smb_filename[256];
    uint16_t    smb_fid;

    /* DCERPC 解析字段 */
    char        dcerpc_uuid[64];
    uint16_t    dcerpc_opnum;

    /* DNS 解析字段 */
    char        dns_query[PP_MAX_DNS_NAME];
    uint16_t    dns_qtype;

    /* HTTP 解析字段 */
    char        http_method[16];
    char        http_uri[1024];
    char        http_host[256];
    char        http_headers[PP_MAX_HTTP_HDR]; /* 所有请求头拼接 */
    char        http_cookie[1024];

    /* RDP 解析字段 */
    uint8_t     rdp_pdu_type;
    char        rdp_channel[64];
} ParsedPacket;

/* =========================================================
 *  协议解析函数声明
 * ========================================================= */

/**
 * @brief  解析原始数据包，填充 ParsedPacket 结构
 * @param  raw_data     原始数据包指针（以太网帧起始）
 * @param  raw_len      数据包长度
 * @param  ts_us        时间戳（微秒）
 * @param  out_pkt      [out] 解析结果
 * @return 1=解析成功，0=解析失败/不支持
 */
int PP_ParsePacket(
    const uint8_t*  raw_data,
    uint32_t        raw_len,
    uint64_t        ts_us,
    ParsedPacket*   out_pkt
);

/**
 * @brief  解析 SMB 层（在 TCP 载荷基础上）
 */
int PP_ParseSMB(ParsedPacket* pkt);

/**
 * @brief  解析 HTTP 层
 */
int PP_ParseHTTP(ParsedPacket* pkt);

/**
 * @brief  解析 DNS 层（UDP载荷）
 */
int PP_ParseDNS(ParsedPacket* pkt);

/**
 * @brief  解析 RDP 层（TPKT/X.224/MCS）
 */
int PP_ParseRDP(ParsedPacket* pkt);

/**
 * @brief  解析 DCERPC 层
 */
int PP_ParseDCERPC(ParsedPacket* pkt);

/**
 * @brief  将 IPv4 地址（网络字节序）转换为字符串
 */
void PP_IpToStr(uint32_t ip_net, char* buf, size_t buf_len);

#endif /* PROTO_PARSER_H */
