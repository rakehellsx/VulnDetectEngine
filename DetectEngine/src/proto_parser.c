/**
 * @file    proto_parser.c
 * @brief   协议解析层实现
 *          支持：以太网 / IPv4 / TCP / UDP / ICMP / DNS / SMB1 / SMB2 / SMBv3压缩 /
 *                HTTP / RDP(TPKT) / DCERPC / NetBIOS Session Service
 */

#include "../include/proto_parser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <arpa/inet.h>
#endif

/* =========================================================
 *  内部辅助宏
 * ========================================================= */
#define SAFE_STRNCPY(dst, src, n) \
    do { strncpy((dst), (src), (n)-1); (dst)[(n)-1] = '\0'; } while(0)

#define BOUNDS_CHECK(ptr, end, size) \
    ((ptr) + (size) <= (end))

/* =========================================================
 *  IP 地址转字符串
 * ========================================================= */
void PP_IpToStr(uint32_t ip_net, char* buf, size_t buf_len)
{
    uint32_t ip_host = ntohl(ip_net);
    snprintf(buf, buf_len, "%u.%u.%u.%u",
        (ip_host >> 24) & 0xFF,
        (ip_host >> 16) & 0xFF,
        (ip_host >>  8) & 0xFF,
        (ip_host      ) & 0xFF);
}

/* =========================================================
 *  十六进制字符串转字节序列（用于 HEX_MATCH 条件预处理）
 * ========================================================= */
static int hex_str_to_bytes(const char* hex, uint8_t* out, int max_len)
{
    int len = 0;
    const char* p = hex;
    while (*p && *(p+1) && len < max_len) {
        char byte_str[3] = { *p, *(p+1), '\0' };
        out[len++] = (uint8_t)strtol(byte_str, NULL, 16);
        p += 2;
    }
    return len;
}

/* =========================================================
 *  SMB 解析
 * ========================================================= */
int PP_ParseSMB(ParsedPacket* pkt)
{
    const uint8_t* data = pkt->payload;
    uint32_t       len  = pkt->payload_len;
    const uint8_t* end  = data + len;

    if (!data || len < 4) return 0;

    /* 跳过 NetBIOS Session Service 头（4字节） */
    const uint8_t* smb_start = data;
    if (len >= 4 && data[0] == 0x00) {
        /* NBSS header */
        smb_start = data + 4;
        if (smb_start >= end) return 0;
    }

    uint32_t magic = 0;
    if ((size_t)(end - smb_start) >= 4) {
        magic = ((uint32_t)smb_start[0] << 24) |
                ((uint32_t)smb_start[1] << 16) |
                ((uint32_t)smb_start[2] <<  8) |
                 (uint32_t)smb_start[3];
    }

    if (magic == SMB1_MAGIC) {
        /* SMBv1 */
        pkt->app_proto = PROTO_SMB1;
        pkt->smb_version = 1;
        if ((size_t)(end - smb_start) >= sizeof(Smb1Header)) {
            const Smb1Header* hdr = (const Smb1Header*)smb_start;
            pkt->smb_command = hdr->command;
            pkt->smb_status  = ntohl(hdr->status);
            pkt->smb_flags2  = ntohs(hdr->flags2);
            pkt->smb_fid     = 0;
        }
    } else if (magic == SMB2_MAGIC) {
        /* SMBv2/3 */
        pkt->app_proto = PROTO_SMB2;
        pkt->smb_version = 2;
        if ((size_t)(end - smb_start) >= sizeof(Smb2Header)) {
            const Smb2Header* hdr = (const Smb2Header*)smb_start;
            pkt->smb_command = (uint8_t)(ntohs(hdr->command) & 0xFF);
            pkt->smb_status  = ntohl(hdr->status);
            pkt->smb_compression = 0;
        }
    } else if (magic == SMB3_COMPRESS) {
        /* SMBv3 压缩包 */
        pkt->app_proto = PROTO_SMB3_COMPRESS;
        pkt->smb_version = 3;
        pkt->smb_compression = 1;
    } else {
        return 0;
    }
    return 1;
}

/* =========================================================
 *  HTTP 解析（仅解析请求行 + 常用请求头）
 * ========================================================= */
int PP_ParseHTTP(ParsedPacket* pkt)
{
    const uint8_t* data = pkt->payload;
    uint32_t       len  = pkt->payload_len;

    if (!data || len < 16) return 0;

    /* 判断是否为 HTTP 请求 */
    const char* methods[] = { "GET ", "POST ", "PUT ", "DELETE ",
                               "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", NULL };
    int is_http = 0;
    for (int i = 0; methods[i]; i++) {
        if (strncmp((const char*)data, methods[i], strlen(methods[i])) == 0) {
            is_http = 1;
            SAFE_STRNCPY(pkt->http_method, methods[i], sizeof(pkt->http_method));
            /* 去掉末尾空格 */
            size_t ml = strlen(pkt->http_method);
            if (ml > 0 && pkt->http_method[ml-1] == ' ')
                pkt->http_method[ml-1] = '\0';
            break;
        }
    }
    if (!is_http) return 0;

    pkt->app_proto = PROTO_HTTP;

    /* 解析请求行：METHOD URI HTTP/x.x */
    const char* line_start = (const char*)data;
    const char* line_end   = (const char*)memchr(data, '\n', len);
    if (!line_end) return 1;

    /* 提取 URI */
    const char* uri_start = strchr(line_start, ' ');
    if (uri_start) {
        uri_start++;
        const char* uri_end = strchr(uri_start, ' ');
        if (!uri_end) uri_end = line_end;
        size_t uri_len = (size_t)(uri_end - uri_start);
        if (uri_len >= sizeof(pkt->http_uri)) uri_len = sizeof(pkt->http_uri) - 1;
        memcpy(pkt->http_uri, uri_start, uri_len);
        pkt->http_uri[uri_len] = '\0';
    }

    /* 解析请求头 */
    const char* hdr_ptr = line_end + 1;
    const char* data_end = (const char*)data + len;
    size_t hdr_copied = 0;

    while (hdr_ptr < data_end) {
        const char* hdr_end = (const char*)memchr(hdr_ptr, '\n', data_end - hdr_ptr);
        if (!hdr_end) break;
        size_t hdr_line_len = (size_t)(hdr_end - hdr_ptr);
        if (hdr_line_len <= 1) break; /* 空行 = 头部结束 */

        /* 去掉 \r */
        char hdr_line[512];
        size_t copy_len = hdr_line_len < sizeof(hdr_line)-1 ? hdr_line_len : sizeof(hdr_line)-1;
        memcpy(hdr_line, hdr_ptr, copy_len);
        hdr_line[copy_len] = '\0';
        if (copy_len > 0 && hdr_line[copy_len-1] == '\r')
            hdr_line[copy_len-1] = '\0';

        /* 提取 Host */
        if (strncasecmp(hdr_line, "Host:", 5) == 0) {
            const char* v = hdr_line + 5;
            while (*v == ' ') v++;
            SAFE_STRNCPY(pkt->http_host, v, sizeof(pkt->http_host));
        }
        /* 提取 Cookie */
        if (strncasecmp(hdr_line, "Cookie:", 7) == 0) {
            const char* v = hdr_line + 7;
            while (*v == ' ') v++;
            SAFE_STRNCPY(pkt->http_cookie, v, sizeof(pkt->http_cookie));
        }

        /* 追加到 http_headers */
        size_t remain = sizeof(pkt->http_headers) - hdr_copied - 1;
        if (remain > 0) {
            size_t append_len = strlen(hdr_line);
            if (append_len > remain) append_len = remain;
            memcpy(pkt->http_headers + hdr_copied, hdr_line, append_len);
            hdr_copied += append_len;
            if (hdr_copied < sizeof(pkt->http_headers) - 2) {
                pkt->http_headers[hdr_copied++] = '\n';
            }
        }

        hdr_ptr = hdr_end + 1;
    }
    pkt->http_headers[hdr_copied] = '\0';

    return 1;
}

/* =========================================================
 *  DNS 解析（仅解析查询域名）
 * ========================================================= */
int PP_ParseDNS(ParsedPacket* pkt)
{
    const uint8_t* data = pkt->payload;
    uint32_t       len  = pkt->payload_len;

    /* DNS 最小头部 12 字节 */
    if (!data || len < 12) return 0;

    /* 仅处理标准查询（QR=0） */
    uint16_t flags = (uint16_t)((data[2] << 8) | data[3]);
    if (flags & 0x8000) return 0; /* 响应包跳过 */

    uint16_t qdcount = (uint16_t)((data[4] << 8) | data[5]);
    if (qdcount == 0) return 0;

    pkt->app_proto = PROTO_DNS;

    /* 解析第一个查询的域名 */
    const uint8_t* ptr = data + 12;
    const uint8_t* end = data + len;
    char name[PP_MAX_DNS_NAME];
    int  name_len = 0;
    int  first    = 1;

    while (ptr < end) {
        uint8_t label_len = *ptr++;
        if (label_len == 0) break;
        if (label_len > 63 || ptr + label_len > end) break;

        if (!first && name_len < PP_MAX_DNS_NAME - 1)
            name[name_len++] = '.';
        first = 0;

        int copy = label_len;
        if (name_len + copy >= PP_MAX_DNS_NAME)
            copy = PP_MAX_DNS_NAME - name_len - 1;
        memcpy(name + name_len, ptr, copy);
        name_len += copy;
        ptr += label_len;
    }
    name[name_len] = '\0';
    SAFE_STRNCPY(pkt->dns_query, name, sizeof(pkt->dns_query));

    /* 查询类型 */
    if (ptr + 4 <= end) {
        pkt->dns_qtype = (uint16_t)((ptr[0] << 8) | ptr[1]);
    }

    return 1;
}

/* =========================================================
 *  RDP 解析（TPKT + X.224 层）
 * ========================================================= */
int PP_ParseRDP(ParsedPacket* pkt)
{
    const uint8_t* data = pkt->payload;
    uint32_t       len  = pkt->payload_len;

    /* TPKT: 0x03 0x00 len_hi len_lo */
    if (!data || len < 4) return 0;
    if (data[0] != 0x03 || data[1] != 0x00) return 0;

    pkt->app_proto = PROTO_RDP;

    /* X.224 Data TPDU (0xF0) 或 Connection Request (0xE0) */
    if (len >= 5) {
        uint8_t x224_type = data[4] & 0xF0;
        pkt->rdp_pdu_type = x224_type;

        /* 检测 MCS Connect Initial（含 GCC Conference Create Request）*/
        /* 简单标记：在载荷中搜索 "MS_T120" 通道名 */
        const char* ms_t120 = "MS_T120";
        if (len > 10) {
            const uint8_t* found = (const uint8_t*)memmem(data, len,
                                    ms_t120, strlen(ms_t120));
            if (found) {
                SAFE_STRNCPY(pkt->rdp_channel, "MS_T120", sizeof(pkt->rdp_channel));
            }
        }
    }

    return 1;
}

/* =========================================================
 *  DCERPC 解析（提取 UUID 和 OpNum）
 * ========================================================= */
int PP_ParseDCERPC(ParsedPacket* pkt)
{
    const uint8_t* data = pkt->payload;
    uint32_t       len  = pkt->payload_len;

    /* DCERPC 最小头部 16 字节，版本字段 = 0x05 */
    if (!data || len < 16) return 0;
    if (data[0] != 0x05) return 0; /* version */

    pkt->app_proto = PROTO_DCERPC;

    uint8_t pkt_type = data[2]; /* 0x0B=Bind, 0x00=Request */

    if (pkt_type == 0x0B && len >= 60) {
        /* Bind 包：提取接口 UUID（偏移44，16字节） */
        const uint8_t* uuid_ptr = data + 44;
        snprintf(pkt->dcerpc_uuid, sizeof(pkt->dcerpc_uuid),
            "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            (uint32_t)(uuid_ptr[0] | (uuid_ptr[1]<<8) | (uuid_ptr[2]<<16) | (uuid_ptr[3]<<24)),
            (uint16_t)(uuid_ptr[4] | (uuid_ptr[5]<<8)),
            (uint16_t)(uuid_ptr[6] | (uuid_ptr[7]<<8)),
            uuid_ptr[8], uuid_ptr[9],
            uuid_ptr[10], uuid_ptr[11], uuid_ptr[12],
            uuid_ptr[13], uuid_ptr[14], uuid_ptr[15]);
    } else if (pkt_type == 0x00 && len >= 24) {
        /* Request 包：OpNum 在偏移 22 */
        pkt->dcerpc_opnum = (uint16_t)(data[22] | (data[23] << 8));
    }

    return 1;
}

/* =========================================================
 *  主解析入口
 * ========================================================= */
int PP_ParsePacket(
    const uint8_t*  raw_data,
    uint32_t        raw_len,
    uint64_t        ts_us,
    ParsedPacket*   out_pkt)
{
    if (!raw_data || raw_len < sizeof(EthHeader) || !out_pkt) return 0;

    memset(out_pkt, 0, sizeof(ParsedPacket));
    out_pkt->timestamp_us = ts_us;
    out_pkt->raw_pkt      = raw_data;
    out_pkt->raw_pkt_len  = raw_len;
    out_pkt->app_proto    = PROTO_UNKNOWN;

    const uint8_t* ptr = raw_data;
    const uint8_t* end = raw_data + raw_len;

    /* ---- 以太网层 ---- */
    const EthHeader* eth = (const EthHeader*)ptr;
    memcpy(out_pkt->src_mac, eth->src_mac, 6);
    memcpy(out_pkt->dst_mac, eth->dst_mac, 6);
    out_pkt->ether_type = ntohs(eth->ether_type);
    ptr += sizeof(EthHeader);

    /* 处理 VLAN tag（802.1Q） */
    if (out_pkt->ether_type == ETHERTYPE_VLAN && ptr + 4 <= end) {
        ptr += 2; /* TCI */
        out_pkt->ether_type = ntohs(*(uint16_t*)ptr);
        ptr += 2;
    }

    if (out_pkt->ether_type != ETHERTYPE_IP) return 1; /* 仅处理 IPv4 */

    /* ---- IPv4 层 ---- */
    if (ptr + sizeof(IPv4Header) > end) return 0;
    const IPv4Header* ip = (const IPv4Header*)ptr;
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || ptr + ihl > end) return 0;

    out_pkt->ip_proto    = ip->protocol;
    out_pkt->ip_ttl      = ip->ttl;
    out_pkt->ip_total_len = ntohs(ip->total_len);

    /* 保存原始网络字节序 IP 地址 */
    out_pkt->src_ip_raw = ip->src_ip;
    out_pkt->dst_ip_raw = ip->dst_ip;
    PP_IpToStr(ip->src_ip, out_pkt->src_ip, sizeof(out_pkt->src_ip));
    PP_IpToStr(ip->dst_ip, out_pkt->dst_ip, sizeof(out_pkt->dst_ip));

    ptr += ihl;

    /* ---- 传输层 ---- */
    if (ip->protocol == IP_PROTO_TCP) {
        if (ptr + sizeof(TcpHeader) > end) return 1;
        const TcpHeader* tcp = (const TcpHeader*)ptr;
        out_pkt->src_port  = ntohs(tcp->src_port);
        out_pkt->dst_port  = ntohs(tcp->dst_port);
        out_pkt->tcp_flags = tcp->flags;
        out_pkt->tcp_seq   = ntohl(tcp->seq_num);
        out_pkt->tcp_ack   = ntohl(tcp->ack_num);

        uint8_t tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20) tcp_hdr_len = 20;
        ptr += tcp_hdr_len;

        out_pkt->payload     = ptr;
        out_pkt->payload_len = (uint32_t)(end - ptr);

        /* ---- 应用层协议识别 ---- */
        uint16_t dport = out_pkt->dst_port;
        uint16_t sport = out_pkt->src_port;

        if ((dport == 445 || sport == 445 || dport == 139 || sport == 139)
            && out_pkt->payload_len >= 4) {
            PP_ParseSMB(out_pkt);
        } else if ((dport == 3389 || sport == 3389) && out_pkt->payload_len >= 4) {
            PP_ParseRDP(out_pkt);
        } else if ((dport == 80 || sport == 80 ||
                    dport == 8080 || sport == 8080 ||
                    dport == 443 || sport == 443) && out_pkt->payload_len >= 16) {
            PP_ParseHTTP(out_pkt);
        } else if ((dport == 135 || sport == 135) && out_pkt->payload_len >= 16) {
            PP_ParseDCERPC(out_pkt);
        }

    } else if (ip->protocol == IP_PROTO_UDP) {
        if (ptr + sizeof(UdpHeader) > end) return 1;
        const UdpHeader* udp = (const UdpHeader*)ptr;
        out_pkt->src_port  = ntohs(udp->src_port);
        out_pkt->dst_port  = ntohs(udp->dst_port);
        ptr += sizeof(UdpHeader);

        out_pkt->payload     = ptr;
        out_pkt->payload_len = (uint32_t)(end - ptr);

        if ((out_pkt->dst_port == 53 || out_pkt->src_port == 53)
            && out_pkt->payload_len >= 12) {
            PP_ParseDNS(out_pkt);
        }

    } else if (ip->protocol == IP_PROTO_ICMP) {
        if (ptr + sizeof(IcmpHeader) > end) return 1;
        const IcmpHeader* icmp = (const IcmpHeader*)ptr;
        out_pkt->icmp_type   = icmp->type;
        out_pkt->icmp_code   = icmp->code;
        out_pkt->payload     = ptr + sizeof(IcmpHeader);
        out_pkt->payload_len = (uint32_t)(end - out_pkt->payload);
    }

    return 1;
}
