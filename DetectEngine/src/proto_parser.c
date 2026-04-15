/**
 * @file    proto_parser.c
 * @brief   协议解析层实现 —— 跨平台双路径
 *
 * 编译策略：
 *   - Linux/macOS : 使用 nDPI 4.x 深度包检测（200+ 协议精准分类）
 *   - Windows     : 使用内置轻量协议解析器（仅依赖 Npcap SDK，零外部依赖）
 *
 * 对外接口在两个平台上完全一致。
 */

#ifdef _WIN32
#  define _CRT_SECURE_NO_WARNINGS
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#else
#  define _GNU_SOURCE
#endif

#include "../include/proto_parser.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <arpa/inet.h>
#endif

/* =========================================================
 *  工具宏
 * ========================================================= */
#define SAFE_COPY(dst, src, sz) do { \
    if ((src) != NULL && (src)[0] != '\0') { \
        strncpy((dst), (src), (sz)-1); \
        (dst)[(sz)-1] = '\0'; \
    } \
} while(0)

#define MIN2(a,b) ((a)<(b)?(a):(b))

/* =========================================================
 *  跨平台 strcasestr 实现（Windows 无此函数）
 * ========================================================= */
#ifdef _WIN32
static const char* vde_strcasestr(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;
    for (; *haystack; haystack++) {
        if (_strnicmp(haystack, needle, nlen) == 0)
            return haystack;
    }
    return NULL;
}
#  define strcasestr vde_strcasestr
#endif

/* =========================================================
 *  PP_IpToStr
 * ========================================================= */
void PP_IpToStr(uint32_t ip_net, char* buf, size_t buf_len)
{
    if (!buf || buf_len < 16) return;
    uint8_t* b = (uint8_t*)&ip_net;
    snprintf(buf, buf_len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* =========================================================
 *  内部：SMB 字段细粒度解析（跨平台，纯字节操作）
 * ========================================================= */
static void parse_smb_fields(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 8) return;

    /* 跳过 NBSS 头（4字节） */
    if (len >= 4 && p[0] == 0x00) {
        p   += 4;
        len -= 4;
    }
    if (len < 4) return;

    uint32_t magic = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
                   | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];

    if (magic == SMB1_MAGIC && len >= sizeof(Smb1Header)) {
        const Smb1Header* h = (const Smb1Header*)p;
        pkt->smb_version = 1;
        pkt->smb_command = h->command;
        pkt->smb_status  = ntohl(h->status);
        pkt->smb_flags2  = ntohs(h->flags2);
        pkt->app_proto   = PROTO_SMB1;
        snprintf(pkt->ndpi_proto_name, sizeof(pkt->ndpi_proto_name), "SMBv1");
    } else if (magic == SMB2_MAGIC && len >= sizeof(Smb2Header)) {
        const Smb2Header* h = (const Smb2Header*)p;
        pkt->smb_version = 2;
        pkt->smb_command = (uint8_t)(ntohs(h->command) & 0xFF);
        pkt->smb_status  = ntohl(h->status);
        pkt->app_proto   = PROTO_SMB2;
        snprintf(pkt->ndpi_proto_name, sizeof(pkt->ndpi_proto_name), "SMBv2/3");
    } else if (magic == SMB3_COMPRESS) {
        pkt->smb_version     = 3;
        pkt->smb_compression = 1;
        pkt->app_proto       = PROTO_SMB3_COMPRESS;
        snprintf(pkt->ndpi_proto_name, sizeof(pkt->ndpi_proto_name), "SMBv3-Compress");
    }
}

/* =========================================================
 *  内部：HTTP 字段细粒度解析（纯字节操作，跨平台）
 * ========================================================= */
static void parse_http_fields_raw(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 8) return;

    uint32_t rlen = MIN2(len, (uint32_t)(PP_MAX_HTTP_HDR - 1));
    memcpy(pkt->http_headers, (const char*)p, rlen);
    pkt->http_headers[rlen] = '\0';

    const char* raw = (const char*)p;

    /* 提取 Method + URI */
    static const char* methods[] = {
        "GET", "POST", "PUT", "DELETE", "HEAD",
        "OPTIONS", "PATCH", "CONNECT", "TRACE", NULL
    };
    for (int i = 0; methods[i]; i++) {
        size_t mlen = strlen(methods[i]);
        if (len > mlen + 1 &&
            memcmp(raw, methods[i], mlen) == 0 &&
            raw[mlen] == ' ')
        {
            strncpy(pkt->http_method, methods[i], sizeof(pkt->http_method) - 1);
            const char* uri_start = raw + mlen + 1;
            const char* uri_end   = strchr(uri_start, ' ');
            if (!uri_end) uri_end = strchr(uri_start, '\r');
            if (uri_end) {
                size_t ulen = MIN2((size_t)(uri_end - uri_start),
                                   sizeof(pkt->http_uri) - 1);
                memcpy(pkt->http_uri, uri_start, ulen);
                pkt->http_uri[ulen] = '\0';
            }
            break;
        }
    }

    /* 提取 Host */
    const char* host_hdr = strcasestr(pkt->http_headers, "\r\nHost:");
    if (!host_hdr) host_hdr = strcasestr(pkt->http_headers, "\nHost:");
    if (host_hdr) {
        host_hdr = strchr(host_hdr, ':') + 1;
        while (*host_hdr == ' ') host_hdr++;
        const char* end2 = strpbrk(host_hdr, "\r\n");
        if (end2) {
            size_t hlen = MIN2((size_t)(end2 - host_hdr), sizeof(pkt->http_host) - 1);
            memcpy(pkt->http_host, host_hdr, hlen);
            pkt->http_host[hlen] = '\0';
        }
    }

    /* 提取 User-Agent */
    const char* ua = strcasestr(pkt->http_headers, "\r\nUser-Agent:");
    if (!ua) ua = strcasestr(pkt->http_headers, "\nUser-Agent:");
    if (ua) {
        ua = strchr(ua, ':') + 1;
        while (*ua == ' ') ua++;
        const char* end2 = strpbrk(ua, "\r\n");
        if (end2) {
            size_t ualen = MIN2((size_t)(end2 - ua), sizeof(pkt->http_user_agent) - 1);
            memcpy(pkt->http_user_agent, ua, ualen);
            pkt->http_user_agent[ualen] = '\0';
        }
    }

    /* 提取 Cookie */
    const char* ck = strcasestr(pkt->http_headers, "\r\nCookie:");
    if (!ck) ck = strcasestr(pkt->http_headers, "\nCookie:");
    if (ck) {
        ck = strchr(ck, ':') + 1;
        while (*ck == ' ') ck++;
        const char* end2 = strpbrk(ck, "\r\n");
        if (end2) {
            size_t clen = MIN2((size_t)(end2 - ck), sizeof(pkt->http_cookie) - 1);
            memcpy(pkt->http_cookie, ck, clen);
            pkt->http_cookie[clen] = '\0';
        }
    }
}

/* =========================================================
 *  内部：DNS 字段细粒度解析（跨平台，纯字节操作）
 * ========================================================= */
static void parse_dns_fields_raw(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 13) return;

    uint16_t qdcount = (uint16_t)((p[4] << 8) | p[5]);
    if (qdcount == 0) return;

    const uint8_t* ptr = p + 12;
    const uint8_t* end = p + len;
    char name[PP_MAX_DNS_NAME];
    int  npos = 0;
    int  first = 1;

    while (ptr < end && *ptr != 0 && npos < (int)sizeof(name) - 2) {
        uint8_t label_len = *ptr++;
        if ((label_len & 0xC0) == 0xC0) break;
        if (ptr + label_len > end) break;
        if (!first) name[npos++] = '.';
        first = 0;
        int copy_len = (int)MIN2((uint32_t)label_len,
                                  (uint32_t)(sizeof(name) - npos - 2));
        memcpy(name + npos, ptr, copy_len);
        npos += copy_len;
        ptr  += label_len;
    }
    name[npos] = '\0';
    if (npos > 0)
        SAFE_COPY(pkt->dns_query, name, sizeof(pkt->dns_query));

    if (ptr + 2 < end) {
        ptr++;
        pkt->dns_qtype = (uint16_t)((ptr[0] << 8) | ptr[1]);
    }
}

/* =========================================================
 *  内部：RDP 字段细粒度解析（跨平台）
 * ========================================================= */
static void parse_rdp_fields(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 8) return;
    if (p[0] != 0x03) return;

    uint8_t cotp_type = (len >= 6) ? p[5] : 0;
    pkt->rdp_pdu_type = cotp_type;

    static const char* channels[] = {
        "MS_T120", "rdpdr", "rdpsnd", "cliprdr", NULL
    };
    for (int i = 0; channels[i]; i++) {
        size_t clen = strlen(channels[i]);
        if (len > clen) {
            for (uint32_t j = 0; j + clen <= len; j++) {
                if (memcmp(p + j, channels[i], clen) == 0) {
                    SAFE_COPY(pkt->rdp_channel, channels[i],
                              sizeof(pkt->rdp_channel));
                    break;
                }
            }
        }
    }
}

/* =========================================================
 *  内部：DCERPC 字段细粒度解析（跨平台）
 * ========================================================= */
static void parse_dcerpc_fields(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 24) return;
    if (p[0] != 0x05) return;

    pkt->dcerpc_opnum = (uint16_t)(p[22] | (p[23] << 8));

    if (len >= 32 && p[2] == 0x0B) {
        snprintf(pkt->dcerpc_uuid, sizeof(pkt->dcerpc_uuid),
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 p[16], p[17], p[18], p[19],
                 p[20], p[21], p[22], p[23],
                 p[24], p[25], p[26], p[27],
                 p[28], p[29], p[30], p[31]);
    }
}

/* =========================================================
 *  内部：Kerberos 字段细粒度解析（跨平台）
 * ========================================================= */
static void parse_kerberos_fields(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 10) return;

    for (uint32_t i = 0; i + 4 < len; i++) {
        if (p[i] == 0x1B) {
            uint8_t slen = p[i + 1];
            if (slen > 0 && slen < 64 && i + 2 + slen <= len) {
                if (pkt->kerb_domain[0] == '\0') {
                    memcpy(pkt->kerb_domain, p + i + 2, slen);
                    pkt->kerb_domain[slen] = '\0';
                } else if (pkt->kerb_hostname[0] == '\0') {
                    memcpy(pkt->kerb_hostname, p + i + 2, slen);
                    pkt->kerb_hostname[slen] = '\0';
                }
            }
        }
    }
}

/* =========================================================
 *  内部：基于端口的协议推断（跨平台回退）
 * ========================================================= */
static ProtoType port_to_proto(uint16_t port)
{
    switch (port) {
        case 80: case 8080: case 8000: case 8443: case 443: case 8888:
            return PROTO_HTTP;
        case 445: case 139:
            return PROTO_SMB1;
        case 53:
            return PROTO_DNS;
        case 3389:
            return PROTO_RDP;
        case 135: case 593:
            return PROTO_DCERPC;
        case 88:
            return PROTO_KERBEROS;
        default:
            return PROTO_UNKNOWN;
    }
}

/* =========================================================
 *  PP_Init / PP_Destroy
 * ========================================================= */
int PP_Init(NdpiContext* ctx)
{
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(NdpiContext));

#ifndef _WIN32
    ctx->ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs);
    if (!ctx->ndpi_struct) {
        fprintf(stderr, "[proto_parser] ndpi_init_detection_module 失败\n");
        return -1;
    }
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ctx->ndpi_struct, &all);
    ndpi_finalize_initialization(ctx->ndpi_struct);
    fprintf(stderr, "[proto_parser] nDPI %s 初始化成功，支持 %u 个协议\n",
            ndpi_revision(),
            ndpi_get_num_supported_protocols(ctx->ndpi_struct));
#else
    ctx->ndpi_struct = NULL;
    fprintf(stderr, "[proto_parser] Windows 内置协议解析器初始化成功\n");
#endif
    return 0;
}

void PP_Destroy(NdpiContext* ctx)
{
    if (!ctx) return;
#ifndef _WIN32
    if (ctx->ndpi_struct) {
        ndpi_exit_detection_module(ctx->ndpi_struct);
        ctx->ndpi_struct = NULL;
    }
#else
    ctx->ndpi_struct = NULL;
#endif
}

/* =========================================================
 *  PP_FlowCreate / PP_FlowDestroy
 * ========================================================= */
NdpiFlowCtx* PP_FlowCreate(void)
{
    NdpiFlowCtx* fctx = (NdpiFlowCtx*)calloc(1, sizeof(NdpiFlowCtx));
    if (!fctx) return NULL;

#ifndef _WIN32
    fctx->flow = (struct ndpi_flow_struct*)calloc(1, sizeof(struct ndpi_flow_struct));
    if (!fctx->flow) {
        free(fctx);
        return NULL;
    }
#else
    fctx->flow = NULL;
#endif
    return fctx;
}

void PP_FlowDestroy(NdpiFlowCtx* fctx)
{
    if (!fctx) return;
#ifndef _WIN32
    if (fctx->flow) {
        ndpi_free_flow_data(fctx->flow);
        free(fctx->flow);
        fctx->flow = NULL;
    }
#endif
    free(fctx);
}

/* =========================================================
 *  PP_ParsePacket —— 主解析函数（跨平台）
 * ========================================================= */
int PP_ParsePacket(
    NdpiContext*    ctx,
    NdpiFlowCtx*    fctx,
    const uint8_t*  raw_data,
    uint32_t        raw_len,
    uint64_t        ts_us,
    ParsedPacket*   out_pkt)
{
    if (!raw_data || raw_len < (uint32_t)sizeof(EthHeader) || !out_pkt)
        return 0;

    memset(out_pkt, 0, sizeof(ParsedPacket));
    out_pkt->timestamp_us = ts_us;
    out_pkt->raw_pkt      = raw_data;
    out_pkt->raw_pkt_len  = raw_len;

    const uint8_t* ptr = raw_data;
    const uint8_t* end = raw_data + raw_len;

    /* ---- 以太网层 ---- */
    const EthHeader* eth = (const EthHeader*)ptr;
    memcpy(out_pkt->src_mac, eth->src_mac, 6);
    memcpy(out_pkt->dst_mac, eth->dst_mac, 6);
    out_pkt->ether_type = ntohs(eth->ether_type);
    ptr += sizeof(EthHeader);

    if (out_pkt->ether_type == ETHERTYPE_VLAN && ptr + 4 <= end) {
        out_pkt->ether_type = ntohs(*(uint16_t*)(ptr + 2));
        ptr += 4;
    }
    if (out_pkt->ether_type != ETHERTYPE_IP) return 1;

    /* ---- IPv4 层 ---- */
    if (ptr + (int)sizeof(IPv4Header) > end) return 0;
    const IPv4Header* ip = (const IPv4Header*)ptr;
    uint8_t ihl = (uint8_t)((ip->ver_ihl & 0x0F) * 4);
    if (ihl < 20 || ptr + ihl > end) return 0;

    out_pkt->ip_proto     = ip->protocol;
    out_pkt->ip_ttl       = ip->ttl;
    out_pkt->ip_total_len = ntohs(ip->total_len);
    out_pkt->src_ip_raw   = ip->src_ip;
    out_pkt->dst_ip_raw   = ip->dst_ip;
    PP_IpToStr(ip->src_ip, out_pkt->src_ip, sizeof(out_pkt->src_ip));
    PP_IpToStr(ip->dst_ip, out_pkt->dst_ip, sizeof(out_pkt->dst_ip));
    ptr += ihl;

    /* ---- 传输层 ---- */
    if (ip->protocol == IP_PROTO_TCP) {
        if (ptr + (int)sizeof(TcpHeader) > end) return 1;
        const TcpHeader* tcp = (const TcpHeader*)ptr;
        out_pkt->src_port  = ntohs(tcp->src_port);
        out_pkt->dst_port  = ntohs(tcp->dst_port);
        out_pkt->tcp_flags = tcp->flags;
        out_pkt->tcp_seq   = ntohl(tcp->seq_num);
        out_pkt->tcp_ack   = ntohl(tcp->ack_num);
        uint8_t tcp_hdr_len = (uint8_t)(((tcp->data_offset >> 4) & 0x0F) * 4);
        if (tcp_hdr_len < 20) tcp_hdr_len = 20;
        ptr += tcp_hdr_len;
        out_pkt->payload     = ptr;
        out_pkt->payload_len = (uint32_t)(end - ptr);
    } else if (ip->protocol == IP_PROTO_UDP) {
        if (ptr + (int)sizeof(UdpHeader) > end) return 1;
        const UdpHeader* udp = (const UdpHeader*)ptr;
        out_pkt->src_port  = ntohs(udp->src_port);
        out_pkt->dst_port  = ntohs(udp->dst_port);
        ptr += sizeof(UdpHeader);
        out_pkt->payload     = ptr;
        out_pkt->payload_len = (uint32_t)(end - ptr);
    } else if (ip->protocol == IP_PROTO_ICMP) {
        if (ptr + (int)sizeof(IcmpHeader) > end) return 1;
        const IcmpHeader* icmp = (const IcmpHeader*)ptr;
        out_pkt->icmp_type   = icmp->type;
        out_pkt->icmp_code   = icmp->code;
        out_pkt->payload     = ptr + sizeof(IcmpHeader);
        out_pkt->payload_len = (uint32_t)(end - out_pkt->payload);
        return 1;
    } else {
        return 1;
    }

/* =========================================================
 *  应用层协议识别（平台分支）
 * ========================================================= */
#ifndef _WIN32
    /* ---- Linux: nDPI 深度包检测 ---- */
    struct ndpi_flow_struct* flow = NULL;
    NdpiFlowCtx* tmp_fctx = NULL;

    if (fctx && fctx->flow) {
        flow = fctx->flow;
    } else if (ctx && ctx->ndpi_struct && out_pkt->payload_len > 0) {
        tmp_fctx = PP_FlowCreate();
        if (tmp_fctx) flow = tmp_fctx->flow;
    }

    ndpi_protocol detected;
    memset(&detected, 0, sizeof(detected));

    if (ctx && ctx->ndpi_struct && flow && out_pkt->payload_len > 0) {
        const uint8_t* ip_start = raw_data + sizeof(EthHeader);
        uint16_t etype = ntohs(((const EthHeader*)raw_data)->ether_type);
        if (etype == ETHERTYPE_VLAN) ip_start += 4;
        uint32_t ip_len = (uint32_t)(end - ip_start);

        detected = ndpi_detection_process_packet(
            ctx->ndpi_struct, flow, ip_start,
            (unsigned short)(ip_len > 65535 ? 65535 : ip_len),
            ts_us / 1000);

        if (detected.master_protocol == NDPI_PROTOCOL_UNKNOWN &&
            detected.app_protocol    == NDPI_PROTOCOL_UNKNOWN) {
            u_int8_t was_guessed = 0;
            detected = ndpi_detection_giveup(ctx->ndpi_struct, flow, 1, &was_guessed);
        }
        if (fctx) {
            fctx->detected_proto      = detected;
            fctx->detection_completed = 1;
        }
    }

    out_pkt->ndpi_master_proto = detected.master_protocol;
    out_pkt->ndpi_sub_proto    = detected.app_protocol;
    if (ctx && ctx->ndpi_struct) {
        ndpi_protocol2name(ctx->ndpi_struct, detected,
                           out_pkt->ndpi_proto_name,
                           sizeof(out_pkt->ndpi_proto_name));
    }

    /* nDPI ID -> ProtoType 映射表 */
    static const struct { uint16_t id; ProtoType pt; } ndpi_map[] = {
        { 16,  PROTO_SMB1    },
        { 41,  PROTO_SMB2    },
        {  7,  PROTO_HTTP    },
        {  5,  PROTO_DNS     },
        { 88,  PROTO_RDP     },
        {127,  PROTO_DCERPC  },
        {111,  PROTO_KERBEROS},
        {  0,  PROTO_UNKNOWN }
    };
    ProtoType pt = PROTO_UNKNOWN;
    uint16_t master = detected.master_protocol;
    uint16_t sub    = detected.app_protocol;
    for (int i = 0; ndpi_map[i].pt != PROTO_UNKNOWN || ndpi_map[i].id == 0; i++) {
        if (ndpi_map[i].id == master || ndpi_map[i].id == sub) {
            pt = ndpi_map[i].pt;
            break;
        }
    }
    out_pkt->app_proto = pt;

    /* 字段级细粒度解析 */
    switch (pt) {
        case PROTO_SMB1: case PROTO_SMB2: case PROTO_SMB3_COMPRESS:
            parse_smb_fields(out_pkt);
            break;
        case PROTO_HTTP:
            if (flow) {
                static const char* http_methods[] = {
                    "UNKNOWN","OPTIONS","GET","HEAD","POST","PUT",
                    "DELETE","TRACE","CONNECT","PATCH"
                };
                int m = (int)flow->http.method;
                if (m >= 0 && m < 10)
                    SAFE_COPY(out_pkt->http_method, http_methods[m],
                              sizeof(out_pkt->http_method));
                if (flow->http.url)
                    SAFE_COPY(out_pkt->http_uri, flow->http.url,
                              sizeof(out_pkt->http_uri));
                if (flow->http.user_agent)
                    SAFE_COPY(out_pkt->http_user_agent, flow->http.user_agent,
                              sizeof(out_pkt->http_user_agent));
            }
            parse_http_fields_raw(out_pkt);
            break;
        case PROTO_DNS:
            parse_dns_fields_raw(out_pkt);
            if (flow && flow->protos.dns.num_queries > 0)
                out_pkt->dns_qtype = flow->protos.dns.query_type;
            break;
        case PROTO_RDP:
            parse_rdp_fields(out_pkt);
            break;
        case PROTO_DCERPC:
            parse_dcerpc_fields(out_pkt);
            break;
        case PROTO_KERBEROS:
            parse_kerberos_fields(out_pkt);
            if (flow) {
                SAFE_COPY(out_pkt->kerb_hostname, flow->protos.kerberos.hostname,
                          sizeof(out_pkt->kerb_hostname));
                SAFE_COPY(out_pkt->kerb_domain, flow->protos.kerberos.domain,
                          sizeof(out_pkt->kerb_domain));
                SAFE_COPY(out_pkt->kerb_username, flow->protos.kerberos.username,
                          sizeof(out_pkt->kerb_username));
            }
            break;
        default: {
            /* 端口回退推断 */
            ProtoType fb = port_to_proto(out_pkt->dst_port);
            if (fb == PROTO_UNKNOWN) fb = port_to_proto(out_pkt->src_port);
            if (fb != PROTO_UNKNOWN) {
                out_pkt->app_proto = fb;
                switch (fb) {
                    case PROTO_SMB1: case PROTO_SMB2: parse_smb_fields(out_pkt); break;
                    case PROTO_HTTP: parse_http_fields_raw(out_pkt); break;
                    case PROTO_DNS:  parse_dns_fields_raw(out_pkt);  break;
                    case PROTO_RDP:  parse_rdp_fields(out_pkt);      break;
                    case PROTO_DCERPC: parse_dcerpc_fields(out_pkt); break;
                    default: break;
                }
            }
            break;
        }
    }

    if (tmp_fctx) PP_FlowDestroy(tmp_fctx);

#else
    /* ---- Windows: 内置轻量协议解析器 ---- */
    (void)ctx;
    (void)fctx;

    /* SMB 检测（端口 + 魔数） */
    if (out_pkt->payload_len >= 8 &&
        (out_pkt->dst_port == 445 || out_pkt->src_port == 445 ||
         out_pkt->dst_port == 139 || out_pkt->src_port == 139))
    {
        parse_smb_fields(out_pkt);
        if (out_pkt->app_proto == PROTO_UNKNOWN)
            out_pkt->app_proto = PROTO_SMB1;
    }

    /* HTTP 检测（请求行特征） */
    if (out_pkt->app_proto == PROTO_UNKNOWN && out_pkt->payload_len >= 4) {
        const char* p4 = (const char*)out_pkt->payload;
        int is_http = (memcmp(p4, "GET ", 4) == 0 ||
                       memcmp(p4, "POST", 4) == 0 ||
                       memcmp(p4, "PUT ", 4) == 0 ||
                       memcmp(p4, "HEAD", 4) == 0 ||
                       memcmp(p4, "DELE", 4) == 0 ||
                       memcmp(p4, "OPTI", 4) == 0 ||
                       memcmp(p4, "PATC", 4) == 0 ||
                       memcmp(p4, "HTTP", 4) == 0);
        if (is_http) {
            out_pkt->app_proto = PROTO_HTTP;
            snprintf(out_pkt->ndpi_proto_name, sizeof(out_pkt->ndpi_proto_name), "HTTP");
            parse_http_fields_raw(out_pkt);
        }
    }

    /* DNS（UDP 53） */
    if (out_pkt->app_proto == PROTO_UNKNOWN &&
        ip->protocol == IP_PROTO_UDP &&
        (out_pkt->dst_port == 53 || out_pkt->src_port == 53))
    {
        out_pkt->app_proto = PROTO_DNS;
        snprintf(out_pkt->ndpi_proto_name, sizeof(out_pkt->ndpi_proto_name), "DNS");
        parse_dns_fields_raw(out_pkt);
    }

    /* RDP（TCP 3389） */
    if (out_pkt->app_proto == PROTO_UNKNOWN &&
        (out_pkt->dst_port == 3389 || out_pkt->src_port == 3389))
    {
        out_pkt->app_proto = PROTO_RDP;
        snprintf(out_pkt->ndpi_proto_name, sizeof(out_pkt->ndpi_proto_name), "RDP");
        parse_rdp_fields(out_pkt);
    }

    /* DCERPC（TCP 135/593） */
    if (out_pkt->app_proto == PROTO_UNKNOWN &&
        (out_pkt->dst_port == 135 || out_pkt->src_port == 135 ||
         out_pkt->dst_port == 593 || out_pkt->src_port == 593))
    {
        out_pkt->app_proto = PROTO_DCERPC;
        snprintf(out_pkt->ndpi_proto_name, sizeof(out_pkt->ndpi_proto_name), "DCERPC");
        parse_dcerpc_fields(out_pkt);
    }

    /* Kerberos（TCP/UDP 88） */
    if (out_pkt->app_proto == PROTO_UNKNOWN &&
        (out_pkt->dst_port == 88 || out_pkt->src_port == 88))
    {
        out_pkt->app_proto = PROTO_KERBEROS;
        snprintf(out_pkt->ndpi_proto_name, sizeof(out_pkt->ndpi_proto_name), "Kerberos");
        parse_kerberos_fields(out_pkt);
    }

    /* 最终端口回退 */
    if (out_pkt->app_proto == PROTO_UNKNOWN) {
        ProtoType fb = port_to_proto(out_pkt->dst_port);
        if (fb == PROTO_UNKNOWN) fb = port_to_proto(out_pkt->src_port);
        if (fb != PROTO_UNKNOWN) out_pkt->app_proto = fb;
    }

#endif /* _WIN32 */

    return 1;
}
