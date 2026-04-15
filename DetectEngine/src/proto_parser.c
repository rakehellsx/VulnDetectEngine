/**
 * @file    proto_parser.c
 * @brief   协议解析层实现 —— 基于 nDPI 深度包检测
 *
 * 架构：
 *   1. Ethernet/IP/TCP/UDP/ICMP 底层解析（自研轻量实现）
 *   2. 应用层协议识别：nDPI 4.x（200+ 协议精准分类）
 *   3. 关键字段提取：SMB/HTTP/DNS/RDP/DCERPC/Kerberos 字段级解析
 */

#define _GNU_SOURCE
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
#define SAFE_COPY_STR(dst, src, sz) do { \
    const char* _s = (src); \
    if (_s && _s[0]) { strncpy((dst), _s, (sz)-1); (dst)[(sz)-1] = '\0'; } \
} while(0)

#define MIN2(a,b) ((a)<(b)?(a):(b))

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
 *  PP_Init — 初始化 nDPI 检测模块
 * ========================================================= */
int PP_Init(NdpiContext* ctx)
{
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(NdpiContext));

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
    return 0;
}

/* =========================================================
 *  PP_Destroy
 * ========================================================= */
void PP_Destroy(NdpiContext* ctx)
{
    if (!ctx) return;
    if (ctx->ndpi_struct) {
        ndpi_exit_detection_module(ctx->ndpi_struct);
        ctx->ndpi_struct = NULL;
    }
}

/* =========================================================
 *  PP_FlowCreate / PP_FlowDestroy
 * ========================================================= */
NdpiFlowCtx* PP_FlowCreate(void)
{
    NdpiFlowCtx* fctx = (NdpiFlowCtx*)calloc(1, sizeof(NdpiFlowCtx));
    if (!fctx) return NULL;
    fctx->flow = (struct ndpi_flow_struct*)calloc(1, sizeof(struct ndpi_flow_struct));
    if (!fctx->flow) { free(fctx); return NULL; }
    return fctx;
}

void PP_FlowDestroy(NdpiFlowCtx* fctx)
{
    if (!fctx) return;
    if (fctx->flow) {
        ndpi_free_flow_data(fctx->flow);
        free(fctx->flow);
        fctx->flow = NULL;
    }
    free(fctx);
}

/* =========================================================
 *  内部：SMB 字段细粒度解析
 * ========================================================= */
static void parse_smb_fields(ParsedPacket* pkt)
{
    const uint8_t* data = pkt->payload;
    uint32_t       len  = pkt->payload_len;
    if (!data || len < 8) return;

    const uint8_t* smb = data;
    if (len >= 4 && data[0] == 0x00) {
        if (len <= 4) return;
        smb = data + 4;
        len -= 4;
    }
    if (len < 4) return;

    uint32_t magic = ((uint32_t)smb[0] << 24) | ((uint32_t)smb[1] << 16) |
                     ((uint32_t)smb[2] <<  8) |  (uint32_t)smb[3];

    if (magic == SMB1_MAGIC && len >= sizeof(Smb1Header)) {
        const Smb1Header* h = (const Smb1Header*)smb;
        pkt->smb_version  = 1;
        pkt->smb_command  = h->command;
        pkt->smb_status   = ntohl(h->status);
        pkt->smb_flags2   = ntohs(h->flags2);
        pkt->app_proto    = PROTO_SMB1;
    } else if (magic == SMB2_MAGIC && len >= sizeof(Smb2Header)) {
        const Smb2Header* h = (const Smb2Header*)smb;
        pkt->smb_version  = 2;
        pkt->smb_command  = (uint8_t)(ntohs(h->command) & 0xFF);
        pkt->smb_status   = ntohl(h->status);
        pkt->app_proto    = PROTO_SMB2;
    } else if (magic == SMB3_COMPRESS) {
        pkt->smb_version     = 3;
        pkt->smb_compression = 1;
        pkt->app_proto       = PROTO_SMB3_COMPRESS;
    }
}

/* =========================================================
 *  内部：HTTP 字段细粒度解析（nDPI + 自研补充）
 * ========================================================= */
static void parse_http_fields(ParsedPacket* pkt,
                               struct ndpi_flow_struct* flow)
{
    /* nDPI 提供的字段 */
    if (flow) {
        if (flow->http.method != NDPI_HTTP_METHOD_UNKNOWN) {
            const char* methods[] = {
                "UNKNOWN","OPTIONS","GET","HEAD","POST","PUT",
                "DELETE","TRACE","CONNECT","PATCH"
            };
            int m = (int)flow->http.method;
            if (m >= 0 && m < 10)
                SAFE_COPY(pkt->http_method, methods[m], sizeof(pkt->http_method));
        }
        if (flow->http.url)
            SAFE_COPY(pkt->http_uri, flow->http.url, sizeof(pkt->http_uri));
        if (flow->http.user_agent)
            SAFE_COPY(pkt->http_user_agent, flow->http.user_agent,
                      sizeof(pkt->http_user_agent));
    }

    /* 从原始载荷补充解析 */
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 8) return;

    uint32_t rlen = MIN2(len, (uint32_t)(PP_MAX_HTTP_HDR - 1));
    memcpy(pkt->http_headers, (const char*)p, rlen);
    pkt->http_headers[rlen] = '\0';

    /* 提取 Host */
    const char* host_hdr = strcasestr(pkt->http_headers, "\r\nHost:");
    if (!host_hdr) host_hdr = strcasestr(pkt->http_headers, "\nHost:");
    if (host_hdr) {
        host_hdr = strchr(host_hdr, ':') + 1;
        while (*host_hdr == ' ') host_hdr++;
        const char* end2 = strpbrk(host_hdr, "\r\n");
        if (end2) {
            size_t hlen = MIN2((size_t)(end2 - host_hdr), sizeof(pkt->http_host)-1);
            memcpy(pkt->http_host, host_hdr, hlen);
            pkt->http_host[hlen] = '\0';
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
            size_t clen = MIN2((size_t)(end2 - ck), sizeof(pkt->http_cookie)-1);
            memcpy(pkt->http_cookie, ck, clen);
            pkt->http_cookie[clen] = '\0';
        }
    }

    /* 若 nDPI 未提取到 URI，从请求行提取 */
    if (pkt->http_uri[0] == '\0') {
        const char* raw = (const char*)p;
        const char* sp1 = strchr(raw, ' ');
        if (sp1) {
            sp1++;
            const char* sp2 = strchr(sp1, ' ');
            if (sp2) {
                size_t ulen = MIN2((size_t)(sp2 - sp1), sizeof(pkt->http_uri)-1);
                memcpy(pkt->http_uri, sp1, ulen);
                pkt->http_uri[ulen] = '\0';
            }
        }
    }

    /* 若 nDPI 未提取到 method，从请求行提取 */
    if (pkt->http_method[0] == '\0') {
        const char* raw = (const char*)p;
        const char* sp = strchr(raw, ' ');
        if (sp) {
            size_t mlen = MIN2((size_t)(sp - raw), sizeof(pkt->http_method)-1);
            memcpy(pkt->http_method, raw, mlen);
            pkt->http_method[mlen] = '\0';
        }
    }
}

/* =========================================================
 *  内部：DNS 字段细粒度解析
 * ========================================================= */
static void parse_dns_fields(ParsedPacket* pkt,
                              struct ndpi_flow_struct* flow)
{
    if (flow && flow->protos.dns.num_queries > 0) {
        pkt->dns_qtype = flow->protos.dns.query_type;
    }

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
 *  内部：RDP 字段细粒度解析
 * ========================================================= */
static void parse_rdp_fields(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 8) return;
    if (p[0] != 0x03) return;

    uint8_t cotp_type = (len >= 6) ? p[5] : 0;
    pkt->rdp_pdu_type = cotp_type;

    const char* channels[] = { "MS_T120", "rdpdr", "rdpsnd", "cliprdr", NULL };
    for (int i = 0; channels[i]; i++) {
        size_t clen = strlen(channels[i]);
        if (len > clen && memmem(p, len, channels[i], clen)) {
            SAFE_COPY(pkt->rdp_channel, channels[i], sizeof(pkt->rdp_channel));
            break;
        }
    }
}

/* =========================================================
 *  内部：DCERPC 字段细粒度解析
 * ========================================================= */
static void parse_dcerpc_fields(ParsedPacket* pkt)
{
    const uint8_t* p   = pkt->payload;
    uint32_t       len = pkt->payload_len;
    if (!p || len < 24) return;
    if (p[0] != 0x05) return;

    pkt->dcerpc_opnum = (uint16_t)(p[22] | ((uint16_t)p[23] << 8));

    if (p[2] == 0x0B && len >= 60) {
        const uint8_t* uuid = p + 44;
        snprintf(pkt->dcerpc_uuid, sizeof(pkt->dcerpc_uuid),
                 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 (unsigned)((uuid[3]<<24)|(uuid[2]<<16)|(uuid[1]<<8)|uuid[0]),
                 (unsigned)((uuid[5]<<8)|uuid[4]),
                 (unsigned)((uuid[7]<<8)|uuid[6]),
                 uuid[8], uuid[9],
                 uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    }
}

/* =========================================================
 *  内部：Kerberos 字段提取（nDPI 提供）
 * ========================================================= */
static void parse_kerberos_fields(ParsedPacket* pkt,
                                   struct ndpi_flow_struct* flow)
{
    if (!flow) return;
    SAFE_COPY(pkt->kerb_hostname, flow->protos.kerberos.hostname,
              sizeof(pkt->kerb_hostname));
    SAFE_COPY(pkt->kerb_domain,   flow->protos.kerberos.domain,
              sizeof(pkt->kerb_domain));
    SAFE_COPY(pkt->kerb_username, flow->protos.kerberos.username,
              sizeof(pkt->kerb_username));
}

/* =========================================================
 *  内部：nDPI 协议 ID 映射到 ProtoType
 * ========================================================= */
static ProtoType ndpi_proto_to_type(uint16_t master, uint16_t sub)
{
    (void)sub;
    switch (master) {
        case NDPI_PROTOCOL_SMBV1:        return PROTO_SMB1;
        case NDPI_PROTOCOL_SMBV23:       return PROTO_SMB2;
        case NDPI_PROTOCOL_HTTP:
        case NDPI_PROTOCOL_HTTP_CONNECT:
        case NDPI_PROTOCOL_HTTP_PROXY:   return PROTO_HTTP;
        case NDPI_PROTOCOL_DNS:
        case NDPI_PROTOCOL_DNSCRYPT:     return PROTO_DNS;
        case NDPI_PROTOCOL_RDP:          return PROTO_RDP;
        case NDPI_PROTOCOL_DCERPC:       return PROTO_DCERPC;
        case NDPI_PROTOCOL_NETBIOS:      return PROTO_NBSS;
        case NDPI_PROTOCOL_KERBEROS:     return PROTO_KERBEROS;
        default:                         return PROTO_UNKNOWN;
    }
}

/* =========================================================
 *  内部：按端口做基础协议推断（nDPI 未识别时的后备）
 * ========================================================= */
static void port_based_fallback(ParsedPacket* pkt,
                                 struct ndpi_flow_struct* flow)
{
    uint16_t dp = pkt->dst_port, sp = pkt->src_port;
    if ((dp == 445 || sp == 445 || dp == 139 || sp == 139)
        && pkt->payload_len >= 4) {
        parse_smb_fields(pkt);
    } else if ((dp == 3389 || sp == 3389) && pkt->payload_len >= 4) {
        pkt->app_proto = PROTO_RDP;
        parse_rdp_fields(pkt);
    } else if ((dp == 135 || sp == 135 || dp == 49152 || sp == 49152)
               && pkt->payload_len >= 16) {
        pkt->app_proto = PROTO_DCERPC;
        parse_dcerpc_fields(pkt);
    } else if ((dp == 53 || sp == 53) && pkt->payload_len >= 12) {
        pkt->app_proto = PROTO_DNS;
        parse_dns_fields(pkt, flow);
    } else if ((dp == 80 || sp == 80 || dp == 8080 || sp == 8080 ||
                dp == 443 || sp == 443 || dp == 8443 || sp == 8443)
               && pkt->payload_len >= 8) {
        pkt->app_proto = PROTO_HTTP;
        parse_http_fields(pkt, flow);
    } else if ((dp == 88 || sp == 88) && pkt->payload_len >= 8) {
        pkt->app_proto = PROTO_KERBEROS;
    }
}

/* =========================================================
 *  PP_ParsePacket — 主入口
 * ========================================================= */
int PP_ParsePacket(
    NdpiContext*    ctx,
    NdpiFlowCtx*    fctx,
    const uint8_t*  raw_data,
    uint32_t        raw_len,
    uint64_t        ts_us,
    ParsedPacket*   out_pkt)
{
    if (!raw_data || raw_len < (uint32_t)sizeof(EthHeader) || !out_pkt) return 0;
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

    if (out_pkt->ether_type == ETHERTYPE_VLAN && ptr + 4 <= end) {
        ptr += 2;
        out_pkt->ether_type = ntohs(*(uint16_t*)ptr);
        ptr += 2;
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

    /* ---- nDPI 应用层协议识别 ---- */
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
        /* nDPI 需要从 IP 头开始的数据 */
        const uint8_t* ip_start = raw_data + sizeof(EthHeader);
        uint16_t etype = ntohs(((const EthHeader*)raw_data)->ether_type);
        if (etype == ETHERTYPE_VLAN) ip_start += 4;
        uint32_t ip_len = (uint32_t)(end - ip_start);

        detected = ndpi_detection_process_packet(
            ctx->ndpi_struct,
            flow,
            ip_start,
            (unsigned short)(ip_len > 65535 ? 65535 : ip_len),
            ts_us / 1000);

        /* 若未确定，尝试 giveup */
        if (detected.master_protocol == NDPI_PROTOCOL_UNKNOWN &&
            detected.app_protocol    == NDPI_PROTOCOL_UNKNOWN) {
            {
                u_int8_t was_guessed = 0;
                detected = ndpi_detection_giveup(ctx->ndpi_struct, flow, 1, &was_guessed);
            }
        }

        if (fctx) {
            fctx->detected_proto      = detected;
            fctx->detection_completed = 1;
        }
    }

    /* 映射 nDPI 协议到 ProtoType */
    uint16_t master = detected.master_protocol;
    uint16_t sub    = detected.app_protocol;
    out_pkt->ndpi_master_proto = master;
    out_pkt->ndpi_sub_proto    = sub;

    if (ctx && ctx->ndpi_struct) {
        ndpi_protocol2name(ctx->ndpi_struct, detected,
                           out_pkt->ndpi_proto_name,
                           sizeof(out_pkt->ndpi_proto_name));
    }

    ProtoType pt = ndpi_proto_to_type(master, sub);
    if (pt == PROTO_UNKNOWN) pt = ndpi_proto_to_type(sub, 0);
    out_pkt->app_proto = pt;

    /* ---- 字段级细粒度解析 ---- */
    switch (pt) {
        case PROTO_SMB1:
        case PROTO_SMB2:
        case PROTO_SMB3_COMPRESS:
            parse_smb_fields(out_pkt);
            break;
        case PROTO_HTTP:
            parse_http_fields(out_pkt, flow);
            break;
        case PROTO_DNS:
            parse_dns_fields(out_pkt, flow);
            break;
        case PROTO_RDP:
            parse_rdp_fields(out_pkt);
            break;
        case PROTO_DCERPC:
            parse_dcerpc_fields(out_pkt);
            break;
        case PROTO_KERBEROS:
            parse_kerberos_fields(out_pkt, flow);
            break;
        default:
            /* nDPI 未识别时，按端口做补充推断 */
            port_based_fallback(out_pkt, flow);
            break;
    }

    if (tmp_fctx) PP_FlowDestroy(tmp_fctx);
    return 1;
}
