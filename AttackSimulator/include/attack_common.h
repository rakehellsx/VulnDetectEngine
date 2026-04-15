/**
 * @file    attack_common.h
 * @brief   攻击模拟测试程序公共定义
 *
 * 本程序通过原始套接字（Raw Socket）或 TCP/UDP 套接字向目标主机发送
 * 与真实漏洞利用流量高度相似的数据包，用于验证 VulnDetectEngine 的
 * 检测能力。
 *
 * !! 警告 !!
 * 本程序仅供安全研究与检测引擎验证使用，严禁在未经授权的网络或
 * 主机上运行。
 */

#ifndef ATTACK_COMMON_H
#define ATTACK_COMMON_H

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  pragma comment(lib, "ws2_32.lib")
#  define SLEEP_MS(ms)  Sleep(ms)
#  define CLOSE_SOCK(s) closesocket(s)
   typedef SOCKET sock_t;
#  define INVALID_SOCK  INVALID_SOCKET
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <errno.h>
#  define SLEEP_MS(ms)  usleep((ms)*1000)
#  define CLOSE_SOCK(s) close(s)
   typedef int sock_t;
#  define INVALID_SOCK  (-1)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* =========================================================
 *  颜色输出（Windows 控制台）
 * ========================================================= */
#ifdef _WIN32
static inline void set_color(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)color);
}
#define COLOR_RED     (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COLOR_GREEN   (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_YELLOW  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_CYAN    (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_WHITE   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define PRINT_OK(fmt, ...)    do { set_color(COLOR_GREEN);  printf("[PASS] " fmt "\n", ##__VA_ARGS__); set_color(COLOR_WHITE); } while(0)
#define PRINT_FAIL(fmt, ...)  do { set_color(COLOR_RED);    printf("[FAIL] " fmt "\n", ##__VA_ARGS__); set_color(COLOR_WHITE); } while(0)
#define PRINT_INFO(fmt, ...)  do { set_color(COLOR_CYAN);   printf("[INFO] " fmt "\n", ##__VA_ARGS__); set_color(COLOR_WHITE); } while(0)
#define PRINT_SEND(fmt, ...)  do { set_color(COLOR_YELLOW); printf("[SEND] " fmt "\n", ##__VA_ARGS__); set_color(COLOR_WHITE); } while(0)
#else
#define PRINT_OK(fmt, ...)    printf("\033[1;32m[PASS]\033[0m " fmt "\n", ##__VA_ARGS__)
#define PRINT_FAIL(fmt, ...)  printf("\033[1;31m[FAIL]\033[0m " fmt "\n", ##__VA_ARGS__)
#define PRINT_INFO(fmt, ...)  printf("\033[1;36m[INFO]\033[0m " fmt "\n", ##__VA_ARGS__)
#define PRINT_SEND(fmt, ...)  printf("\033[1;33m[SEND]\033[0m " fmt "\n", ##__VA_ARGS__)
#endif

/* =========================================================
 *  测试结果统计
 * ========================================================= */
typedef struct {
    int total;
    int sent;
    int failed;
} TestStats;

static inline void stats_print(const TestStats* s) {
    printf("\n========================================\n");
    printf("  测试汇总: 共 %d 项 | 发送 %d 项 | 失败 %d 项\n",
           s->total, s->sent, s->failed);
    printf("========================================\n\n");
}

/* =========================================================
 *  套接字工具函数
 * ========================================================= */
static inline int net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

static inline void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* 创建 TCP 套接字并连接（非阻塞，超时 timeout_ms） */
static inline sock_t tcp_connect(const char* ip, uint16_t port, int timeout_ms) {
    sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCK) return INVALID_SOCK;

    /* 设置非阻塞 */
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    {
        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(s, (struct sockaddr*)&addr, sizeof(addr));

    /* select 等待连接 */
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int ret = select((int)s + 1, NULL, &wfds, NULL, &tv);

    /* 恢复阻塞 */
#ifdef _WIN32
    mode = 0;
    ioctlsocket(s, FIONBIO, &mode);
#else
    {
        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
    }
#endif

    if (ret <= 0) { CLOSE_SOCK(s); return INVALID_SOCK; }
    return s;
}

/* 创建 UDP 套接字 */
static inline sock_t udp_socket(void) {
    return socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

/* UDP 发送 */
static inline int udp_send(sock_t s, const char* ip, uint16_t port,
                            const uint8_t* data, int len) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    return (int)sendto(s, (const char*)data, len, 0,
                       (struct sockaddr*)&addr, sizeof(addr));
}

/* TCP 发送全部数据 */
static inline int tcp_send_all(sock_t s, const uint8_t* data, int len) {
    int sent = 0;
    while (sent < len) {
        int r = (int)send(s, (const char*)data + sent, len - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return sent;
}

/* TCP 接收（最多 buf_len 字节，超时 timeout_ms） */
static inline int tcp_recv(sock_t s, uint8_t* buf, int buf_len, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int ret = select((int)s + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return 0;
    return (int)recv(s, (char*)buf, buf_len, 0);
}

/* 打印十六进制转储 */
static inline void hex_dump(const uint8_t* data, int len, int max_bytes) {
    int show = len < max_bytes ? len : max_bytes;
    for (int i = 0; i < show; i++) printf("%02X ", data[i]);
    if (len > max_bytes) printf("...");
    printf("\n");
}

#endif /* ATTACK_COMMON_H */
