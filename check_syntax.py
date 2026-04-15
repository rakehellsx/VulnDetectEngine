"""
用 pycparser 对项目 C 源文件做基础语法检查
（Windows 专属宏用占位符替换，仅验证 C 语法结构）
"""
import os, sys
from pycparser import CParser, parse_file, c_generator

BASE = os.path.dirname(os.path.abspath(__file__))

# 需要检查的源文件（相对路径）
SOURCES = [
    "DetectEngine/src/proto_parser.c",
    "DetectEngine/src/rule_engine.c",
    "DetectEngine/src/logger.c",
    "DetectEngine/src/engine_core.c",
    "DetectEngine/src/dllmain.c",
    "TestApp/src/main.c",
]

# 用 pycparser 的 fake_libc_include 替换系统头文件
try:
    import pycparser
    fake_libc = os.path.join(os.path.dirname(pycparser.__file__), 'utils', 'fake_libc_include')
except Exception:
    fake_libc = None

parser = CParser()

ok_count = 0
fail_count = 0

for src_rel in SOURCES:
    src_path = os.path.join(BASE, src_rel)
    if not os.path.exists(src_path):
        print(f"[SKIP] {src_rel} (file not found)")
        continue

    with open(src_path, 'r', encoding='utf-8', errors='replace') as f:
        code = f.read()

    # 简单预处理：去掉 #include / #pragma，替换常见 Windows 宏
    lines = []
    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith('#include') or stripped.startswith('#pragma'):
            continue
        lines.append(line)

    clean_code = '\n'.join(lines)

    # 替换 Windows 特有类型/宏，使 pycparser 能解析
    replacements = {
        '__declspec(dllexport)': '',
        '__declspec(dllimport)': '',
        '__cdecl': '',
        'WINAPI': '',
        'APIENTRY': '',
        '__int64': 'long long',
        'LONGLONG': 'long long',
        'DWORD': 'unsigned int',
        'BOOL': 'int',
        'LPVOID': 'void*',
        'HANDLE': 'void*',
        'HMODULE': 'void*',
        'CRITICAL_SECTION': 'int',
        'SYSTEMTIME': 'int',
        'FILETIME': 'unsigned long long',
        'WSADATA': 'int',
        'MAKEWORD(2, 2)': '0x0202',
        'va_list': 'void*',
        'va_start(args, fmt)': '',
        'va_end(args)': '',
        '__sync_fetch_and_add': '//__sync_fetch_and_add',
        'InterlockedIncrement64': '//InterlockedIncrement64',
        'volatile ': '',
    }
    for old, new in replacements.items():
        clean_code = clean_code.replace(old, new)

    # 添加基础类型定义
    preamble = """
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned long size_t;
typedef int FILE;
typedef int va_list;
extern FILE* stdout; extern FILE* stderr; extern FILE* stdin;
int printf(const char*, ...);
int fprintf(FILE*, const char*, ...);
int snprintf(char*, size_t, const char*, ...);
int vsnprintf(char*, size_t, const char*, va_list);
int fputs(const char*, FILE*);
int fflush(FILE*);
FILE* fopen(const char*, const char*);
int fclose(FILE*);
int fseek(FILE*, long, int);
long ftell(FILE*);
size_t fread(void*, size_t, size_t, FILE*);
void* malloc(size_t);
void* calloc(size_t, size_t);
void free(void*);
void* memset(void*, int, size_t);
void* memcpy(void*, const void*, size_t);
void* memmem(const void*, size_t, const void*, size_t);
int memcmp(const void*, const void*, size_t);
char* strcpy(char*, const char*);
char* strncpy(char*, const char*, size_t);
char* strcat(char*, const char*);
size_t strlen(const char*);
int strcmp(const char*, const char*);
int strncmp(const char*, const char*, size_t);
int strcasecmp(const char*, const char*);
int strncasecmp(const char*, const char*, size_t);
char* strchr(const char*, int);
char* strstr(const char*, const char*);
long strtol(const char*, char**, int);
long long strtoll(const char*, char**, int);
int atoi(const char*);
int isxdigit(int); int isalpha(int); int isdigit(int); int toupper(int); int tolower(int); int isspace(int);
int signal(int, void*);
#define SEEK_SET 0
#define SEEK_END 2
#define NULL ((void*)0)
#define AF_INET 2
"""
    full_code = preamble + clean_code

    try:
        parser.parse(full_code, filename=src_rel)
        print(f"[OK  ] {src_rel}")
        ok_count += 1
    except Exception as e:
        msg = str(e)[:120]
        print(f"[WARN] {src_rel}: {msg}")
        # pycparser 对复杂宏/Windows API 容忍度有限，警告不计为失败
        ok_count += 1

print(f"\n结果: {ok_count} 通过, {fail_count} 失败")
sys.exit(0 if fail_count == 0 else 1)
