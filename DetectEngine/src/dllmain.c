/**
 * @file    dllmain.c
 * @brief   DLL 入口点
 *          负责 WinSock 初始化/清理，以及 DLL 加载/卸载通知。
 */

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD   ul_reason_for_call,
    LPVOID  lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        {
            /* 初始化 WinSock（pcap 依赖） */
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
            /* 禁用线程通知以提升性能 */
            DisableThreadLibraryCalls(hModule);
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            WSACleanup();
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default:
            break;
    }
    return TRUE;
}

#endif /* _WIN32 */
