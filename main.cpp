// ============================================================================
//  CoJ2ChatFilter.dll  -  Call of Juarez: Bound in Blood
//  v3: target auto-verification + debug log
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <intrin.h>
#include <vector>
#include <string>
#include "MinHook.h"

static HMODULE g_hModule = NULL;
static HMODULE g_hGame   = NULL;

static int  g_teamOnly   = 0;
static int  g_useNames   = 1;
static int  g_debug      = 0;
static std::vector<std::string> g_mutes;

struct CChatMsg;
struct CNetPlayer;

typedef int  (__thiscall CChatMsg::*DisplayChatMFn)(int param2);
typedef void (__thiscall CNetPlayer::*GetNameMFn)(void* out, const void* def);

// ---------------------------------------------------------------- config ----
static void LoadConfig()
{
    g_mutes.clear();
    g_teamOnly = 0;
    g_useNames = 1;
    g_debug    = 0;

    char path[MAX_PATH];
    GetModuleFileNameA(g_hModule, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) strcpy_s(slash + 1, MAX_PATH - (slash + 1 - path), "chatfilter.ini");

    FILE* f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (_strnicmp(p, "teamonly", 8) == 0) {
            p += 8; while (*p == ' ' || *p == '\t') ++p;
            g_teamOnly = (atoi(p) != 0);
        }
        else if (_strnicmp(p, "mutenames", 9) == 0) {
            p += 9; while (*p == ' ' || *p == '\t') ++p;
            g_useNames = (atoi(p) != 0);
        }
        else if (_strnicmp(p, "debug", 5) == 0) {
            p += 5; while (*p == ' ' || *p == '\t') ++p;
            g_debug = (atoi(p) != 0);
        }
        else if (_strnicmp(p, "mute", 4) == 0) {
            p += 4; while (*p == ' ' || *p == '\t') ++p;
            char* e = p + strlen(p);
            while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) --e;
            *e = 0;
            if (*p) g_mutes.push_back(p);
        }
    }
    fclose(f);
}

static void DbgLog(const char* fmt, ...)
{
    if (!g_debug) return;
    char path[MAX_PATH];
    GetModuleFileNameA(g_hModule, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) strcpy_s(slash + 1, MAX_PATH - (slash + 1 - path), "chatfilter.log");

    FILE* f = NULL;
    if (fopen_s(&f, path, "a") != 0 || !f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// ------------------------------------------------------------------ hook ----
static DisplayChatMFn g_origDisplay = NULL;

static int __fastcall Hook_DisplayChat(void* self, int /*edx_unused*/)
{
    static bool f6Down = false;
    if (GetAsyncKeyState(VK_F6) & 0x8000) { if (!f6Down) { f6Down = true; LoadConfig(); } }
    else f6Down = false;

    int param2 = *(int*)((char*)_AddressOfReturnAddress() + 4);
    unsigned char flags = *(unsigned char*)((char*)self + 0x20);

    DbgLog("hook fired: self=%p flags=%02x", self, flags);

    if (g_teamOnly && !(flags & 0x01))
        return param2;

    if (g_useNames && !g_mutes.empty()) {
        void* player = *(void**)((char*)self + 0x14);
        if (player) {
            void** vtbl = *(void***)player;
            const void* defStr = (const char*)g_hGame + 0x7ED894;
            union { void* p; GetNameMFn m; } u = { NULL };
            u.p = (char*)vtbl + 0x14;
            char strBuf[32];
            memset(strBuf, 0, sizeof(strBuf));
            __try {
                (reinterpret_cast<CNetPlayer*>(player)->*u.m)(strBuf, defStr);
                const char* name = *(const char**)&strBuf[0];
                DbgLog("  nameptr=%p raw=%02x %02x %02x %02x",
                       name, (unsigned char)strBuf[0], (unsigned char)strBuf[1],
                       (unsigned char)strBuf[2], (unsigned char)strBuf[3]);
                if (name && (SIZE_T)name > 0x10000 && !IsBadReadPtr(name, 1)) {
                    size_t nl = strnlen(name, 64);
                    DbgLog("  namelen=%u name='%.*s'", (unsigned)nl,
                           (int)(nl < 32 ? nl : 32), name);
                    if (nl > 0 && nl < 64) {
                        for (size_t i = 0; i < g_mutes.size(); ++i)
                            if (_stricmp(g_mutes[i].c_str(), name) == 0)
                                return param2;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgLog("  EXCEPTION reading name");
            }
        }
    }
    DbgLog("  calling original, param2=%08x", param2);
    int ret = (reinterpret_cast<CChatMsg*>(self)->*g_origDisplay)(param2);
    DbgLog("  original returned %08x", ret);
    return ret;
}

// ------------------------------------------------------------- install ------
#define RVA_DISPLAY_CHAT  0x3436B0
#define RVA_DEF_STRING    0x7ED894

// FUN_103436b0 references &ChatTeamModeMsgPrefix (RVA 0x7ED8E8) within its
// first bytes. Scan for a rel32 that resolves to that address: if absent,
// the target address is WRONG (bad image base) -> do not hook.
static bool VerifyTarget(void* target)
{
    unsigned char* base = (unsigned char*)g_hGame;
    for (int i = 0; i < 0x200 - 4; ++i) {
        DWORD rel = *(DWORD*)((unsigned char*)target + i);
        DWORD instrRva = (DWORD)((unsigned char*)target + i + 4 - base);
        if (instrRva + rel == RVA_DEF_STRING)
            return true;
    }
    return false;
}

static void Install()
{
    for (int i = 0; i < 120 && !g_hGame; ++i) {
        g_hGame = GetModuleHandleA("CoJ2_x86.dll");
        if (!g_hGame) Sleep(500);
    }
    if (!g_hGame) { DbgLog("ERROR: CoJ2_x86.dll not found"); return; }

    LoadConfig();

    void* target = (char*)g_hGame + RVA_DISPLAY_CHAT;
    DbgLog("base=%p target=%p", g_hGame, target);

    if (!VerifyTarget(target)) {
        DbgLog("VERIFY FAILED: target is NOT FUN_103436b0 - image base assumption wrong");
        return;
    }
    DbgLog("VERIFY OK");

    if (MH_Initialize() != MH_OK) { DbgLog("MH_Initialize failed"); return; }
    void* tramp = NULL;
    if (MH_CreateHook(target, &Hook_DisplayChat, &tramp) != MH_OK) { DbgLog("MH_CreateHook failed"); return; }
    if (MH_EnableHook(target) != MH_OK) { DbgLog("MH_EnableHook failed"); return; }

    union { void* p; DisplayChatMFn m; } u = { NULL };
    u.p = tramp;
    g_origDisplay = u.m;

    DbgLog("installed. teamonly=%d mutenames=%d mutes=%u tramp=%p",
           g_teamOnly, g_useNames, (unsigned)g_mutes.size(), tramp);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0,
            [](LPVOID) -> DWORD { Sleep(1000); Install(); return 0; },
            NULL, 0, NULL);
    }
    return TRUE;
}
