// ============================================================================
//  CoJ2ChatFilter.dll  -  Call of Juarez: Bound in Blood
//  Client-side chat filter: mute by player name + team-only mode
//
//  Target : CoJ2_x86.dll  (32-bit)
//  Hook   : FUN_103436b0  (RVA = 0x103436B0 - image base, see below)
//           The "format & display chat line" handler. The net message object
//           ('this') layout decoded from the decompiled function:
//             +0x14 : player object (vtable[+0x14] = GetName(engineString*, def))
//             +0x20 : mode flags  0x01 = TEAM, 0x10 = inactive, 0x20 = dead
//             +0x24 : message text
//             +0x99 : processed flag
//
//  Build  : Visual Studio, Win32 (x86!), Release, static runtime (/MT)
//           Add MinHook (minhook.c/.h) to the project.
//  Inject : any x86 DLL injector into CoJBiBGame_x86.exe AFTER the game
//           started (the dll waits for CoJ2_x86.dll and retries).
//  Config : chatfilter.ini next to this dll:
//             teamonly 1        -> show only team messages
//             mute SomePlayer   -> hide all messages from SomePlayer
//             mutenames 1       -> enable name-based muting (0 = flags only)
//           Press F6 in-game to reload the config.
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include "MinHook.h"

static HMODULE g_hModule = NULL;
static HMODULE g_hGame   = NULL;

static int  g_teamOnly   = 0;
static int  g_useNames   = 1;
static std::vector<std::string> g_mutes;

// ---------------------------------------------------------------- config ----
static void LoadConfig()
{
    g_mutes.clear();
    g_teamOnly = 0;
    g_useNames = 1;

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

// ----------------------------------------------------------------- hook -----
typedef int (__thiscall *DisplayChatFn)(void* self, int param2);
static DisplayChatFn g_origDisplay = NULL;

static int __thiscall Hook_DisplayChat(void* self, int param2)
{
    // F6 = reload config
    static bool f6Down = false;
    if (GetAsyncKeyState(VK_F6) & 0x8000) { if (!f6Down) { f6Down = true; LoadConfig(); } }
    else f6Down = false;

    unsigned char flags = *(unsigned char*)((char*)self + 0x20);
    if (g_teamOnly && !(flags & 0x01))
        return param2;                                  // not a team message -> drop

    if (g_useNames && !g_mutes.empty()) {
        void* player = *(void**)((char*)self + 0x14);
        if (player) {
            void** vtbl = *(void***)player;
            // vtable[5] (+0x14): GetName(engineString* out, const char* def)
            typedef void (__thiscall *GetNameFn)(void*, void*, const char*);
            GetNameFn getName = (GetNameFn)((char*)vtbl + 0x14);

            char strBuf[16];
            memset(strBuf, 0, sizeof(strBuf));
            __try {
                getName(player, strBuf, "");
                const char* name = *(const char**)&strBuf[0];
                if (name && (SIZE_T)name > 0x10000 && !IsBadReadPtr(name, 1)) {
                    size_t nl = strnlen(name, 64);
                    if (nl > 0 && nl < 64) {
                        for (size_t i = 0; i < g_mutes.size(); ++i) {
                            if (_stricmp(g_mutes[i].c_str(), name) == 0)
                                return param2;          // muted player -> drop
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { /* name read failed: show msg */ }
        }
    }
    return g_origDisplay(self, param2);
}

// ------------------------------------------------------------- install ------
// IMPORTANT: verify the image base in Ghidra (Program -> Memory / headers).
// Default Chrome Engine dll base is 0x10000000, so the RVA of FUN_103436b0 is:
#define RVA_DISPLAY_CHAT  0x3436B0   // = 0x103436B0 - 0x10000000

static void Install()
{
    // wait until the game module is loaded (max ~60 s)
    for (int i = 0; i < 120 && !g_hGame; ++i) {
        g_hGame = GetModuleHandleA("CoJ2_x86.dll");
        if (!g_hGame) Sleep(500);
    }
    if (!g_hGame) return;

    void* target = (char*)g_hGame + RVA_DISPLAY_CHAT;

    LoadConfig();

    if (MH_Initialize() != MH_OK) return;
    if (MH_CreateHook(target, &Hook_DisplayChat, (void**)&g_origDisplay) != MH_OK) return;
    if (MH_EnableHook(target) != MH_OK) return;
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
