// ============================================================================
//  CoJ2ChatFilter.dll  -  Call of Juarez: Bound in Blood
//  v6: hook via function-pointer table patching (no code patch, no MinHook)
//      drop = empty message text; original always runs intact
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <vector>
#include <string>

static HMODULE g_hModule = NULL;
static HMODULE g_hGame   = NULL;

static int  g_teamOnly   = 0;
static int  g_useNames   = 1;
static int  g_debug      = 0;
static std::vector<std::string> g_mutes;

#define VA_DISPLAY_CHAT   0x103436B0
#define VA_TEAM_PREFIX    0x107ED8E8
#define VA_DEF_STRING     0x107ED894

// function-pointer table slots that point to FUN_103436b0 (from Ghidra xrefs)
static const DWORD g_slotVAs[] = {
    0x107702e4, 0x10797af4, 0x107d3644,
    0x107de5e4, 0x107de714, 0x107de844, 0x107de974, 0x107deaa4,
    0x107debd4, 0x107ded04, 0x107dee34, 0x107def64, 0x107df094,
    0x107df1c4, 0x107df2f4, 0x107df424, 0x107df554,
    0x107e10e4, 0x107e24c4, 0x107e42dc, 0x107e440c,
    0x107e4ac4, 0x107e4bf4, 0x107e4d24,
    0x107e6f0c, 0x107e7964,
    0x107e8eb4, 0x107e8fe4, 0x107e9114,
    0x107edbb4
};

static void* g_origFn    = NULL;
static void* g_defString = NULL;

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

// ------------------------------------------------------- module scanning ----
static size_t ModuleSize(HMODULE h)
{
    MEMORY_BASIC_INFORMATION mbi;
    size_t size = 0;
    unsigned char* p = (unsigned char*)h;
    while (VirtualQuery(p, &mbi, sizeof(mbi)) && mbi.AllocationBase == (void*)h) {
        size += mbi.RegionSize;
        p += mbi.RegionSize;
    }
    return size;
}

static bool FindBytes(const char* pattern, size_t len, void** out)
{
    unsigned char* start = (unsigned char*)g_hGame;
    unsigned char* end = start + ModuleSize(g_hGame);
    unsigned char* p = start;
    while (p + len < end) {
        p = (unsigned char*)memchr(p, (unsigned char)pattern[0], end - p - len);
        if (!p) return false;
        if (memcmp(p, pattern, len) == 0) { *out = p; return true; }
        ++p;
    }
    return false;
}

// ------------------------------------------------------------------ hook ----
static void EmptyMessageText(void* self)
{
    __try {
        char** txtPtr = (char**)((char*)self + 0x24);
        if (!IsBadReadPtr(txtPtr, 4)) {
            char* txt = *txtPtr;
            if (txt && (SIZE_T)txt > 0x10000 && !IsBadReadPtr(txt, 1))
                txt[0] = 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// called via table pointers with __thiscall: ECX = this, [ESP+4] = param2
static int __fastcall Hook_DisplayChat(void* self, int /*edx_unused*/)
{
    static bool f6Down = false;
    if (GetAsyncKeyState(VK_F6) & 0x8000) { if (!f6Down) { f6Down = true; LoadConfig(); } }
    else f6Down = false;

    unsigned char flags = *(unsigned char*)((char*)self + 0x20);
    int param2 = *(int*)((char*)_AddressOfReturnAddress() + 4);
    bool drop = false;

    if (g_teamOnly && !(flags & 0x01))
        drop = true;

    if (!drop && g_useNames && !g_mutes.empty()) {
        void* player = *(void**)((char*)self + 0x14);
        if (player && !IsBadReadPtr(player, 4)) {
            void** vtbl = *(void***)player;
            if (vtbl && !IsBadReadPtr(vtbl, 4)) {
                union { void* p; GetNameMFn m; } u = { NULL };
                u.p = (char*)vtbl + 0x14;
                char strBuf[32];
                memset(strBuf, 0, sizeof(strBuf));
                __try {
                    (reinterpret_cast<CNetPlayer*>(player)->*u.m)(strBuf, g_defString);
                    const char* name = *(const char**)&strBuf[0];
                    DbgLog("hook: flags=%02x nameptr=%p", flags, name);
                    if (name && (SIZE_T)name > 0x10000 && !IsBadReadPtr(name, 1)) {
                        size_t nl = strnlen(name, 64);
                        DbgLog("  name='%.*s'", (int)(nl < 32 ? nl : 32), name);
                        if (nl > 0 && nl < 64)
                            for (size_t i = 0; i < g_mutes.size(); ++i)
                                if (_stricmp(g_mutes[i].c_str(), name) == 0) { drop = true; break; }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgLog("  EXCEPTION reading name");
                }
            }
        }
    }
    else {
        DbgLog("hook: flags=%02x", flags);
    }

    if (drop) {
        DbgLog("  -> DROPPED (emptied)");
        EmptyMessageText(self);
    }

    union { void* p; DisplayChatMFn m; } uo = { NULL };
    uo.p = g_origFn;
    return (reinterpret_cast<CChatMsg*>(self)->*uo.m)(param2);
}

// ------------------------------------------------------------- install ------
static void Install()
{
    for (int i = 0; i < 120 && !g_hGame; ++i) {
        g_hGame = GetModuleHandleA("CoJ2_x86.dll");
        if (!g_hGame) Sleep(500);
    }
    if (!g_hGame) { DbgLog("ERROR: CoJ2_x86.dll not found"); return; }

    LoadConfig();

    void* sTeam = NULL;
    if (!FindBytes("&ChatTeamModeMsgPrefix&", 24, &sTeam)) {
        DbgLog("ERROR: team prefix string not found in module");
        return;
    }
    ptrdiff_t delta = (char*)sTeam - (char*)VA_TEAM_PREFIX;
    g_origFn    = (char*)VA_DISPLAY_CHAT + delta;
    g_defString = (char*)VA_DEF_STRING + delta;
    DbgLog("base=%p found=%p delta=%+d orig=%p", g_hGame, sTeam, (int)delta, g_origFn);

    // patch every table slot that currently points to the original function
    int patched = 0, skipped = 0;
    for (size_t i = 0; i < sizeof(g_slotVAs)/sizeof(g_slotVAs[0]); ++i) {
        void** slot = (void**)((char*)g_hGame + (ptrdiff_t)g_slotVAs[i] + delta - 0x10000000);
        // note: slotVAs are Ghidra VAs with base 0x10000000 baked in -> convert to RVA
        // (delta already accounts for the runtime base difference)
        slot = (void**)((char*)0 + (ptrdiff_t)g_slotVAs[i] + delta);
        if (!IsBadReadPtr(slot, 4) && *slot == g_origFn) {
            DWORD oldProt;
            if (VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt)) {
                *slot = (void*)&Hook_DisplayChat;
                VirtualProtect(slot, 4, oldProt, &oldProt);
                ++patched;
            }
            else ++skipped;
        }
        else ++skipped;
    }
    DbgLog("installed: slots patched=%d skipped=%d teamonly=%d mutenames=%d mutes=%u",
           patched, skipped, g_teamOnly, g_useNames, (unsigned)g_mutes.size());
    if (patched == 0) DbgLog("WARNING: no slots patched - hook inactive!");
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
