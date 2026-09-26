// ============================================================================
//  CoJ2ChatFilter.dll - MINIMAL PASSTROUGH TEST
//  Naked jmp hook: zero C++ in the interception path.
//  If this still crashes -> table patching is the problem.
//  If stable -> the C++ hook body was the problem.
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static HMODULE g_hModule = NULL;
static HMODULE g_hGame   = NULL;
static void*   g_origFn  = NULL;

#define VA_DISPLAY_CHAT   0x103436B0
#define VA_TEAM_PREFIX    0x107ED8E8

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

static void Log(const char* fmt, ...)
{
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

// THE HOOK: a naked indirect jump to the original function.
// ECX (this), the stack, every register: untouched.
__declspec(naked) void Hook_Naked()
{
    __asm {
        jmp dword ptr [g_origFn]
    }
}

static void Install()
{
    for (int i = 0; i < 120 && !g_hGame; ++i) {
        g_hGame = GetModuleHandleA("CoJ2_x86.dll");
        if (!g_hGame) Sleep(500);
    }
    if (!g_hGame) { Log("ERROR: CoJ2_x86.dll not found"); return; }

    void* sTeam = NULL;
    if (!FindBytes("&ChatTeamModeMsgPrefix&", 24, &sTeam)) {
        Log("ERROR: string not found");
        return;
    }
    ptrdiff_t delta = (char*)sTeam - (char*)VA_TEAM_PREFIX;
    g_origFn = (char*)VA_DISPLAY_CHAT + delta;
    Log("base=%p orig=%p", g_hGame, g_origFn);

    int patched = 0, skipped = 0;
    for (size_t i = 0; i < sizeof(g_slotVAs)/sizeof(g_slotVAs[0]); ++i) {
        void** slot = (void**)((char*)0 + (ptrdiff_t)g_slotVAs[i] + delta);
        if (!IsBadReadPtr(slot, 4) && *slot == g_origFn) {
            DWORD oldProt;
            if (VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt)) {
                *slot = (void*)&Hook_Naked;
                VirtualProtect(slot, 4, oldProt, &oldProt);
                ++patched;
            } else ++skipped;
        } else ++skipped;
    }
    Log("MINIMAL TEST installed: patched=%d skipped=%d", patched, skipped);
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
