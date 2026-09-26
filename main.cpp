// ============================================================================
//  CoJ2ChatFilter.dll  -  v7: explicit-asm calls (no member ptrs, no intrinsics)
//  team-only filter + per-player mute + table-based hook (proven stable)
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
static std::vector<std::string> g_mutes;

static void* g_origFn    = NULL;
static void* g_defString = NULL;

#define VA_DISPLAY_CHAT   0x103436B0
#define VA_TEAM_PREFIX    0x107ED8E8
#define VA_DEF_STRING     0x107ED894

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

// ------------------------------------------------------------- name read ----
// thiscall: ecx=player, args on stack: (engineString* out, engineString* def)
// separate function, no C++ objects -> SEH allowed
static bool ReadName(void* player, char* buf, size_t bufSize)
{
    __try {
        void** vtbl = *(void***)player;
        void* getName = (char*)vtbl + 0x14;
        memset(buf, 0, bufSize);
        __asm {
            mov  ecx, player
            push dword ptr [g_defString]
            mov  eax, buf
            push eax
            mov  edx, getName
            call edx
            
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

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

// ------------------------------------------------------------------ hook ----
// fastcall(ecx=this, edx=param2) reached via the naked stub below
static int __fastcall Hook_Impl(void* self, int param2)
{
    static bool f6Down = false;
    if (GetAsyncKeyState(VK_F6) & 0x8000) { if (!f6Down) { f6Down = true; LoadConfig(); } }
    else f6Down = false;

    unsigned char flags = *(unsigned char*)((char*)self + 0x20);
    bool drop = false;

    if (g_teamOnly && !(flags & 0x01))
        drop = true;

    if (!drop && g_useNames && !g_mutes.empty()) {
        void* player = *(void**)((char*)self + 0x14);
        if (player && !IsBadReadPtr(player, 4)) {
            char buf[32];
            if (ReadName(player, buf, sizeof(buf))) {
                const char* name = *(const char**)&buf[0];
                if (name && (SIZE_T)name > 0x10000 && !IsBadReadPtr(name, 1)) {
                    size_t nl = strnlen(name, 64);
                    if (nl > 0 && nl < 64)
                        for (size_t i = 0; i < g_mutes.size(); ++i)
                            if (_stricmp(g_mutes[i].c_str(), name) == 0) { drop = true; break; }
                }
            }
        }
    }

    if (drop)
        EmptyMessageText(self);

    int ret;
    __asm {
        mov  ecx, self
        push param2
        call dword ptr [g_origFn]
       
        mov  ret, eax
    }
    return ret;
}

// table entries jump here: __thiscall state (ecx=this, [esp+4]=param2)
__declspec(naked) void Hook_DisplayChat()
{
    __asm {
        mov  edx, [esp+4]      // param2
        jmp  Hook_Impl         // fastcall(ecx=this, edx=param2)
    }
}

// ------------------------------------------------------------- install ------
static void Install()
{
    for (int i = 0; i < 120 && !g_hGame; ++i) {
        g_hGame = GetModuleHandleA("CoJ2_x86.dll");
        if (!g_hGame) Sleep(500);
    }
    if (!g_hGame) { Log("ERROR: CoJ2_x86.dll not found"); return; }

    LoadConfig();

    void* sTeam = NULL;
    if (!FindBytes("&ChatTeamModeMsgPrefix&", 24, &sTeam)) {
        Log("ERROR: string not found");
        return;
    }
    ptrdiff_t delta = (char*)sTeam - (char*)VA_TEAM_PREFIX;
    g_origFn    = (char*)VA_DISPLAY_CHAT + delta;
    g_defString = (char*)VA_DEF_STRING + delta;
    Log("base=%p orig=%p def=%p teamonly=%d mutenames=%d mutes=%u",
        g_hGame, g_origFn, g_defString, g_teamOnly, g_useNames, (unsigned)g_mutes.size());

    int patched = 0, skipped = 0;
    for (size_t i = 0; i < sizeof(g_slotVAs)/sizeof(g_slotVAs[0]); ++i) {
        void** slot = (void**)((char*)0 + (ptrdiff_t)g_slotVAs[i] + delta);
        if (!IsBadReadPtr(slot, 4) && *slot == g_origFn) {
            DWORD oldProt;
            if (VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt)) {
                *slot = (void*)&Hook_DisplayChat;
                VirtualProtect(slot, 4, oldProt, &oldProt);
                ++patched;
            } else ++skipped;
        } else ++skipped;
    }
    Log("v7 installed: patched=%d skipped=%d", patched, skipped);
    if (patched == 0) Log("WARNING: hook inactive");
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
