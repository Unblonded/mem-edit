// veh_agent.dll - injected into the target by mem-edit's VEH debugger.
//
// Two watchpoint methods, both handled by a vectored exception handler *inside* the target, so no
// Windows debugger is ever attached:
//
//   mode 0  hardware   - arms the CPU debug registers DR0-DR3. Fast and exact, but the DR values
//                        are visible to anti-debug that scans them.
//   mode 1  page-guard - marks the watched value's page PAGE_GUARD and catches the access fault.
//                        Touches no debug registers, so DR-scanning protections can't see it; the
//                        cost is that every access to that page faults.
//
// Either way, hits (faulting instruction pointer + registers) are streamed to the host through the
// shared block.
#include "code/veh_ipc.h"

#include <windows.h>
#include <tlhelp32.h>

using namespace vehipc;

#ifndef STATUS_GUARD_PAGE_VIOLATION
#define STATUS_GUARD_PAGE_VIOLATION ((DWORD)0x80000001L)
#endif

static Block* g_block = nullptr;
static PVOID g_veh = nullptr;
static DWORD g_agentTid = 0;
static DWORD g_mode = 0;
static DWORD g_tls = TLS_OUT_OF_INDEXES; // per-thread "re-arm the guard on the next single step"
static SIZE_T g_pageSize = 0x1000;

static CRITICAL_SECTION g_cs;            // guards the page-guard bookkeeping below
struct GuardPage
{
    uint64_t base = 0;   // page base address in the target
    DWORD orig = 0;      // protection to restore (without PAGE_GUARD)
    bool active = false;
};
static GuardPage g_guards[kSlots * 2];   // each slot can straddle two pages

// ---------------------------------------------------------------------------
// Hardware (DR) mode.

static void ArmThreadDR(HANDLE th)
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(th, &ctx)) return;

    DWORD64 dr[4] = {};
    DWORD64 dr7 = 0;
    if (g_mode == 0) // only populate DRs in hardware mode; page-guard mode leaves them clear
    {
        for (int i = 0; i < kSlots; i++)
        {
            const Slot& s = g_block->slots[i];
            if (!s.active) continue;
            dr[i] = s.address;
            DWORD64 rw = s.kind == 0 ? 1 : 3;
            DWORD64 len = s.size == 1 ? 0 : s.size == 2 ? 1 : s.size == 8 ? 2 : 3;
            dr7 |= 1ull << (i * 2);
            dr7 |= (rw << (16 + i * 4)) | (len << (18 + i * 4));
        }
    }
    ctx.Dr0 = dr[0];
    ctx.Dr1 = dr[1];
    ctx.Dr2 = dr[2];
    ctx.Dr3 = dr[3];
    ctx.Dr6 = 0;
    ctx.Dr7 = dr7;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(th, &ctx);
}

static void ArmAllThreads()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    DWORD pid = GetCurrentProcessId();
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == g_agentTid) continue;
            HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE,
                                   te.th32ThreadID);
            if (!th) continue;
            if (SuspendThread(th) != (DWORD)-1)
            {
                ArmThreadDR(th);
                ResumeThread(th);
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// ---------------------------------------------------------------------------
// Page-guard mode.

static void ClearGuards()
{
    for (auto& g : g_guards)
    {
        if (!g.active) continue;
        DWORD old = 0;
        VirtualProtect((LPVOID)g.base, g_pageSize, g.orig, &old);
        g.active = false;
    }
}

static void AddGuardPage(uint64_t pageBase)
{
    for (auto& g : g_guards) // already tracked?
        if (g.active && g.base == pageBase) return;
    for (auto& g : g_guards)
    {
        if (g.active) continue;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)pageBase, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return;
        DWORD orig = mbi.Protect & ~PAGE_GUARD;
        DWORD old = 0;
        if (!VirtualProtect((LPVOID)pageBase, g_pageSize, orig | PAGE_GUARD, &old)) return;
        g.base = pageBase;
        g.orig = orig;
        g.active = true;
        return;
    }
}

static void SetupGuards()
{
    ClearGuards();
    for (int i = 0; i < kSlots; i++)
    {
        const Slot& s = g_block->slots[i];
        if (!s.active) continue;
        uint64_t first = s.address & ~(uint64_t)(g_pageSize - 1);
        uint64_t last = (s.address + (s.size ? s.size - 1 : 0)) & ~(uint64_t)(g_pageSize - 1);
        AddGuardPage(first);
        if (last != first) AddGuardPage(last);
    }
}

static void RearmGuards()
{
    for (auto& g : g_guards)
    {
        if (!g.active) continue;
        DWORD old = 0;
        VirtualProtect((LPVOID)g.base, g_pageSize, g.orig | PAGE_GUARD, &old);
    }
}

static bool IsGuardedPage(uint64_t pageBase)
{
    for (auto& g : g_guards)
        if (g.active && g.base == pageBase) return true;
    return false;
}

// ---------------------------------------------------------------------------

static void RecordHit(int slot, CONTEXT* c)
{
    uint32_t seq = (uint32_t)InterlockedIncrement((volatile LONG*)&g_block->hitSeq);
    Hit& h = g_block->hits[(seq - 1) % kMaxHits];
    h.ip = c->Rip;
    const DWORD64 gp[16] = { c->Rax, c->Rcx, c->Rdx, c->Rbx, c->Rsp, c->Rbp, c->Rsi, c->Rdi,
                             c->R8,  c->R9,  c->R10, c->R11, c->R12, c->R13, c->R14, c->R15 };
    for (int g = 0; g < 16; g++) h.gp[g] = gp[g];
    h.flags = c->EFlags;
    h.slot = (uint32_t)slot;
}

static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* ep)
{
    if (!g_block) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (g_mode == 0) // hardware: our data breakpoints raise a single-step with DR6 bits set
    {
        if (code != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
        DWORD64 bits = c->Dr6 & 0xF;
        if (!bits) return EXCEPTION_CONTINUE_SEARCH;
        for (int i = 0; i < kSlots; i++)
            if (bits & (1ull << i)) RecordHit(i, c);
        c->Dr6 = 0;
        c->EFlags |= 0x10000; // RF
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // page-guard mode -------------------------------------------------------
    if (code == STATUS_GUARD_PAGE_VIOLATION)
    {
        uint64_t accessAddr = ep->ExceptionRecord->ExceptionInformation[1];
        ULONG_PTR accessType = ep->ExceptionRecord->ExceptionInformation[0]; // 0 read, 1 write, 8 exec
        uint64_t pageBase = accessAddr & ~(uint64_t)(g_pageSize - 1);

        EnterCriticalSection(&g_cs);
        bool ours = IsGuardedPage(pageBase);
        if (ours)
        {
            for (int i = 0; i < kSlots; i++)
            {
                const Slot& s = g_block->slots[i];
                if (!s.active) continue;
                if (accessAddr < s.address || accessAddr >= s.address + s.size) continue; // other data on the page
                bool wantWrite = (s.kind == 0);
                if (wantWrite && accessType != 1) continue;     // writes-only, this was a read
                if (accessType == 8) continue;                  // ignore instruction fetches
                RecordHit(i, c);
            }
        }
        LeaveCriticalSection(&g_cs);

        if (!ours) return EXCEPTION_CONTINUE_SEARCH; // e.g. the OS's own stack-growth guard page

        // The fault auto-cleared PAGE_GUARD on the page. Let the instruction re-run, then re-arm the
        // guard on the following single step.
        c->EFlags |= 0x100; // TF
        if (g_tls != TLS_OUT_OF_INDEXES) TlsSetValue(g_tls, (LPVOID)1);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == EXCEPTION_SINGLE_STEP)
    {
        if (g_tls != TLS_OUT_OF_INDEXES && TlsGetValue(g_tls))
        {
            TlsSetValue(g_tls, (LPVOID)0);
            EnterCriticalSection(&g_cs);
            RearmGuards();
            LeaveCriticalSection(&g_cs);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH; // the target's own single step
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Apply the current config: pick the mode, clear the other method, arm the chosen one.
static void ApplyConfig()
{
    DWORD newMode = g_block->mode;
    EnterCriticalSection(&g_cs);
    if (newMode != g_mode)
    {
        // Switching methods: tear down the old one first.
        if (g_mode == 1) ClearGuards();
        g_mode = newMode;
        if (g_mode == 0) { LeaveCriticalSection(&g_cs); ArmAllThreads(); return; }
    }
    if (g_mode == 1) SetupGuards();
    LeaveCriticalSection(&g_cs);
    if (g_mode == 0) ArmAllThreads(); // hardware mode also needs new threads armed
}

static DWORD WINAPI AgentMain(LPVOID)
{
    g_agentTid = GetCurrentThreadId();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    g_pageSize = si.dwPageSize ? si.dwPageSize : 0x1000;
    g_tls = TlsAlloc();
    InitializeCriticalSection(&g_cs);

    wchar_t name[64];
    MappingName(GetCurrentProcessId(), name, 64);

    HANDLE map = nullptr;
    for (int tries = 0; tries < 200 && !map; tries++)
    {
        map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!map) Sleep(10);
    }
    if (!map) return 0;

    Block* b = (Block*)MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Block));
    if (!b || b->magic != kMagic) { if (b) UnmapViewOfFile(b); CloseHandle(map); return 0; }
    g_block = b;
    g_mode = b->mode;

    g_veh = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_veh) { UnmapViewOfFile(b); CloseHandle(map); g_block = nullptr; return 0; }

    ApplyConfig();
    b->appliedGen = b->configGen;
    b->agentReady = 1;

    int sinceRescan = 0;
    while (!b->stop)
    {
        if (b->configGen != b->appliedGen)
        {
            ApplyConfig();
            b->appliedGen = b->configGen;
        }
        else if (g_mode == 0 && ++sinceRescan >= 12) // ~250ms: catch new threads (hardware mode only)
        {
            ArmAllThreads();
            sinceRescan = 0;
        }
        Sleep(20);
    }

    EnterCriticalSection(&g_cs);
    ClearGuards();
    for (int i = 0; i < kSlots; i++) b->slots[i].active = 0;
    g_mode = 0;
    LeaveCriticalSection(&g_cs);
    ArmAllThreads(); // clear debug registers
    RemoveVectoredExceptionHandler(g_veh);
    g_veh = nullptr;
    g_block = nullptr;
    UnmapViewOfFile(b);
    CloseHandle(map);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(mod);
        HANDLE t = CreateThread(nullptr, 0, AgentMain, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
