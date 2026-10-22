#include "code/tracer.h"
#include "core/values.h"

#include <Zydis/Zydis.h>

#include <tlhelp32.h>
#include <algorithm>
#include <cstring>

#ifndef STATUS_WX86_SINGLE_STEP
#define STATUS_WX86_SINGLE_STEP ((DWORD)0x4000001EL)
#endif
#ifndef STATUS_WX86_BREAKPOINT
#define STATUS_WX86_BREAKPOINT ((DWORD)0x4000001FL)
#endif

const char* TraceRegName(int i, bool is64)
{
    static const char* r64[] = { "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
                                 "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15" };
    static const char* r32[] = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
    if (is64) return i < 16 ? r64[i] : "?";
    return i < 8 ? r32[i] : "?";
}

int AccessTracer::Add(DWORD pid, bool is64, uint64_t address, int size, TraceKind kind, std::string& error)
{
    // A different process (or a stopped session) needs a fresh debugger thread.
    if (m_thread.joinable() && (!m_running || pid != m_pid)) Shutdown();

    int slot = -1;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (int i = 0; i < kSlots; i++)
        {
            if (!m_slots[i].used)
            {
                slot = i;
                break;
            }
        }
        if (slot < 0)
        {
            error = "All 4 hardware breakpoints are in use. Close a trace window first.";
            return -1;
        }
        // Hardware watchpoints must be 1, 2, 4 or 8 bytes and naturally aligned.
        int len = 8;
        while (len > 1 && (len > size || address % len != 0)) len /= 2;
        Slot& s = m_slots[slot];
        s = Slot{};
        s.used = true;
        s.address = address;
        s.size = len;
        s.kind = kind;
        m_error.clear();
    }
    m_dirty = true;

    if (!m_thread.joinable())
    {
        m_pid = pid;
        m_is64 = is64;
        m_stop = false;
        m_running = true;
        m_thread = std::thread([this]() { Run(); });
    }
    return slot;
}

void AccessTracer::Remove(int slot)
{
    if (slot < 0 || slot >= kSlots) return;
    bool any = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_slots[slot] = Slot{};
        for (const auto& s : m_slots) any |= s.used;
    }
    m_dirty = true;
    if (!any) Shutdown(); // detach once nothing is being watched
}

void AccessTracer::Clear(int slot)
{
    if (slot < 0 || slot >= kSlots) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_slots[slot].hits.clear();
}

std::vector<TraceHit> AccessTracer::Hits(int slot) const
{
    std::vector<TraceHit> out;
    if (slot < 0 || slot >= kSlots) return out;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [ip, h] : m_slots[slot].hits) out.push_back(h);
    std::sort(out.begin(), out.end(), [](const TraceHit& a, const TraceHit& b) { return a.address < b.address; });
    return out;
}

std::string AccessTracer::Error() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_error;
}

void AccessTracer::Shutdown()
{
    m_stop = true;
    if (m_thread.joinable()) m_thread.join();
    m_running = false;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& s : m_slots) s = Slot{};
}

// ---------------------------------------------------------------------------
// Debugger thread. Every Debug API call must happen on this one thread.

void AccessTracer::ApplyToThread(HANDLE thread)
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return;

    DWORD64 dr[4] = {};
    DWORD64 dr7 = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (int i = 0; i < kSlots; i++)
        {
            const Slot& s = m_slots[i];
            if (!s.used) continue;
            dr[i] = s.address;
            DWORD64 rw = s.kind == TraceKind::Writes ? 1 : 3; // 01 = write, 11 = read/write
            DWORD64 len = s.size == 1 ? 0 : s.size == 2 ? 1 : s.size == 8 ? 2 : 3;
            dr7 |= 1ull << (i * 2);                         // local enable
            dr7 |= (rw << (16 + i * 4)) | (len << (18 + i * 4));
        }
    }
    ctx.Dr0 = dr[0];
    ctx.Dr1 = dr[1];
    ctx.Dr2 = dr[2];
    ctx.Dr3 = dr[3];
    ctx.Dr6 = 0;
    ctx.Dr7 = dr7;
    SetThreadContext(thread, &ctx);
}

void AccessTracer::ApplyAll(bool suspend)
{
    for (auto& [tid, h] : m_threads)
    {
        if (suspend && SuspendThread(h) == (DWORD)-1) continue;
        ApplyToThread(h);
        if (suspend) ResumeThread(h);
    }
}

TraceHit DecodeTraceHit(HANDLE process, bool is64, uint64_t ipAfter, const TraceRegs& regs,
                        uint64_t watched, int watchedSize, bool ipIsStart)
{
    TraceHit hit;
    hit.regs = regs;

    // Page-guard faults point the ip at the faulting instruction itself: decode it directly.
    if (ipIsStart)
    {
        uint8_t ib[16] = {};
        SIZE_T g = 0;
        ReadProcessMemory(process, (LPCVOID)ipAfter, ib, sizeof(ib), &g);
        hit.address = ipAfter;
        ZydisDecoder d2;
        if (is64) ZydisDecoderInit(&d2, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        else ZydisDecoderInit(&d2, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (g > 0 && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&d2, ib, g, &ins, ops)))
        {
            hit.length = ins.length;
            hit.bytes.assign(ib, ib + ins.length);
            ZydisFormatter fmt;
            ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterSetProperty(&fmt, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
            char text[256];
            if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &ins, ops, ins.operand_count_visible, text,
                                                             sizeof(text), hit.address, nullptr)))
                hit.text = text;
            else
                hit.text = BytesToHex(hit.bytes.data(), hit.bytes.size());
        }
        else
            hit.text = "(could not decode)";
        return hit;
    }

    // The CPU reports data breakpoints *after* the instruction ran, so search
    // backwards for the instruction that ends exactly at ipAfter.
    uint8_t buf[16] = {};
    SIZE_T got = 0;
    uint64_t from = ipAfter >= 15 ? ipAfter - 15 : 0;
    size_t span = (size_t)(ipAfter - from);
    ReadProcessMemory(process, (LPCVOID)from, buf, span, &got);
    if (got != span)
    {
        // Partially unreadable (start of a page): only use the readable tail.
        memset(buf, 0, sizeof(buf));
        for (size_t k = 1; k <= span; k++)
        {
            SIZE_T g = 0;
            if (!ReadProcessMemory(process, (LPCVOID)(ipAfter - k), buf + span - k, k, &g) || g != k) break;
            got = k;
        }
        from = ipAfter - got;
        memmove(buf, buf + (span - got), got);
        span = got;
    }

    ZydisDecoder dec;
    if (is64) ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    else ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

    ZydisRegisterContext rc{};
    for (int i = 0; i < 16; i++)
    {
        rc.values[ZYDIS_REGISTER_RAX + i] = regs.gp[i];
        if (i < 8) rc.values[ZYDIS_REGISTER_EAX + i] = regs.gp[i] & 0xFFFFFFFF;
        else rc.values[ZYDIS_REGISTER_R8D + (i - 8)] = regs.gp[i] & 0xFFFFFFFF;
    }

    int bestScore = -1, bestLen = 0;
    ZydisDecodedInstruction best{};
    ZydisDecodedOperand bestOps[ZYDIS_MAX_OPERAND_COUNT];
    for (size_t k = 1; k <= span; k++)
    {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        const uint8_t* p = buf + span - k;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, k, &ins, ops)) || ins.length != k) continue;
        uint64_t insAddr = ipAfter - k;
        int score = 0;
        for (int o = 0; o < ins.operand_count_visible; o++)
        {
            if (ops[o].type != ZYDIS_OPERAND_TYPE_MEMORY || ops[o].mem.type == ZYDIS_MEMOP_TYPE_AGEN) continue;
            score = std::max(score, 1);
            ZyanU64 ea = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(&ins, &ops[o], insAddr, &rc, &ea)) &&
                ea < watched + watchedSize && ea + ops[o].size / 8 > watched)
                score = 2; // its memory operand really points at the watched bytes
        }
        if (ins.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) score = std::max(score, 1);
        if (score > bestScore)
        {
            bestScore = score;
            bestLen = (int)k;
            best = ins;
            memcpy(bestOps, ops, sizeof(ops));
        }
    }

    if (bestLen == 0)
    {
        hit.address = ipAfter;
        hit.text = "(could not decode)";
        return hit;
    }
    hit.address = ipAfter - bestLen;
    hit.length = bestLen;
    hit.bytes.assign(buf + span - bestLen, buf + span);

    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&fmt, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
    char text[256];
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &best, bestOps, best.operand_count_visible, text,
                                                     sizeof(text), hit.address, nullptr)))
        hit.text = text;
    else
        hit.text = BytesToHex(hit.bytes.data(), hit.bytes.size());
    return hit;
}

void AccessTracer::Record(int slot, const TraceRegs& regs)
{
    uint64_t watched;
    int size;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Slot& s = m_slots[slot];
        if (!s.used) return;
        auto it = s.hits.find(regs.ip);
        if (it != s.hits.end())
        {
            it->second.count++;
            it->second.regs = regs;
            return;
        }
        watched = s.address;
        size = s.size;
    }
    // First time this instruction fires: disassemble outside the lock.
    TraceHit hit = DecodeTraceHit(m_process, m_is64, regs.ip, regs, watched, size);
    hit.count = 1;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_slots[slot].used) m_slots[slot].hits.emplace(regs.ip, std::move(hit));
}

bool AccessTracer::HandleSingleStep(HANDLE thread)
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return false;
    DWORD64 bits = ctx.Dr6 & 0xF;
    if (!bits) return false; // not ours (e.g. the program single-steps itself)

    TraceRegs r;
    r.is64 = m_is64;
    if (m_is64)
    {
        const DWORD64 gp[16] = { ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsp, ctx.Rbp, ctx.Rsi, ctx.Rdi,
                                 ctx.R8,  ctx.R9,  ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15 };
        memcpy(r.gp, gp, sizeof(gp));
        r.ip = ctx.Rip;
        r.flags = ctx.EFlags;
    }
    else
    {
        WOW64_CONTEXT w{};
        w.ContextFlags = WOW64_CONTEXT_FULL;
        if (Wow64GetThreadContext(thread, &w))
        {
            const DWORD gp[8] = { w.Eax, w.Ecx, w.Edx, w.Ebx, w.Esp, w.Ebp, w.Esi, w.Edi };
            for (int i = 0; i < 8; i++) r.gp[i] = gp[i];
            r.ip = w.Eip;
            r.flags = w.EFlags;
        }
    }

    for (int i = 0; i < kSlots; i++)
        if (bits & (1ull << i)) Record(i, r);

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    ctx.Dr6 = 0;
    SetThreadContext(thread, &ctx);
    return true;
}

void AccessTracer::Run()
{
    if (!DebugActiveProcess(m_pid))
    {
        DWORD e = GetLastError();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_error = "Could not attach the debugger (error " + std::to_string(e) +
                  "). The process may already be debugged or need administrator rights.";
        m_running = false;
        return;
    }
    DebugSetProcessKillOnExit(FALSE); // never take the target down with us

    bool exited = false;
    bool sawNativeBreak = false, sawWowBreak = false;
    while (!m_stop && !exited)
    {
        DEBUG_EVENT ev{};
        if (!WaitForDebugEvent(&ev, 30))
        {
            if (m_dirty.exchange(false)) ApplyAll(true);
            continue;
        }
        DWORD status = DBG_CONTINUE;
        switch (ev.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
            m_process = ev.u.CreateProcessInfo.hProcess;
            m_threads[ev.dwThreadId] = ev.u.CreateProcessInfo.hThread;
            ApplyToThread(ev.u.CreateProcessInfo.hThread);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            m_threads[ev.dwThreadId] = ev.u.CreateThread.hThread;
            ApplyToThread(ev.u.CreateThread.hThread);
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            m_threads.erase(ev.dwThreadId);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            exited = true;
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT:
        {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            auto it = m_threads.find(ev.dwThreadId);
            if (code == EXCEPTION_SINGLE_STEP || code == STATUS_WX86_SINGLE_STEP)
            {
                bool ours = it != m_threads.end() && HandleSingleStep(it->second);
                status = ours ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
            }
            else if (code == EXCEPTION_BREAKPOINT && !sawNativeBreak)
            {
                sawNativeBreak = true; // the break-in from DebugActiveProcess
            }
            else if (code == STATUS_WX86_BREAKPOINT && !sawWowBreak)
            {
                sawWowBreak = true;
            }
            else
            {
                status = DBG_EXCEPTION_NOT_HANDLED; // the program's own exceptions
            }
            break;
        }
        default:
            break;
        }
        // All threads are frozen while an event is pending: a safe moment to update them.
        if (m_dirty.exchange(false)) ApplyAll(false);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
    }

    if (!exited)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& s : m_slots) s.used = false;
        }
        ApplyAll(true); // clear the debug registers before letting go
        DebugActiveProcessStop(m_pid);
    }
    else
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_error = "Target process exited";
    }
    m_threads.clear();
    m_process = nullptr;
    m_running = false;
}
