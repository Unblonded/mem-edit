#pragma once
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

enum class TraceKind
{
    Writes,
    Accesses, // reads or writes
};

// Register snapshot taken the last time an instruction hit the watchpoint.
struct TraceRegs
{
    uint64_t gp[16] = {}; // rax rcx rdx rbx rsp rbp rsi rdi r8..r15 (x86: eax..edi)
    uint64_t ip = 0;      // instruction pointer *after* the access
    uint64_t flags = 0;
    bool is64 = true;
};

struct TraceHit
{
    uint64_t address = 0;    // start of the instruction that touched the memory
    uint64_t count = 0;
    int length = 0;
    std::string text;        // disassembly
    std::vector<uint8_t> bytes;
    TraceRegs regs;
};

// Data breakpoints fire *after* the instruction, so given the instruction pointer afterwards (plus
// the register snapshot and the watched range) this searches backwards for the instruction that
// made the access and disassembles it. Shared by both tracer backends. `process` is read only.
// With ipIsStart=false the ip is the address *after* the access (hardware breakpoint) and we search
// backwards; with ipIsStart=true the ip is the faulting instruction itself (page-guard) and we
// decode it forwards.
TraceHit DecodeTraceHit(HANDLE process, bool is64, uint64_t ipAfter, const TraceRegs& regs,
                        uint64_t watched, int watchedSize, bool ipIsStart = false);

const char* TraceRegName(int i, bool is64);

// A memory-access tracer: both the Windows-debugger and the injected-VEH backend implement this,
// so the UI can drive either interchangeably.
class ITracer
{
public:
    static constexpr int kSlots = 4;
    virtual ~ITracer() = default;

    // Returns a slot id (0-3) or -1 with `error` set.
    virtual int Add(DWORD pid, bool is64, uint64_t address, int size, TraceKind kind, std::string& error) = 0;
    virtual void Remove(int slot) = 0;
    virtual void Clear(int slot) = 0;
    virtual std::vector<TraceHit> Hits(int slot) const = 0;
    virtual bool Attached() const = 0;
    virtual std::string Error() const = 0;
    virtual void Shutdown() = 0;
};

// Finds the instructions that write to / access an address, using the CPU's
// hardware debug registers (DR0-DR3). Attaches to the target as a debugger
// while at least one watch is active, and detaches without killing it.
class AccessTracer : public ITracer
{
public:
    ~AccessTracer() override { Shutdown(); }

    int Add(DWORD pid, bool is64, uint64_t address, int size, TraceKind kind, std::string& error) override;
    void Remove(int slot) override;
    void Clear(int slot) override;
    std::vector<TraceHit> Hits(int slot) const override;
    bool Attached() const override { return m_running; }
    std::string Error() const override;
    void Shutdown() override;

    static const char* RegName(int i, bool is64) { return TraceRegName(i, is64); }

private:
    struct Slot
    {
        bool used = false;
        uint64_t address = 0;
        int size = 4;
        TraceKind kind = TraceKind::Writes;
        std::map<uint64_t, TraceHit> hits; // keyed by IP after the access
    };

    void Run();
    void ApplyToThread(HANDLE thread);
    void ApplyAll(bool suspend);
    bool HandleSingleStep(HANDLE thread);
    void Record(int slot, const TraceRegs& regs);

    mutable std::mutex m_mutex;
    Slot m_slots[kSlots];
    std::string m_error;

    std::thread m_thread;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_stop{ false };
    std::atomic<bool> m_dirty{ false };
    DWORD m_pid = 0;
    bool m_is64 = true;

    // Debugger-thread state
    HANDLE m_process = nullptr;
    std::map<DWORD, HANDLE> m_threads;
};
