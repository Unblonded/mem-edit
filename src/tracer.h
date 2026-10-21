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

// Finds the instructions that write to / access an address, using the CPU's
// hardware debug registers (DR0-DR3). Attaches to the target as a debugger
// while at least one watch is active, and detaches without killing it.
class AccessTracer
{
public:
    static constexpr int kSlots = 4;

    ~AccessTracer() { Shutdown(); }

    // Returns a slot id (0-3) or -1 with `error` set.
    int Add(DWORD pid, bool is64, uint64_t address, int size, TraceKind kind, std::string& error);
    void Remove(int slot);
    void Clear(int slot);
    std::vector<TraceHit> Hits(int slot) const;
    bool Attached() const { return m_running; }
    std::string Error() const;
    void Shutdown();

    static const char* RegName(int i, bool is64);

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
    TraceHit Decode(uint64_t ipAfter, const TraceRegs& regs, uint64_t watched, int watchedSize) const;

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
