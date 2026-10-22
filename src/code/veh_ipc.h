#pragma once
// Shared memory layout for the VEH debugger. The host (mem-edit) creates one of these blocks in a
// named file mapping, injects veh_agent.dll into the target, and the agent opens the same mapping.
// The agent installs a vectored exception handler + hardware breakpoints inside the target and
// appends every hit here; the host polls and disassembles them. Both sides include this header, so
// keep it a plain C-compatible POD with a fixed layout.
#include <cstdint>
#include <cwchar>

namespace vehipc
{
constexpr uint32_t kMagic = 0x31484556;   // 'VEH1'
constexpr uint32_t kVersion = 1;
constexpr int kSlots = 4;                 // DR0-DR3
constexpr uint32_t kMaxHits = 16384;      // ring buffer of recent hits

struct Slot
{
    uint32_t active;   // 0/1
    uint32_t size;     // 1, 2, 4 or 8 bytes
    uint32_t kind;     // 0 = writes, 1 = reads+writes
    uint32_t _pad;
    uint64_t address;
};

// A register snapshot the agent captured when a breakpoint fired (x64 layout).
struct Hit
{
    uint64_t ip;        // instruction pointer after the access
    uint64_t gp[16];    // rax rcx rdx rbx rsp rbp rsi rdi r8..r15
    uint64_t flags;
    uint32_t slot;      // which watch fired
    uint32_t _pad;
};

struct Block
{
    uint32_t magic;
    uint32_t version;
    volatile uint32_t configGen;   // host bumps this whenever slots change
    volatile uint32_t appliedGen;  // agent copies configGen here after it re-arms the threads
    volatile uint32_t stop;        // host sets 1 to make the agent unhook and exit
    volatile uint32_t agentReady;  // agent sets 1 once the handler is installed
    volatile uint32_t hitSeq;      // total hits ever written (monotonic); ring index = (seq-1) % kMaxHits
    uint32_t is64;                 // target bitness (agent only supports 1 for now)
    uint32_t mode;                 // 0 = hardware (DR0-DR3), 1 = page-guard (software, DR-free)
    uint32_t _pad2;
    Slot slots[kSlots];
    Hit hits[kMaxHits];
};

// "Local\\memedit_veh_<pid>" - both sides derive the same name from the target pid.
inline void MappingName(uint32_t pid, wchar_t* out, size_t count)
{
    swprintf(out, count, L"Local\\memedit_veh_%u", pid);
}
} // namespace vehipc
