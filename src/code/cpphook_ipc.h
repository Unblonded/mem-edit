#pragma once
// Shared memory layout for the C++ hook runner. The host (mem-edit) compiles the user's C++ into a
// DLL, injects it, and both sides talk through one named file mapping (keyed by the target pid).
//
// The injected DLL, from a worker thread it starts in DllMain:
//   - publishes the address of its exported hook callback into `onCall` and bumps `loadGen`,
//   - polls `runGen`; when the host bumps it, runs the user's OnRun(args, out) body and echoes
//     `runGen` into `runAck`, writing any text output into `out`.
// The host writes `args`, bumps `runGen`, waits for `runAck`, then reads `out`.
//
// Both sides include this header, so keep it a plain C-compatible POD with a fixed layout.
#include <cstdint>
#include <cwchar>

namespace cpphookipc
{
constexpr uint32_t kMagic = 0x4b48504a;   // 'JPHK'
constexpr uint32_t kVersion = 2;
constexpr uint32_t kArgsMax = 4096;
constexpr uint32_t kOutMax = 1u << 16;
constexpr uint32_t kMaxSites = 16;         // distinct hook sites, each passed to OnCall as `site`

struct Block
{
    uint32_t magic;
    uint32_t version;
    volatile uint32_t loadGen;     // DLL bumps this each time a fresh build publishes itself
    volatile uint32_t ready;       // DLL sets 1 once its worker is live
    volatile uint32_t siteCount;   // host: number of hook sites in use
    volatile uint32_t _pad;
    volatile uint64_t trampolines[kMaxSites]; // host: each site's call-original address (before the DLL arms)
    volatile uint64_t onCallThunks[kMaxSites];// DLL: each site's callback thunk (0 if the build has no OnCall)
    volatile uint32_t runGen;      // host bumps to request a manual OnRun
    volatile uint32_t runAck;      // DLL copies runGen here when that run has finished
    volatile uint32_t outLen;      // bytes the DLL wrote into out
    volatile uint32_t stop;        // host sets 1 to make the worker exit
    char args[kArgsMax];           // host -> DLL: the custom params typed in the window
    char out[kOutMax];             // DLL -> host: text the user's code emitted
};

// "Local\\memedit_cpphook_<pid>" - both sides derive the same name from the target pid.
inline void MappingName(uint32_t pid, wchar_t* out, size_t count)
{
    swprintf(out, count, L"Local\\memedit_cpphook_%u", pid);
}
} // namespace cpphookipc
