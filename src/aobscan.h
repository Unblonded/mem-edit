#pragma once
#include "target.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// A byte pattern ("signature") with per-nibble wildcards.
//
// Accepted syntax (whitespace between bytes is optional):
//   48 8B 05 ?? ?? ?? ??     IDA style; ? and ?? are whole-byte wildcards
//   48 8B 4? ?8              nibble wildcards: 4? matches 40-4F, ?8 matches 08, 18 ... F8
//   E8 | ?? ?? ?? ??         '|' marks where each result should point (here: the call's rel32)
//   \x48\x8B\x05 xx?         code style: escaped bytes followed by an x/? mask
struct AobPattern
{
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;  // per byte: FF exact, F0 high nibble only, 0F low nibble only, 00 any
    int resultOffset = 0;       // from '|': results point this far into the match

    bool Parse(const std::string& text, std::string& error);
    size_t Size() const { return bytes.size(); }
    bool Empty() const { return bytes.empty(); }
    int SolidBytes() const;     // bytes with no wildcard at all
    bool MatchAt(const uint8_t* p) const;

    std::string ToIda() const;  // "48 8B 05 ?? ?? ?? ??" (nibble wildcards written as 4?)
    std::string ToCodeBytes() const; // "\x48\x8B\x05\x00..." (wildcards as \x00)
    std::string ToCodeMask() const;  // "xxx????"
};

struct AobScanOptions
{
    uint64_t start = 0;
    uint64_t end = ~0ull;
    bool executableOnly = false;  // code only: what signatures are usually for
    bool writableOnly = false;
    bool includeImage = true;
    bool includePrivate = true;
    bool includeMapped = false;
    size_t maxResults = 100000;
};

// Searches committed memory for a pattern on worker threads; results are match addresses with the
// pattern's '|' offset applied, in ascending order.
class AobScanner
{
public:
    ~AobScanner();

    bool Start(const Process& proc, const AobPattern& pattern, const AobScanOptions& opts, std::string& error);
    void Cancel();
    void Update();  // commit a finished scan; call once per frame from the UI
    void Reset();

    bool Busy() const { return m_busy; }
    float Progress() const;
    double LastDurationMs() const { return m_lastMs; }
    uint64_t BytesScanned() const { return m_lastBytes; }
    bool Truncated() const { return m_truncated; }
    const std::string& LastError() const { return m_lastError; }

    const std::vector<uint64_t>& Results() const { return m_results; }
    const AobPattern& Pattern() const { return m_pattern; }

private:
    void Run(const Process* proc, AobPattern pattern, AobScanOptions opts);

    std::vector<uint64_t> m_results;
    AobPattern m_pattern;
    double m_lastMs = 0;
    uint64_t m_lastBytes = 0;
    bool m_truncated = false;
    std::string m_lastError;

    std::atomic<bool> m_busy{ false };
    std::atomic<bool> m_cancel{ false };
    std::atomic<uint64_t> m_done{ 0 };
    std::atomic<uint64_t> m_total{ 1 };
    std::thread m_thread;

    std::mutex m_mutex;
    bool m_pendingReady = false;
    std::vector<uint64_t> m_pending;
    AobPattern m_pendingPattern;
    double m_pendingMs = 0;
    uint64_t m_pendingBytes = 0;
    bool m_pendingTruncated = false;
    std::string m_pendingError;
};

// Synchronous search for small jobs (signature lists, uniqueness checks). Stops after `limit` hits.
std::vector<uint64_t> AobFind(const Process& proc, const AobPattern& pattern, const AobScanOptions& opts, size_t limit);

// One decoded instruction at an address, for result lists.
struct AobInsn
{
    bool ok = false;
    std::string text;          // "mov rax, qword ptr [rip+0x1234]"
    uint64_t target = 0;       // absolute branch / RIP-relative address, when there is one
    bool hasTarget = false;
    int length = 0;
};
AobInsn AobDecode(const Process& proc, uint64_t address);

// Builds the shortest pattern starting at `address` that matches exactly once in `scope`
// (the containing module's code by default). Instructions are decoded so the bytes that change
// between builds - relative branch targets, RIP-relative displacements and, optionally, other
// 32-bit displacements and immediates - become wildcards.
struct SigMakerOptions
{
    bool wildcardRelative = true;   // rel8/rel32 branch targets and RIP-relative displacements
    bool wildcardWide = false;      // also 32-bit displacements / immediates (struct offsets, constants)
    bool wholeProcess = false;      // uniqueness across all executable memory, not just the module
    int maxBytes = 96;
};
struct SigMakerResult
{
    bool ok = false;
    bool unique = false;
    AobPattern pattern;
    size_t matches = 0;             // in scope (1 when unique)
    int instructions = 0;
    std::string scope;              // "game.exe code" / "all executable memory"
    std::string error;
};
SigMakerResult MakeSignature(const Process& proc, uint64_t address, const SigMakerOptions& opts);
