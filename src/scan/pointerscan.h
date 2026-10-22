#pragma once
#include "core/target.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// A multi-level pointer path:  [[["module"+baseOffset]+off0]+off1]... that resolves to a target.
// A static base (inside a module) is what makes the path survive a restart - the module reloads at
// a new address, but module+baseOffset still names the same slot, and the offset chain is stable.
struct PointerChain
{
    bool staticBase = false;         // base sits in a module (survives restarts)
    std::string module;              // module name when staticBase
    uint64_t baseOffset = 0;         // offset of the base within that module
    uint64_t base = 0;               // absolute static base address at scan time
    std::vector<int64_t> offsets;    // forward order: [base]+off0, then +off1, ... last is the add
    uint64_t resolved = 0;           // what it resolved to (== target when found / after a filter)

    // "[[\"mod\"+X]+o0]+o1" - an expression EvaluateAddress understands, for the address list.
    std::string Expression() const;
};

struct PointerScanOptions
{
    uint64_t target = 0;
    int maxDepth = 4;                // number of offsets (pointer hops); depth 1 = [base]+off
    uint64_t maxOffset = 0x800;      // largest +offset added at each hop
    bool allowNegative = false;      // also try offsets down to -maxOffset
    bool staticOnly = true;          // only keep paths whose base is in a module
    size_t maxResults = 20000;

    // Which regions to mine for pointer values (the "pointer map").
    bool includeImage = true;
    bool includePrivate = true;
    bool includeMapped = false;
};

// Finds pointer paths to an address by reverse-walking a snapshot of every pointer in the target,
// then verifies each path against the live process so there are no false positives.
class PointerScanner
{
public:
    ~PointerScanner();

    bool Start(const Process& proc, const PointerScanOptions& opts, std::string& error);
    void Cancel();
    void Update();                   // commit a finished scan; call once per frame from the UI
    void Reset();

    bool Busy() const { return m_busy; }
    float Progress() const;
    double LastDurationMs() const { return m_lastMs; }
    const std::string& LastError() const { return m_lastError; }
    const char* Phase() const { return m_phase.load(); }

    const std::vector<PointerChain>& Results() const { return m_results; }
    uint64_t PointerMapSize() const { return m_mapSize; }
    uint64_t LastTarget() const { return m_lastTarget; }

    // Re-resolve every current path against the live process and keep only those that now equal
    // newTarget. This is the "rescan after a restart" step that proves which paths are stable.
    // Returns how many paths remain.
    size_t Filter(const Process& proc, uint64_t newTarget);

private:
    void Run(const Process* proc, PointerScanOptions opts);

    std::vector<PointerChain> m_results;
    uint64_t m_mapSize = 0;
    uint64_t m_lastTarget = 0;

    std::atomic<bool> m_busy{ false };
    std::atomic<bool> m_cancel{ false };
    std::atomic<uint64_t> m_done{ 0 };
    std::atomic<uint64_t> m_total{ 1 };
    std::atomic<const char*> m_phase{ "" };

    std::thread m_thread;
    double m_lastMs = 0;
    std::string m_lastError;

    std::mutex m_mutex;
    std::unique_ptr<std::vector<PointerChain>> m_pending;
    bool m_pendingReady = false;
    std::string m_pendingError;
    double m_pendingMs = 0;
    uint64_t m_pendingMapSize = 0;
    uint64_t m_pendingTarget = 0;
};
