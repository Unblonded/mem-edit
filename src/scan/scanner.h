#pragma once
#include "core/target.h"
#include "core/values.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

enum class ScanCompare : int
{
    Exact, NotEqual, Greater, Less, Between, Unknown,
    Changed, Unchanged, Increased, Decreased, IncreasedBy, DecreasedBy,
    Count
};

const char* ScanCompareName(ScanCompare c);
bool CompareNeedsValue(ScanCompare c);
bool CompareNeedsTwoValues(ScanCompare c);
bool CompareNeedsPrevious(ScanCompare c);

struct ScanOptions
{
    ValueType type = ValueType::Int32;
    ScanCompare compare = ScanCompare::Exact;
    std::string value1;
    std::string value2;
    bool hexInput = false;
    bool caseSensitive = true;

    bool fastScan = true;       // only check addresses aligned to `alignment`
    int alignment = 4;
    bool requireWritable = true;
    bool includeExecutable = true;
    bool includeImage = true;
    bool includePrivate = true;
    bool includeMapped = false;
    uint64_t startAddress = 0;
    uint64_t endAddress = 0x00007FFFFFFFFFFFull;
};

struct SnapshotRegion
{
    uint64_t base = 0;
    std::vector<uint8_t> data;
    std::vector<uint8_t> valid; // empty means fully valid
};

struct ScanState
{
    bool valid = false;
    bool snapshot = false;   // "unknown initial value" - no address list yet
    ValueType type = ValueType::Int32;
    size_t valueSize = 4;
    size_t step = 4;
    std::vector<uint64_t> addresses;
    std::vector<uint8_t> values; // valueSize bytes per address (value at scan time)
    std::vector<SnapshotRegion> regions;
    uint64_t snapshotCandidates = 0;
    uint64_t scanNumber = 0;

    size_t Count() const { return snapshot ? (size_t)snapshotCandidates : addresses.size(); }
};

class Scanner
{
public:
    ~Scanner();

    // Starts an asynchronous scan. `first` = new scan, otherwise filters the current results.
    bool Start(const Process& proc, const ScanOptions& opts, bool first, std::string& error);
    void Cancel();
    // Must be called once per frame from the UI thread: commits finished scans.
    void Update();
    void Reset();
    bool Undo();
    bool CanUndo() const { return m_undo && m_undo->valid; }

    bool Busy() const { return m_busy; }
    float Progress() const;
    double LastDurationMs() const { return m_lastMs; }
    const std::string& LastError() const { return m_lastError; }

    const ScanState& State() const { return m_state; }
    bool HasResults() const { return m_state.valid; }

private:
    void RunFirst(const Process* proc, ScanOptions opts);
    void RunNext(const Process* proc, ScanOptions opts);
    void Finish(std::unique_ptr<ScanState> st, double ms, const std::string& err);

    ScanState m_state;
    std::unique_ptr<ScanState> m_undo;
    std::unique_ptr<ScanState> m_pending;
    std::mutex m_pendingMutex;
    bool m_pendingReady = false;
    std::string m_pendingError;
    double m_pendingMs = 0;

    std::thread m_thread;
    std::atomic<bool> m_busy{ false };
    std::atomic<bool> m_cancel{ false };
    std::atomic<uint64_t> m_done{ 0 };
    std::atomic<uint64_t> m_total{ 1 };
    double m_lastMs = 0;
    std::string m_lastError;
};
