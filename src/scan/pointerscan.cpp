#include "scan/pointerscan.h"

#include "core/values.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace
{
// A half-open address span [base, end). Used both for "where a pointer may point" (committed
// readable memory) and for module ranges (to tell a static base apart).
struct Span
{
    uint64_t base = 0;
    uint64_t end = 0;
};

// spans sorted by base and non-overlapping; returns the index of the span containing a, or -1.
int SpanIndex(const std::vector<Span>& spans, uint64_t a)
{
    size_t lo = 0, hi = spans.size();
    while (lo < hi)
    {
        size_t mid = (lo + hi) / 2;
        if (a < spans[mid].base) hi = mid;
        else if (a >= spans[mid].end) lo = mid + 1;
        else return (int)mid;
    }
    return -1;
}

bool InSpans(const std::vector<Span>& spans, uint64_t a) { return SpanIndex(spans, a) >= 0; }

template <typename Fn>
void ParallelFor(size_t count, Fn&& fn)
{
    unsigned n = std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), 32));
    if (count < n) n = (unsigned)std::max<size_t>(1, count);
    std::atomic<size_t> next{ 0 };
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < n; t++)
        pool.emplace_back([&]() {
            for (;;)
            {
                size_t i = next.fetch_add(1);
                if (i >= count) break;
                fn(i);
            }
        });
    for (auto& th : pool) th.join();
}

// One pointer found in the target: location L holds pointer value V (so read_ptr(L) == V).
struct Entry
{
    uint64_t v = 0; // the pointer value stored there
    uint64_t l = 0; // where it is stored
};

// A concurrent "have we queued this address?" set, sharded so parallel search threads rarely
// contend. Each hop address is processed once; whichever thread claims it first keeps it.
struct VisitedSet
{
    static constexpr int kShards = 64; // power of two
    std::unordered_set<uint64_t> sets[kShards];
    std::mutex locks[kShards];
    std::atomic<size_t> count{ 0 };

    bool insert(uint64_t a)
    {
        int s = (int)((a >> 4) & (kShards - 1));
        std::lock_guard<std::mutex> lk(locks[s]);
        if (sets[s].insert(a).second) { count.fetch_add(1, std::memory_order_relaxed); return true; }
        return false;
    }
    size_t size() const { return count.load(std::memory_order_relaxed); }
};

constexpr size_t kChunk = 8 * 1024 * 1024;
} // namespace

std::string PointerChain::Expression() const
{
    std::string b;
    if (staticBase)
        b = "\"" + module + "\"+" + ToHex(baseOffset);
    else
        b = ToHex(base);

    std::string s(offsets.size(), '[');
    s += b;
    for (size_t i = 0; i < offsets.size(); i++)
    {
        s += "]";
        int64_t o = offsets[i];
        if (o < 0) s += "-" + ToHex((uint64_t)(-o));
        else s += "+" + ToHex((uint64_t)o);
    }
    return s;
}

PointerScanner::~PointerScanner()
{
    Cancel();
    if (m_thread.joinable()) m_thread.join();
}

void PointerScanner::Cancel()
{
    m_cancel = true;
}

float PointerScanner::Progress() const
{
    uint64_t t = m_total.load();
    if (t == 0) return 0.0f;
    return std::min(1.0f, (float)((double)m_done.load() / (double)t));
}

void PointerScanner::Reset()
{
    Cancel();
    if (m_thread.joinable()) m_thread.join();
    m_results.clear();
    m_mapSize = 0;
    m_lastTarget = 0;
    m_lastError.clear();
    m_cancel = false;
}

bool PointerScanner::Start(const Process& proc, const PointerScanOptions& opts, std::string& error)
{
    if (m_busy) { error = "A pointer scan is already running."; return false; }
    if (!proc.IsOpen()) { error = "No process attached."; return false; }
    if (opts.target == 0) { error = "Enter a target address first."; return false; }
    if (opts.maxDepth < 1) { error = "Max depth must be at least 1."; return false; }

    if (m_thread.joinable()) m_thread.join();
    m_cancel = false;
    m_busy = true;
    m_done = 0;
    m_total = 1;
    m_lastError.clear();
    m_phase = "Starting";
    const Process* p = &proc;
    m_thread = std::thread([this, p, opts]() { Run(p, opts); });
    return true;
}

void PointerScanner::Update()
{
    std::lock_guard<std::mutex> lk(m_mutex);
    if (!m_pendingReady) return;
    m_pendingReady = false;
    if (m_pending)
    {
        m_results = std::move(*m_pending);
        m_pending.reset();
        m_mapSize = m_pendingMapSize;
        m_lastTarget = m_pendingTarget;
    }
    m_lastMs = m_pendingMs;
    m_lastError = m_pendingError;
}

// Resolve a chain against the live process: final = read_ptr(..read_ptr(read_ptr(base)+o0)..)+oLast.
static bool ResolveChain(const Process& proc, uint64_t base, const std::vector<int64_t>& offs, uint64_t& out)
{
    if (offs.empty()) return false;
    uint64_t t = 0;
    if (!proc.ReadPointer(base, t)) return false;
    for (size_t i = 0; i + 1 < offs.size(); i++)
        if (!proc.ReadPointer(t + (uint64_t)offs[i], t)) return false;
    out = t + (uint64_t)offs.back();
    return true;
}

void PointerScanner::Run(const Process* proc, PointerScanOptions o)
{
    auto t0 = std::chrono::steady_clock::now();

    // Committed readable spans: any valid pointer must land inside one of these.
    std::vector<Span> committed;
    for (const auto& r : proc->QueryRegions(true))
        if (IsReadable(r.protect)) committed.push_back({ r.base, r.base + r.size });
    std::sort(committed.begin(), committed.end(), [](const Span& a, const Span& b) { return a.base < b.base; });

    // Module spans + names, to recognise a static base.
    std::vector<Span> modSpans;
    std::vector<std::string> modNames;
    std::vector<uint64_t> modBases;
    for (const auto& m : proc->Modules())
    {
        modSpans.push_back({ m.base, m.base + m.size });
        modNames.push_back(m.name);
        modBases.push_back(m.base);
    }
    // Keep the three arrays in base order together.
    {
        std::vector<size_t> idx(modSpans.size());
        for (size_t i = 0; i < idx.size(); i++) idx[i] = i;
        std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return modSpans[a].base < modSpans[b].base; });
        std::vector<Span> s2; std::vector<std::string> n2; std::vector<uint64_t> b2;
        for (size_t i : idx) { s2.push_back(modSpans[i]); n2.push_back(modNames[i]); b2.push_back(modBases[i]); }
        modSpans = std::move(s2); modNames = std::move(n2); modBases = std::move(b2);
    }

    const int ptrSize = proc->PointerSize();

    // --- Phase 1: build the pointer map (every stored pointer that lands in committed memory). ---
    m_phase = "Building pointer map";
    struct Chunk { uint64_t base; size_t size; };
    std::vector<Chunk> chunks;
    uint64_t total = 0;
    for (const auto& r : proc->QueryRegions(true))
    {
        if (!IsReadable(r.protect)) continue;
        if (r.type == MEM_IMAGE && !o.includeImage) continue;
        if (r.type == MEM_PRIVATE && !o.includePrivate) continue;
        if (r.type == MEM_MAPPED && !o.includeMapped) continue;
        for (uint64_t x = r.base; x < r.base + r.size; x += kChunk)
        {
            size_t sz = (size_t)std::min<uint64_t>(kChunk, r.base + r.size - x);
            chunks.push_back({ x, sz });
            total += sz;
        }
    }
    m_total = std::max<uint64_t>(1, total);

    std::vector<std::vector<Entry>> perChunk(chunks.size());
    ParallelFor(chunks.size(), [&](size_t ci) {
        if (m_cancel) return;
        const Chunk& c = chunks[ci];
        std::vector<uint8_t> buf(c.size);
        size_t got = proc->Read(c.base, buf.data(), c.size);
        if (got >= (size_t)ptrSize)
        {
            auto& out = perChunk[ci];
            const size_t limit = got - (size_t)ptrSize;
            for (size_t off = 0; off <= limit; off += ptrSize)
            {
                uint64_t v = 0;
                memcpy(&v, buf.data() + off, ptrSize); // little-endian; 4 or 8 bytes
                if (InSpans(committed, v)) out.push_back({ v, c.base + off });
            }
        }
        m_done += c.size;
    });

    if (m_cancel) { std::lock_guard<std::mutex> lk(m_mutex); m_pendingReady = true; m_pendingError = "Scan cancelled"; m_busy = false; return; }

    // Merge and sort the map by pointer value for range queries.
    std::vector<Entry> map;
    {
        size_t n = 0;
        for (auto& c : perChunk) n += c.size();
        map.reserve(n);
        for (auto& c : perChunk) { map.insert(map.end(), c.begin(), c.end()); c = {}; }
    }
    std::sort(map.begin(), map.end(), [](const Entry& a, const Entry& b) { return a.v < b.v; });
    const uint64_t mapSize = map.size();

    // --- Phase 2: reverse-walk from the target up to any static base. ---
    m_phase = "Searching for paths";
    m_total = 1;
    m_done = 0;

    auto classifyStatic = [&](uint64_t l, std::string& mod, uint64_t& offInMod) -> bool {
        int mi = SpanIndex(modSpans, l);
        if (mi < 0) return false;
        mod = modNames[mi];
        offInMod = l - modBases[mi];
        return true;
    };

    struct Node { uint64_t addr; std::vector<int64_t> offs; };
    std::vector<Node> frontier;
    frontier.push_back({ o.target, {} });
    VisitedSet visited;
    visited.insert(o.target);

    auto out = std::make_unique<std::vector<PointerChain>>();
    std::unordered_set<std::string> seen; // dedup identical paths
    const uint64_t loSpan = o.maxOffset;
    const uint64_t hiSpan = o.allowNegative ? o.maxOffset : 0;
    const size_t kVisitedCap = 4000000;
    std::atomic<size_t> emitted{ 0 };

    for (int depth = 0; depth < o.maxDepth && !frontier.empty() && !m_cancel; depth++)
    {
        // Process every frontier node in parallel. Each node only reads the shared sorted map and
        // the live process (both safe), claims hop addresses through the sharded visited set, and
        // writes its finds to its own slot - so the threads never touch the same memory.
        std::vector<std::vector<PointerChain>> nodeHits(frontier.size());
        std::vector<std::vector<Node>> nodeNext(frontier.size());
        const bool lastHop = depth + 1 >= o.maxDepth;

        ParallelFor(frontier.size(), [&](size_t ni) {
            if (m_cancel || emitted.load(std::memory_order_relaxed) >= o.maxResults) return;
            const Node& node = frontier[ni];

            // Pointers whose value V satisfies V + off == node.addr for off in [-hiSpan, loSpan].
            uint64_t lo = node.addr > loSpan ? node.addr - loSpan : 0;
            uint64_t hi = node.addr + hiSpan;
            auto itLo = std::lower_bound(map.begin(), map.end(), lo,
                                         [](const Entry& e, uint64_t val) { return e.v < val; });
            auto itHi = std::upper_bound(map.begin(), map.end(), hi,
                                         [](uint64_t val, const Entry& e) { return val < e.v; });
            for (auto it = itLo; it != itHi; ++it)
            {
                if (m_cancel) return;
                int64_t off = (int64_t)(node.addr - it->v); // forward add at this hop
                uint64_t l = it->l;

                std::vector<int64_t> newOffs;
                newOffs.reserve(node.offs.size() + 1);
                newOffs.push_back(off);
                newOffs.insert(newOffs.end(), node.offs.begin(), node.offs.end());

                // Static base? Emit the path (verified against the live process below).
                std::string mod; uint64_t offInMod = 0;
                if (classifyStatic(l, mod, offInMod))
                {
                    PointerChain ch;
                    ch.staticBase = true;
                    ch.module = mod;
                    ch.baseOffset = offInMod;
                    ch.base = l;
                    ch.offsets = newOffs;
                    uint64_t resolved = 0;
                    if (ResolveChain(*proc, ch.base, ch.offsets, resolved) && resolved == o.target)
                    {
                        ch.resolved = resolved;
                        nodeHits[ni].push_back(std::move(ch));
                        emitted.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                else if (!o.staticOnly && lastHop)
                {
                    // Deepest level and non-static allowed: keep a dynamic base as a last resort.
                    PointerChain ch;
                    ch.base = l;
                    ch.offsets = newOffs;
                    uint64_t resolved = 0;
                    if (ResolveChain(*proc, ch.base, ch.offsets, resolved) && resolved == o.target)
                    {
                        ch.resolved = resolved;
                        nodeHits[ni].push_back(std::move(ch));
                        emitted.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                // Walk further up unless this location is already queued or we've gone too wide.
                if (!lastHop && visited.size() < kVisitedCap && visited.insert(l))
                    nodeNext[ni].push_back({ l, std::move(newOffs) });
            }
        });

        if (m_cancel) break;

        // Merge finds in node order (deterministic) with a final dedup / result cap.
        std::vector<Node> nextFrontier;
        bool full = false;
        for (size_t ni = 0; ni < frontier.size() && !full; ni++)
        {
            for (auto& ch : nodeHits[ni])
            {
                if (out->size() >= o.maxResults) { full = true; break; }
                if (seen.insert(ch.Expression()).second) out->push_back(std::move(ch));
            }
            for (auto& nx : nodeNext[ni]) nextFrontier.push_back(std::move(nx));
        }
        if (full) break;
        frontier = std::move(nextFrontier);
    }

    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_pending = std::move(out);
        m_pendingReady = true;
        m_pendingMapSize = mapSize;
        m_pendingTarget = o.target;
        m_pendingMs = ms;
        m_pendingError = m_cancel ? "Scan cancelled" : std::string();
    }
    m_busy = false;
}

size_t PointerScanner::Filter(const Process& proc, uint64_t newTarget)
{
    std::vector<PointerChain> kept;
    kept.reserve(m_results.size());
    for (auto& ch : m_results)
    {
        // Re-anchor a static base to the module's current address (it may have reloaded elsewhere).
        uint64_t base = ch.base;
        if (ch.staticBase)
        {
            ModuleInfo m;
            if (proc.FindModule(ch.module, m)) base = m.base + ch.baseOffset;
        }
        uint64_t resolved = 0;
        if (ResolveChain(proc, base, ch.offsets, resolved) && resolved == newTarget)
        {
            ch.base = base;
            ch.resolved = resolved;
            kept.push_back(std::move(ch));
        }
    }
    m_results = std::move(kept);
    m_lastTarget = newTarget;
    return m_results.size();
}
