#include "scan/scanner.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstring>
#include <type_traits>

const char* ScanCompareName(ScanCompare c)
{
    switch (c)
    {
    case ScanCompare::Exact: return "Exact value";
    case ScanCompare::NotEqual: return "Not equal to";
    case ScanCompare::Greater: return "Bigger than";
    case ScanCompare::Less: return "Smaller than";
    case ScanCompare::Between: return "Value between";
    case ScanCompare::Unknown: return "Unknown initial value";
    case ScanCompare::Changed: return "Changed value";
    case ScanCompare::Unchanged: return "Unchanged value";
    case ScanCompare::Increased: return "Increased value";
    case ScanCompare::Decreased: return "Decreased value";
    case ScanCompare::IncreasedBy: return "Increased by";
    case ScanCompare::DecreasedBy: return "Decreased by";
    default: return "?";
    }
}

bool CompareNeedsValue(ScanCompare c)
{
    switch (c)
    {
    case ScanCompare::Exact: case ScanCompare::NotEqual: case ScanCompare::Greater:
    case ScanCompare::Less: case ScanCompare::Between: case ScanCompare::IncreasedBy:
    case ScanCompare::DecreasedBy:
        return true;
    default:
        return false;
    }
}

bool CompareNeedsTwoValues(ScanCompare c) { return c == ScanCompare::Between; }

bool CompareNeedsPrevious(ScanCompare c)
{
    return c == ScanCompare::Changed || c == ScanCompare::Unchanged || c == ScanCompare::Increased ||
           c == ScanCompare::Decreased || c == ScanCompare::IncreasedBy || c == ScanCompare::DecreasedBy;
}

namespace
{
struct Ctx
{
    ValueType type = ValueType::Int32;
    ScanCompare cmp = ScanCompare::Exact;
    size_t vsize = 4;
    size_t step = 4;
    ParsedValue v1, v2;
    uint8_t a[8] = {}, b[8] = {};
    double tol = 0;
    bool cs = true;
};

template <typename T>
inline bool MatchNum(const Ctx& c, T cur, T prev)
{
    T a, b;
    memcpy(&a, c.a, sizeof(T));
    memcpy(&b, c.b, sizeof(T));
    if constexpr (std::is_floating_point_v<T>)
    {
        if (std::isnan(cur)) return false;
        switch (c.cmp)
        {
        case ScanCompare::Exact: return std::fabs((double)cur - (double)a) < c.tol;
        case ScanCompare::NotEqual: return !(std::fabs((double)cur - (double)a) < c.tol);
        case ScanCompare::Greater: return cur > a;
        case ScanCompare::Less: return cur < a;
        case ScanCompare::Between: return cur >= a && cur <= b;
        case ScanCompare::Unknown: return true;
        case ScanCompare::Changed: return cur != prev;
        case ScanCompare::Unchanged: return cur == prev;
        case ScanCompare::Increased: return cur > prev;
        case ScanCompare::Decreased: return cur < prev;
        case ScanCompare::IncreasedBy: return std::fabs(((double)cur - (double)prev) - (double)a) < c.tol;
        case ScanCompare::DecreasedBy: return std::fabs(((double)prev - (double)cur) - (double)a) < c.tol;
        default: return false;
        }
    }
    else
    {
        switch (c.cmp)
        {
        case ScanCompare::Exact: return cur == a;
        case ScanCompare::NotEqual: return cur != a;
        case ScanCompare::Greater: return cur > a;
        case ScanCompare::Less: return cur < a;
        case ScanCompare::Between: return cur >= a && cur <= b;
        case ScanCompare::Unknown: return true;
        case ScanCompare::Changed: return cur != prev;
        case ScanCompare::Unchanged: return cur == prev;
        case ScanCompare::Increased: return cur > prev;
        case ScanCompare::Decreased: return cur < prev;
        case ScanCompare::IncreasedBy: return (T)(cur - prev) == a;
        case ScanCompare::DecreasedBy: return (T)(prev - cur) == a;
        default: return false;
        }
    }
}

inline bool PatternAt(const Ctx& c, const uint8_t* p)
{
    const auto& v = c.v1;
    size_t n = v.bytes.size();
    if (c.cs)
    {
        for (size_t i = 0; i < n; i++)
            if (v.mask[i] && p[i] != v.bytes[i]) return false;
    }
    else
    {
        for (size_t i = 0; i < n; i++)
            if (v.mask[i] && tolower(p[i]) != tolower(v.bytes[i])) return false;
    }
    return true;
}

inline bool MatchBytes(const Ctx& c, const uint8_t* cur, const uint8_t* prev)
{
    switch (c.cmp)
    {
    case ScanCompare::Exact: return PatternAt(c, cur);
    case ScanCompare::NotEqual: return !PatternAt(c, cur);
    case ScanCompare::Changed: return memcmp(cur, prev, c.vsize) != 0;
    case ScanCompare::Unchanged: return memcmp(cur, prev, c.vsize) == 0;
    default: return false;
    }
}

template <typename T>
bool MatchT(const Ctx& c, const uint8_t* cur, const uint8_t* prev)
{
    T x, y{};
    memcpy(&x, cur, sizeof(T));
    if (prev) memcpy(&y, prev, sizeof(T));
    return MatchNum<T>(c, x, y);
}

using MatchFn = bool (*)(const Ctx&, const uint8_t*, const uint8_t*);

MatchFn PickMatcher(ValueType t)
{
    switch (t)
    {
    case ValueType::Int8: return &MatchT<int8_t>;
    case ValueType::UInt8: return &MatchT<uint8_t>;
    case ValueType::Int16: return &MatchT<int16_t>;
    case ValueType::UInt16: return &MatchT<uint16_t>;
    case ValueType::Int32: return &MatchT<int32_t>;
    case ValueType::UInt32: return &MatchT<uint32_t>;
    case ValueType::Int64: return &MatchT<int64_t>;
    case ValueType::UInt64: return &MatchT<uint64_t>;
    case ValueType::Float: return &MatchT<float>;
    case ValueType::Double: return &MatchT<double>;
    default: return &MatchBytes;
    }
}

struct Output
{
    std::vector<uint64_t> addrs;
    std::vector<uint8_t> vals;

    void Add(uint64_t a, const uint8_t* v, size_t n)
    {
        addrs.push_back(a);
        vals.insert(vals.end(), v, v + n);
    }
};

// Scans one contiguous, fully-readable run. Positions are relative to `buf`;
// candidates are positions p in [from, posLimit) with p + vsize <= runEnd.
template <typename T>
void ScanRunNum(const Ctx& c, uint64_t base, const uint8_t* buf, const uint8_t* prev, size_t from, size_t posLimit,
                size_t runEnd, Output& out)
{
    if (runEnd < sizeof(T)) return;
    size_t last = std::min(posLimit, runEnd - sizeof(T) + 1);
    size_t step = c.step;
    size_t p = (from + step - 1) / step * step;
    for (; p < last; p += step)
    {
        T cur;
        memcpy(&cur, buf + p, sizeof(T));
        T pv{};
        if (prev) memcpy(&pv, prev + p, sizeof(T));
        if (MatchNum<T>(c, cur, pv)) out.Add(base + p, buf + p, sizeof(T));
    }
}

void ScanRunBytes(const Ctx& c, uint64_t base, const uint8_t* buf, const uint8_t* prev, size_t from, size_t posLimit,
                  size_t runEnd, Output& out)
{
    size_t n = c.vsize;
    if (runEnd < n) return;
    size_t last = std::min(posLimit, runEnd - n + 1);
    bool fastFirst = c.cmp == ScanCompare::Exact && c.cs && !c.v1.mask.empty() && c.v1.mask[0];
    uint8_t first = c.v1.bytes.empty() ? 0 : c.v1.bytes[0];
    for (size_t p = from; p < last; p++)
    {
        if (fastFirst)
        {
            const void* hit = memchr(buf + p, first, last - p);
            if (!hit) break;
            p = (const uint8_t*)hit - buf;
        }
        if (MatchBytes(c, buf + p, prev ? prev + p : nullptr)) out.Add(base + p, buf + p, n);
    }
}

void ScanRun(const Ctx& c, uint64_t base, const uint8_t* buf, const uint8_t* prev, size_t from, size_t posLimit,
             size_t runEnd, Output& out)
{
    switch (c.type)
    {
    case ValueType::Int8: ScanRunNum<int8_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::UInt8: ScanRunNum<uint8_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::Int16: ScanRunNum<int16_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::UInt16: ScanRunNum<uint16_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::Int32: ScanRunNum<int32_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::UInt32: ScanRunNum<uint32_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::Int64: ScanRunNum<int64_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::UInt64: ScanRunNum<uint64_t>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::Float: ScanRunNum<float>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    case ValueType::Double: ScanRunNum<double>(c, base, buf, prev, from, posLimit, runEnd, out); break;
    default: ScanRunBytes(c, base, buf, prev, from, posLimit, runEnd, out); break;
    }
}

// Splits a buffer into valid runs (mask may be null = all valid) and scans each.
void ScanBlock(const Ctx& c, uint64_t base, const uint8_t* buf, size_t scanLen, size_t bufLen, const uint8_t* valid,
               const uint8_t* prev, Output& out)
{
    if (!valid)
    {
        ScanRun(c, base, buf, prev, 0, scanLen, bufLen, out);
        return;
    }
    size_t i = 0;
    while (i < scanLen)
    {
        while (i < scanLen && !valid[i]) i++;
        if (i >= scanLen) break;
        size_t s = i;
        while (i < bufLen && valid[i]) i++;
        ScanRun(c, base, buf, prev, s, scanLen, i, out);
    }
}

bool BuildCtx(const ScanOptions& o, Ctx& c, std::string& err)
{
    c.type = o.type;
    c.cmp = o.compare;
    c.cs = o.caseSensitive;
    if (CompareNeedsValue(o.compare))
    {
        c.v1 = ParseValue(o.type, o.value1, o.hexInput);
        if (!c.v1.ok) { err = "Invalid value: '" + o.value1 + "'"; return false; }
        if (CompareNeedsTwoValues(o.compare))
        {
            c.v2 = ParseValue(o.type, o.value2, o.hexInput);
            if (!c.v2.ok) { err = "Invalid second value: '" + o.value2 + "'"; return false; }
        }
    }
    if (IsNumeric(o.type))
    {
        c.vsize = ValueTypeSize(o.type);
        c.step = o.fastScan ? (size_t)std::max(1, o.alignment) : 1;
        if (c.v1.ok) memcpy(c.a, c.v1.bytes.data(), c.vsize);
        if (c.v2.ok) memcpy(c.b, c.v2.bytes.data(), c.vsize);
        c.tol = c.v1.floatTolerance;
        if (c.cmp == ScanCompare::Between)
        {
            double x = NumericAsDouble(o.type, c.a), y = NumericAsDouble(o.type, c.b);
            if (x > y) std::swap(c.a, c.b);
        }
    }
    else
    {
        if (o.compare == ScanCompare::Unknown) { err = "Unknown initial value requires a numeric type"; return false; }
        if (o.compare != ScanCompare::Exact && o.compare != ScanCompare::NotEqual &&
            o.compare != ScanCompare::Changed && o.compare != ScanCompare::Unchanged)
        {
            err = "This comparison is not supported for strings / byte arrays";
            return false;
        }
        c.step = 1;
        c.vsize = c.v1.ok ? c.v1.bytes.size() : 0;
    }
    return true;
}

template <typename Fn>
void ParallelFor(size_t count, Fn&& fn)
{
    unsigned n = std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), 32));
    if (count < n) n = (unsigned)std::max<size_t>(1, count);
    std::atomic<size_t> next{ 0 };
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < n; t++)
    {
        pool.emplace_back([&]() {
            for (;;)
            {
                size_t i = next.fetch_add(1);
                if (i >= count) break;
                fn(i);
            }
        });
    }
    for (auto& th : pool) th.join();
}

struct WorkItem
{
    uint64_t base;
    size_t size;
    uint64_t regionEnd;
};

constexpr size_t kChunk = 16 * 1024 * 1024;
} // namespace

Scanner::~Scanner()
{
    Cancel();
    if (m_thread.joinable()) m_thread.join();
}

float Scanner::Progress() const
{
    uint64_t t = m_total.load();
    return t ? (float)((double)m_done.load() / (double)t) : 0.f;
}

void Scanner::Cancel() { m_cancel = true; }

void Scanner::Reset()
{
    if (m_busy) return;
    m_state = ScanState{};
    m_undo.reset();
    m_lastError.clear();
}

bool Scanner::Undo()
{
    if (m_busy || !m_undo) return false;
    m_state = std::move(*m_undo);
    m_undo.reset();
    return true;
}

bool Scanner::Start(const Process& proc, const ScanOptions& opts, bool first, std::string& error)
{
    if (m_busy) { error = "A scan is already running"; return false; }
    if (!proc.IsOpen()) { error = "No process attached"; return false; }
    if (m_thread.joinable()) m_thread.join();

    if (first)
    {
        if (CompareNeedsPrevious(opts.compare)) { error = "That comparison needs a previous scan"; return false; }
    }
    else
    {
        if (!m_state.valid) { error = "No previous scan"; return false; }
        if (opts.compare == ScanCompare::Unknown) { error = "'Unknown initial value' is only for a first scan"; return false; }
        if (opts.type != m_state.type) { error = "Value type differs from the previous scan"; return false; }
    }
    Ctx c;
    if (!BuildCtx(opts, c, error)) return false;
    if (!first && !IsNumeric(opts.type) && c.vsize != 0 && c.vsize != m_state.valueSize)
    {
        error = "Pattern length differs from the previous scan";
        return false;
    }

    m_cancel = false;
    m_done = 0;
    m_total = 1;
    m_busy = true;
    m_lastError.clear();
    const Process* p = &proc;
    if (first) m_thread = std::thread([this, p, opts]() { RunFirst(p, opts); });
    else m_thread = std::thread([this, p, opts]() { RunNext(p, opts); });
    return true;
}

void Scanner::Finish(std::unique_ptr<ScanState> st, double ms, const std::string& err)
{
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    m_pending = std::move(st);
    m_pendingMs = ms;
    m_pendingError = err;
    m_pendingReady = true;
}

void Scanner::Update()
{
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        if (!m_pendingReady) return;
        m_pendingReady = false;
    }
    if (m_thread.joinable()) m_thread.join();
    m_lastError = m_pendingError;
    m_lastMs = m_pendingMs;
    if (m_pending)
    {
        if (m_state.valid) m_undo = std::make_unique<ScanState>(std::move(m_state));
        m_state = std::move(*m_pending);
        m_pending.reset();
    }
    m_busy = false;
}

void Scanner::RunFirst(const Process* proc, ScanOptions o)
{
    auto t0 = std::chrono::steady_clock::now();
    Ctx c;
    std::string err;
    BuildCtx(o, c, err);

    std::vector<WorkItem> items;
    uint64_t total = 0;
    for (const auto& r : proc->QueryRegions(true))
    {
        if (!IsReadable(r.protect)) continue;
        if (o.requireWritable && !IsWritable(r.protect)) continue;
        if (!o.includeExecutable && IsExecutable(r.protect)) continue;
        if (r.type == MEM_IMAGE && !o.includeImage) continue;
        if (r.type == MEM_PRIVATE && !o.includePrivate) continue;
        if (r.type == MEM_MAPPED && !o.includeMapped) continue;
        uint64_t b = std::max(r.base, o.startAddress);
        uint64_t e = std::min(r.base + r.size, o.endAddress);
        if (b >= e) continue;
        for (uint64_t x = b; x < e; x += kChunk)
        {
            size_t sz = (size_t)std::min<uint64_t>(kChunk, e - x);
            items.push_back({ x, sz, e });
            total += sz;
        }
    }
    m_total = std::max<uint64_t>(1, total);

    auto st = std::make_unique<ScanState>();
    st->type = o.type;
    st->valueSize = c.vsize;
    st->step = c.step;
    st->scanNumber = 1;

    bool snapshot = o.compare == ScanCompare::Unknown;
    std::vector<Output> outs(snapshot ? 0 : items.size());
    std::vector<SnapshotRegion> snaps(snapshot ? items.size() : 0);
    size_t overlap = c.vsize > 0 ? c.vsize - 1 : 0;

    ParallelFor(items.size(), [&](size_t i) {
        if (m_cancel) return;
        const WorkItem& it = items[i];
        size_t readLen = (size_t)std::min<uint64_t>(it.size + overlap, it.regionEnd - it.base);
        if (snapshot)
        {
            SnapshotRegion& s = snaps[i];
            s.base = it.base;
            s.data.resize(it.size);
            std::vector<uint8_t> valid;
            size_t got = proc->Read(it.base, s.data.data(), it.size, &valid);
            if (got == 0) s.data.clear();
            else if (got != it.size) s.valid = std::move(valid);
        }
        else
        {
            std::vector<uint8_t> buf(readLen);
            std::vector<uint8_t> valid;
            size_t got = proc->Read(it.base, buf.data(), readLen, &valid);
            if (got == readLen) ScanBlock(c, it.base, buf.data(), it.size, readLen, nullptr, nullptr, outs[i]);
            else if (got > 0) ScanBlock(c, it.base, buf.data(), it.size, readLen, valid.data(), nullptr, outs[i]);
        }
        m_done += it.size;
    });

    if (m_cancel)
    {
        Finish(nullptr, 0, "Scan cancelled");
        return;
    }

    if (snapshot)
    {
        st->snapshot = true;
        for (auto& s : snaps)
        {
            if (s.data.empty()) continue;
            st->snapshotCandidates += s.data.size() / c.step;
            st->regions.push_back(std::move(s));
        }
    }
    else
    {
        size_t n = 0;
        for (auto& out : outs) n += out.addrs.size();
        st->addresses.reserve(n);
        st->values.reserve(n * c.vsize);
        for (auto& out : outs)
        {
            st->addresses.insert(st->addresses.end(), out.addrs.begin(), out.addrs.end());
            st->values.insert(st->values.end(), out.vals.begin(), out.vals.end());
            out = Output{};
        }
    }
    st->valid = true;
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    Finish(std::move(st), ms, {});
}

void Scanner::RunNext(const Process* proc, ScanOptions o)
{
    auto t0 = std::chrono::steady_clock::now();
    const ScanState& old = m_state; // read-only while busy
    Ctx c;
    std::string err;
    BuildCtx(o, c, err);
    c.vsize = old.valueSize;
    c.step = old.step;

    auto st = std::make_unique<ScanState>();
    st->type = old.type;
    st->valueSize = old.valueSize;
    st->step = old.step;
    st->scanNumber = old.scanNumber + 1;

    std::vector<Output> outs;

    if (old.snapshot)
    {
        uint64_t total = 0;
        for (const auto& r : old.regions) total += r.data.size();
        m_total = std::max<uint64_t>(1, total);
        outs.resize(old.regions.size());

        ParallelFor(old.regions.size(), [&](size_t i) {
            if (m_cancel) return;
            const SnapshotRegion& r = old.regions[i];
            std::vector<uint8_t> cur(r.data.size());
            std::vector<uint8_t> valid;
            size_t got = proc->Read(r.base, cur.data(), cur.size(), &valid);
            if (got == cur.size() && r.valid.empty())
            {
                ScanBlock(c, r.base, cur.data(), cur.size(), cur.size(), nullptr, r.data.data(), outs[i]);
            }
            else if (got > 0)
            {
                if (!r.valid.empty())
                    for (size_t k = 0; k < valid.size(); k++) valid[k] &= r.valid[k];
                ScanBlock(c, r.base, cur.data(), cur.size(), cur.size(), valid.data(), r.data.data(), outs[i]);
            }
            m_done += r.data.size();
        });
    }
    else
    {
        const size_t n = old.addresses.size();
        const size_t blockSize = 1 << 16;
        size_t blocks = (n + blockSize - 1) / blockSize;
        m_total = std::max<uint64_t>(1, n);
        outs.resize(blocks);
        MatchFn match = PickMatcher(old.type);
        const size_t vs = old.valueSize;

        ParallelFor(blocks, [&](size_t bi) {
            if (m_cancel) return;
            size_t i0 = bi * blockSize, i1 = std::min(n, i0 + blockSize);
            const size_t window = 64 * 1024;
            std::vector<uint8_t> buf(window + 64);
            std::vector<uint8_t> valid;
            uint64_t winBase = 0, winEnd = 0;
            Output& out = outs[bi];
            for (size_t i = i0; i < i1; i++)
            {
                uint64_t a = old.addresses[i];
                if (a < winBase || a + vs > winEnd)
                {
                    winBase = a & ~0xFFFull;
                    size_t len = std::max(window, (size_t)(a - winBase) + vs);
                    if (buf.size() < len) buf.resize(len);
                    proc->Read(winBase, buf.data(), len, &valid);
                    winEnd = winBase + len;
                }
                size_t off = (size_t)(a - winBase);
                bool ok = true;
                for (size_t k = 0; k < vs; k++)
                    if (!valid[off + k]) { ok = false; break; }
                if (!ok) continue;
                const uint8_t* prev = old.values.data() + i * vs;
                if (match(c, buf.data() + off, prev)) out.Add(a, buf.data() + off, vs);
            }
            m_done += i1 - i0;
        });
    }

    if (m_cancel)
    {
        Finish(nullptr, 0, "Scan cancelled");
        return;
    }

    size_t total = 0;
    for (auto& out : outs) total += out.addrs.size();
    st->addresses.reserve(total);
    st->values.reserve(total * st->valueSize);
    for (auto& out : outs)
    {
        st->addresses.insert(st->addresses.end(), out.addrs.begin(), out.addrs.end());
        st->values.insert(st->values.end(), out.vals.begin(), out.vals.end());
        out = Output{};
    }
    st->valid = true;
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    Finish(std::move(st), ms, {});
}
