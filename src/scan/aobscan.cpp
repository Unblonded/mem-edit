#include "scan/aobscan.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>

namespace
{
int HexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// How common a byte is in x86 code and data; the search anchors on the least common solid byte
// so memchr skips as much as possible.
int Commonness(uint8_t b)
{
    switch (b)
    {
    case 0x00: case 0xFF: case 0xCC: return 10;
    case 0x48: case 0x8B: case 0x89: case 0x90: case 0x24: case 0x4C: case 0x0F: return 6;
    case 0x01: case 0x83: case 0xC0: case 0xE8: case 0x44: case 0x8D: return 4;
    default: return 0;
    }
}

int ChooseAnchor(const AobPattern& p)
{
    int best = -1, bestScore = 1 << 30;
    for (int i = 0; i < (int)p.Size(); i++)
    {
        if (p.mask[i] != 0xFF) continue;
        int score = Commonness(p.bytes[i]) * 4 + i / 8; // prefer rare, then early
        if (score < bestScore) best = i, bestScore = score;
    }
    return best;
}

// Calls fn(offset) for every match start in data[0, n) whose whole span lies inside the buffer.
// `starts` limits which offsets may begin a match (the rest belong to the next chunk).
template <class Fn>
void SearchBuffer(const AobPattern& p, int anchor, const uint8_t* data, size_t n, size_t starts, Fn&& fn)
{
    const size_t len = p.Size();
    if (n < len) return;
    starts = std::min(starts, n - len + 1);
    if (anchor < 0)
    {
        for (size_t s = 0; s < starts; s++)
            if (p.MatchAt(data + s) && !fn(s)) return;
        return;
    }
    const uint8_t v = p.bytes[anchor];
    const uint8_t* cur = data + anchor;
    const uint8_t* stop = data + anchor + starts; // exclusive bound for the anchor position
    while (cur < stop)
    {
        const uint8_t* hit = (const uint8_t*)memchr(cur, v, (size_t)(stop - cur));
        if (!hit) break;
        size_t s = (size_t)(hit - data) - anchor;
        if (p.MatchAt(data + s) && !fn(s)) return;
        cur = hit + 1;
    }
}

bool RegionWanted(const RegionInfo& r, const AobScanOptions& o)
{
    if (r.state != MEM_COMMIT || !IsReadable(r.protect)) return false;
    if (o.executableOnly && !IsExecutable(r.protect)) return false;
    if (o.writableOnly && !IsWritable(r.protect)) return false;
    if (r.type == MEM_IMAGE && !o.includeImage) return false;
    if (r.type == MEM_PRIVATE && !o.includePrivate) return false;
    if (r.type == MEM_MAPPED && !o.includeMapped) return false;
    return r.base + r.size > o.start && r.base < o.end;
}

struct WorkItem
{
    uint64_t begin = 0;     // first address a match may start at
    uint64_t end = 0;       // one past the last start address
    uint64_t readEnd = 0;   // read up to here so matches straddling `end` are complete
};

template <typename Fn>
void ParallelFor(size_t count, Fn&& fn)
{
    unsigned n = std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), 16));
    if (count < n) n = (unsigned)std::max<size_t>(1, count);
    std::atomic<size_t> next{ 0 };
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < n; t++)
        pool.emplace_back([&]() {
            for (size_t i; (i = next.fetch_add(1)) < count;) fn(i);
        });
    for (auto& th : pool) th.join();
}

// The shared search used by the async scanner and AobFind.
void Search(const Process& proc, const AobPattern& p, const AobScanOptions& o, size_t limit, std::atomic<bool>* cancel,
            std::atomic<uint64_t>* done, std::atomic<uint64_t>* total, std::vector<uint64_t>& out, uint64_t& bytes,
            bool& truncated)
{
    constexpr uint64_t kChunk = 8ull << 20;
    const uint64_t len = p.Size();
    std::vector<WorkItem> items;
    uint64_t sum = 0;
    for (const auto& r : proc.QueryRegions(true))
    {
        if (!RegionWanted(r, o)) continue;
        uint64_t b = std::max(r.base, o.start), e = std::min(r.base + r.size, o.end);
        if (e <= b || e - b < len) continue;
        for (uint64_t x = b; x < e; x += kChunk)
        {
            uint64_t ce = std::min(e, x + kChunk);
            items.push_back({ x, ce, std::min(e, ce + len - 1) });
        }
        sum += e - b;
    }
    if (total) *total = std::max<uint64_t>(sum, 1);
    bytes = sum;

    const int anchor = ChooseAnchor(p);
    std::vector<std::vector<uint64_t>> found(items.size());
    std::atomic<size_t> hits{ 0 };
    std::atomic<bool> full{ false };
    ParallelFor(items.size(), [&](size_t i) {
        if ((cancel && *cancel) || full) return;
        const WorkItem& it = items[i];
        std::vector<uint8_t> buf((size_t)(it.readEnd - it.begin));
        std::vector<uint8_t> valid;
        size_t got = proc.Read(it.begin, buf.data(), buf.size(), &valid);
        if (got)
        {
            const bool allValid = std::find(valid.begin(), valid.end(), (uint8_t)0) == valid.end();
            SearchBuffer(p, anchor, buf.data(), buf.size(), (size_t)(it.end - it.begin), [&](size_t s) {
                // Unreadable pages read as zeros; never let them complete a match.
                if (!allValid)
                    for (size_t k = s; k < s + len; k++)
                        if (!valid[k]) return true;
                found[i].push_back(it.begin + s + (int64_t)p.resultOffset);
                if (hits.fetch_add(1) + 1 >= limit) { full = true; return false; }
                return true;
            });
        }
        if (done) *done += it.end - it.begin;
    });

    out.clear();
    for (auto& f : found) out.insert(out.end(), f.begin(), f.end());
    std::sort(out.begin(), out.end());
    truncated = full;
    if (out.size() > limit) out.resize(limit);
}

ZydisDecoder MakeDecoder(bool x64)
{
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    return dec;
}
} // namespace

// ---------------------------------------------------------------------------
// AobPattern

bool AobPattern::Parse(const std::string& text, std::string& error)
{
    bytes.clear();
    mask.clear();
    resultOffset = 0;
    bool haveMarker = false;
    auto push = [&](uint8_t b, uint8_t m) { bytes.push_back(b & m); mask.push_back(m); };

    // Code style: \x48\x8B\x05\x00 followed by an optional x/? mask.
    std::string lower = text;
    for (auto& c : lower) c = (char)tolower((unsigned char)c);
    if (lower.find("\\x") != std::string::npos)
    {
        size_t i = 0;
        while (i < text.size())
        {
            if (text[i] == '\\' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X'))
            {
                int h = i + 2 < text.size() ? HexDigit(text[i + 2]) : -1;
                int l = i + 3 < text.size() ? HexDigit(text[i + 3]) : -1;
                if (h < 0 || l < 0) { error = "Bad \\x escape at position " + std::to_string(i + 1); return false; }
                push((uint8_t)(h << 4 | l), 0xFF);
                i += 4;
            }
            else if (isspace((unsigned char)text[i]) || text[i] == '"' || text[i] == ',') i++;
            else break;
        }
        std::string m;
        for (; i < text.size(); i++)
        {
            char c = text[i];
            if (c == 'x' || c == 'X' || c == '?') m += c;
            else if (!isspace((unsigned char)c) && c != '"' && c != ',') { error = std::string("Unexpected '") + c + "' in the mask"; return false; }
        }
        if (!m.empty())
        {
            if (m.size() != bytes.size())
            {
                error = "The mask has " + std::to_string(m.size()) + " characters but there are " +
                        std::to_string(bytes.size()) + " bytes";
                return false;
            }
            for (size_t k = 0; k < m.size(); k++)
                if (m[k] == '?') bytes[k] = 0, mask[k] = 0;
        }
    }
    else
    {
        size_t i = 0;
        const size_t n = text.size();
        while (i < n)
        {
            char c = text[i];
            if (isspace((unsigned char)c) || c == ',') { i++; continue; }
            if (c == '|')
            {
                if (haveMarker) { error = "Only one '|' result marker is allowed"; return false; }
                haveMarker = true;
                resultOffset = (int)bytes.size();
                i++;
                continue;
            }
            char d = i + 1 < n ? text[i + 1] : ' ';
            int hc = HexDigit(c), hd = HexDigit(d);
            if (c == '?')
            {
                if (d == '?') { push(0, 0x00); i += 2; }          // ??
                else if (hd >= 0) { push((uint8_t)hd, 0x0F); i += 2; } // ?8
                else { push(0, 0x00); i += 1; }                 // ?
                continue;
            }
            if (hc >= 0)
            {
                if (hd >= 0) { push((uint8_t)(hc << 4 | hd), 0xFF); i += 2; }
                else if (d == '?') { push((uint8_t)(hc << 4), 0xF0); i += 2; }
                else { error = "Each byte needs two hex digits (near position " + std::to_string(i + 1) + ")"; return false; }
                continue;
            }
            error = std::string("Unexpected '") + c + "' at position " + std::to_string(i + 1);
            return false;
        }
    }

    if (bytes.empty()) { error = "Enter a pattern, e.g. 48 8B 05 ?? ?? ?? ??"; return false; }
    if (bytes.size() > 1024) { error = "Patterns are limited to 1024 bytes"; return false; }
    if (std::all_of(mask.begin(), mask.end(), [](uint8_t m) { return m == 0; }))
    {
        error = "A pattern needs at least one byte that isn't a wildcard";
        return false;
    }
    error.clear();
    return true;
}

int AobPattern::SolidBytes() const
{
    return (int)std::count(mask.begin(), mask.end(), (uint8_t)0xFF);
}

bool AobPattern::MatchAt(const uint8_t* p) const
{
    const size_t n = bytes.size();
    for (size_t i = 0; i < n; i++)
        if ((p[i] & mask[i]) != bytes[i]) return false;
    return true;
}

std::string AobPattern::ToIda() const
{
    static const char* hex = "0123456789ABCDEF";
    std::string s;
    for (size_t i = 0; i < bytes.size(); i++)
    {
        if ((int)i == resultOffset && resultOffset > 0) s += "| ";
        s += (mask[i] & 0xF0) ? hex[bytes[i] >> 4] : '?';
        s += (mask[i] & 0x0F) ? hex[bytes[i] & 15] : '?';
        if (i + 1 < bytes.size()) s += ' ';
    }
    if (resultOffset > 0 && resultOffset == (int)bytes.size()) s += " |";
    return s;
}

std::string AobPattern::ToCodeBytes() const
{
    static const char* hex = "0123456789ABCDEF";
    std::string s;
    for (size_t i = 0; i < bytes.size(); i++)
    {
        uint8_t b = mask[i] == 0xFF ? bytes[i] : 0;
        s += "\\x";
        s += hex[b >> 4];
        s += hex[b & 15];
    }
    return s;
}

std::string AobPattern::ToCodeMask() const
{
    std::string s;
    for (uint8_t m : mask) s += m == 0xFF ? 'x' : '?';
    return s;
}

// ---------------------------------------------------------------------------
// AobScanner

AobScanner::~AobScanner()
{
    Cancel();
    if (m_thread.joinable()) m_thread.join();
}

void AobScanner::Cancel() { m_cancel = true; }

float AobScanner::Progress() const
{
    uint64_t t = m_total.load();
    return t ? std::min(1.0f, (float)((double)m_done.load() / (double)t)) : 0.f;
}

void AobScanner::Reset()
{
    Cancel();
    if (m_thread.joinable()) m_thread.join();
    m_results.clear();
    m_lastError.clear();
    m_truncated = false;
    m_cancel = false;
}

bool AobScanner::Start(const Process& proc, const AobPattern& pattern, const AobScanOptions& opts, std::string& error)
{
    if (m_busy) { error = "A scan is already running."; return false; }
    if (!proc.IsOpen()) { error = "No process attached."; return false; }
    if (pattern.Empty()) { error = "Enter a pattern first."; return false; }
    if (m_thread.joinable()) m_thread.join();
    m_cancel = false;
    m_busy = true;
    m_done = 0;
    m_total = 1;
    m_lastError.clear();
    const Process* p = &proc;
    m_thread = std::thread([this, p, pattern, opts]() { Run(p, pattern, opts); });
    return true;
}

void AobScanner::Update()
{
    std::lock_guard<std::mutex> lk(m_mutex);
    if (!m_pendingReady) return;
    m_pendingReady = false;
    m_results = std::move(m_pending);
    m_pattern = m_pendingPattern;
    m_lastMs = m_pendingMs;
    m_lastBytes = m_pendingBytes;
    m_truncated = m_pendingTruncated;
    m_lastError = m_pendingError;
}

void AobScanner::Run(const Process* proc, AobPattern pattern, AobScanOptions opts)
{
    auto t0 = std::chrono::steady_clock::now();
    std::vector<uint64_t> out;
    uint64_t bytes = 0;
    bool truncated = false;
    Search(*proc, pattern, opts, std::max<size_t>(opts.maxResults, 1), &m_cancel, &m_done, &m_total, out, bytes, truncated);
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_pending = std::move(out);
        m_pendingPattern = pattern;
        m_pendingMs = ms;
        m_pendingBytes = bytes;
        m_pendingTruncated = truncated;
        m_pendingError = m_cancel ? "Scan cancelled - showing what was found so far." : "";
        m_pendingReady = true;
    }
    m_busy = false;
}

std::vector<uint64_t> AobFind(const Process& proc, const AobPattern& pattern, const AobScanOptions& opts, size_t limit)
{
    std::vector<uint64_t> out;
    uint64_t bytes = 0;
    bool truncated = false;
    if (proc.IsOpen() && !pattern.Empty())
        Search(proc, pattern, opts, std::max<size_t>(limit, 1), nullptr, nullptr, nullptr, out, bytes, truncated);
    return out;
}

// ---------------------------------------------------------------------------
// Instruction decoding

AobInsn AobDecode(const Process& proc, uint64_t address)
{
    AobInsn r;
    uint8_t buf[ZYDIS_MAX_INSTRUCTION_LENGTH] = {};
    size_t got = proc.Read(address, buf, sizeof(buf));
    if (!got) return r;
    ZydisDecoder dec = MakeDecoder(proc.Is64());
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, buf, got, &ins, ops))) return r;

    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    char text[256];
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &ins, ops, ins.operand_count_visible, text, sizeof(text), address,
                                                     nullptr)))
        r.text = text;
    r.ok = true;
    r.length = ins.length;
    for (int i = 0; i < ins.operand_count_visible && !r.hasTarget; i++)
    {
        const ZydisDecodedOperand& op = ops[i];
        bool rel = (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) ||
                   (op.type == ZYDIS_OPERAND_TYPE_MEMORY && (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP));
        ZyanU64 abs = 0;
        if (rel && ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, address, &abs)))
        {
            r.target = abs;
            r.hasTarget = true;
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// Signature maker

namespace
{
// Memory the signature has to be unique in, read once so each extension is checked in-process.
struct Snapshot
{
    struct Block { uint64_t base; std::vector<uint8_t> data; };
    std::vector<Block> blocks;
};

bool InAnyModule(const std::vector<ModuleInfo>& mods, uint64_t v)
{
    for (const auto& m : mods)
        if (v >= m.base && v < m.base + m.size) return true;
    return false;
}
} // namespace

SigMakerResult MakeSignature(const Process& proc, uint64_t address, const SigMakerOptions& opts)
{
    SigMakerResult res;
    if (!proc.IsOpen()) { res.error = "No process attached."; return res; }

    // Scope: the module's code, or every executable region. The address's own region always counts.
    ModuleInfo mod;
    const bool inModule = proc.ModuleFromAddress(address, mod);
    const bool whole = opts.wholeProcess || !inModule;
    uint64_t lo = whole ? 0 : mod.base, hi = whole ? ~0ull : mod.base + mod.size;
    res.scope = whole ? "all executable memory" : mod.name + " code";

    RegionInfo own;
    if (!proc.QueryRegion(address, own) || own.state != MEM_COMMIT || !IsReadable(own.protect))
    {
        res.error = "That address isn't readable.";
        return res;
    }
    Snapshot snap;
    for (const auto& r : proc.QueryRegions(true))
    {
        const bool isOwn = address >= r.base && address < r.base + r.size;
        if (!isOwn && (!IsReadable(r.protect) || !IsExecutable(r.protect))) continue;
        uint64_t b = std::max(r.base, lo), e = std::min(r.base + r.size, hi);
        if (e <= b) continue;
        Snapshot::Block blk{ b, std::vector<uint8_t>((size_t)(e - b)) };
        std::vector<uint8_t> valid;
        if (!proc.Read(b, blk.data.data(), blk.data.size(), &valid)) continue;
        snap.blocks.push_back(std::move(blk));
    }

    // The code to describe.
    std::vector<uint8_t> code((size_t)opts.maxBytes + ZYDIS_MAX_INSTRUCTION_LENGTH);
    size_t got = proc.Read(address, code.data(), code.size());
    if (!got) { res.error = "Couldn't read the code at that address."; return res; }

    const auto mods = proc.Modules();
    ZydisDecoder dec = MakeDecoder(proc.Is64());
    AobPattern& pat = res.pattern;
    bool haveCandidates = false;
    struct Cand { size_t block; size_t off; };
    std::vector<Cand> cands;

    size_t off = 0;
    while (off < got && (int)pat.Size() < opts.maxBytes)
    {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code.data() + off, got - off, &ins, ops))) break;

        // Bytes of this instruction, with the build-specific fields wildcarded.
        std::vector<uint8_t> m(ins.length, 0xFF);
        auto clear = [&](int at, int bits) {
            for (int k = 0; k < bits / 8 && at + k < (int)m.size(); k++) m[at + k] = 0;
        };
        bool ripRel = false, absMem = false;
        for (int i = 0; i < ins.operand_count; i++)
            if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (ops[i].mem.base == ZYDIS_REGISTER_RIP || ops[i].mem.base == ZYDIS_REGISTER_EIP) ripRel = true;
                if (ops[i].mem.base == ZYDIS_REGISTER_NONE && ops[i].mem.index == ZYDIS_REGISTER_NONE) absMem = true;
            }
        if (ins.raw.disp.size)
        {
            const uint64_t dv = (uint64_t)ins.raw.disp.value;
            bool wild = (opts.wildcardRelative && (ripRel || absMem || InAnyModule(mods, dv))) ||
                        (opts.wildcardWide && ins.raw.disp.size >= 32);
            if (wild) clear(ins.raw.disp.offset, ins.raw.disp.size);
        }
        for (const auto& imm : ins.raw.imm)
        {
            if (!imm.size) continue;
            const uint64_t iv = imm.value.u;
            bool wild = (opts.wildcardRelative && (imm.is_relative || (imm.size >= 32 && InAnyModule(mods, iv)))) ||
                        (opts.wildcardWide && imm.size >= 32);
            if (wild) clear(imm.offset, imm.size);
        }
        for (int k = 0; k < ins.length; k++)
        {
            pat.bytes.push_back(code[off + k] & m[k]);
            pat.mask.push_back(m[k]);
        }
        off += ins.length;
        res.instructions++;

        // Matches of the pattern so far: a full search the first time, then each extension can only
        // shrink the set, so just re-check the survivors.
        if (!haveCandidates)
        {
            if (pat.SolidBytes() < 2 && (int)pat.Size() < opts.maxBytes) continue; // too vague to search yet
            const int anchor = ChooseAnchor(pat);
            for (size_t b = 0; b < snap.blocks.size(); b++)
            {
                const auto& d = snap.blocks[b].data;
                SearchBuffer(pat, anchor, d.data(), d.size(), d.size(), [&](size_t s) {
                    cands.push_back({ b, s });
                    return true;
                });
            }
            haveCandidates = true;
        }
        else
        {
            cands.erase(std::remove_if(cands.begin(), cands.end(),
                                       [&](const Cand& c) {
                                           const auto& d = snap.blocks[c.block].data;
                                           return c.off + pat.Size() > d.size() || !pat.MatchAt(d.data() + c.off);
                                       }),
                        cands.end());
        }
        if (cands.size() <= 1) break;
    }

    // Trailing wildcards add nothing.
    while (!pat.mask.empty() && pat.mask.back() == 0)
    {
        pat.mask.pop_back();
        pat.bytes.pop_back();
    }
    if (pat.Empty()) { res.error = "Couldn't decode any instructions at that address."; return res; }
    res.ok = true;
    res.matches = cands.size();
    res.unique = cands.size() == 1;
    if (!res.unique && cands.empty()) res.error = "The pattern didn't match its own address - the code may be changing.";
    else if (!res.unique)
        res.error = "Still " + std::to_string(cands.size()) + " matches after " + std::to_string(pat.Size()) +
                    " bytes - try a nearby instruction, a larger limit, or turn off wide wildcards.";
    return res;
}
