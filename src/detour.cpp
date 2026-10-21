#include "detour.h"

#include "decompiler.h"

#include <Zydis/Zydis.h>

#include <windows.h>

namespace
{
std::string Hex(uint64_t v)
{
    char b[32];
    snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v);
    return b;
}

// Stolen instructions get copied into the cave at a new address, so any RIP-relative
// memory access or relative branch inside them would now point somewhere else and
// crash the target. Rewrite those displacements/offsets so they still refer to the
// same absolute target from the cave. Returns false (with a reason) for anything we
// can't safely relocate, rather than letting the game fault on a bad cave.
bool RelocateStolen(bool x64, uint64_t origAddr, uint64_t caveAddr,
                    std::vector<uint8_t>& bytes, std::string& error)
{
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

    size_t off = 0;
    while (off < bytes.size())
    {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, bytes.data() + off, bytes.size() - off, &ins, ops)))
        {
            error = "Could not decode a stolen instruction to relocate it.";
            return false;
        }

        const uint64_t oldInsn = origAddr + off;
        const uint64_t newInsn = caveAddr + off;

        // RIP-relative memory operand: keep the same absolute target from the new address.
        if (ins.raw.disp.size == 32)
        {
            bool ripRel = false;
            for (int i = 0; i < ins.operand_count; i++)
                if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RIP)
                    ripRel = true;
            if (ripRel)
            {
                int64_t nd = ins.raw.disp.value + (int64_t)oldInsn - (int64_t)newInsn;
                if (nd < INT32_MIN || nd > INT32_MAX)
                {
                    error = "A stolen RIP-relative instruction lands too far from the cave to relocate.";
                    return false;
                }
                int32_t d32 = (int32_t)nd;
                memcpy(bytes.data() + off + ins.raw.disp.offset, &d32, 4);
            }
        }

        // Relative branch/call: retarget to the same absolute destination.
        if (ins.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
        {
            for (int i = 0; i < 2; i++)
            {
                if (!ins.raw.imm[i].is_relative || ins.raw.imm[i].size == 0) continue;
                uint64_t target = oldInsn + ins.length + (uint64_t)ins.raw.imm[i].value.s;
                int64_t newRel = (int64_t)target - (int64_t)(newInsn + ins.length);
                if (ins.raw.imm[i].size == 32)
                {
                    if (newRel < INT32_MIN || newRel > INT32_MAX)
                    {
                        error = "A stolen branch lands too far from the cave to relocate.";
                        return false;
                    }
                    int32_t r32 = (int32_t)newRel;
                    memcpy(bytes.data() + off + ins.raw.imm[i].offset, &r32, 4);
                }
                else
                {
                    error = "A stolen short branch can't be relocated into the cave.\n"
                            "Pick an entry whose first bytes have no short jump.";
                    return false;
                }
            }
        }

        off += ins.length;
    }
    return true;
}

// A RIP-relative instruction stolen into the cave can only reach its global if the
// cave sits within +/-2GB of it, so allocate the cave near the hook site rather than
// wherever the OS picks. Scans free pages outward from `near`; returns null if none fit.
LPVOID AllocNear(HANDLE h, uint64_t anchor, size_t size)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const uint64_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    const uint64_t minA = (uint64_t)si.lpMinimumApplicationAddress;
    const uint64_t maxA = (uint64_t)si.lpMaximumApplicationAddress;
    const uint64_t range = 0x7FFF0000ull; // a touch under 2GB for margin
    const uint64_t base0 = anchor & ~(gran - 1);

    for (uint64_t delta = 0; delta <= range; delta += gran)
    {
        for (int dir = 0; dir < 2; dir++)
        {
            if (dir == 1 && delta == 0) continue;
            uint64_t cand = dir == 0 ? base0 + delta : base0 - delta;
            if (cand < minA || cand + size > maxA) continue;

            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQueryEx(h, (LPVOID)cand, &mbi, sizeof(mbi))) continue;
            if (mbi.State != MEM_FREE) continue;
            uint64_t freeFrom = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
            if (cand + size > freeFrom) continue;

            LPVOID p = VirtualAllocEx(h, (LPVOID)cand, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
    }
    return nullptr;
}
} // namespace

size_t JumpSize(bool x64) { return x64 ? 14 : 5; }

std::vector<uint8_t> MakeJump(uint64_t from, uint64_t to, bool x64)
{
    std::vector<uint8_t> j;
    if (x64)
    {
        // jmp qword ptr [rip+0]; dq <to>   (absolute, clobbers nothing, any range)
        j = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        for (int i = 0; i < 8; i++) j.push_back((uint8_t)((to >> (i * 8)) & 0xFF));
    }
    else
    {
        // E9 rel32
        int32_t rel = (int32_t)((int64_t)to - (int64_t)(from + 5));
        j = { 0xE9 };
        for (int i = 0; i < 4; i++) j.push_back((uint8_t)(((uint32_t)rel >> (i * 8)) & 0xFF));
    }
    return j;
}

bool DetourManager::StealLength(const Process& proc, uint64_t addr, size_t min, size_t& len, std::string& error)
{
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, proc.Is64() ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     proc.Is64() ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

    uint8_t buf[64];
    size_t got = proc.Read(addr, buf, sizeof(buf));
    if (got == 0)
    {
        error = "Could not read code at " + Hex(addr);
        return false;
    }

    size_t off = 0;
    while (off < min)
    {
        ZydisDecodedInstruction ins;
        if (off >= got || !ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, buf + off, got - off, &ins)))
        {
            error = "Could not decode enough instructions at the entry to place a " + std::to_string(min) +
                    "-byte jump.";
            return false;
        }
        off += ins.length;
    }
    len = off;
    return true;
}

Detour* DetourManager::FindMutable(uint64_t entry)
{
    for (auto& d : m_detours)
        if (d.entry == entry) return &d;
    return nullptr;
}

const Detour* DetourManager::Find(uint64_t entry) const
{
    for (const auto& d : m_detours)
        if (d.entry == entry) return &d;
    return nullptr;
}

const Detour* DetourManager::CaveForAddress(uint64_t addr) const
{
    // Anywhere inside the whole cave allocation - so we never hook a cave address by mistake.
    for (const auto& d : m_detours)
        if (d.cave && addr >= d.cave && addr < d.cave + d.caveSize) return &d;
    return nullptr;
}

bool DetourManager::Redirect(const Process& proc, uint64_t entry, uint64_t target, std::string& error)
{
    if (!proc.IsOpen()) { error = "No process attached"; return false; }
    if (Find(entry)) { error = "This address is already detoured. Remove it first."; return false; }

    const bool x64 = proc.Is64();
    const size_t jsz = JumpSize(x64);
    size_t stolen = 0;
    if (!StealLength(proc, entry, jsz, stolen, error)) return false;

    std::vector<uint8_t> original(stolen);
    if (!proc.ReadExact(entry, original.data(), original.size()))
    {
        error = "Could not read the original bytes at " + Hex(entry);
        return false;
    }

    std::vector<uint8_t> hook = MakeJump(entry, target, x64);
    hook.resize(stolen, 0x90); // pad the rest of the stolen bytes with NOPs
    if (!proc.Write(entry, hook.data(), hook.size()))
    {
        error = "Write failed at " + Hex(entry) + " (page protected?)";
        return false;
    }

    Detour d;
    d.entry = entry;
    d.original = original;
    d.hook = hook;
    d.target = target;
    d.stolenLen = stolen;
    d.kind = "redirect";
    d.location = proc.Symbolize(entry);
    m_detours.push_back(std::move(d));
    return true;
}

bool DetourManager::InstallTrampoline(const Process& proc, uint64_t entry, size_t userBytes, std::string& error)
{
    if (!proc.IsOpen()) { error = "No process attached"; return false; }
    if (Find(entry)) { error = "This address is already detoured. Remove it first."; return false; }

    const bool x64 = proc.Is64();
    const size_t jsz = JumpSize(x64);
    size_t stolen = 0;
    if (!StealLength(proc, entry, jsz, stolen, error)) return false;

    std::vector<uint8_t> original(stolen);
    if (!proc.ReadExact(entry, original.data(), original.size()))
    {
        error = "Could not read the original bytes at " + Hex(entry);
        return false;
    }

    // cave = [user NOPs][stolen bytes][jump back to entry+stolen]
    size_t jmpBack = jsz;
    size_t caveSize = userBytes + stolen + jmpBack;
    // Prefer a cave within +/-2GB of the entry so stolen RIP-relative accesses still reach.
    LPVOID cave = AllocNear(proc.Handle(), entry, caveSize);
    if (!cave)
        cave = VirtualAllocEx(proc.Handle(), nullptr, caveSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!cave)
    {
        error = "VirtualAllocEx failed (code cave could not be allocated).";
        return false;
    }
    uint64_t caveAddr = (uint64_t)cave;

    std::vector<uint8_t> caveBytes(caveSize, 0x90);
    std::vector<uint8_t> relocated = original;
    if (!RelocateStolen(x64, entry, caveAddr + userBytes, relocated, error))
    {
        VirtualFreeEx(proc.Handle(), cave, 0, MEM_RELEASE);
        return false;
    }
    memcpy(caveBytes.data() + userBytes, relocated.data(), stolen);
    std::vector<uint8_t> back = MakeJump(caveAddr + userBytes + stolen, entry + stolen, x64);
    memcpy(caveBytes.data() + userBytes + stolen, back.data(), back.size());
    if (!proc.Write(caveAddr, caveBytes.data(), caveBytes.size()))
    {
        error = "Could not write the code cave.";
        VirtualFreeEx(proc.Handle(), cave, 0, MEM_RELEASE);
        return false;
    }

    std::vector<uint8_t> hook = MakeJump(entry, caveAddr, x64);
    hook.resize(stolen, 0x90);
    if (!proc.Write(entry, hook.data(), hook.size()))
    {
        error = "Write failed at " + Hex(entry) + " (page protected?)";
        VirtualFreeEx(proc.Handle(), cave, 0, MEM_RELEASE);
        return false;
    }

    Detour d;
    d.entry = entry;
    d.original = original;
    d.hook = hook;
    d.target = caveAddr;
    d.cave = caveAddr;
    d.caveSize = caveSize;
    d.caveUserSize = userBytes;
    d.stolenLen = stolen;
    d.kind = "trampoline";
    d.location = proc.Symbolize(entry);
    m_detours.push_back(std::move(d));
    return true;
}

bool DetourManager::ReplaceInstruction(const Process& proc, uint64_t addr, const std::vector<uint8_t>& newInsn,
                                       std::string& error)
{
    if (!proc.IsOpen()) { error = "No process attached"; return false; }
    if (newInsn.empty()) { error = "Nothing to assemble"; return false; }

    // Already hooked here? Don't stack a second trampoline - undo the old one (restoring the
    // original bytes and freeing its cave) and build a fresh one in its place.
    if (Find(addr)) Remove(proc, addr);

    const bool x64 = proc.Is64();
    const size_t jsz = JumpSize(x64);

    // Length of the instruction we're replacing.
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    uint8_t cb[32];
    size_t cg = proc.Read(addr, cb, sizeof(cb));
    ZydisDecodedInstruction ci;
    if (cg == 0 || !ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, cb, cg, &ci)))
    { error = "Could not decode the instruction to replace."; return false; }
    const size_t replLen = ci.length;

    // Steal whole instructions to make room for the jump, keep the originals to restore.
    size_t stolen = 0;
    if (!StealLength(proc, addr, jsz, stolen, error)) return false;
    std::vector<uint8_t> original(stolen);
    if (!proc.ReadExact(addr, original.data(), original.size()))
    { error = "Could not read the original bytes at " + Hex(addr); return false; }

    // The instructions the jump clobbers after the one we're replacing must still run.
    std::vector<uint8_t> remaining(original.begin() + replLen, original.end());

    const size_t caveSize = newInsn.size() + remaining.size() + jsz;
    LPVOID cave = AllocNear(proc.Handle(), addr, caveSize);
    if (!cave) cave = VirtualAllocEx(proc.Handle(), nullptr, caveSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!cave) { error = "Could not allocate a cave for the larger instruction."; return false; }
    const uint64_t caveAddr = (uint64_t)cave;

    // cave = [new instruction][remaining stolen instructions][jump back], all RIP-fixed.
    std::vector<uint8_t> n = newInsn;
    if (!RelocateStolen(x64, addr, caveAddr, n, error)) { VirtualFreeEx(proc.Handle(), cave, 0, MEM_RELEASE); return false; }
    std::vector<uint8_t> rem = remaining;
    if (!RelocateStolen(x64, addr + replLen, caveAddr + n.size(), rem, error))
    { VirtualFreeEx(proc.Handle(), cave, 0, MEM_RELEASE); return false; }

    std::vector<uint8_t> caveBytes;
    caveBytes.insert(caveBytes.end(), n.begin(), n.end());
    caveBytes.insert(caveBytes.end(), rem.begin(), rem.end());
    std::vector<uint8_t> back = MakeJump(caveAddr + n.size() + rem.size(), addr + stolen, x64);
    caveBytes.insert(caveBytes.end(), back.begin(), back.end());
    if (!proc.Write(caveAddr, caveBytes.data(), caveBytes.size()))
    { error = "Could not write the cave."; VirtualFreeEx(proc.Handle(), cave, 0, MEM_RELEASE); return false; }

    std::vector<uint8_t> hook = MakeJump(addr, caveAddr, x64);
    hook.resize(stolen, 0x90);
    if (!proc.Write(addr, hook.data(), hook.size()))
    { error = "Write failed at " + Hex(addr) + " (page protected?)"; VirtualFreeEx(proc.Handle(), cave, 0, MEM_RELEASE); return false; }

    Detour d;
    d.entry = addr;
    d.original = original;
    d.hook = hook;
    d.target = caveAddr;
    d.cave = caveAddr;
    d.caveSize = caveSize;
    d.caveUserSize = newInsn.size();
    d.stolenLen = stolen;
    d.kind = "assemble";
    d.location = proc.Symbolize(addr);
    m_detours.push_back(std::move(d));
    return true;
}

bool DetourManager::SetCaveImmediate(const Process& proc, uint64_t entry, uint64_t value, std::string& error)
{
    if (!proc.IsOpen()) { error = "No process attached"; return false; }
    Detour* d = FindMutable(entry);
    if (!d || !d->cave) { error = "This entry has no cave."; return false; }

    const bool x64 = proc.Is64();
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

    // Locate the first stolen instruction that carries a plain (non-branch) immediate.
    size_t ao = 0, al = 0;
    bool found = false;
    for (size_t off = 0; off < d->original.size();)
    {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, d->original.data() + off, d->original.size() - off, &ins, ops)))
            break;
        for (int i = 0; i < ins.operand_count_visible; i++)
            if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !ops[i].imm.is_relative) { found = true; break; }
        if (found) { ao = off; al = ins.length; break; }
        off += ins.length;
    }
    if (!found) { error = "No immediate instruction was stolen into this cave."; return false; }

    std::vector<uint8_t> insn(d->original.begin() + ao, d->original.begin() + ao + al);
    std::vector<uint8_t> encoded;
    if (!EncodeImmediateReloc(insn, x64, value, entry + ao, d->cave, encoded, error)) return false;
    if (encoded.size() > d->caveUserSize)
    {
        error = "Not enough free bytes (" + std::to_string(encoded.size()) + " needed, " +
                std::to_string(d->caveUserSize) + " free). Reinstall the cave with more free bytes.";
        return false;
    }

    // Free region = the widened instruction followed by NOPs.
    std::vector<uint8_t> freeBytes(d->caveUserSize, 0x90);
    memcpy(freeBytes.data(), encoded.data(), encoded.size());
    if (!proc.Write(d->cave, freeBytes.data(), freeBytes.size())) { error = "Could not write the cave."; return false; }

    // NOP the stolen copy of that instruction so the value isn't applied twice.
    std::vector<uint8_t> nops(al, 0x90);
    proc.Write(d->cave + d->caveUserSize + ao, nops.data(), nops.size());
    return true;
}

void DetourManager::SetEnabled(const Process& proc, uint64_t entry, bool enabled)
{
    Detour* d = FindMutable(entry);
    if (!d || d->enabled == enabled) return;
    const std::vector<uint8_t>& bytes = enabled ? d->hook : d->original;
    if (proc.Write(entry, bytes.data(), bytes.size())) d->enabled = enabled;
}

void DetourManager::Remove(const Process& proc, uint64_t entry)
{
    for (auto it = m_detours.begin(); it != m_detours.end(); ++it)
        if (it->entry == entry)
        {
            proc.Write(entry, it->original.data(), it->original.size());
            if (it->cave) VirtualFreeEx(proc.Handle(), (LPVOID)it->cave, 0, MEM_RELEASE);
            m_detours.erase(it);
            return;
        }
}

void DetourManager::RestoreAll(const Process& proc)
{
    for (auto& d : m_detours)
    {
        proc.Write(d.entry, d.original.data(), d.original.size());
        d.enabled = false;
    }
}

void DetourManager::Clear() { m_detours.clear(); }
