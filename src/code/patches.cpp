#include "code/patches.h"

#include <cstdio>

CodePatch* PatchManager::FindMutable(uint64_t address)
{
    for (auto& p : m_patches)
        if (p.address == address) return &p;
    return nullptr;
}

const CodePatch* PatchManager::Find(uint64_t address) const
{
    for (const auto& p : m_patches)
        if (p.address == address) return &p;
    return nullptr;
}

bool PatchManager::Store(const Process& proc, const InstructionRow& row, const std::vector<uint8_t>& newBytes,
                         const std::string& label, std::string& error)
{
    if (!proc.Write(row.address, newBytes.data(), newBytes.size()))
    {
        error = "Write failed - the page may be read-only or protected.";
        return false;
    }

    CodePatch* existing = FindMutable(row.address);
    if (existing)
    {
        // Keep the very first original so a later restore always reaches untouched code.
        existing->patched = newBytes;
        existing->label = label;
        existing->enabled = true;
        return true;
    }

    CodePatch p;
    p.address = row.address;
    p.original = row.bytes;
    p.patched = newBytes;
    p.label = label;
    p.location = proc.Symbolize(row.address);
    p.enabled = true;
    m_patches.push_back(std::move(p));
    return true;
}

bool PatchManager::Nop(const Process& proc, const InstructionRow& row, std::string& error)
{
    std::vector<uint8_t> nops(row.bytes.size(), 0x90);
    return Store(proc, row, nops, "NOP", error);
}

bool PatchManager::SetImmediate(const Process& proc, const InstructionRow& row, uint64_t value, std::string& error)
{
    std::vector<uint8_t> encoded;
    if (!EncodeImmediate(row.bytes, proc.Is64(), value, encoded, error)) return false;

    char label[64];
    snprintf(label, sizeof(label), "set %llu -> %llu", (unsigned long long)row.immediate, (unsigned long long)value);
    return Store(proc, row, encoded, row.hasImmediate ? label : "set bytes", error);
}

bool PatchManager::SetBytes(const Process& proc, const InstructionRow& row, const std::vector<uint8_t>& bytes,
                            std::string& error)
{
    if (bytes.size() != row.bytes.size())
    {
        error = "Enter exactly " + std::to_string(row.bytes.size()) + " bytes to keep the instruction length.";
        return false;
    }
    return Store(proc, row, bytes, "edit bytes", error);
}

void PatchManager::SetEnabled(const Process& proc, uint64_t address, bool enabled)
{
    CodePatch* p = FindMutable(address);
    if (!p || p->enabled == enabled) return;
    const std::vector<uint8_t>& bytes = enabled ? p->patched : p->original;
    if (proc.Write(address, bytes.data(), bytes.size())) p->enabled = enabled;
}

void PatchManager::Remove(const Process& proc, uint64_t address)
{
    for (auto it = m_patches.begin(); it != m_patches.end(); ++it)
        if (it->address == address)
        {
            proc.Write(address, it->original.data(), it->original.size());
            m_patches.erase(it);
            return;
        }
}

void PatchManager::RestoreAll(const Process& proc)
{
    for (auto& p : m_patches)
    {
        proc.Write(p.address, p.original.data(), p.original.size());
        p.enabled = false;
    }
}
