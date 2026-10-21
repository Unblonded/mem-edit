#pragma once
#include "decompiler.h"
#include "target.h"

#include <cstdint>
#include <string>
#include <vector>

// A single code patch: the bytes we wrote and the bytes that were there before, so it can be
// toggled on and off and fully reverted. Patches live only in the target's memory.
struct CodePatch
{
    uint64_t address = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
    std::string label;     // "NOP", "set 25 -> 28", "edit bytes"
    std::string location;  // module+offset at the time it was made
    bool enabled = true;
};

// Owns every code patch made from the Decompile window. Writes go through the Process; the
// manager keeps the original bytes so disabling or removing a patch restores them exactly.
class PatchManager
{
public:
    // Replace the whole instruction with NOPs.
    bool Nop(const Process& proc, const InstructionRow& row, std::string& error);
    // Re-encode the instruction's immediate operand to `value`.
    bool SetImmediate(const Process& proc, const InstructionRow& row, uint64_t value, std::string& error);
    // Overwrite `address` with raw bytes (same length as the original instruction).
    bool SetBytes(const Process& proc, const InstructionRow& row, const std::vector<uint8_t>& bytes,
                  std::string& error);

    void SetEnabled(const Process& proc, uint64_t address, bool enabled);
    void Remove(const Process& proc, uint64_t address);  // restores the original, then forgets it
    void RestoreAll(const Process& proc);                // writes back every original, keeps the list
    void Clear() { m_patches.clear(); }

    const CodePatch* Find(uint64_t address) const;
    const std::vector<CodePatch>& All() const { return m_patches; }
    bool Empty() const { return m_patches.empty(); }

private:
    CodePatch* FindMutable(uint64_t address);
    bool Store(const Process& proc, const InstructionRow& row, const std::vector<uint8_t>& newBytes,
               const std::string& label, std::string& error);

    std::vector<CodePatch> m_patches;
};
