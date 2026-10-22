#pragma once
#include "core/target.h"

#include <cstdint>
#include <string>
#include <vector>

// A function hook. We overwrite the first whole instructions at `entry` with a jump. For a
// redirect the jump goes to `target`. For a trampoline detour we allocate a code cave in the
// target: [your bytes][the stolen instructions][jump back], and the entry jumps into the cave,
// so the original behaviour is preserved and your bytes run first.
struct Detour
{
    uint64_t entry = 0;
    std::vector<uint8_t> original;   // bytes we overwrote at the entry (to restore)
    std::vector<uint8_t> hook;       // the jump (+ NOP padding) we wrote at the entry
    uint64_t target = 0;             // redirect destination, or the cave address
    uint64_t cave = 0;               // allocated cave (0 for a plain redirect)
    size_t caveSize = 0;
    size_t caveUserSize = 0;         // size of the editable free region in the cave
    size_t caveFreeOff = 0;          // offset of the free region within the cave (see InstallTrampoline)
    size_t stolenLen = 0;
    std::string kind;                // "redirect" or "trampoline"
    std::string location;
    bool enabled = true;
};

// Installs and tracks detours. All memory lives in the target; the manager keeps the original
// bytes and frees any allocated caves on removal.
class DetourManager
{
public:
    ~DetourManager() { Clear(); }

    // Redirect the function at `entry` straight to `target` (no trampoline). Used to send a
    // function elsewhere, or point it at a cave / a `ret`.
    bool Redirect(const Process& proc, uint64_t entry, uint64_t target, std::string& error);

    // Allocate a code cave and route `entry` through it, preserving the original. `userBytes` is
    // how many editable NOP bytes to reserve at the start of the cave for your own code.
    bool InstallTrampoline(const Process& proc, uint64_t entry, size_t userBytes, std::string& error);

    // Replaces the instruction at `addr` with `newInsn` when it doesn't fit in place: installs a
    // jump into a fresh cave holding [newInsn][the other stolen instructions][jump back], so a
    // larger instruction has room. RIP-relative operands in the new and stolen bytes are fixed up.
    bool ReplaceInstruction(const Process& proc, uint64_t addr, const std::vector<uint8_t>& newInsn,
                            std::string& error);

    // Rewrites the stolen immediate instruction (e.g. an `add [gold], 25`) in the cave with a new
    // value, letting it grow past the original immediate width. The widened instruction goes in the
    // cave's free bytes and the stolen copy of it is NOP'd, so the new value takes effect.
    bool SetCaveImmediate(const Process& proc, uint64_t entry, uint64_t value, std::string& error);

    // Replaces the instruction at `addr` inside a cave's free region with `newInsn`, reflowing the
    // instructions after it: a larger instruction pushes them down (into the NOP padding), a smaller
    // one pulls them up and re-pads with NOPs. RIP-relative and relative operands in the shifted
    // instructions are fixed for their new address. Fails if the result won't fit the free region.
    bool EditCaveCode(const Process& proc, uint64_t addr, const std::vector<uint8_t>& newInsn,
                      std::string& error);

    void SetEnabled(const Process& proc, uint64_t entry, bool enabled);
    void Remove(const Process& proc, uint64_t entry);  // restores original, frees the cave
    void RestoreAll(const Process& proc);
    void Clear();                                       // forget all (does not free - process gone)

    const Detour* Find(uint64_t entry) const;
    // The detour whose cave's free region contains `addr` (where you'd write your own code),
    // or null. Lets the host write assembled bytes straight into a cave instead of re-hooking.
    const Detour* CaveForAddress(uint64_t addr) const;
    const std::vector<Detour>& All() const { return m_detours; }
    bool Empty() const { return m_detours.empty(); }

private:
    // Whole instructions at `addr` totalling at least `min` bytes; false if it can't be decoded.
    bool StealLength(const Process& proc, uint64_t addr, size_t min, size_t& len, std::string& error);
    Detour* FindMutable(uint64_t entry);

    std::vector<Detour> m_detours;
};

// Bytes for a jump from `from` to `to` on the given architecture (14-byte absolute on x64,
// 5-byte relative on x86).
std::vector<uint8_t> MakeJump(uint64_t from, uint64_t to, bool x64);
size_t JumpSize(bool x64);
