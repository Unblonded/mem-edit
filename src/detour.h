#pragma once
#include "target.h"

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
    size_t caveUserSize = 0;         // editable region at the start of the cave
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

    // Rewrites the stolen immediate instruction (e.g. an `add [gold], 25`) in the cave with a new
    // value, letting it grow past the original immediate width. The widened instruction goes in the
    // cave's free bytes and the stolen copy of it is NOP'd, so the new value takes effect.
    bool SetCaveImmediate(const Process& proc, uint64_t entry, uint64_t value, std::string& error);

    void SetEnabled(const Process& proc, uint64_t entry, bool enabled);
    void Remove(const Process& proc, uint64_t entry);  // restores original, frees the cave
    void RestoreAll(const Process& proc);
    void Clear();                                       // forget all (does not free - process gone)

    const Detour* Find(uint64_t entry) const;
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
