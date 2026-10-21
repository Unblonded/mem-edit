#pragma once
#include "target.h"

#include <cstdint>
#include <string>
#include <vector>

// Lifts the function that contains `address` into C-like pseudo code. On x64 the function
// bounds come from the exception directory; otherwise the code reachable from `address` is
// used. Registers become locals, flags come from the last compare, and control flow is
// recovered into if / while / do-while where the shape allows, falling back to goto. Anything
// not modelled is kept as a /* assembly */ comment.
bool DecompileFunction(const Process& proc, uint64_t address, std::string& out, std::string& error);

struct InstructionRow
{
    uint64_t address = 0;
    std::vector<uint8_t> bytes;
    std::string text;
    bool hasImmediate = false; // a plain immediate operand (not a branch target) that can be patched
    bool isBranch = false;     // call / jump / conditional branch (do not NOP blindly)
    uint64_t immediate = 0;
};

// Linear disassembly of the function that contains `address`.
bool DisassembleFunction(const Process& proc, uint64_t address, std::vector<InstructionRow>& out, std::string& error);

// Linear disassembly of a raw byte buffer, decoded as if it were loaded at `base`. Useful for
// bytes that no longer live at their original address (e.g. a detour's saved original code).
void DisassembleBytes(const std::vector<uint8_t>& bytes, uint64_t base, bool x64, std::vector<InstructionRow>& out);

// Re-encodes `insnBytes` with its immediate operand set to `value`. The result is at most as
// long as the input, padded with NOPs if shorter. Does not touch the target.
bool EncodeImmediate(const std::vector<uint8_t>& insnBytes, bool x64, uint64_t value,
                     std::vector<uint8_t>& encoded, std::string& error);

// Re-encodes the instruction in `row` with its immediate set to `value` and writes it into the
// target. `original` receives the bytes that were there before.
bool PatchImmediate(const Process& proc, const InstructionRow& row, uint64_t value,
                    std::vector<uint8_t>& original, std::string& error);

// Assembles a single Intel-syntax instruction (e.g. "mov dword ptr [0x7FF6BD4FB004], 100") into
// machine code. `atAddr` is where the bytes will live, so an absolute [address] is encoded
// RIP-relative to reach it. Immediates are decimal unless prefixed 0x. Relative branches
// (jmp/call to an address) are not supported. Returns false with a human-readable error.
bool AssembleInstruction(const std::string& text, bool x64, uint64_t atAddr,
                         std::vector<uint8_t>& out, std::string& error);

// Re-encodes `insnBytes` with its immediate set to `value`, ALLOWING the encoding to grow (so a
// value too big for the original immediate width still works), and fixes a RIP-relative memory
// operand so the instruction still targets the same absolute address when placed at `newAddr`
// (it originally lived at `origAddr`). Intended for writing a widened instruction into a cave.
bool EncodeImmediateReloc(const std::vector<uint8_t>& insnBytes, bool x64, uint64_t value,
                          uint64_t origAddr, uint64_t newAddr, std::vector<uint8_t>& encoded,
                          std::string& error);
