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

// Re-encodes `insnBytes` with its immediate operand set to `value`. The result is at most as
// long as the input, padded with NOPs if shorter. Does not touch the target.
bool EncodeImmediate(const std::vector<uint8_t>& insnBytes, bool x64, uint64_t value,
                     std::vector<uint8_t>& encoded, std::string& error);

// Re-encodes the instruction in `row` with its immediate set to `value` and writes it into the
// target. `original` receives the bytes that were there before.
bool PatchImmediate(const Process& proc, const InstructionRow& row, uint64_t value,
                    std::vector<uint8_t>& original, std::string& error);
