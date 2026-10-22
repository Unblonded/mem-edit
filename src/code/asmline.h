#pragma once
#include "core/target.h"

#include <cstdint>
#include <string>
#include <vector>

// One line of the Memory View's assembler: several instructions separated by ';', on top of the
// single-instruction AssembleInstruction. Adds what that can't do:
//   jmp / call / jcc <address>   relative branches to an address or expression (game.exe+1F00),
//                                short form when it reaches, near otherwise, and on x64 an absolute
//                                14-byte jmp / 16-byte call when the target is beyond +-2 GB
//   nop <n>                      one n-byte NOP sequence (multi-byte NOPs, not n x 90)
//   db <hex bytes>               raw bytes, e.g. db 90 90 C3
struct AsmPart
{
    std::string source;          // the text this came from
    uint64_t address = 0;        // where it will live
    std::vector<uint8_t> bytes;
};

bool AssembleLine(const Process& proc, const std::string& text, uint64_t at, std::vector<AsmPart>& parts,
                  std::string& error);

// The shortest run of recommended multi-byte NOPs covering exactly n bytes.
std::vector<uint8_t> NopFill(size_t n);
