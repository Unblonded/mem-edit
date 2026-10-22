#pragma once
#include "core/values.h"
#include "imgui.h"

#include <string>

// Colour coding shared by every view, so a call, a float or an error looks the same wherever it
// appears. Hues are muted to sit on the dark glass without shouting.
namespace Syntax
{
// Instruction classes
inline const ImVec4 kCall(0.94f, 0.76f, 0.46f, 1.f);    // amber   call
inline const ImVec4 kJump(0.95f, 0.61f, 0.47f, 1.f);    // coral   jmp / jcc / loop
inline const ImVec4 kRet(0.93f, 0.50f, 0.60f, 1.f);     // rose    ret
inline const ImVec4 kMove(0.62f, 0.76f, 0.96f, 1.f);    // sky     mov / lea / push / pop
inline const ImVec4 kArith(0.46f, 0.84f, 0.77f, 1.f);   // teal    add / sub / xor / shifts
inline const ImVec4 kCompare(0.77f, 0.66f, 0.96f, 1.f); // violet  cmp / test
inline const ImVec4 kSimd(0.88f, 0.66f, 0.91f, 1.f);    // orchid  SSE / AVX / x87
inline const ImVec4 kSystem(0.96f, 0.47f, 0.47f, 1.f);  // red     syscall / int / cpuid
// Operands and other tokens
inline const ImVec4 kRegister(0.84f, 0.88f, 0.97f, 1.f);
inline const ImVec4 kNumber(0.71f, 0.87f, 0.56f, 1.f);  // green
inline const ImVec4 kModule(0.62f, 0.84f, 0.78f, 1.f);  // module names (same green as static addresses)
inline const ImVec4 kPunct(0.52f, 0.58f, 0.70f, 1.f);   // brackets, commas, "qword ptr"
inline const ImVec4 kDim(0.46f, 0.50f, 0.60f, 1.f);     // nop / int3 / padding

// Colour for a mnemonic such as "call" or "vmovaps".
ImVec4 MnemonicColor(const std::string& mnemonic);

// An Intel-syntax instruction ("mov rax, qword ptr [rip+0x10]") as coloured runs, laid out like
// ImGui::TextUnformatted on the current line.
void Instruction(const char* text);
// The same into a draw list; returns the x where the text ends.
float DrawInstruction(ImDrawList* dl, ImVec2 pos, const char* text, float alpha = 1.f);

// An address expression or pointer path: ["game.exe"+1F0]+18
void Expression(const char* text);

// Draws C++ source into a draw list, coloured by token (keywords, types, strings, comments,
// numbers, preprocessor), handling newlines and /* */ blocks. Uses the current font for metrics,
// so push a monospace font first. Returns the drawn content size (width, height) from `origin`.
ImVec2 DrawCppCode(ImDrawList* dl, ImVec2 origin, const char* text, float alpha = 1.f);

// Draws multi-line Intel assembly (one instruction per line) into a draw list, each line coloured
// by Instruction(). Returns the content size (width, height) from `origin`.
ImVec2 DrawAsmCode(ImDrawList* dl, ImVec2 origin, const char* text, float alpha = 1.f);

// Value types: integers sky, floats teal, strings amber, byte arrays orchid.
ImVec4 TypeColor(ValueType t);

// A log line coloured by what it reports (errors, attach/detach, scans, traces, patches).
// The leading "[hh:mm:ss]" stamp is drawn dimmed.
void LogLine(const std::string& line);
} // namespace Syntax
