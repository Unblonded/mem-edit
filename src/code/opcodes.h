#pragma once
#include <string>
#include <vector>

// The x86 / x64 instruction reference behind the Opcodes window: what each instruction does, how it
// is encoded, which flags it changes, and what it is good for when patching code.
struct OpcodeRef
{
    std::string mnemonic;   // "mov", "jne", or a topic name for encoding notes and recipes
    std::string aliases;    // other spellings: "jnz" for jne
    std::string category;
    std::string encodings;  // "89 /r  8B /r  B8+r id"
    std::string summary;    // one line
    std::string details;    // the long explanation
    std::string flags;      // flags written, or "" when none
    std::string example;    // "mov eax, dword ptr [rcx+0x24]"
    std::string exampleBytes; // "8B 41 24"
    std::string tip;        // what it means for game modding / patching
};

const std::vector<OpcodeRef>& OpcodeReference();
const std::vector<std::string>& OpcodeCategories(); // in display order
