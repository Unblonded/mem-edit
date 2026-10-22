#include "code/asmline.h"

#include "code/decompiler.h"

#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>

namespace
{
std::string Trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
}

std::string Lower(std::string s)
{
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

void Put32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; i++) v.push_back((uint8_t)(x >> (8 * i)));
}
void Put64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8 * i)));
}

// Condition-code number for a jcc mnemonic ("jne" -> 5), or -1.
int ConditionCode(const std::string& m)
{
    static const struct { const char* n; int cc; } kCc[] = {
        { "jo", 0 }, { "jno", 1 }, { "jb", 2 }, { "jc", 2 }, { "jnae", 2 }, { "jae", 3 }, { "jnb", 3 }, { "jnc", 3 },
        { "je", 4 }, { "jz", 4 }, { "jne", 5 }, { "jnz", 5 }, { "jbe", 6 }, { "jna", 6 }, { "ja", 7 }, { "jnbe", 7 },
        { "js", 8 }, { "jns", 9 }, { "jp", 10 }, { "jpe", 10 }, { "jnp", 11 }, { "jpo", 11 }, { "jl", 12 },
        { "jnge", 12 }, { "jge", 13 }, { "jnl", 13 }, { "jle", 14 }, { "jng", 14 }, { "jg", 15 }, { "jnle", 15 },
    };
    for (const auto& c : kCc)
        if (m == c.n) return c.cc;
    return -1;
}

// jmp / call / jcc to an absolute target from `at`. Returns false with a reason when it can't reach.
bool EncodeBranch(const std::string& m, uint64_t at, uint64_t target, bool x64, std::vector<uint8_t>& out,
                  std::string& error)
{
    auto rel = [&](int len) { return (int64_t)(target - (at + len)); };
    auto fits8 = [](int64_t d) { return d >= -128 && d <= 127; };
    auto fits32 = [&](int64_t d) { return !x64 || (d >= INT32_MIN && d <= INT32_MAX); };
    const int cc = ConditionCode(m);
    if (m == "jmp")
    {
        if (fits8(rel(2))) out = { 0xEB, (uint8_t)rel(2) };
        else if (fits32(rel(5))) { out = { 0xE9 }; Put32(out, (uint32_t)rel(5)); }
        else
        {
            // jmp qword ptr [rip+0] ; <absolute target>
            out = { 0xFF, 0x25, 0, 0, 0, 0 };
            Put64(out, target);
        }
        return true;
    }
    if (m == "call")
    {
        if (fits32(rel(5))) { out = { 0xE8 }; Put32(out, (uint32_t)rel(5)); }
        else
        {
            // call qword ptr [rip+2] ; jmp +8 (over the address) ; <absolute target>
            out = { 0xFF, 0x15, 0x02, 0, 0, 0, 0xEB, 0x08 };
            Put64(out, target);
        }
        return true;
    }
    if (cc >= 0)
    {
        if (fits8(rel(2))) out = { (uint8_t)(0x70 + cc), (uint8_t)rel(2) };
        else if (fits32(rel(6))) { out = { 0x0F, (uint8_t)(0x80 + cc) }; Put32(out, (uint32_t)rel(6)); }
        else
        {
            error = m + ": the target is more than 2 GB away - jump to a cave with jmp first";
            return false;
        }
        return true;
    }
    return false;
}
} // namespace

std::vector<uint8_t> NopFill(size_t n)
{
    static const std::vector<uint8_t> kNops[10] = {
        {},
        { 0x90 },
        { 0x66, 0x90 },
        { 0x0F, 0x1F, 0x00 },
        { 0x0F, 0x1F, 0x40, 0x00 },
        { 0x0F, 0x1F, 0x44, 0x00, 0x00 },
        { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 },
        { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 },
        { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    std::vector<uint8_t> out;
    while (n > 0)
    {
        size_t k = n > 9 ? 9 : n;
        out.insert(out.end(), kNops[k].begin(), kNops[k].end());
        n -= k;
    }
    return out;
}

bool AssembleLine(const Process& proc, const std::string& text, uint64_t at, std::vector<AsmPart>& parts,
                  std::string& error)
{
    parts.clear();
    const bool x64 = proc.Is64();
    uint64_t addr = at;
    size_t start = 0;
    while (start <= text.size())
    {
        size_t semi = text.find(';', start);
        std::string piece = Trim(text.substr(start, semi == std::string::npos ? std::string::npos : semi - start));
        start = semi == std::string::npos ? text.size() + 1 : semi + 1;
        if (piece.empty()) continue;

        size_t sp = piece.find_first_of(" \t");
        const std::string m = Lower(sp == std::string::npos ? piece : piece.substr(0, sp));
        const std::string arg = sp == std::string::npos ? "" : Trim(piece.substr(sp));
        AsmPart part;
        part.source = piece;
        part.address = addr;
        std::string err;

        if (m == "db")
        {
            // db 90 90 C3   /   db 0x90, 0xC3
            std::string a = arg;
            for (auto& c : a)
                if (c == ',') c = ' ';
            size_t i = 0;
            while (i < a.size())
            {
                while (i < a.size() && isspace((unsigned char)a[i])) i++;
                if (i >= a.size()) break;
                size_t j = i;
                while (j < a.size() && !isspace((unsigned char)a[j])) j++;
                std::string tok = a.substr(i, j - i);
                if (tok.size() > 2 && (tok[1] == 'x' || tok[1] == 'X')) tok = tok.substr(2);
                char* end = nullptr;
                unsigned long v = strtoul(tok.c_str(), &end, 16);
                if (tok.empty() || *end || v > 0xFF) { error = "db: '" + a.substr(i, j - i) + "' isn't a hex byte"; return false; }
                part.bytes.push_back((uint8_t)v);
                i = j;
            }
            if (part.bytes.empty()) { error = "db needs at least one byte, e.g. db 90 C3"; return false; }
        }
        else if (m == "nop" && !arg.empty() && isdigit((unsigned char)arg[0]) && arg.find_first_not_of("0123456789") == std::string::npos)
        {
            long n = strtol(arg.c_str(), nullptr, 10);
            if (n < 1 || n > 256) { error = "nop <n>: n must be 1-256"; return false; }
            part.bytes = NopFill((size_t)n);
        }
        else if ((m == "jmp" || m == "call" || ConditionCode(m) >= 0) && !arg.empty() && arg.find('[') == std::string::npos)
        {
            // A branch to an address expression; registers ("jmp rax") fall through to the assembler.
            uint64_t target = 0;
            std::string evalErr;
            if (EvaluateAddress(proc, arg, target, &evalErr))
            {
                if (!EncodeBranch(m, addr, target, x64, part.bytes, err)) { error = err; return false; }
            }
            else if (!AssembleInstruction(piece, x64, addr, part.bytes, err))
            {
                error = m + ": can't resolve '" + arg + "' (" + evalErr + ")";
                return false;
            }
        }
        else if (!AssembleInstruction(piece, x64, addr, part.bytes, err))
        {
            error = parts.empty() && start > text.size() ? err : "'" + piece + "': " + err;
            return false;
        }
        addr += part.bytes.size();
        parts.push_back(std::move(part));
    }
    if (parts.empty()) { error = "Type an instruction"; return false; }
    return true;
}
