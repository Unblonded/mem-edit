#include "ui/syntax.h"

#include <cctype>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

namespace Syntax
{
namespace
{
struct Run
{
    const char* begin;
    const char* end;
    ImVec4 col;
};

bool StartsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }
bool EndsWith(const std::string& s, const char* p)
{
    size_t n = strlen(p);
    return s.size() >= n && s.compare(s.size() - n, n, p) == 0;
}
bool OneOf(const std::string& s, std::initializer_list<const char*> set)
{
    for (const char* x : set)
        if (s == x) return true;
    return false;
}
bool IsIdentStart(char c) { return isalpha((unsigned char)c) || c == '_'; }
bool IsIdent(char c) { return isalnum((unsigned char)c) || c == '_'; }

// Splits an Intel-syntax instruction into coloured runs.
std::vector<Run> TokenizeInstruction(const char* text)
{
    std::vector<Run> runs;
    const ImVec4 plain = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    const char* p = text;
    auto word = [&](const char* s) {
        const char* e = s;
        while (IsIdent(*e)) e++;
        return e;
    };

    // Prefixes ("lock", "rep") then the mnemonic.
    static const char* kPrefixes[] = { "lock", "rep", "repe", "repz", "repne", "repnz", "bnd", "notrack", "xacquire", "xrelease" };
    while (*p)
    {
        while (*p == ' ') runs.push_back({ p, p + 1, plain }), p++;
        const char* e = word(p);
        if (e == p) break;
        std::string w(p, e);
        bool prefix = false;
        for (const char* x : kPrefixes)
            if (w == x) prefix = true;
        runs.push_back({ p, e, prefix ? kDim : MnemonicColor(w) });
        p = e;
        if (!prefix) break;
    }

    // Operands.
    while (*p)
    {
        const char c = *p;
        if (c == ' ')
        {
            runs.push_back({ p, p + 1, plain });
            p++;
        }
        else if (isdigit((unsigned char)c))
        {
            const char* e = p;
            while (isxdigit((unsigned char)*e) || *e == 'x' || *e == 'X') e++;
            runs.push_back({ p, e, kNumber });
            p = e;
        }
        else if (IsIdentStart(c))
        {
            const char* e = word(p);
            std::string w(p, e);
            static const char* kKeywords[] = { "byte", "word", "dword", "qword", "tword", "tbyte", "xmmword", "ymmword",
                                               "zmmword", "ptr", "far", "near", "short", "fword", "oword" };
            bool kw = false;
            for (const char* k : kKeywords)
                if (w == k) kw = true;
            runs.push_back({ p, e, kw ? kPunct : kRegister });
            p = e;
        }
        else
        {
            runs.push_back({ p, p + 1, kPunct });
            p++;
        }
    }
    return runs;
}

void DrawRuns(const std::vector<Run>& runs)
{
    // Consecutive same-colour runs are merged so a line is a handful of items.
    bool first = true;
    for (size_t i = 0; i < runs.size();)
    {
        size_t j = i + 1;
        while (j < runs.size() && runs[j].begin == runs[j - 1].end && memcmp(&runs[j].col, &runs[i].col, sizeof(ImVec4)) == 0) j++;
        if (!first) ImGui::SameLine(0, 0);
        first = false;
        ImGui::PushStyleColor(ImGuiCol_Text, runs[i].col);
        ImGui::TextUnformatted(runs[i].begin, runs[j - 1].end);
        ImGui::PopStyleColor();
        i = j;
    }
    if (first) ImGui::TextUnformatted("");
}
} // namespace

ImVec4 MnemonicColor(const std::string& m)
{
    if (m.empty()) return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    if (m == "call") return kCall;
    if (StartsWith(m, "ret") || StartsWith(m, "iret")) return kRet;
    if (m[0] == 'j' || StartsWith(m, "loop")) return kJump;
    if (OneOf(m, { "nop", "int3", "ud2", "hlt", "pause", "fnop", "endbr64", "endbr32" }) || StartsWith(m, "nop")) return kDim;
    if (OneOf(m, { "syscall", "sysenter", "sysexit", "sysret", "int", "int1", "into", "cpuid", "rdtsc", "rdtscp", "rdmsr",
                   "wrmsr", "in", "out", "cli", "sti" }))
        return kSystem;
    if (StartsWith(m, "cmov") || StartsWith(m, "mov") || StartsWith(m, "push") || StartsWith(m, "pop") ||
        OneOf(m, { "lea", "xchg", "bswap", "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo", "leave", "enter" }) ||
        StartsWith(m, "set") || StartsWith(m, "stos") || StartsWith(m, "lods") || StartsWith(m, "xlat"))
        return kMove;
    if (StartsWith(m, "cmp") || OneOf(m, { "test", "bt", "bts", "btr", "btc", "ptest", "vptest" }) || StartsWith(m, "scas") ||
        StartsWith(m, "comis") || StartsWith(m, "ucomis") || StartsWith(m, "vcomis") || StartsWith(m, "vucomis"))
        return kCompare;
    if (OneOf(m, { "add", "adc", "sub", "sbb", "inc", "dec", "neg", "not", "and", "or", "xor", "shl", "shr", "sal", "sar",
                   "rol", "ror", "rcl", "rcr", "imul", "mul", "div", "idiv", "shld", "shrd", "andn", "popcnt", "lzcnt",
                   "tzcnt", "bsf", "bsr", "xadd", "adcx", "adox", "blsr", "blsi", "blsmsk", "bzhi", "sarx", "shlx", "shrx",
                   "rorx", "mulx", "pdep", "pext" }))
        return kArith;
    if (m[0] == 'v' || m[0] == 'p' || m[0] == 'f' || StartsWith(m, "cvt") || EndsWith(m, "ps") || EndsWith(m, "pd") ||
        EndsWith(m, "ss") || EndsWith(m, "sd") || StartsWith(m, "sqrt") || StartsWith(m, "shuf") || StartsWith(m, "unpck"))
        return kSimd;
    return ImGui::GetStyleColorVec4(ImGuiCol_Text);
}

void Instruction(const char* text)
{
    DrawRuns(TokenizeInstruction(text ? text : ""));
}

float DrawInstruction(ImDrawList* dl, ImVec2 pos, const char* text, float alpha)
{
    for (const Run& r : TokenizeInstruction(text ? text : ""))
    {
        ImVec4 c = r.col;
        c.w *= alpha;
        dl->AddText(pos, ImGui::ColorConvertFloat4ToU32(c), r.begin, r.end);
        pos.x += ImGui::CalcTextSize(r.begin, r.end).x;
    }
    return pos.x;
}

void Expression(const char* text)
{
    // ["game.exe"+1F0]+18  /  [[game.exe+10]+8]  /  7FF6A0001000
    std::vector<Run> runs;
    const char* p = text ? text : "";
    while (*p)
    {
        const char c = *p;
        if (c == '"')
        {
            const char* e = strchr(p + 1, '"');
            e = e ? e + 1 : p + strlen(p);
            runs.push_back({ p, e, kModule });
            p = e;
        }
        else if (isxdigit((unsigned char)c) || c == '#')
        {
            // A run of word characters: a number unless it contains a '.' (game.exe).
            const char* e = p;
            bool name = false;
            while (IsIdent(*e) || *e == '.' || *e == '#')
            {
                if (*e == '.' || !isxdigit((unsigned char)*e)) name |= *e != '#' && !isxdigit((unsigned char)*e);
                e++;
            }
            runs.push_back({ p, e, name ? kModule : kNumber });
            p = e;
        }
        else if (IsIdentStart(c))
        {
            const char* e = p;
            while (IsIdent(*e) || *e == '.' || *e == '-') e++;
            runs.push_back({ p, e, kModule });
            p = e;
        }
        else
        {
            runs.push_back({ p, p + 1, kPunct });
            p++;
        }
    }
    DrawRuns(runs);
}

ImVec4 TypeColor(ValueType t)
{
    switch (t)
    {
    case ValueType::Float:
    case ValueType::Double: return kArith;
    case ValueType::String:
    case ValueType::WString: return kCall;
    case ValueType::ByteArray: return kSimd;
    default: return kMove;
    }
}

void LogLine(const std::string& line)
{
    // "[17:29:58] message"
    size_t msg = 0;
    if (!line.empty() && line[0] == '[')
    {
        size_t close = line.find(']');
        if (close != std::string::npos && close < 12)
        {
            msg = close + 1;
            ImGui::PushStyleColor(ImGuiCol_Text, kDim);
            ImGui::TextUnformatted(line.c_str(), line.c_str() + msg);
            ImGui::PopStyleColor();
            ImGui::SameLine(0, 0);
        }
    }
    std::string low = line.substr(msg);
    for (auto& ch : low) ch = (char)tolower((unsigned char)ch);
    auto has = [&](const char* s) { return low.find(s) != std::string::npos; };

    ImVec4 col = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    if (has("fail") || has("error") || has("invalid") || has("could not") || has("cannot") || has("couldn't") ||
        has("denied"))
        col = kSystem;
    else if (has("attached") || has("saved") || has("loaded") || has("resumed") || has("installed") ||
             has("running as administrator") || has("restored"))
        col = kModule;
    else if (has("detached") || has("exited") || has("suspended") || has("not elevated") || has("cancel"))
        col = kJump;
    else if (has("watching") || has("trace") || has("breakpoint") || has("accesses") || has("writes to"))
        col = kCall;
    else if (has("nop") || has("redirect") || has("patch") || has("cave") || has("detour") || has("assembl"))
        col = kSimd;
    else if (has("scan") || has("results") || has("matches") || has("paths") || has("modules refreshed"))
        col = kMove;
    ImGui::PushStyleColor(ImGuiCol_Text, col);
    ImGui::TextUnformatted(line.c_str() + msg, line.c_str() + line.size());
    ImGui::PopStyleColor();
}

namespace
{
// C++ token colours (reuse the shared palette so the editor matches the rest of the app).
const ImVec4 kCppKeyword = kCompare;                 // violet
const ImVec4 kCppType = kMove;                       // sky
const ImVec4 kCppString = kCall;                     // amber
const ImVec4 kCppNumber = kNumber;                   // green
const ImVec4 kCppComment = kDim;                     // dim grey
const ImVec4 kCppPreproc = kSimd;                    // orchid
const ImVec4 kCppPunct = kPunct;

bool IsKeyword(const std::string& w)
{
    static const std::unordered_set<std::string> k = {
        "alignas","alignof","and","asm","auto","break","case","catch","class","const","consteval",
        "constexpr","constinit","const_cast","continue","decltype","default","delete","do","dynamic_cast",
        "else","enum","explicit","export","extern","false","for","friend","goto","if","inline","mutable",
        "namespace","new","noexcept","not","nullptr","operator","or","private","protected","public",
        "register","reinterpret_cast","return","sizeof","static","static_assert","static_cast","struct",
        "switch","template","this","thread_local","throw","true","try","typedef","typaname","typename",
        "union","using","virtual","volatile","while","__try","__except","__declspec","__forceinline"
    };
    return k.count(w) != 0;
}
bool IsType(const std::string& w)
{
    static const std::unordered_set<std::string> t = {
        "void","bool","char","short","int","long","float","double","signed","unsigned","wchar_t","size_t",
        "int8_t","int16_t","int32_t","int64_t","uint8_t","uint16_t","uint32_t","uint64_t","intptr_t","uintptr_t",
        "DWORD","WORD","BYTE","QWORD","HANDLE","HMODULE","LPVOID","BOOL","UINT","ULONG","Regs","std"
    };
    return t.count(w) != 0;
}
} // namespace

ImVec2 DrawCppCode(ImDrawList* dl, ImVec2 origin, const char* s, float alpha)
{
    const float lineH = ImGui::GetTextLineHeight();
    const ImVec4 textCol = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    ImVec2 pos = origin;
    float maxX = origin.x;

    auto draw = [&](const char* b, const char* e, const ImVec4& c) {
        if (e <= b) return;
        ImVec4 cc(c.x, c.y, c.z, c.w * alpha);
        dl->AddText(pos, ImGui::GetColorU32(cc), b, e);
        pos.x += ImGui::CalcTextSize(b, e).x;
        if (pos.x > maxX) maxX = pos.x;
    };

    bool block = false;
    const char* p = s;
    while (*p)
    {
        if (*p == '\n') { pos.x = origin.x; pos.y += lineH; p++; continue; }
        if (block)
        {
            const char* b = p;
            while (*p && *p != '\n') { if (p[0] == '*' && p[1] == '/') { p += 2; block = false; break; } p++; }
            draw(b, p, kCppComment);
            continue;
        }
        if (*p == ' ' || *p == '\t') { const char* b = p; while (*p == ' ' || *p == '\t') p++; draw(b, p, textCol); continue; }
        if (p[0] == '/' && p[1] == '/') { const char* b = p; while (*p && *p != '\n') p++; draw(b, p, kCppComment); continue; }
        if (p[0] == '/' && p[1] == '*')
        {
            const char* b = p; p += 2; block = true;
            while (*p && *p != '\n') { if (p[0] == '*' && p[1] == '/') { p += 2; block = false; break; } p++; }
            draw(b, p, kCppComment);
            continue;
        }
        if (*p == '"' || *p == '\'')
        {
            char q = *p; const char* b = p; p++;
            while (*p && *p != '\n') { if (*p == '\\' && p[1]) { p += 2; continue; } if (*p == q) { p++; break; } p++; }
            draw(b, p, kCppString);
            continue;
        }
        if (*p == '#') { const char* b = p; p++; while (isalpha((unsigned char)*p)) p++; draw(b, p, kCppPreproc); continue; }
        if (isdigit((unsigned char)*p) || (*p == '.' && isdigit((unsigned char)p[1])))
        {
            const char* b = p;
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { p += 2; while (isxdigit((unsigned char)*p) || *p == '\'') p++; }
            else { while (isalnum((unsigned char)*p) || *p == '.' || *p == '\'') p++; }
            draw(b, p, kCppNumber);
            continue;
        }
        if (isalpha((unsigned char)*p) || *p == '_')
        {
            const char* b = p;
            while (isalnum((unsigned char)*p) || *p == '_') p++;
            std::string id(b, p);
            const ImVec4& c = IsKeyword(id) ? kCppKeyword : (IsType(id) ? kCppType : textCol);
            draw(b, p, c);
            continue;
        }
        const char* b = p; p++; draw(b, p, kCppPunct);
    }
    return ImVec2(maxX - origin.x, (pos.y + lineH) - origin.y);
}
} // namespace Syntax
