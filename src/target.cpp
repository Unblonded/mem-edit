#include "target.h"
#include "values.h"

#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iterator>

std::string WideToUtf8(const wchar_t* w)
{
    if (!w || !*w) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(len > 0 ? len - 1 : 0, '\0');
    if (len > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}

std::string ProtectToString(DWORD p)
{
    std::string s;
    switch (p & 0xFF)
    {
    case PAGE_NOACCESS: s = "---"; break;
    case PAGE_READONLY: s = "R--"; break;
    case PAGE_READWRITE: s = "RW-"; break;
    case PAGE_WRITECOPY: s = "RC-"; break;
    case PAGE_EXECUTE: s = "--X"; break;
    case PAGE_EXECUTE_READ: s = "R-X"; break;
    case PAGE_EXECUTE_READWRITE: s = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: s = "RCX"; break;
    default: s = p ? "???" : ""; break;
    }
    if (p & PAGE_GUARD) s += " G";
    if (p & PAGE_NOCACHE) s += " NC";
    if (p & PAGE_WRITECOMBINE) s += " WC";
    return s;
}

std::string StateToString(DWORD s)
{
    switch (s)
    {
    case MEM_COMMIT: return "Commit";
    case MEM_RESERVE: return "Reserve";
    case MEM_FREE: return "Free";
    default: return "?";
    }
}

std::string TypeToString(DWORD t)
{
    switch (t)
    {
    case MEM_IMAGE: return "Image";
    case MEM_MAPPED: return "Mapped";
    case MEM_PRIVATE: return "Private";
    default: return "";
    }
}

bool IsReadable(DWORD p)
{
    if (p & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    return (p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool IsWritable(DWORD p)
{
    if (p & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    return (p & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool IsExecutable(DWORD p)
{
    return (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool EnableDebugPrivilege()
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege",&tp.Privileges[0].Luid) &&
              AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

bool IsElevated()
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION e{};
    DWORD sz = 0;
    bool r = GetTokenInformation(token, TokenElevation, &e, sizeof(e), &sz) && e.TokenIsElevated;
    CloseHandle(token);
    return r;
}

static bool QueryIs64(HANDLE h)
{
    BOOL wow = FALSE;
    if (!IsWow64Process(h, &wow)) return true;
    return !wow;
}

std::vector<ProcessInfo> Process::Enumerate()
{
    std::vector<ProcessInfo> list;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return list;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.parentPid = pe.th32ParentProcessID;
            info.threads = pe.cntThreads;
            info.name = WideToUtf8(pe.szExeFile);
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h)
            {
                info.is64 = QueryIs64(h);
                CloseHandle(h);
            }
            else
            {
                info.accessible = false;
            }
            if (info.pid != 0) list.push_back(std::move(info));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return list;
}

bool Process::Open(DWORD pid, std::string& error)
{
    Close();
    DWORD access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                   PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME;
    HANDLE h = OpenProcess(access, FALSE, pid);
    if (!h)
    {
        // Fall back to read-only access.
        h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!h)
        {
            error = "OpenProcess failed (error " + std::to_string(GetLastError()) + "). Try running as administrator.";
            return false;
        }
    }
    m_handle = h;
    m_pid = pid;
    m_is64 = QueryIs64(h);

    wchar_t path[MAX_PATH * 2];
    DWORD len = (DWORD)std::size(path);
    if (QueryFullProcessImageNameW(h, 0, path, &len))
    {
        std::string full = WideToUtf8(path);
        size_t slash = full.find_last_of("\\/");
        m_name = slash == std::string::npos ? full : full.substr(slash + 1);
    }
    else
    {
        m_name = "pid " + std::to_string(pid);
    }
    RefreshModules();
    return true;
}

void Process::Close()
{
    if (m_handle)
    {
        if (m_suspended) Resume();
        CloseHandle(m_handle);
    }
    m_handle = nullptr;
    m_pid = 0;
    m_name.clear();
    m_suspended = false;
    std::lock_guard<std::mutex> lock(m_modMutex);
    m_modules.clear();
}

bool Process::IsAlive() const
{
    if (!m_handle) return false;
    DWORD code = 0;
    return GetExitCodeProcess(m_handle, &code) && code == STILL_ACTIVE;
}

size_t Process::Read(uint64_t address, void* buffer, size_t size, std::vector<uint8_t>* valid) const
{
    if (valid) valid->assign(size, 0);
    if (!m_handle || size == 0) return 0;

    SIZE_T got = 0;
    if (ReadProcessMemory(m_handle, (LPCVOID)address, buffer, size, &got) && got == size)
    {
        if (valid) valid->assign(size, 1);
        return size;
    }

    // Partial: go page by page.
    memset(buffer, 0, size);
    size_t total = 0;
    uint64_t cur = address;
    uint64_t end = address + size;
    while (cur < end)
    {
        uint64_t pageEnd = (cur & ~0xFFFull) + 0x1000;
        size_t chunk = (size_t)(std::min(pageEnd, end) - cur);
        uint8_t* dst = (uint8_t*)buffer + (cur - address);
        SIZE_T r = 0;
        if (ReadProcessMemory(m_handle, (LPCVOID)cur, dst, chunk, &r) && r == chunk)
        {
            total += chunk;
            if (valid) memset(valid->data() + (cur - address), 1, chunk);
        }
        cur += chunk;
    }
    return total;
}

bool Process::ReadExact(uint64_t address, void* buffer, size_t size) const
{
    SIZE_T got = 0;
    return m_handle && ReadProcessMemory(m_handle, (LPCVOID)address, buffer, size, &got) && got == size;
}

bool Process::ReadPointer(uint64_t address, uint64_t& out) const
{
    out = 0;
    if (m_is64) return ReadExact(address, &out, 8);
    uint32_t v = 0;
    if (!ReadExact(address, &v, 4)) return false;
    out = v;
    return true;
}

bool Process::Write(uint64_t address, const void* buffer, size_t size) const
{
    if (!m_handle) return false;
    SIZE_T w = 0;
    if (WriteProcessMemory(m_handle, (LPVOID)address, buffer, size, &w) && w == size) return true;

    DWORD old = 0;
    if (!VirtualProtectEx(m_handle, (LPVOID)address, size, PAGE_EXECUTE_READWRITE, &old)) return false;
    bool ok = WriteProcessMemory(m_handle, (LPVOID)address, buffer, size, &w) && w == size;
    VirtualProtectEx(m_handle, (LPVOID)address, size, old, &old);
    if (ok) FlushInstructionCache(m_handle, (LPCVOID)address, size);
    return ok;
}

std::vector<RegionInfo> Process::QueryRegions(bool committedOnly) const
{
    std::vector<RegionInfo> out;
    if (!m_handle) return out;
    uint64_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (addr < MaxAddress() && VirtualQueryEx(m_handle, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        RegionInfo r;
        r.base = (uint64_t)mbi.BaseAddress;
        r.size = mbi.RegionSize;
        r.allocBase = (uint64_t)mbi.AllocationBase;
        r.state = mbi.State;
        r.protect = mbi.Protect;
        r.type = mbi.Type;
        if (!committedOnly || r.state == MEM_COMMIT) out.push_back(r);
        uint64_t next = r.base + r.size;
        if (next <= addr) break;
        addr = next;
    }
    return out;
}

bool Process::QueryRegion(uint64_t address, RegionInfo& r) const
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!m_handle || VirtualQueryEx(m_handle, (LPCVOID)address, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    r.base = (uint64_t)mbi.BaseAddress;
    r.size = mbi.RegionSize;
    r.allocBase = (uint64_t)mbi.AllocationBase;
    r.state = mbi.State;
    r.protect = mbi.Protect;
    r.type = mbi.Type;
    return true;
}

void Process::RefreshModules()
{
    std::vector<ModuleInfo> mods;
    HANDLE snap = INVALID_HANDLE_VALUE;
    for (int tries = 0; tries < 5 && snap == INVALID_HANDLE_VALUE; tries++)
    {
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
        if (snap == INVALID_HANDLE_VALUE && GetLastError() != ERROR_BAD_LENGTH) break;
    }
    if (snap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W me{ sizeof(me) };
        if (Module32FirstW(snap, &me))
        {
            do
            {
                ModuleInfo m;
                m.name = WideToUtf8(me.szModule);
                m.path = WideToUtf8(me.szExePath);
                m.base = (uint64_t)me.modBaseAddr;
                m.size = me.modBaseSize;
                mods.push_back(std::move(m));
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    std::sort(mods.begin(), mods.end(), [](const ModuleInfo& a, const ModuleInfo& b) { return a.base < b.base; });
    std::lock_guard<std::mutex> lock(m_modMutex);
    m_modules = std::move(mods);
}

std::vector<ModuleInfo> Process::Modules() const
{
    std::lock_guard<std::mutex> lock(m_modMutex);
    return m_modules;
}

bool Process::ModuleFromAddress(uint64_t address, ModuleInfo& out) const
{
    std::lock_guard<std::mutex> lock(m_modMutex);
    auto it = std::upper_bound(m_modules.begin(), m_modules.end(), address,
                               [](uint64_t a, const ModuleInfo& m) { return a < m.base; });
    if (it == m_modules.begin()) return false;
    --it;
    if (address < it->base + it->size)
    {
        out = *it;
        return true;
    }
    return false;
}

std::string Process::Symbolize(uint64_t address) const
{
    ModuleInfo m;
    if (ModuleFromAddress(address, m))
    {
        // Quote names the expression parser would otherwise split (spaces, dashes...).
        bool plain = true;
        for (char c : m.name)
            if (!isalnum((unsigned char)c) && c != '_' && c != '.') plain = false;
        std::string name = plain ? m.name : "\"" + m.name + "\"";
        return name + "+" + ToHex(address - m.base);
    }
    return ToHex(address, m_is64 ? 16 : 8);
}

static bool IEquals(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return false;
    return true;
}

bool Process::FindModule(const std::string& name, ModuleInfo& out) const
{
    std::lock_guard<std::mutex> lock(m_modMutex);
    for (const auto& m : m_modules)
    {
        if (IEquals(m.name, name))
        {
            out = m;
            return true;
        }
    }
    return false;
}

typedef LONG(NTAPI* NtProcFn)(HANDLE);

static NtProcFn GetNtFn(const char* name)
{
    return (NtProcFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name);
}

bool Process::Suspend()
{
    static NtProcFn fn = GetNtFn("NtSuspendProcess");
    if (!m_handle || !fn || m_suspended) return false;
    if (fn(m_handle) >= 0) m_suspended = true;
    return m_suspended;
}

bool Process::Resume()
{
    static NtProcFn fn = GetNtFn("NtResumeProcess");
    if (!m_handle || !fn || !m_suspended) return false;
    if (fn(m_handle) >= 0) m_suspended = false;
    return !m_suspended;
}

// ---------------------------------------------------------------------------
// Address expression evaluator

namespace
{
struct ExprParser
{
    const Process& proc;
    const std::string& s;
    size_t pos = 0;
    std::string error;

    void SkipWs()
    {
        while (pos < s.size() && isspace((unsigned char)s[pos])) pos++;
    }

    bool Fail(const std::string& msg)
    {
        if (error.empty()) error = msg;
        return false;
    }

    bool ParseExpr(uint64_t& out)
    {
        if (!ParseTerm(out)) return false;
        for (;;)
        {
            SkipWs();
            if (pos >= s.size() || (s[pos] != '+' && s[pos] != '-')) return true;
            char op = s[pos++];
            uint64_t rhs;
            if (!ParseTerm(rhs)) return false;
            out = op == '+' ? out + rhs : out - rhs;
        }
    }

    bool ParseTerm(uint64_t& out)
    {
        if (!ParseFactor(out)) return false;
        for (;;)
        {
            SkipWs();
            if (pos >= s.size() || s[pos] != '*') return true;
            pos++;
            uint64_t rhs;
            if (!ParseFactor(rhs)) return false;
            out *= rhs;
        }
    }

    bool ParseFactor(uint64_t& out)
    {
        SkipWs();
        if (pos >= s.size()) return Fail("Unexpected end of expression");
        char c = s[pos];
        if (c == '[')
        {
            pos++;
            uint64_t inner;
            if (!ParseExpr(inner)) return false;
            SkipWs();
            if (pos >= s.size() || s[pos] != ']') return Fail("Missing ']'");
            pos++;
            if (!proc.ReadPointer(inner, out)) return Fail("Cannot read pointer at " + ToHex(inner));
            return true;
        }
        if (c == '(')
        {
            pos++;
            if (!ParseExpr(out)) return false;
            SkipWs();
            if (pos >= s.size() || s[pos] != ')') return Fail("Missing ')'");
            pos++;
            return true;
        }
        if (c == '"')
        {
            size_t end = s.find('"', pos + 1);
            if (end == std::string::npos) return Fail("Missing closing quote");
            std::string name = s.substr(pos + 1, end - pos - 1);
            pos = end + 1;
            ModuleInfo m;
            if (!proc.FindModule(name, m)) return Fail("Unknown module '" + name + "'");
            out = m.base;
            return true;
        }
        size_t start = pos;
        while (pos < s.size() && (isalnum((unsigned char)s[pos]) || s[pos] == '_' || s[pos] == '.' || s[pos] == '#')) pos++;
        std::string tok = s.substr(start, pos - start);
        if (tok.empty()) return Fail(std::string("Unexpected '") + c + "'");

        ModuleInfo m;
        if (proc.FindModule(tok, m))
        {
            out = m.base;
            return true;
        }
        if (tok[0] == '#')
        {
            out = strtoull(tok.c_str() + 1, nullptr, 10);
            return true;
        }
        if (ParseHexU64(tok, out)) return true;
        return Fail("Unknown symbol '" + tok + "'");
    }
};
} // namespace

bool EvaluateAddress(const Process& proc, const std::string& expr, uint64_t& out, std::string* error)
{
    ExprParser p{ proc, expr };
    uint64_t v = 0;
    bool ok = p.ParseExpr(v);
    if (ok)
    {
        p.SkipWs();
        if (p.pos != expr.size()) ok = p.Fail("Unexpected trailing characters");
    }
    if (!ok)
    {
        if (error) *error = p.error;
        return false;
    }
    out = v;
    return true;
}
