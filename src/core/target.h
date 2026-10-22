#pragma once
#include <windows.h>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

struct ProcessInfo
{
    DWORD pid = 0;
    DWORD parentPid = 0;
    DWORD threads = 0;
    std::string name;
    bool is64 = true;
    bool accessible = true;
};

struct ModuleInfo
{
    std::string name;
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
};

struct RegionInfo
{
    uint64_t base = 0;
    uint64_t size = 0;
    uint64_t allocBase = 0;
    DWORD state = 0;
    DWORD protect = 0;
    DWORD type = 0;
};

std::string ProtectToString(DWORD protect);
std::string StateToString(DWORD state);
std::string TypeToString(DWORD type);
bool IsReadable(DWORD protect);
bool IsWritable(DWORD protect);
bool IsExecutable(DWORD protect);
std::string WideToUtf8(const wchar_t* w);

bool EnableDebugPrivilege();
bool IsElevated();

class Process
{
public:
    ~Process() { Close(); }

    static std::vector<ProcessInfo> Enumerate();

    bool Open(DWORD pid, std::string& error);
    void Close();
    bool IsOpen() const { return m_handle != nullptr; }
    bool IsAlive() const;

    DWORD Pid() const { return m_pid; }
    const std::string& Name() const { return m_name; }
    bool Is64() const { return m_is64; }
    int PointerSize() const { return m_is64 ? 8 : 4; }
    HANDLE Handle() const { return m_handle; }

    // Reads as much as possible. Unreadable pages are zero-filled and,
    // if `valid` is non-null, flagged false byte-by-byte. Returns bytes read.
    size_t Read(uint64_t address, void* buffer, size_t size, std::vector<uint8_t>* valid = nullptr) const;
    bool ReadExact(uint64_t address, void* buffer, size_t size) const;
    bool ReadPointer(uint64_t address, uint64_t& out) const;
    // Writes memory, temporarily changing page protection if necessary.
    bool Write(uint64_t address, const void* buffer, size_t size) const;

    std::vector<RegionInfo> QueryRegions(bool committedOnly = true) const;
    bool QueryRegion(uint64_t address, RegionInfo& out) const;

    void RefreshModules();
    std::vector<ModuleInfo> Modules() const;
    // Formats an address as "module.dll+1A2B" when it falls inside a module.
    std::string Symbolize(uint64_t address) const;
    bool FindModule(const std::string& name, ModuleInfo& out) const;
    bool ModuleFromAddress(uint64_t address, ModuleInfo& out) const;

    bool Suspend();
    bool Resume();
    bool IsSuspended() const { return m_suspended; }

    uint64_t MaxAddress() const { return m_is64 ? 0x00007FFFFFFFFFFFull : 0xFFFFFFFFull; }

private:
    HANDLE m_handle = nullptr;
    DWORD m_pid = 0;
    std::string m_name;
    bool m_is64 = true;
    bool m_suspended = false;

    mutable std::mutex m_modMutex;
    std::vector<ModuleInfo> m_modules; // sorted by base
};

// Address expressions such as:  game.exe+1F00   [[game.exe+1F00]+10]+8   7FF6A0001000
// Numbers are hexadecimal; brackets dereference a pointer of the target's pointer size.
bool EvaluateAddress(const Process& proc, const std::string& expr, uint64_t& out, std::string* error = nullptr);
