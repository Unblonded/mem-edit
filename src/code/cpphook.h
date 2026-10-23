#pragma once
#include "core/target.h"
#include "code/detour.h"
#include "code/cpphook_ipc.h"

#include <windows.h>
#include <string>
#include <vector>

// Compiles the C++ you type in the "C++ Hooks" window into a DLL, injects it into the target, and
// bridges to it through a shared-memory block (cpphook_ipc.h). The DLL's OnCall runs on every call
// to the hooked function; its OnRun runs when you press Run. Recompiling hot-swaps the callback.
class CppHook
{
public:
    ~CppHook() { Detach(); }

    bool Available(std::string& whyNot) const; // is a C++ compiler (cl.exe via vswhere) reachable?

    // Opens the target and creates the shared block. Safe to call repeatedly for the same pid.
    bool Attach(const Process& proc, std::string& error);
    void Detach();
    bool Attached() const { return m_block != nullptr; }
    DWORD Pid() const { return m_pid; }

    // Full cycle: compile `source`, inject the DLL, wait for it to publish, and point each hook site
    // at its new per-site OnCall thunk. `sites` are the hooked entries, in order (site index = list
    // position). `log` gets the compiler output on failure.
    bool Apply(const Process& proc, DetourManager& det, const std::vector<uint64_t>& sites,
               const std::string& source, std::string& log);

    // Trigger OnRun once with `args`; blocks briefly for it to finish and returns its printed output.
    bool Run(const std::string& args, std::string& out, std::string& error);

    uint32_t LoadGen() const { return m_block ? m_block->loadGen : 0; }
    const std::string& BuildDir() const { return m_buildDir; }

private:
    bool Compile(const std::string& source, std::string& dllPath, std::string& log);
    bool Inject(const std::string& dll, std::string& error);
    bool FindCompiler(std::string& vcvars) const;
    bool EnsureEnv(std::string& error) const; // cache the toolchain env + cl.exe path (once)

    DWORD m_pid = 0;
    HANDLE m_process = nullptr;
    HANDLE m_mapping = nullptr;
    cpphookipc::Block* m_block = nullptr;
    std::string m_buildDir;
    int m_build = 0;
    mutable std::string m_vcvarsCache;
    mutable std::string m_envBlock; // VAR=VAL\0...\0 from vcvars, reused for every build
    mutable std::string m_clPath;   // full path to cl.exe
};
