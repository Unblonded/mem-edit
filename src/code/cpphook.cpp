#include "code/cpphook.h"
#include "code/cpphook_embedded.h"

#include <windows.h>

#include <cstdio>
#include <fstream>

using namespace cpphookipc;

namespace
{
// Runs an exe with its output captured, no console window. `env` is a VAR=VAL\0...\0 block (or empty
// to inherit), `cwd` the working directory (or empty). Returns the combined stdout+stderr.
int RunExe(const std::string& exe, const std::string& args, const std::string& cwd,
           const std::string& env, std::string& out)
{
    out.clear();
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { out = "CreatePipe failed."; return -1; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    std::string cmd = "\"" + exe + "\" " + args;
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                             env.empty() ? nullptr : (LPVOID)env.data(),
                             cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); out = "CreateProcess failed (" + std::to_string(GetLastError()) + ")."; return -1; }

    char buf[4096];
    DWORD n;
    while (ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n) out.append(buf, n);
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)code;
}

std::string EnvVar(const char* name)
{
    char* v = nullptr;
    size_t len = 0;
    if (_dupenv_s(&v, &len, name) == 0 && v) { std::string s(v); free(v); return s; }
    return {};
}

bool WriteFile(const std::string& path, const std::string& text)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(text.data(), (std::streamsize)text.size());
    return (bool)f;
}
} // namespace

bool CppHook::FindCompiler(std::string& vcvars) const
{
    if (!m_vcvarsCache.empty()) { vcvars = m_vcvarsCache; return true; }

    std::string pf = EnvVar("ProgramFiles(x86)");
    if (pf.empty()) pf = EnvVar("ProgramFiles");
    std::string vswhere = pf + "\\Microsoft Visual Studio\\Installer\\vswhere.exe";
    if (GetFileAttributesA(vswhere.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

    std::string install;
    RunExe(vswhere, "-latest -prerelease -products * "
                    "-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 "
                    "-property installationPath", "", "", install);
    while (!install.empty() && (install.back() == '\r' || install.back() == '\n' || install.back() == ' '))
        install.pop_back();
    if (install.empty()) return false;

    std::string path = install + "\\VC\\Auxiliary\\Build\\vcvars64.bat";
    if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    m_vcvarsCache = path;
    vcvars = path;
    return true;
}

bool CppHook::Available(std::string& whyNot) const
{
    std::string vc;
    if (FindCompiler(vc)) return true;
    whyNot = "No Visual C++ compiler was found. Install the \"Desktop development with C++\" workload "
             "(the same one that builds mem-edit) so cl.exe is available.";
    return false;
}

bool CppHook::Attach(const Process& proc, std::string& error)
{
    if (m_block && m_pid == proc.Pid()) return true;
    Detach();
    m_pid = proc.Pid();

    m_process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                PROCESS_VM_WRITE | PROCESS_VM_READ,
                            FALSE, m_pid);
    if (!m_process) { error = "Could not open the target (error " + std::to_string(GetLastError()) + ")."; return false; }

    wchar_t name[64];
    MappingName(m_pid, name, 64);
    m_mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    bool created = false;
    if (!m_mapping)
    {
        m_mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                       (DWORD)(sizeof(Block) >> 32), (DWORD)(sizeof(Block) & 0xFFFFFFFF), name);
        created = (m_mapping != nullptr) && (GetLastError() != ERROR_ALREADY_EXISTS);
    }
    if (!m_mapping) { error = "Could not create the shared block."; Detach(); return false; }

    m_block = (Block*)MapViewOfFile(m_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Block));
    if (!m_block) { error = "Could not map the shared block."; Detach(); return false; }
    if (created)
    {
        memset(m_block, 0, sizeof(Block));
        m_block->magic = kMagic;
        m_block->version = kVersion;
    }

    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    m_buildDir = std::string(tmp) + "memedit_cpphook\\" + std::to_string(m_pid);
    CreateDirectoryA((std::string(tmp) + "memedit_cpphook").c_str(), nullptr);
    CreateDirectoryA(m_buildDir.c_str(), nullptr);
    return true;
}

void CppHook::Detach()
{
    if (m_block) { m_block->stop = 1; UnmapViewOfFile(m_block); m_block = nullptr; }
    if (m_mapping) { CloseHandle(m_mapping); m_mapping = nullptr; }
    if (m_process) { CloseHandle(m_process); m_process = nullptr; }
    m_pid = 0;
}

bool CppHook::EnsureEnv(std::string& error) const
{
    if (!m_envBlock.empty() && !m_clPath.empty()) return true;

    std::string vcvars;
    if (!FindCompiler(vcvars)) { error = "No Visual C++ compiler (cl.exe) was found."; return false; }

    // Run vcvars once and capture the resulting environment, so later builds skip it entirely.
    char comspec[MAX_PATH]; if (!GetEnvironmentVariableA("ComSpec", comspec, MAX_PATH)) strcpy_s(comspec, "cmd.exe");
    std::string out;
    RunExe(comspec, "/c \"\"" + vcvars + "\" >nul 2>&1 && set\"", "", "", out);

    std::string block;
    std::string path;
    size_t start = 0;
    while (start < out.size())
    {
        size_t nl = out.find('\n', start);
        std::string line = out.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.find('=') != std::string::npos)
        {
            block.append(line);
            block.push_back('\0');
            if (_strnicmp(line.c_str(), "PATH=", 5) == 0) path = line.substr(5);
        }
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    block.push_back('\0'); // terminating double-null
    if (path.empty()) { error = "vcvars did not produce a PATH (is the C++ workload installed?)."; return false; }

    // Find cl.exe on the toolchain PATH.
    size_t p = 0;
    while (p < path.size())
    {
        size_t semi = path.find(';', p);
        std::string dir = path.substr(p, semi == std::string::npos ? std::string::npos : semi - p);
        if (!dir.empty())
        {
            std::string cand = dir + (dir.back() == '\\' ? "" : "\\") + "cl.exe";
            if (GetFileAttributesA(cand.c_str()) != INVALID_FILE_ATTRIBUTES) { m_clPath = cand; break; }
        }
        if (semi == std::string::npos) break;
        p = semi + 1;
    }
    if (m_clPath.empty()) { error = "cl.exe was not found on the toolchain PATH."; return false; }

    m_envBlock.swap(block);
    return true;
}

bool CppHook::Compile(const std::string& source, std::string& dllPath, std::string& log)
{
    if (!EnsureEnv(log)) return false;

    // Fresh headers + source for this build, so the build folder always matches the running tool.
    WriteFile(m_buildDir + "\\cpphook_ipc.h", cpphookembed::kCppHookIpcH);
    WriteFile(m_buildDir + "\\memhook.h", cpphookembed::kMemHookH);

    int n = ++m_build;
    std::string cpp = "user_" + std::to_string(n) + ".cpp";
    std::string dll = "user_" + std::to_string(n) + ".dll";
    if (!WriteFile(m_buildDir + "\\" + cpp, source)) { log = "Could not write the source file."; return false; }

    // Call cl.exe directly with the cached toolchain environment: no cmd, no window, no vcvars re-run.
    // Unoptimised (/Od) because these are tiny hook files and build speed matters more than codegen.
    std::string args = "/nologo /LD /std:c++17 /EHsc /Od /MD /I. \"" + cpp + "\" "
                       "/Fe:\"" + dll + "\" /Fo:\"user_" + std::to_string(n) + ".obj\" "
                       "/link /INCREMENTAL:NO";
    RunExe(m_clPath, args, m_buildDir, m_envBlock, log);

    dllPath = m_buildDir + "\\" + dll;
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        if (log.empty()) log = "The compiler produced no DLL (see output).";
        return false;
    }
    return true;
}

bool CppHook::Inject(const std::string& dll, std::string& error)
{
    std::wstring wdll(dll.begin(), dll.end());
    SIZE_T bytes = (wdll.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(m_process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { error = "VirtualAllocEx failed in the target."; return false; }
    if (!WriteProcessMemory(m_process, remote, wdll.c_str(), bytes, nullptr))
    {
        error = "WriteProcessMemory failed in the target.";
        VirtualFreeEx(m_process, remote, 0, MEM_RELEASE);
        return false;
    }
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE th = CreateRemoteThread(m_process, nullptr, 0, loadLib, remote, 0, nullptr);
    if (!th)
    {
        error = "CreateRemoteThread failed (error " + std::to_string(GetLastError()) + ").";
        VirtualFreeEx(m_process, remote, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    VirtualFreeEx(m_process, remote, 0, MEM_RELEASE);
    return true;
}

bool CppHook::Apply(const Process& proc, DetourManager& det, uint64_t hookedEntry,
                    const std::string& source, std::string& log)
{
    if (!Attach(proc, log)) return false;

    std::string dll;
    if (!Compile(source, dll, log)) return false;

    // Make sure the trampoline for the hooked function is published before the DLL arms itself.
    if (hookedEntry)
    {
        const Detour* d = det.Find(hookedEntry);
        if (d && d->cave) m_block->trampoline = d->cave + 16; // dispatch is 16 bytes; tramp follows
    }

    uint32_t oldGen = m_block->loadGen;
    m_block->stop = 0;
    std::string err;
    if (!Inject(dll, err)) { log += "\n" + err; return false; }

    for (int i = 0; i < 400 && m_block->loadGen == oldGen; i++) Sleep(10);
    if (m_block->loadGen == oldGen)
    {
        log += "\nThe injected DLL did not start inside the target.";
        return false;
    }
    for (int i = 0; i < 200 && !m_block->ready; i++) Sleep(10);

    if (hookedEntry)
    {
        uint64_t target = m_block->onCall ? m_block->onCall : m_block->trampoline;
        det.SetHookTarget(proc, hookedEntry, target);
    }

    char ver[96];
    snprintf(ver, sizeof(ver), "Build %u loaded%s.", m_block->loadGen,
             m_block->onCall ? " (OnCall armed)" : (hookedEntry ? " (no OnCall - passthrough)" : ""));
    if (!log.empty()) log += "\n";
    log += ver;
    return true;
}

bool CppHook::Run(const std::string& args, std::string& out, std::string& error)
{
    if (!m_block) { error = "No C++ build is loaded. Compile & Apply first."; return false; }
    if (!m_block->ready) { error = "The injected DLL is not ready yet."; return false; }

    strncpy_s(m_block->args, args.c_str(), _TRUNCATE);
    uint32_t gen = m_block->runGen + 1;
    m_block->runGen = gen;
    for (int i = 0; i < 1000 && m_block->runAck != gen; i++) Sleep(5); // up to ~5s
    if (m_block->runAck != gen) { error = "OnRun did not finish in time (is it looping?)."; return false; }

    m_block->out[cpphookipc::kOutMax - 1] = '\0';
    out.assign(m_block->out, m_block->out + m_block->outLen);
    return true;
}
