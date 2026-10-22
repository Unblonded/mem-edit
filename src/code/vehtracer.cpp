#include "code/vehtracer.h"

#include <algorithm>
#include <string>

using namespace vehipc;

int VehTracer::Add(DWORD pid, bool is64, uint64_t address, int size, TraceKind kind, std::string& error)
{
    if (!is64)
    {
        error = "The VEH debugger currently supports 64-bit targets only. Use the Windows debugger.";
        return -1;
    }
    // A different process (or a stopped session) needs a fresh agent connection.
    if (m_running && pid != m_pid) Shutdown();

    int slot = -1;
    for (int i = 0; i < kSlots; i++)
        if (!m_slots[i].used) { slot = i; break; }
    if (slot < 0)
    {
        error = "All 4 hardware breakpoints are in use. Close a trace window first.";
        return -1;
    }

    // Hardware watchpoints must be 1, 2, 4 or 8 bytes and naturally aligned.
    int len = 8;
    while (len > 1 && (len > size || address % len != 0)) len /= 2;

    m_pid = pid;
    m_is64 = is64;
    if (!m_running)
    {
        if (!EnsureAgent(error)) return -1;
        m_stop = false;
        m_running = true;
        m_poll = std::thread([this]() { PollLoop(); });
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Slot& s = m_slots[slot];
        s = Slot{};
        s.used = true;
        s.address = address;
        s.size = len;
        s.kind = kind;
        m_error.clear();
    }
    PushConfig();
    return slot;
}

void VehTracer::Remove(int slot)
{
    if (slot < 0 || slot >= kSlots) return;
    bool any = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_slots[slot] = Slot{};
        for (const auto& s : m_slots) any |= s.used;
    }
    PushConfig();
    if (!any) Shutdown(); // disarm and disconnect once nothing is watched
}

void VehTracer::Clear(int slot)
{
    if (slot < 0 || slot >= kSlots) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_slots[slot].hits.clear();
}

std::vector<TraceHit> VehTracer::Hits(int slot) const
{
    std::vector<TraceHit> out;
    if (slot < 0 || slot >= kSlots) return out;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [ip, h] : m_slots[slot].hits) out.push_back(h);
    std::sort(out.begin(), out.end(), [](const TraceHit& a, const TraceHit& b) { return a.address < b.address; });
    return out;
}

std::string VehTracer::Error() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_error;
}

void VehTracer::SetMethod(int method)
{
    m_method = method ? 1 : 0;
    if (m_block)
    {
        m_block->mode = (uint32_t)m_method;
        InterlockedIncrement((volatile LONG*)&m_block->configGen);
    }
}

void VehTracer::Shutdown()
{
    m_stop = true;
    if (m_poll.joinable()) m_poll.join();

    // Disarm the agent (clears the debug registers) but leave it resident - the DLL stays loaded so a
    // later session can reconnect without re-injecting (LoadLibrary wouldn't re-run DllMain anyway).
    if (m_block)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& s : m_block->slots) s.active = 0;
        InterlockedIncrement((volatile LONG*)&m_block->configGen);
    }
    if (m_block) { UnmapViewOfFile(m_block); m_block = nullptr; }
    if (m_mapping) { CloseHandle(m_mapping); m_mapping = nullptr; }
    if (m_process) { CloseHandle(m_process); m_process = nullptr; }

    m_running = false;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& s : m_slots) s = Slot{};
}

bool VehTracer::EnsureAgent(std::string& error)
{
    m_process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                PROCESS_VM_WRITE | PROCESS_VM_READ,
                            FALSE, m_pid);
    if (!m_process) { error = "Could not open the target (error " + std::to_string(GetLastError()) + ")."; return false; }

    wchar_t name[64];
    MappingName(m_pid, name, 64);

    // Reconnect to an agent already injected earlier this run, otherwise create a fresh block.
    bool created = false;
    m_mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!m_mapping)
    {
        m_mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                       (DWORD)(sizeof(Block) >> 32), (DWORD)(sizeof(Block) & 0xFFFFFFFF), name);
        created = (m_mapping != nullptr) && (GetLastError() != ERROR_ALREADY_EXISTS);
    }
    if (!m_mapping) { error = "Could not create the shared block."; CloseHandle(m_process); m_process = nullptr; return false; }

    m_block = (Block*)MapViewOfFile(m_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Block));
    if (!m_block) { error = "Could not map the shared block."; CloseHandle(m_mapping); m_mapping = nullptr; CloseHandle(m_process); m_process = nullptr; return false; }

    if (created)
    {
        m_block->magic = kMagic;
        m_block->version = kVersion;
        m_block->is64 = 1;
        m_block->mode = (uint32_t)m_method;
        m_block->configGen = 0;
        m_block->appliedGen = 0;
        m_block->stop = 0;
        m_block->agentReady = 0;
        m_block->hitSeq = 0;
        for (auto& s : m_block->slots) s = vehipc::Slot{};
        if (!InjectAgent(error)) { Shutdown(); return false; }
    }
    else
    {
        // Reconnecting to a resident agent: make sure it's on our chosen method.
        m_block->mode = (uint32_t)m_method;
        InterlockedIncrement((volatile LONG*)&m_block->configGen);
    }

    // Wait for the agent to signal the handler is live.
    for (int i = 0; i < 300 && !m_block->agentReady; i++) Sleep(10);
    if (!m_block->agentReady) { error = "The VEH agent did not start inside the target."; Shutdown(); return false; }

    m_tail = m_block->hitSeq; // ignore anything from before we connected
    return true;
}

bool VehTracer::InjectAgent(std::string& error)
{
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring dll = exePath;
    size_t slash = dll.find_last_of(L"\\/");
    dll = (slash == std::wstring::npos ? L"" : dll.substr(0, slash + 1)) + L"veh_agent.dll";
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        error = "veh_agent.dll was not found next to mem-edit.exe.";
        return false;
    }

    SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(m_process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { error = "VirtualAllocEx failed in the target."; return false; }
    if (!WriteProcessMemory(m_process, remote, dll.c_str(), bytes, nullptr))
    {
        error = "WriteProcessMemory failed in the target.";
        VirtualFreeEx(m_process, remote, 0, MEM_RELEASE);
        return false;
    }

    // kernel32 loads at the same address in every process this session, so LoadLibraryW's address is
    // valid in the target too.
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

void VehTracer::PushConfig()
{
    if (!m_block) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (int i = 0; i < kSlots; i++)
    {
        const Slot& s = m_slots[i];
        m_block->slots[i].active = s.used ? 1 : 0;
        m_block->slots[i].size = (uint32_t)s.size;
        m_block->slots[i].kind = s.kind == TraceKind::Writes ? 0 : 1;
        m_block->slots[i].address = s.address;
    }
    InterlockedIncrement((volatile LONG*)&m_block->configGen);
}

void VehTracer::Record(int slot, const vehipc::Hit& h)
{
    uint64_t watched;
    int size;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Slot& s = m_slots[slot];
        if (!s.used) return;
        auto it = s.hits.find(h.ip);
        if (it != s.hits.end())
        {
            it->second.count++;
            return;
        }
        watched = s.address;
        size = s.size;
    }

    TraceRegs r;
    r.is64 = m_is64;
    for (int i = 0; i < 16; i++) r.gp[i] = h.gp[i];
    r.ip = h.ip;
    r.flags = h.flags;

    TraceHit hit = DecodeTraceHit(m_process, m_is64, h.ip, r, watched, size, m_method == 1);
    hit.count = 1;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_slots[slot].used) m_slots[slot].hits.emplace(h.ip, std::move(hit));
}

void VehTracer::PollLoop()
{
    while (!m_stop)
    {
        uint32_t seq = m_block->hitSeq;
        if (seq != m_tail)
        {
            // If we fell more than a full ring behind, skip forward to the oldest still-present hit.
            if (seq - m_tail > kMaxHits) m_tail = seq - kMaxHits;
            while (m_tail != seq && !m_stop)
            {
                Hit h = m_block->hits[m_tail % kMaxHits]; // copy out
                if (h.slot < (uint32_t)kSlots) Record((int)h.slot, h);
                m_tail++;
            }
        }
        Sleep(8);
    }
}
