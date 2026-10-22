#pragma once
#include "code/tracer.h"
#include "code/veh_ipc.h"

#include <windows.h>

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// The VEH ("vectored exception handler") debugger. Instead of attaching the Windows debugger, it
// injects veh_agent.dll into the target; the agent installs the breakpoints and a VEH *inside* the
// process and streams hits back through shared memory. No debug port is opened, so simple anti-debug
// checks (IsDebuggerPresent, the debug object) don't see it. 64-bit targets only for now.
class VehTracer : public ITracer
{
public:
    ~VehTracer() override { Shutdown(); }

    int Add(DWORD pid, bool is64, uint64_t address, int size, TraceKind kind, std::string& error) override;
    void Remove(int slot) override;
    void Clear(int slot) override;
    std::vector<TraceHit> Hits(int slot) const override;
    bool Attached() const override { return m_running; }
    std::string Error() const override;
    void Shutdown() override;

    // 0 = hardware (DR), 1 = page-guard (software, DR-free). Takes effect on the next arm; if a
    // session is already live it's pushed to the agent immediately.
    void SetMethod(int method);
    int Method() const { return m_method; }

private:
    struct Slot
    {
        bool used = false;
        uint64_t address = 0;
        int size = 4;
        TraceKind kind = TraceKind::Writes;
        std::map<uint64_t, TraceHit> hits; // keyed by IP after the access
    };

    bool EnsureAgent(std::string& error);  // open target, map shared block, inject the agent
    bool InjectAgent(std::string& error);
    void PushConfig();                     // copy slots into the shared block and bump the generation
    void PollLoop();                       // drain the hit ring and disassemble
    void Record(int slot, const vehipc::Hit& h);

    mutable std::mutex m_mutex;
    Slot m_slots[kSlots];
    std::string m_error;

    DWORD m_pid = 0;
    bool m_is64 = true;
    int m_method = 0; // 0 = hardware (DR), 1 = page-guard
    HANDLE m_process = nullptr;
    HANDLE m_mapping = nullptr;
    vehipc::Block* m_block = nullptr;
    uint32_t m_tail = 0; // next hit sequence number to consume

    std::thread m_poll;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_stop{ false };
};
