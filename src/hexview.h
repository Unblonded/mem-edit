#pragma once
#include "target.h"
#include "tracer.h"
#include "values.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct ImFont;

class HexView
{
public:
    void Draw(const char* title, bool* open, Process& proc);
    void GoTo(uint64_t address, bool pushHistory = true);
    void FocusEdit(uint64_t address, uint64_t selectLen); // byte-edit mode, cursor + region highlighted
    uint64_t Cursor() const { return m_cursor; }

    // Callback the host app installs so "Add to address list" works from here.
    std::function<void(uint64_t, ValueType)> onAddToList;
    std::function<void(const std::string&)> onLog;
    std::function<void(uint64_t, int, TraceKind)> onFindAccess;
    std::function<void(uint64_t)> onDecompile;
    // Install a larger assembled instruction via a trampoline cave (returns false + a reason on
    // failure, a short status on success). Set by the host; when unset, growth overwrites in place.
    std::function<bool(uint64_t, const std::vector<uint8_t>&, std::string&)> onAssembleHook;
    ImFont* monoFont = nullptr;

private:
    void DrawToolbar(Process& proc);
    void DrawBytes(Process& proc);
    void DrawDisasm(Process& proc);
    uint64_t PrevInstr(Process& proc, uint64_t addr);
    void DrawInspector(Process& proc);
    void DrawContextMenu(Process& proc);
    void HandleKeyboard(Process& proc, int visibleRows);
    void MoveCursor(int64_t delta, bool extend, int visibleRows);
    void EnsureVisible(int visibleRows);
    void WriteByte(Process& proc, uint64_t addr, uint8_t v);
    uint64_t SelMin() const { return m_selAnchor < m_cursor ? m_selAnchor : m_cursor; }
    uint64_t SelMax() const { return m_selAnchor < m_cursor ? m_cursor : m_selAnchor; }

    uint64_t m_top = 0;
    uint64_t m_cursor = 0;
    uint64_t m_selAnchor = 0;
    int m_bytesPerRow = 16;
    bool m_disasm = false;
    char m_asmInput[128] = "";
    std::string m_asmStatus;
    int m_nibble = 0;
    bool m_asciiFocus = false;
    bool m_dragging = false;
    bool m_focusAddress = false;

    std::vector<uint64_t> m_back, m_fwd;
    char m_addrInput[256] = "";
    std::string m_addrError;

    // Data for the visible window and change highlighting.
    std::vector<uint8_t> m_data, m_valid, m_prev;
    std::vector<float> m_changeTime;
    uint64_t m_prevTop = ~0ull;
    size_t m_prevSize = 0;

    int m_inspectorEditRow = -1;
    char m_inspectorBuf[16][128] = {};
};
