#include "ui/hexview.h"

#include "code/decompiler.h"
#include "ui/glass.h"
#include "ui/icons.h"
#include "ui/syntax.h"
#include "code/asmline.h"
#include "imgui.h"
#include "ui/ui.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace
{
const ImU32 kColAddr = IM_COL32(120, 140, 175, 255);
const ImU32 kColByte = IM_COL32(220, 222, 228, 255);
const ImU32 kColZero = IM_COL32(110, 112, 120, 255);
const ImU32 kColInvalid = IM_COL32(80, 80, 88, 255);
const ImU32 kColAscii = IM_COL32(170, 185, 215, 255);
const ImU32 kColChanged = IM_COL32(242, 148, 132, 255);
const ImU32 kColSel = IM_COL32(143, 171, 219, 70);
const ImU32 kColCursor = IM_COL32(199, 217, 247, 255);
const ImU32 kColRowAlt = IM_COL32(255, 255, 255, 8);

ImU32 LerpCol(ImU32 a, ImU32 b, float t)
{
    ImVec4 x = ImGui::ColorConvertU32ToFloat4(a), y = ImGui::ColorConvertU32ToFloat4(b);
    return ImGui::ColorConvertFloat4ToU32(ImVec4(x.x + (y.x - x.x) * t, x.y + (y.y - x.y) * t,
                                                 x.z + (y.z - x.z) * t, x.w + (y.w - x.w) * t));
}
} // namespace

void HexView::GoTo(uint64_t address, bool pushHistory)
{
    if (pushHistory && address != m_cursor)
    {
        m_back.push_back(m_cursor);
        if (m_back.size() > 256) m_back.erase(m_back.begin());
        m_fwd.clear();
    }
    m_cursor = m_selAnchor = address;
    m_nibble = 0;
    // Put the target a few rows below the top so context is visible.
    uint64_t row = address - (address % (uint64_t)m_bytesPerRow);
    uint64_t back = (uint64_t)m_bytesPerRow * 4;
    m_top = row > back ? row - back : 0;
    snprintf(m_addrInput, sizeof(m_addrInput), "%llX", (unsigned long long)address);
}

void HexView::FocusEdit(uint64_t address, uint64_t selectLen)
{
    m_disasm = false; // the hex grid is where you type bytes, so leave disassembly mode
    GoTo(address);
    // Highlight the editable span (e.g. a cave's free bytes) but keep the cursor on its
    // first byte, so typing hex starts there and you can see how much room you have.
    if (selectLen > 1)
    {
        m_cursor = address;
        m_selAnchor = address + selectLen - 1;
        m_nibble = 0;
    }
}

void HexView::FocusDisasm(uint64_t address)
{
    m_disasm = true;  // the instruction view, where the assembler bar lives
    GoTo(address);
    m_top = address;  // start decoding exactly on this instruction so it lines up
}

void HexView::Draw(const char* title, bool* open, Process& proc)
{
    Glass::PrepareWindow(title);
    if (!ImGui::Begin(title, open))
    {
        ImGui::End();
        return;
    }
    if (!proc.IsOpen())
    {
        if (Glass::EmptyState(ICON_CHIP, "No process attached",
                              "Attach to a process to browse and edit its memory. You can also press Ctrl+O.",
                              ICON_LINK "  Attach to process") &&
            onRequestAttach)
            onRequestAttach();
        ImGui::End();
        return;
    }

    DrawToolbar(proc);
    ImGui::Separator();

    float inspectorW = Px(290);
    float avail = ImGui::GetContentRegionAvail().x;
    bool showInspector = avail > inspectorW + Px(300);
    if (m_disasm) showInspector = false;
    ImGui::BeginChild("##bytes", ImVec2(showInspector ? avail - inspectorW - 6.f : 0.f, 0), ImGuiChildFlags_None,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoNav);
    if (m_disasm) DrawDisasm(proc);
    else DrawBytes(proc);
    ImGui::EndChild();
    if (showInspector)
    {
        ImGui::SameLine();
        ImGui::BeginChild("##inspector", ImVec2(Px(0), 0), ImGuiChildFlags_Borders);
        DrawInspector(proc);
        ImGui::EndChild();
    }
    ImGui::End();
}

void HexView::DrawToolbar(Process& proc)
{
    ImGui::BeginDisabled(m_back.empty());
    if (ImGui::ArrowButton("##back", ImGuiDir_Left))
    {
        m_fwd.push_back(m_cursor);
        uint64_t a = m_back.back();
        m_back.pop_back();
        GoTo(a, false);
    }
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Back (Alt+Left)");
    ImGui::SameLine(0, 2);
    ImGui::BeginDisabled(m_fwd.empty());
    if (ImGui::ArrowButton("##fwd", ImGuiDir_Right))
    {
        m_back.push_back(m_cursor);
        uint64_t a = m_fwd.back();
        m_fwd.pop_back();
        GoTo(a, false);
    }
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Forward (Alt+Right)");

    ImGui::SameLine();
    if (m_focusAddress)
    {
        ImGui::SetKeyboardFocusHere();
        m_focusAddress = false;
    }
    ImGui::SetNextItemWidth(Px(280));
    bool go = ImGui::InputTextWithHint("##addr", "Address or expression, e.g. game.exe+1F0 or [rax+8]", m_addrInput,
                                       sizeof(m_addrInput), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SetItemTooltip("Hex numbers, module names, + - *, and [ ] to dereference pointers.\nCtrl+G to focus.");
    ImGui::SameLine();
    go |= ImGui::Button("Go");
    if (go)
    {
        uint64_t a;
        if (EvaluateAddress(proc, m_addrInput, a, &m_addrError))
        {
            m_addrError.clear();
            GoTo(a);
        }
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(m_disasm);
    ImGui::SetNextItemWidth(Px(84));
    const char* widths[] = { "8", "16", "32" };
    int wi = m_bytesPerRow == 8 ? 0 : m_bytesPerRow == 16 ? 1 : 2;
    if (ImGui::Combo("##bpr", &wi, widths, 3)) m_bytesPerRow = wi == 0 ? 8 : wi == 1 ? 16 : 32;
    ImGui::SetItemTooltip("Bytes per row");
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Checkbox("Disasm", &m_disasm) && m_disasm) m_top = m_cursor;
    ImGui::SetItemTooltip("Show the bytes decoded as instructions");

    ImGui::SameLine();
    RegionInfo r;
    if (proc.QueryRegion(m_cursor, r))
    {
        ModuleInfo m;
        std::string mod = proc.ModuleFromAddress(m_cursor, m) ? "  " + m.name : "";
        ImGui::TextDisabled("%s  %llX-%llX  %s %s%s", StateToString(r.state).c_str(), (unsigned long long)r.base,
                            (unsigned long long)(r.base + r.size), ProtectToString(r.protect).c_str(),
                            TypeToString(r.type).c_str(), mod.c_str());
    }
    if (!m_addrError.empty())
    {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "%s", m_addrError.c_str());
    }
}

void HexView::WriteByte(Process& proc, uint64_t addr, uint8_t v)
{
    if (!proc.Write(addr, &v, 1) && onLog) onLog("Write failed at " + ToHex(addr));
}

void HexView::EnsureVisible(int rows)
{
    uint64_t bpr = (uint64_t)m_bytesPerRow;
    if (m_cursor < m_top) m_top = m_cursor - (m_cursor % bpr);
    uint64_t viewEnd = m_top + bpr * (uint64_t)rows;
    if (m_cursor >= viewEnd) m_top = m_cursor - (m_cursor % bpr) - bpr * (uint64_t)(rows - 1);
}

void HexView::MoveCursor(int64_t delta, bool extend, int rows)
{
    if (delta < 0 && (uint64_t)(-delta) > m_cursor) m_cursor = 0;
    else m_cursor += delta;
    if (!extend) m_selAnchor = m_cursor;
    m_nibble = 0;
    EnsureVisible(rows);
}

void HexView::HandleKeyboard(Process& proc, int rows)
{
    ImGuiIO& io = ImGui::GetIO();
    bool shift = io.KeyShift;
    int64_t bpr = m_bytesPerRow;

    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow) && !m_back.empty())
    {
        m_fwd.push_back(m_cursor);
        uint64_t a = m_back.back();
        m_back.pop_back();
        GoTo(a, false);
        return;
    }
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow) && !m_fwd.empty())
    {
        m_back.push_back(m_cursor);
        uint64_t a = m_fwd.back();
        m_fwd.pop_back();
        GoTo(a, false);
        return;
    }
    if (io.KeyAlt) return;

    if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) MoveCursor(-1, shift, rows);
    if (ImGui::IsKeyPressed(ImGuiKey_RightArrow)) MoveCursor(1, shift, rows);
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) MoveCursor(-bpr, shift, rows);
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) MoveCursor(bpr, shift, rows);
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp))
    {
        uint64_t d = (uint64_t)bpr * rows;
        m_top = m_top > d ? m_top - d : 0;
        MoveCursor(-(int64_t)d, shift, rows);
    }
    if (ImGui::IsKeyPressed(ImGuiKey_PageDown))
    {
        uint64_t d = (uint64_t)bpr * rows;
        m_top += d;
        MoveCursor((int64_t)d, shift, rows);
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Home)) MoveCursor(-(int64_t)(m_cursor % bpr), shift, rows);
    if (ImGui::IsKeyPressed(ImGuiKey_End)) MoveCursor(bpr - 1 - (int64_t)(m_cursor % bpr), shift, rows);
    if (ImGui::IsKeyPressed(ImGuiKey_Tab)) { m_asciiFocus = !m_asciiFocus; m_nibble = 0; }

    if (io.KeyCtrl)
    {
        if (ImGui::IsKeyPressed(ImGuiKey_G)) m_focusAddress = true;
        if (ImGui::IsKeyPressed(ImGuiKey_C))
        {
            size_t n = (size_t)std::min<uint64_t>(SelMax() - SelMin() + 1, 1 << 20);
            std::vector<uint8_t> buf(n);
            proc.Read(SelMin(), buf.data(), n);
            ImGui::SetClipboardText(BytesToHex(buf.data(), n).c_str());
        }
        return;
    }

    // Typed characters edit memory in place.
    for (int i = 0; i < io.InputQueueCharacters.Size; i++)
    {
        ImWchar ch = io.InputQueueCharacters[i];
        if (m_asciiFocus)
        {
            if (ch >= 32 && ch < 127)
            {
                WriteByte(proc, m_cursor, (uint8_t)ch);
                MoveCursor(1, false, rows);
            }
            continue;
        }
        int d = -1;
        if (ch >= '0' && ch <= '9') d = ch - '0';
        else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
        if (d < 0) continue;
        uint8_t cur = 0;
        if (!proc.ReadExact(m_cursor, &cur, 1)) continue;
        if (m_nibble == 0)
        {
            WriteByte(proc, m_cursor, (uint8_t)((d << 4) | (cur & 0x0F)));
            m_nibble = 1;
            m_selAnchor = m_cursor;
        }
        else
        {
            WriteByte(proc, m_cursor, (uint8_t)((cur & 0xF0) | d));
            MoveCursor(1, false, rows);
        }
    }
    io.InputQueueCharacters.resize(0);
}

void HexView::DrawBytes(Process& proc)
{
    if (monoFont) ImGui::PushFont(monoFont);
    ImGuiIO& io = ImGui::GetIO();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float cw = ImGui::CalcTextSize("F").x;
    const float lh = ImGui::GetTextLineHeightWithSpacing();
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const int bpr = m_bytesPerRow;
    const int rows = std::max(1, (int)(avail.y / lh));
    const int digits = proc.Is64() ? 16 : 8;
    const size_t size = (size_t)rows * bpr;

    m_top -= m_top % bpr;
    m_data.resize(size);
    proc.Read(m_top, m_data.data(), size, &m_valid);

    // Change tracking only makes sense when the same window is displayed.
    float now = (float)ImGui::GetTime();
    if (m_prevTop != m_top || m_prevSize != size)
    {
        m_changeTime.assign(size, -100.f);
    }
    else
    {
        for (size_t i = 0; i < size; i++)
            if (m_valid[i] && m_prev[i] != m_data[i]) m_changeTime[i] = now;
    }
    m_prev = m_data;
    m_prevTop = m_top;
    m_prevSize = size;

    const float addrX = origin.x + 4;
    const float hexX = addrX + (digits + 2) * cw;
    auto byteX = [&](int i) { return hexX + i * 3 * cw + (i / 8) * cw; };
    const float asciiX = byteX(bpr) + cw * 1.5f;

    ImGui::InvisibleButton("##hexarea", ImVec2(std::max(avail.x, 1.f), std::max(avail.y, 1.f)),
                           ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    bool hovered = ImGui::IsItemHovered();
    bool focused = ImGui::IsWindowFocused();

    auto hitTest = [&](ImVec2 p, uint64_t& addr, bool& ascii) -> bool {
        int row = (int)((p.y - origin.y) / lh);
        if (row < 0 || row >= rows) return false;
        int col = -1;
        if (p.x >= hexX && p.x < byteX(bpr))
        {
            for (int i = 0; i < bpr; i++)
                if (p.x < byteX(i) + 3 * cw) { col = i; break; }
            ascii = false;
        }
        else if (p.x >= asciiX && p.x < asciiX + bpr * cw)
        {
            col = (int)((p.x - asciiX) / cw);
            ascii = true;
        }
        if (col < 0) return false;
        addr = m_top + (uint64_t)row * bpr + col;
        return true;
    };

    if (hovered)
    {
        if (io.MouseWheel != 0)
        {
            int64_t delta = (int64_t)(-io.MouseWheel * 3) * bpr * (io.KeyShift ? rows / 3 + 1 : 1);
            if (delta < 0 && (uint64_t)(-delta) > m_top) m_top = 0;
            else m_top += delta;
        }
        uint64_t a;
        bool ascii;
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && hitTest(io.MousePos, a, ascii))
        {
            m_cursor = a;
            if (!io.KeyShift) m_selAnchor = a;
            m_asciiFocus = ascii;
            m_nibble = 0;
            m_dragging = true;
        }
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Right) && hitTest(io.MousePos, a, ascii))
        {
            if (a < SelMin() || a > SelMax()) m_cursor = m_selAnchor = a;
        }
    }
    if (m_dragging)
    {
        if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) m_dragging = false;
        else
        {
            uint64_t a;
            bool ascii;
            if (hitTest(io.MousePos, a, ascii)) m_cursor = a;
        }
    }

    if (focused) HandleKeyboard(proc, rows);
    ImGui::OpenPopupOnItemClick("##hexctx", ImGuiPopupFlags_MouseButtonRight);
    DrawContextMenu(proc);

    // Re-read if keyboard scrolling moved the view this frame.
    if (m_top != m_prevTop)
    {
        m_top -= m_top % bpr;
        proc.Read(m_top, m_data.data(), size, &m_valid);
        m_changeTime.assign(size, -100.f);
        m_prev = m_data;
        m_prevTop = m_top;
    }

    // Render
    uint64_t selA = SelMin(), selB = SelMax();
    char buf[32];
    for (int r = 0; r < rows; r++)
    {
        float y = origin.y + r * lh;
        uint64_t rowAddr = m_top + (uint64_t)r * bpr;
        if (r & 1) dl->AddRectFilled(ImVec2(origin.x, y), ImVec2(origin.x + avail.x, y + lh), kColRowAlt);
        snprintf(buf, sizeof(buf), "%0*llX", digits, (unsigned long long)rowAddr);
        dl->AddText(ImVec2(addrX, y), kColAddr, buf);

        for (int i = 0; i < bpr; i++)
        {
            size_t idx = (size_t)r * bpr + i;
            uint64_t a = rowAddr + i;
            float bx = byteX(i);
            float ax = asciiX + i * cw;
            bool sel = a >= selA && a <= selB;
            if (sel)
            {
                dl->AddRectFilled(ImVec2(bx - cw * 0.25f, y), ImVec2(bx + cw * 2.25f, y + lh), kColSel);
                dl->AddRectFilled(ImVec2(ax, y), ImVec2(ax + cw, y + lh), kColSel);
            }
            if (!m_valid[idx])
            {
                dl->AddText(ImVec2(bx, y), kColInvalid, "??");
                dl->AddText(ImVec2(ax, y), kColInvalid, "?");
                continue;
            }
            uint8_t v = m_data[idx];
            float age = now - m_changeTime[idx];
            ImU32 col = v == 0 ? kColZero : kColByte;
            if (age < 1.5f) col = LerpCol(kColChanged, col, age / 1.5f);
            snprintf(buf, sizeof(buf), "%02X", v);
            dl->AddText(ImVec2(bx, y), col, buf);
            char c = (v >= 32 && v < 127) ? (char)v : '.';
            buf[0] = c;
            buf[1] = 0;
            dl->AddText(ImVec2(ax, y), age < 1.5f ? col : (c == '.' ? kColZero : kColAscii), buf);
        }

        if (m_cursor >= rowAddr && m_cursor < rowAddr + bpr)
        {
            int i = (int)(m_cursor - rowAddr);
            float bx = byteX(i), ax = asciiX + i * cw;
            ImU32 hexCol = m_asciiFocus ? IM_COL32(199, 217, 247, 90) : kColCursor;
            ImU32 ascCol = m_asciiFocus ? kColCursor : IM_COL32(199, 217, 247, 90);
            if (!m_asciiFocus && m_nibble == 1)
                dl->AddRect(ImVec2(bx + cw - 1, y), ImVec2(bx + 2 * cw + 1, y + lh), hexCol);
            else
                dl->AddRect(ImVec2(bx - 2, y), ImVec2(bx + 2 * cw + 2, y + lh), hexCol);
            dl->AddRect(ImVec2(ax - 1, y), ImVec2(ax + cw + 1, y + lh), ascCol);
        }
    }
    // Column separators
    ImU32 sepCol = ImGui::GetColorU32(ImGuiCol_Separator);
    dl->AddLine(ImVec2(hexX - cw, origin.y), ImVec2(hexX - cw, origin.y + rows * lh), sepCol);
    dl->AddLine(ImVec2(asciiX - cw * 0.75f, origin.y), ImVec2(asciiX - cw * 0.75f, origin.y + rows * lh), sepCol);

    if (monoFont) ImGui::PopFont();
}

uint64_t HexView::PrevInstr(Process& proc, uint64_t addr)
{
    // Find the instruction start closest below `addr` whose length lands exactly on it.
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, proc.Is64() ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     proc.Is64() ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    for (int back = 1; back <= 15; back++)
    {
        if (addr < (uint64_t)back) break;
        uint64_t s = addr - back;
        uint8_t buf[16];
        if (proc.Read(s, buf, sizeof(buf)) == 0) continue;
        ZydisDecodedInstruction ins;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, buf, sizeof(buf), &ins)) &&
            s + ins.length == addr)
            return s;
    }
    return addr > 0 ? addr - 1 : 0;
}

void HexView::DrawDisasm(Process& proc)
{
    ImGuiIO& io = ImGui::GetIO();

    // --- Assembler bar: assemble one or more instructions at the cursor ---------------------
    ZydisDecoder asmDec;
    ZydisDecoderInit(&asmDec, proc.Is64() ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     proc.Is64() ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    ZydisFormatter asmFmt;
    ZydisFormatterInit(&asmFmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&asmFmt, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
    struct Decoded
    {
        bool ok = false;
        int len = 1;
        std::string text;
    };
    auto decodeBytes = [&](const uint8_t* b, size_t n, uint64_t at) {
        Decoded d;
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (n > 0 && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&asmDec, b, n, &ins, ops)))
        {
            char t[128];
            ZydisFormatterFormatInstruction(&asmFmt, &ins, ops, ins.operand_count_visible, t, sizeof(t), at, nullptr);
            d.ok = true;
            d.len = ins.length;
            d.text = t;
        }
        return d;
    };
    auto decodeAt = [&](uint64_t at) {
        uint8_t b[16];
        size_t g = proc.Read(at, b, sizeof(b));
        return decodeBytes(b, g, at);
    };
    const Decoded cur = decodeAt(m_cursor);

    // Row 1: where, and what is there now.
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("asm @");
    ImGui::SameLine(0, 4);
    ImGui::TextUnformatted(proc.Symbolize(m_cursor).c_str());
    ImGui::SameLine(0, Px(14));
    if (monoFont) ImGui::PushFont(monoFont);
    if (cur.ok) Syntax::Instruction(cur.text.c_str());
    else ImGui::TextDisabled("(not code)");
    if (monoFont) ImGui::PopFont();
    ImGui::SameLine();
    ImGui::TextDisabled("%d byte%s - Tab loads it", cur.len, cur.len == 1 ? "" : "s");

    // Row 2: the input, Assemble / NOP / Undo.
    struct CallbackData { const char* fill; HexView* self; };
    CallbackData cbData{ cur.ok ? cur.text.c_str() : "", this };
    auto inputCb = [](ImGuiInputTextCallbackData* data) -> int {
        auto* cd = (CallbackData*)data->UserData;
        HexView* self = cd->self;
        auto replace = [&](const std::string& s) {
            data->DeleteChars(0, data->BufTextLen);
            data->InsertChars(0, s.c_str());
        };
        if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion && cd->fill && *cd->fill) replace(cd->fill);
        else if (data->EventFlag == ImGuiInputTextFlags_CallbackHistory && !self->m_asmHistory.empty())
        {
            // Up walks back through earlier lines, Down forward again and finally to an empty box.
            int n = (int)self->m_asmHistory.size();
            int& pos = self->m_asmHistPos;
            if (data->EventKey == ImGuiKey_UpArrow) pos = pos < 0 ? n - 1 : (pos > 0 ? pos - 1 : 0);
            else if (data->EventKey == ImGuiKey_DownArrow && pos >= 0) pos = pos + 1 < n ? pos + 1 : -1;
            replace(pos >= 0 ? self->m_asmHistory[pos] : "");
        }
        return 0;
    };

    // Live assembly of what's typed, and how much of the existing code it covers.
    std::vector<AsmPart> parts;
    std::string asmErr;
    const bool have = m_asmInput[0] && AssembleLine(proc, m_asmInput, m_cursor, parts, asmErr);
    std::vector<uint8_t> bytes;
    for (const auto& p : parts) bytes.insert(bytes.end(), p.bytes.begin(), p.bytes.end());
    int covered = 0, coveredLen = 0;
    for (uint64_t a = m_cursor; have && coveredLen < (int)bytes.size() && covered < 64; covered++)
    {
        Decoded c = decodeAt(a);
        coveredLen += c.len;
        a += c.len;
    }
    const int newLen = (int)bytes.size();
    const bool grows = have && newLen > cur.len;
    const bool viaCave = grows && (bool)onAssembleHook;

    const ImGuiStyle& st = ImGui::GetStyle();
    const char* asmLabel = viaCave ? ICON_FLASH "  Assemble via cave" : ICON_FLASH "  Assemble";
    const float asmW = ImGui::CalcTextSize(asmLabel).x + st.FramePadding.x * 2;
    const float nopW = ImGui::CalcTextSize("NOP").x + st.FramePadding.x * 2;
    const float undoW = ImGui::CalcTextSize(ICON_UNDO " Undo").x + st.FramePadding.x * 2;
    if (m_refocusAsm) { ImGui::SetKeyboardFocusHere(); m_refocusAsm = false; }
    ImGui::SetNextItemWidth(std::max(Px(200), ImGui::GetContentRegionAvail().x - asmW - nopW - undoW - st.ItemSpacing.x * 3));
    if (monoFont) ImGui::PushFont(monoFont);
    bool enter = ImGui::InputTextWithHint("##asm", "mov eax, 1 ; jmp game.exe+1F00 ; nop 3 ; db 90 C3", m_asmInput,
                                          sizeof(m_asmInput),
                                          ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackCompletion |
                                              ImGuiInputTextFlags_CallbackHistory,
                                          inputCb, &cbData);
    if (monoFont) ImGui::PopFont();
    ImGui::SetItemTooltip("Intel syntax; separate several instructions with ;\n"
                          "Immediates are decimal unless prefixed 0x. jmp / call / jcc take an address or an\n"
                          "expression (game.exe+1F00, hex). nop 5 = one 5-byte NOP; db 90 C3 = raw bytes.\n"
                          "Tab loads the current instruction, Up / Down recall earlier lines.");

    // Writes `w` at the cursor, remembering what was there for Undo.
    auto writeInPlace = [&](const std::vector<uint8_t>& w, const std::string& what) {
        std::vector<uint8_t> old(w.size());
        if (!proc.ReadExact(m_cursor, old.data(), old.size())) { m_asmStatus = "x can't read the bytes being replaced"; return false; }
        if (!proc.Write(m_cursor, w.data(), w.size())) { m_asmStatus = "x write failed (page protected?)"; return false; }
        m_asmUndo.push_back({ m_cursor, std::move(old), what });
        if (m_asmUndo.size() > 64) m_asmUndo.erase(m_asmUndo.begin());
        if (onLog) onLog("asm: " + what + " -> " + BytesToHex(w.data(), w.size()) + " at " + proc.Symbolize(m_cursor));
        return true;
    };
    auto remember = [&] {
        std::string line = m_asmInput;
        if (m_asmHistory.empty() || m_asmHistory.back() != line) m_asmHistory.push_back(line);
        if (m_asmHistory.size() > 100) m_asmHistory.erase(m_asmHistory.begin());
        m_asmHistPos = -1;
    };
    // Pad to a whole-instruction boundary so no half instruction is left behind.
    auto padded = [&](int toLen) {
        std::vector<uint8_t> w = bytes;
        if ((int)w.size() < toLen)
        {
            auto pad = NopFill((size_t)(toLen - (int)w.size()));
            w.insert(w.end(), pad.begin(), pad.end());
        }
        return w;
    };

    ImGui::SameLine();
    ImGui::BeginDisabled(!have);
    bool doAssemble = Glass::AccentButton(asmLabel, ImVec2(asmW, 0));
    ImGui::EndDisabled();
    if (enter && have) doAssemble = true;
    if (enter) m_refocusAsm = true; // stay in the box to keep assembling
    if (doAssemble)
    {
        if (viaCave)
        {
            // Too big to fit in place: the host routes it through a trampoline cave.
            std::string res;
            if (onAssembleHook(m_cursor, bytes, res))
            {
                m_asmStatus = BytesToHex(bytes.data(), bytes.size()) + "  -> cave: " + res + "  (undo it from the Detours tab)";
                remember();
            }
            else m_asmStatus = "x " + res;
        }
        else
        {
            const int target = grows ? coveredLen : cur.len;
            if (writeInPlace(padded(target), m_asmInput))
            {
                m_asmStatus = BytesToHex(bytes.data(), bytes.size()) +
                              (newLen < target ? "  (+" + std::to_string(target - newLen) + " NOP bytes)" : "");
                remember();
            }
        }
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!cur.ok);
    if (ImGui::Button("NOP", ImVec2(nopW, 0)) && writeInPlace(NopFill((size_t)cur.len), "nop " + cur.text))
        m_asmStatus = "NOPed " + cur.text + " (" + std::to_string(cur.len) + " bytes)";
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Replace the instruction at the cursor with a NOP of the same length");
    ImGui::SameLine();
    ImGui::BeginDisabled(m_asmUndo.empty());
    if (ImGui::Button(ICON_UNDO " Undo", ImVec2(undoW, 0)))
    {
        AsmUndo u = m_asmUndo.back();
        m_asmUndo.pop_back();
        if (proc.Write(u.address, u.original.data(), u.original.size()))
        {
            m_cursor = m_selAnchor = u.address;
            m_asmStatus = "Restored " + std::to_string(u.original.size()) + " bytes at " + proc.Symbolize(u.address);
            if (onLog) onLog("asm: undid '" + u.what + "' at " + proc.Symbolize(u.address));
        }
        else m_asmStatus = "x undo failed: couldn't write " + proc.Symbolize(u.address);
    }
    ImGui::EndDisabled();
    if (!m_asmUndo.empty()) ImGui::SetItemTooltip("Undo '%s' at %s", m_asmUndo.back().what.c_str(), proc.Symbolize(m_asmUndo.back().address).c_str());

    // Row 3: live preview while typing, otherwise the result of the last action.
    if (m_asmInput[0])
    {
        if (!have) ImGui::TextColored(Syntax::kSystem, ICON_WARNING " %s", asmErr.c_str());
        else
        {
            if (monoFont) ImGui::PushFont(monoFont);
            ImGui::TextColored(Syntax::kNumber, "%s", BytesToHex(bytes.data(), bytes.size()).c_str());
            for (const auto& p : parts)
            {
                ImGui::SameLine(0, Px(14));
                ImGui::TextDisabled("|");
                ImGui::SameLine(0, Px(14));
                Decoded d = decodeBytes(p.bytes.data(), p.bytes.size(), p.address);
                if (d.ok && d.len == (int)p.bytes.size()) Syntax::Instruction(d.text.c_str());
                else ImGui::TextUnformatted(p.source.c_str()); // multi-instruction output (long call, nop n, db)
            }
            if (monoFont) ImGui::PopFont();

            // What happens to the code that's there now.
            const char* curText = cur.ok ? cur.text.c_str() : "the bytes here";
            if (newLen == cur.len)
                ImGui::TextColored(Syntax::kModule, "Exact fit - replaces %s.", curText);
            else if (newLen < cur.len)
                ImGui::TextColored(Syntax::kModule, "Fits - replaces %s; the spare %d byte%s become a NOP.", curText,
                                   cur.len - newLen, cur.len - newLen == 1 ? "" : "s");
            else
            {
                ImGui::TextColored(Syntax::kCall, ICON_WARNING " %d bytes - longer than %s (%d).", newLen, curText, cur.len);
                ImGui::SameLine();
                if (viaCave)
                {
                    ImGui::TextDisabled("Assemble routes it through a code cave, or");
                    ImGui::SameLine();
                    char label[96];
                    snprintf(label, sizeof(label), "overwrite the next %d instruction%s##ovw", covered, covered == 1 ? "" : "s");
                    if (ImGui::SmallButton(label) && writeInPlace(padded(coveredLen), m_asmInput))
                    {
                        m_asmStatus = BytesToHex(bytes.data(), bytes.size()) + "  (overwrote " + std::to_string(covered) +
                                      " instructions, " + std::to_string(coveredLen - newLen) + " NOP bytes)";
                        remember();
                    }
                    ImGui::SetItemTooltip("Writes in place over %d bytes (whole instructions), NOP-padding the rest.\n"
                                          "Only safe if nothing jumps into the middle of them.",
                                          coveredLen);
                }
                else
                    ImGui::TextDisabled("It will overwrite the next %d instruction%s (%d bytes, NOP-padded).", covered,
                                        covered == 1 ? "" : "s", coveredLen);
            }
        }
    }
    else if (!m_asmStatus.empty())
    {
        const bool bad = m_asmStatus[0] == 'x';
        ImGui::TextColored(bad ? Syntax::kSystem : Syntax::kMove, "%s%s", bad ? ICON_WARNING " " : "", bad ? m_asmStatus.c_str() + 2 : m_asmStatus.c_str());
    }
    else ImGui::TextDisabled("Type an instruction above. The bytes and how it fits show up here before anything is written.");
    if (m_asmInput[0] && !m_asmStatus.empty())
    {
        // Keep the last result visible after a write too, under the preview.
        const bool bad = m_asmStatus[0] == 'x';
        ImGui::TextColored(bad ? Syntax::kSystem : Syntax::kDim, "last: %s", bad ? m_asmStatus.c_str() + 2 : m_asmStatus.c_str());
    }
    ImGui::Separator();

    if (monoFont) ImGui::PushFont(monoFont);
    const float lh = ImGui::GetTextLineHeightWithSpacing();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const int rows = std::max(1, (int)(avail.y / lh));

    // Note: the view scrolls freely with the wheel; the arrow-key handlers below keep the
    // cursor on screen when you navigate, so m_top is deliberately not pinned to the cursor.

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, proc.Is64() ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     proc.Is64() ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&fmt, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    uint64_t a = m_top;
    size_t firstLen = 1;
    uint64_t lastAddr = m_top;
    uint64_t clicked = 0;
    bool didClick = false;

    for (int r = 0; r < rows; r++)
    {
        uint8_t buf[16];
        size_t got = proc.Read(a, buf, sizeof(buf));
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        bool ok = got > 0 && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, buf, got, &ins, ops));
        int len = ok ? ins.length : 1;
        if (r == 0) firstLen = (size_t)len;

        char text[128] = "(unreadable)";
        if (ok)
            ZydisFormatterFormatInstruction(&fmt, &ins, ops, ins.operand_count_visible, text, sizeof(text), a, nullptr);

        std::string bytes = BytesToHex(buf, (size_t)len);
        if (bytes.size() < 23) bytes.resize(23, ' '); // ~7 bytes wide, so the text column lines up

        // Address and bytes in fixed-width columns, then the syntax-highlighted instruction.
        char head[128];
        snprintf(head, sizeof(head), "%-20s ", proc.Symbolize(a).c_str());

        ImGui::PushID((void*)(uintptr_t)a);
        bool sel = (a == m_cursor);
        if (ImGui::Selectable("##dline", sel, ImGuiSelectableFlags_SpanAllColumns, ImVec2(0, ImGui::GetTextLineHeight())))
        {
            clicked = a;
            didClick = true;
        }
        {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 p = ImGui::GetItemRectMin();
            dl->AddText(p, kColAddr, head);
            p.x += ImGui::CalcTextSize(head).x;
            dl->AddText(p, IM_COL32(150, 158, 178, 255), bytes.c_str());
            p.x += ImGui::CalcTextSize((bytes + "  ").c_str()).x;
            if (ok) Syntax::DrawInstruction(dl, p, text);
            else dl->AddText(p, kColZero, "??");
        }
        if (ImGui::BeginPopupContextItem("##dctx"))
        {
            m_cursor = m_selAnchor = a;
            if (onExplain && ok && ImGui::MenuItem("Explain this instruction")) onExplain(text);
            if (onDecompile && ImGui::MenuItem("Decompile this function")) onDecompile(a);
            if (drawDetourMenu) drawDetourMenu(a);
            if (onMakeSignature && ImGui::MenuItem("Make AOB signature here")) onMakeSignature(a);
            if (onFindAccess)
            {
                int sz = std::min((int)len, 8);
                if (ImGui::MenuItem("Find what writes here")) onFindAccess(a, sz, TraceKind::Writes);
                if (ImGui::MenuItem("Find what accesses here")) onFindAccess(a, sz, TraceKind::Accesses);
            }
            if (ImGui::MenuItem("Copy bytes")) ImGui::SetClipboardText(BytesToHex(buf, (size_t)len).c_str());
            if (ImGui::MenuItem("Copy instruction")) ImGui::SetClipboardText(text);
            ImGui::EndPopup();
        }
        ImGui::PopID();

        lastAddr = a;
        a += len;
    }

    if (didClick)
    {
        m_cursor = m_selAnchor = clicked;
        snprintf(m_addrInput, sizeof(m_addrInput), "%llX", (unsigned long long)clicked);
    }

    // Scroll with the wheel (a few instructions per notch). AllowWhenBlockedByActiveItem keeps
    // this working while the assembler input box is the active item.
    if (ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem) && io.MouseWheel != 0.f)
    {
        int steps = 3;
        if (io.MouseWheel > 0) // scroll up: back up whole instructions
            for (int i = 0; i < steps; i++) m_top = PrevInstr(proc, m_top);
        else // scroll down: advance past whole instructions
            for (int i = 0; i < steps; i++)
            {
                uint8_t b[16];
                if (proc.Read(m_top, b, sizeof(b)) == 0) break;
                ZydisDecodedInstruction ins;
                int len = ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, b, sizeof(b), &ins)) ? ins.length : 1;
                m_top += len;
            }
    }

    // Keyboard: step the cursor instruction by instruction.
    if (ImGui::IsWindowFocused())
    {
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow))
        {
            uint8_t buf[16];
            if (proc.Read(m_cursor, buf, sizeof(buf)))
            {
                ZydisDecodedInstruction ins;
                int len = ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, buf, sizeof(buf), &ins)) ? ins.length : 1;
                m_cursor += len;
            }
            if (m_cursor > lastAddr) m_top = PrevInstr(proc, PrevInstr(proc, m_cursor));
        }
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow))
        {
            m_cursor = PrevInstr(proc, m_cursor);
            if (m_cursor < m_top) m_top = m_cursor;
        }
        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G)) m_focusAddress = true;
    }

    if (monoFont) ImGui::PopFont();
    (void)firstLen;
}

void HexView::DrawContextMenu(Process& proc)
{
    if (!ImGui::BeginPopup("##hexctx")) return;
    uint64_t a = SelMin(), b = SelMax();
    size_t n = (size_t)std::min<uint64_t>(b - a + 1, 1 << 20);
    ImGui::TextDisabled("%s  (%zu bytes)", proc.Symbolize(a).c_str(), n);
    ImGui::Separator();
    if (ImGui::MenuItem("Copy address")) ImGui::SetClipboardText(ToHex(a).c_str());
    if (ImGui::MenuItem("Copy as module+offset")) ImGui::SetClipboardText(proc.Symbolize(a).c_str());
    if (ImGui::MenuItem("Copy bytes (hex)", "Ctrl+C"))
    {
        std::vector<uint8_t> buf(n);
        proc.Read(a, buf.data(), n);
        ImGui::SetClipboardText(BytesToHex(buf.data(), n).c_str());
    }
    if (ImGui::MenuItem("Copy bytes as C array"))
    {
        std::vector<uint8_t> buf(n);
        proc.Read(a, buf.data(), n);
        std::string s = "unsigned char data[" + std::to_string(n) + "] = {";
        for (size_t i = 0; i < n; i++)
        {
            char t[8];
            snprintf(t, sizeof(t), "%s0x%02X", i ? ", " : " ", buf[i]);
            s += t;
        }
        s += " };";
        ImGui::SetClipboardText(s.c_str());
    }
    ImGui::Separator();
    uint64_t ptr;
    if (ImGui::MenuItem("Follow pointer", nullptr, false, proc.ReadPointer(m_cursor, ptr)))
    {
        proc.ReadPointer(m_cursor, ptr);
        GoTo(ptr);
    }
    if (ImGui::BeginMenu("Add to address list as", (bool)onAddToList))
    {
        for (int t = 0; t < (int)ValueType::Count; t++)
            if (ImGui::MenuItem(ValueTypeName((ValueType)t))) onAddToList(a, (ValueType)t);
        ImGui::EndMenu();
    }
    if (onFindAccess)
    {
        int size = (int)std::min<size_t>(n, 8);
        if (ImGui::MenuItem("Find out what writes to this address")) onFindAccess(a, size, TraceKind::Writes);
        if (ImGui::MenuItem("Find out what accesses this address")) onFindAccess(a, size, TraceKind::Accesses);
    }
    if (onDecompile && ImGui::MenuItem("Decompile function here")) onDecompile(a);
    if (drawDetourMenu) drawDetourMenu(a);
    if (onMakeSignature && ImGui::MenuItem("Make AOB signature here")) onMakeSignature(a);
    if (ImGui::BeginMenu("Fill selection"))
    {
        auto fill = [&](uint8_t v) {
            std::vector<uint8_t> buf(n, v);
            if (!proc.Write(a, buf.data(), n) && onLog) onLog("Fill failed at " + ToHex(a));
        };
        if (ImGui::MenuItem("00")) fill(0x00);
        if (ImGui::MenuItem("90 (NOP)")) fill(0x90);
        if (ImGui::MenuItem("CC (INT3)")) fill(0xCC);
        if (ImGui::MenuItem("FF")) fill(0xFF);
        ImGui::EndMenu();
    }
    if (ImGui::MenuItem("Paste hex bytes"))
    {
        const char* clip = ImGui::GetClipboardText();
        ParsedValue pv = ParseValue(ValueType::ByteArray, clip ? clip : "", true);
        if (pv.ok)
        {
            for (size_t i = 0; i < pv.bytes.size(); i++)
                if (pv.mask[i]) WriteByte(proc, a + i, pv.bytes[i]);
        }
        else if (onLog) onLog("Clipboard does not contain hex bytes");
    }
    ImGui::Separator();
    RegionInfo r;
    if (ImGui::MenuItem("Go to region start", nullptr, false, proc.QueryRegion(m_cursor, r)))
    {
        proc.QueryRegion(m_cursor, r);
        GoTo(r.base);
    }
    if (ImGui::MenuItem("Go to allocation base", nullptr, false, proc.QueryRegion(m_cursor, r)))
    {
        proc.QueryRegion(m_cursor, r);
        GoTo(r.allocBase);
    }
    ImGui::EndPopup();
}

void HexView::DrawInspector(Process& proc)
{
    ImGui::TextDisabled("DATA INSPECTOR");
    ImGui::Text("%s", proc.Symbolize(m_cursor).c_str());
    if (SelMax() != SelMin()) ImGui::TextDisabled("Selection: %llu bytes", (unsigned long long)(SelMax() - SelMin() + 1));
    ImGui::Spacing();

    uint8_t raw[64] = {};
    std::vector<uint8_t> valid;
    proc.Read(m_cursor, raw, sizeof(raw), &valid);
    size_t validLen = 0;
    while (validLen < valid.size() && valid[validLen]) validLen++;

    struct Row
    {
        const char* label;
        ValueType type;
        bool hex;
    };
    const Row rows[] = {
        { "Int8", ValueType::Int8, false },     { "UInt8", ValueType::UInt8, false },
        { "Int16", ValueType::Int16, false },   { "UInt16", ValueType::UInt16, false },
        { "Int32", ValueType::Int32, false },   { "UInt32", ValueType::UInt32, false },
        { "Int64", ValueType::Int64, false },   { "UInt64", ValueType::UInt64, false },
        { "Float", ValueType::Float, false },   { "Double", ValueType::Double, false },
        { "Hex32", ValueType::UInt32, true },   { "Hex64", ValueType::UInt64, true },
        { "ASCII", ValueType::String, false },  { "UTF-16", ValueType::WString, false },
    };
    const int nRows = (int)(sizeof(rows) / sizeof(rows[0]));

    if (ImGui::BeginTable("##insp", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp))
    {
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, Px(60));
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        for (int i = 0; i < nRows; i++)
        {
            const Row& row = rows[i];
            size_t need = ValueTypeSize(row.type);
            bool isStr = need == 0;
            size_t len = isStr ? std::min<size_t>(validLen, 32) : need;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("%s", row.label);
            ImGui::TableNextColumn();
            if (validLen < (isStr ? 1 : need))
            {
                ImGui::TextDisabled("??");
                continue;
            }
            if (m_inspectorEditRow != i)
            {
                std::string s = FormatValue(row.type, raw, len, row.hex);
                snprintf(m_inspectorBuf[i], sizeof(m_inspectorBuf[i]), "%s", s.c_str());
            }
            ImGui::PushID(i);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (monoFont) ImGui::PushFont(monoFont);
            bool enter = ImGui::InputText("##v", m_inspectorBuf[i], sizeof(m_inspectorBuf[i]),
                                          ImGuiInputTextFlags_EnterReturnsTrue);
            if (monoFont) ImGui::PopFont();
            if (ImGui::IsItemActive()) m_inspectorEditRow = i;
            else if (m_inspectorEditRow == i) m_inspectorEditRow = -1;
            if (enter)
            {
                ParsedValue pv = ParseValue(row.type, m_inspectorBuf[i], row.hex);
                if (pv.ok)
                {
                    if (!proc.Write(m_cursor, pv.bytes.data(), pv.bytes.size()) && onLog)
                        onLog("Write failed at " + ToHex(m_cursor));
                }
                else if (onLog)
                {
                    onLog(std::string("Invalid ") + row.label + " value");
                }
                m_inspectorEditRow = -1;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();
    if (validLen >= 1)
    {
        char bits[10];
        for (int b = 0; b < 8; b++) bits[b] = (raw[0] >> (7 - b)) & 1 ? '1' : '0';
        bits[8] = 0;
        ImGui::TextDisabled("Binary");
        ImGui::SameLine(Px(70));
        ImGui::Text("%s", bits);
    }

    uint64_t ptr = 0;
    if (validLen >= (size_t)proc.PointerSize())
    {
        memcpy(&ptr, raw, proc.PointerSize());
        RegionInfo r;
        bool points = proc.QueryRegion(ptr, r) && r.state == MEM_COMMIT && IsReadable(r.protect);
        ImGui::TextDisabled("Pointer");
        ImGui::SameLine(Px(70));
        if (points)
        {
            std::string label = proc.Symbolize(ptr) + "##ptr";
            if (ImGui::SmallButton(label.c_str())) GoTo(ptr);
            ImGui::SetItemTooltip("Follow pointer");
        }
        else
        {
            ImGui::TextDisabled("%s (invalid)", ToHex(ptr).c_str());
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextDisabled("Keys: arrows / PgUp / PgDn move, Shift selects,\n"
                        "0-9 A-F edit hex, Tab toggles ASCII editing,\n"
                        "Ctrl+G goto, Ctrl+C copy, Alt+Left/Right history.");
}
