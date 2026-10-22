#include "app/app.h"

#include "code/decompiler.h"
#include "ui/glass.h"
#include "ui/icons.h"
#include "ui/syntax.h"
#include "code/opcodes.h"
#include "imgui.h"
#include "ui/ui.h"
#include "imgui_internal.h"
#include "misc/cpp/imgui_stdlib.h"

#include <windows.h>
#include <commdlg.h>
#include <algorithm>
#include <cctype>
#include <climits>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sstream>

namespace
{
// Icon + label; the ### part is the stable window ID used by the layout and the .ini.
const char* kWinScanner = ICON_SEARCH "  Scanner###Scanner";
const char* kWinResults = ICON_LIST "  Scan Results###Scan Results";
const char* kWinHex = ICON_CHIP "  Memory View###Memory View";
const char* kWinWatch = ICON_STAR "  Address List###Address List";
const char* kWinRegions = ICON_GRID "  Memory Regions###Memory Regions";
const char* kWinModules = ICON_PUZZLE "  Modules###Modules";
const char* kWinLog = ICON_LOG "  Log###Log";
const char* kWinDecompile = ICON_CODE "  Decompile###Decompile";
const char* kWinAob = ICON_FLASH "  AOB Scan###AOB Scan";
const char* kWinOpcodes = ICON_DOC "  Opcodes###Opcodes";
const char* kWinCppHook = ICON_CODE "  C++ Hooks###C++ Hooks";

// Status colours stay distinguishable but are muted to sit in the duotone palette.
const ImVec4 kColErr(0.93f, 0.55f, 0.58f, 1.0f);
const ImVec4 kColOk(0.62f, 0.84f, 0.78f, 1.0f);
const ImVec4 kColChanged(0.95f, 0.58f, 0.52f, 1.0f);
const ImVec4 kColAccent = Glass::kAccentHi;

std::string Lower(std::string s)
{
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

bool Contains(const std::string& hay, const char* needle)
{
    if (!needle || !*needle) return true;
    return Lower(hay).find(Lower(needle)) != std::string::npos;
}

std::string HumanSize(uint64_t b)
{
    char buf[32];
    if (b >= (1ull << 30)) snprintf(buf, sizeof(buf), "%.2f GB", b / (double)(1ull << 30));
    else if (b >= (1ull << 20)) snprintf(buf, sizeof(buf), "%.2f MB", b / (double)(1ull << 20));
    else if (b >= 1024) snprintf(buf, sizeof(buf), "%.1f KB", b / 1024.0);
    else snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
    return buf;
}

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

bool FileDialog(HWND owner, bool save, const wchar_t* filter, const wchar_t* defExt, std::wstring& path)
{
    wchar_t buf[MAX_PATH * 2] = {};
    if (!path.empty()) wcsncpy_s(buf, path.c_str(), _TRUNCATE);
    OPENFILENAMEW ofn{ sizeof(ofn) };
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = (DWORD)std::size(buf);
    ofn.lpstrDefExt = defExt;
    ofn.Flags = OFN_NOCHANGEDIR | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    BOOL ok = save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
    if (ok) path = buf;
    return ok != FALSE;
}

bool CompareAllowed(ScanCompare c, ValueType t, bool first)
{
    bool numeric = IsNumeric(t);
    if (!numeric)
    {
        if (c == ScanCompare::Exact || c == ScanCompare::NotEqual) return true;
        return !first && (c == ScanCompare::Changed || c == ScanCompare::Unchanged);
    }
    if (first) return !CompareNeedsPrevious(c);
    return c != ScanCompare::Unknown;
}
} // namespace

// ---------------------------------------------------------------------------

void App::Init(void* hwnd, ImFont* uiFont, ImFont* monoFont)
{
    (void)uiFont;
    m_hwnd = hwnd;
    m_mono = monoFont;
    m_hex.monoFont = monoFont;
    m_hex.onAddToList = [this](uint64_t a, ValueType t) { AddWatch(a, t); };
    m_hex.onLog = [this](const std::string& s) { Log(s); };
    m_hex.onFindAccess = [this](uint64_t a, int size, TraceKind k) { StartTrace(a, size, k); };
    m_hex.onDecompile = [this](uint64_t a) { StartDecompile(a); };
    m_hex.onRequestAttach = [this] { m_openPicker = true; };
    m_hex.onMakeSignature = [this](uint64_t a) { OpenSigMaker(a); };
    m_hex.drawDetourMenu = [this](uint64_t a) { DrawDetourMenu(a); };
    m_hex.onExplain = [this](const std::string& insn) { OpenOpcodes(insn); };
    m_hex.onAssembleHook = [this](uint64_t a, const std::vector<uint8_t>& bytes, std::string& status) -> bool {
        // Inside an existing trampoline's cave? Never hook a cave address. Any instruction in the
        // cave ([head stolen][free][trailing jmp/jump back]) is editable except the jump back, which
        // stays last. Editing one reflows the rest: a longer one pushes the following code down into
        // the free padding, a shorter one pulls it up and re-pads with NOPs.
        if (m_detours.CaveForAddress(a))
        {
            if (!m_detours.EditCaveCode(m_proc, a, bytes, status)) return false;
            status = "written into the cave at " + ToHex(a) + " (following code reflowed to fit)";
            return true;
        }
        if (!m_detours.ReplaceInstruction(m_proc, a, bytes, status)) return false;
        const Detour* d = m_detours.Find(a);
        status = "cave at " + ToHex(d ? d->cave : 0);
        RunDecompile();
        return true;
    };
    m_elevated = IsElevated();
    bool dbg = EnableDebugPrivilege();
    Log(std::string("Started. ") + (m_elevated ? "Running as administrator" : "Not elevated - some processes will be inaccessible") +
        (dbg ? ", SeDebugPrivilege enabled." : "."));
}

void App::Log(const std::string& msg)
{
    SYSTEMTIME t;
    GetLocalTime(&t);
    char ts[16];
    snprintf(ts, sizeof(ts), "[%02d:%02d:%02d] ", t.wHour, t.wMinute, t.wSecond);
    m_log.push_back(ts + msg);
    if (m_log.size() > 2000) m_log.erase(m_log.begin(), m_log.begin() + 500);
    m_logScroll = true;
}

std::string App::AddrText(uint64_t a) const
{
    return ToHex(a, m_proc.Is64() ? 16 : 8);
}

void App::Attach(DWORD pid)
{
    if (m_scanner.Busy())
    {
        Log("Cannot attach while a scan is running");
        return;
    }
    Detach();
    std::string err;
    if (!m_proc.Open(pid, err))
    {
        Log(err);
        return;
    }
    m_opts.endAddress = m_proc.MaxAddress();
    snprintf(m_rangeEnd, sizeof(m_rangeEnd), "%llX", (unsigned long long)m_opts.endAddress);
    Log("Attached to " + m_proc.Name() + " (PID " + std::to_string(pid) + ", " + (m_proc.Is64() ? "x64" : "x86") +
        "), " + std::to_string(m_proc.Modules().size()) + " modules");
    auto mods = m_proc.Modules();
    if (!mods.empty()) m_hex.GoTo(mods.front().base, false);
    m_regionsRefreshed = -100;
}

void App::Detach()
{
    if (m_scanner.Busy()) return;
    if (m_proc.IsOpen()) Log("Detached from " + m_proc.Name());
    m_tracer.Shutdown();
    m_veh.Shutdown();
    m_cpp.Detach();
    m_cppHookedEntry = 0;
    m_traces.clear();
    m_patches.clear();
    // Undo detours and free their caves while we still have the handle.
    if (m_proc.IsOpen() && m_proc.IsAlive())
    {
        std::vector<uint64_t> es;
        for (const auto& d : m_detours.All()) es.push_back(d.entry);
        for (uint64_t e : es) m_detours.Remove(m_proc, e);
    }
    m_detours.Clear();
    m_patchmgr.Clear();
    m_instructions.clear();
    m_proc.Close();
    m_scanner.Reset();
    m_regions.clear();
    m_resSel.Clear();
    m_aob.Reset(); // results are addresses in the old process
    m_aobSel.Clear();
    m_aobModules.clear();
    m_aobScope = 0;
    for (auto& e : m_sigList) e.scanned = false;
    for (auto& w : m_watches) w.frozen = false;
}

void App::AddWatch(uint64_t address, ValueType type, int length)
{
    WatchEntry e;
    e.expression = m_proc.Symbolize(address);
    e.type = type;
    // `length` is in bytes; the watch stores characters for UTF-16 strings.
    e.length = type == ValueType::WString ? std::max(1, length / 2) : length;
    if (type == ValueType::ByteArray && length == 32) e.length = 8;
    m_watches.push_back(std::move(e));
}

void App::UpdateWatches()
{
    if (!m_proc.IsOpen()) return;
    for (auto& w : m_watches)
    {
        w.resolved = EvaluateAddress(m_proc, w.expression, w.address, &w.error);
        if (w.resolved) w.error.clear();
        if (w.frozen && w.resolved && !w.frozenBytes.empty())
            m_proc.Write(w.address, w.frozenBytes.data(), w.frozenBytes.size());
    }
}

static size_t WatchSize(const WatchEntry& w)
{
    size_t s = ValueTypeSize(w.type);
    if (s) return s;
    int len = std::clamp(w.length, 1, 4096);
    return w.type == ValueType::WString ? (size_t)len * 2 : (size_t)len;
}

void App::Frame()
{
    if (m_proc.IsOpen() && !m_proc.IsAlive())
    {
        // A running scan must finish (cancelled) before we can detach.
        if (m_scanner.Busy()) m_scanner.Cancel();
        else
        {
            Log("Target process exited");
            Detach();
        }
    }

    bool wasBusy = m_scanner.Busy();
    m_scanner.Update();
    if (wasBusy && !m_scanner.Busy())
    {
        if (!m_scanner.LastError().empty()) Log(m_scanner.LastError());
        else
            Log("Scan #" + std::to_string(m_scanner.State().scanNumber) + ": " +
                std::to_string(m_scanner.State().Count()) + " results in " +
                std::to_string((int)m_scanner.LastDurationMs()) + " ms");
    }

    bool ptrWasBusy = m_ptrScan.Busy();
    m_ptrScan.Update();
    if (ptrWasBusy && !m_ptrScan.Busy())
    {
        if (!m_ptrScan.LastError().empty()) Log("Pointer scan: " + m_ptrScan.LastError());
        else
            Log("Pointer scan: " + std::to_string(m_ptrScan.Results().size()) + " paths from " +
                std::to_string(m_ptrScan.PointerMapSize()) + " pointers in " +
                std::to_string((int)m_ptrScan.LastDurationMs()) + " ms");
    }

    bool aobWasBusy = m_aob.Busy();
    m_aob.Update();
    if (aobWasBusy && !m_aob.Busy())
    {
        m_aobSel.Clear();
        Log("AOB scan: " + std::to_string(m_aob.Results().size()) + (m_aob.Truncated() ? "+" : "") + " matches for " +
            m_aob.Pattern().ToIda() + " in " + std::to_string((int)m_aob.LastDurationMs()) + " ms");
    }

    UpdateWatches();

    ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) m_openPicker = true;

    Glass::DrawBackdrop();
    // Each window is drawn at the DPI of the monitor it's on (see Glass::PrepareWindow).
    Glass::PrepareWindow("##MainMenuBar");
    DrawMenuBar();
    Glass::PrepareWindow("##statusbar");
    DrawStatusBar();
    Glass::PrepareMain();

    // The dockspace host stays clear so the backdrop shows between docked panes.
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0));
    // Tabs carry their own close buttons; the per-pane X would just duplicate them.
    ImGuiID dock = ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport(), (ImGuiDockNodeFlags)ImGuiDockNodeFlags_NoCloseButton);
    ImGui::PopStyleColor();
    if (!m_layoutInit)
    {
        m_layoutInit = true;
        ImGuiDockNode* node = ImGui::DockBuilderGetNode(dock);
        // An .ini from before the window IDs changed has no entry for them: rebuild the layout.
        bool knownIds = ImGui::FindWindowSettingsByID(ImHashStr(kWinScanner)) != nullptr;
        if (m_forceLayout || !node || !node->IsSplitNode() || !knownIds) SetupDefaultLayout(dock);
        m_forceLayout = false;
    }

    if (m_showScanner) DrawScanner();
    if (m_showResults) DrawResults();
    if (m_showHex) m_hex.Draw(kWinHex, &m_showHex, m_proc);
    if (m_showWatch) DrawAddressList();
    if (m_showRegions) DrawRegions();
    if (m_showModules) DrawModules();
    if (m_showLog) DrawLog();
    if (m_showAbout) DrawAbout();
    if (m_showDecompile) DrawDecompile();
    if (m_showCalc) DrawCalculator();
    if (m_showOpcodes) DrawOpcodes();
    if (m_showCppHook) DrawCppHooks();
    if (m_showPtrScan) DrawPointerScan();
    if (m_showAob) DrawAobScan();
    DrawTraceWindows();
    Glass::PrepareMain(); // the modals open over the main window
    DrawProcessPicker();
    DrawEditValuePopup();
    Glass::DecorateWindows();
}

void App::SetupDefaultLayout(unsigned int id)
{
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::DockBuilderRemoveNode(id);
    ImGui::DockBuilderAddNode(id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(id, vp->WorkSize);

    ImGuiID left, right, leftTop, leftBottom, center, bottom;
    ImGui::DockBuilderSplitNode(id, ImGuiDir_Left, 0.33f, &left, &right);
    ImGui::DockBuilderSplitNode(left, ImGuiDir_Up, 0.45f, &leftTop, &leftBottom);
    ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.38f, &bottom, &center);

    ImGui::DockBuilderDockWindow(kWinScanner, leftTop);
    ImGui::DockBuilderDockWindow(kWinResults, leftBottom);
    ImGui::DockBuilderDockWindow(kWinHex, center);
    ImGui::DockBuilderDockWindow(kWinWatch, bottom);
    ImGui::DockBuilderDockWindow(kWinRegions, bottom);
    ImGui::DockBuilderDockWindow(kWinModules, bottom);
    ImGui::DockBuilderDockWindow(kWinLog, bottom);
    ImGui::DockBuilderFinish(id);
}

// ---------------------------------------------------------------------------

void App::DrawMenuBar()
{
    // A taller bar: it doubles as the window's title bar (see Glass::Caption and WM_NCHITTEST).
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                        ImVec2(ImGui::GetStyle().FramePadding.x, (Px(40) - ImGui::GetFontSize()) * 0.5f));
    bool barOpen = ImGui::BeginMainMenuBar();
    ImGui::PopStyleVar();
    if (!barOpen) return;

    ImGuiContext& g = *GImGui;
    Glass::Caption& cap = Glass::GetCaption();
    cap.solid.clear();
    const ImVec2 barMin = ImGui::GetWindowPos();
    const ImVec2 barMax(barMin.x + ImGui::GetWindowWidth(), barMin.y + ImGui::GetWindowHeight());
    cap.barMin = barMin;
    cap.barMax = barMax;
    cap.blocked = ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId) ||
                  (g.HoveredWindow && g.HoveredWindow != ImGui::GetCurrentWindow());
    ImDrawList* bar = ImGui::GetWindowDrawList();
    bar->AddLine(ImVec2(barMin.x, barMax.y - 1), ImVec2(barMax.x, barMax.y - 1), IM_COL32(255, 255, 255, 18));

    // Brand mark, matching the app icon.
    const float logo = IM_ROUND(Px(26));
    Glass::RamLogo(bar, ImVec2(IM_ROUND(barMin.x + Px(12)), IM_ROUND(barMin.y + (barMax.y - barMin.y - logo) * 0.5f)), logo);
    ImGui::SetCursorPosX(Px(12) + logo + Px(8));
    const float menusX0 = ImGui::GetCursorScreenPos().x;

    if (ImGui::BeginMenu("File"))
    {
        if (ImGui::MenuItem("Attach to process...", "Ctrl+O")) m_openPicker = true;
        if (ImGui::MenuItem("Detach", nullptr, false, m_proc.IsOpen() && !m_scanner.Busy())) Detach();
        ImGui::Separator();
        if (ImGui::MenuItem("Load address table...")) LoadTable();
        if (ImGui::MenuItem("Save address table...", nullptr, false, !m_watches.empty())) SaveTable();
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4")) m_quit = true;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Process", m_proc.IsOpen()))
    {
        if (m_proc.IsSuspended())
        {
            if (ImGui::MenuItem("Resume process")) { m_proc.Resume(); Log("Process resumed"); }
        }
        else if (ImGui::MenuItem("Suspend process"))
        {
            if (m_proc.Suspend()) Log("Process suspended");
            else Log("Suspend failed");
        }
        if (ImGui::MenuItem("Refresh modules"))
        {
            m_proc.RefreshModules();
            Log("Modules refreshed: " + std::to_string(m_proc.Modules().size()));
        }
        if (ImGui::MenuItem("Refresh memory regions")) m_regionsRefreshed = -100;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View"))
    {
        ImGui::MenuItem(kWinScanner, nullptr, &m_showScanner);
        ImGui::MenuItem(kWinResults, nullptr, &m_showResults);
        ImGui::MenuItem(kWinHex, nullptr, &m_showHex);
        ImGui::MenuItem(kWinWatch, nullptr, &m_showWatch);
        ImGui::MenuItem(kWinRegions, nullptr, &m_showRegions);
        ImGui::MenuItem(kWinModules, nullptr, &m_showModules);
        ImGui::MenuItem(kWinLog, nullptr, &m_showLog);
        ImGui::MenuItem(kWinDecompile, nullptr, &m_showDecompile);
        ImGui::MenuItem(kWinAob, nullptr, &m_showAob);
        ImGui::MenuItem(kWinCppHook, nullptr, &m_showCppHook);
        ImGui::Separator();
        if (ImGui::MenuItem("Reset layout"))
        {
            m_showScanner = m_showResults = m_showHex = m_showWatch = m_showRegions = m_showModules = m_showLog = true;
            m_layoutInit = false;
            m_forceLayout = true;
        }
        ImGui::EndMenu();
    }
    if (ImGui::MenuItem("Calculator")) m_showCalc = true;
    if (ImGui::MenuItem("Opcodes")) m_showOpcodes = true;
    if (ImGui::MenuItem("Pointer scan")) m_showPtrScan = true;
    if (ImGui::MenuItem("AOB scan")) m_showAob = true;
    if (ImGui::MenuItem("C++ hooks")) { m_showCppHook = true; ImGui::SetWindowFocus(kWinCppHook); }
    if (ImGui::BeginMenu("Debugger"))
    {
        // The two backends don't share hardware-breakpoint slots, so only switch when nothing is
        // being traced. Close the trace windows first otherwise.
        bool canSwitch = m_traces.empty();
        ImGui::BeginDisabled(!canSwitch);
        if (ImGui::MenuItem("Windows debugger", nullptr, m_debuggerMode == 0)) m_debuggerMode = 0;
        if (ImGui::MenuItem("VEH debugger (injected)", nullptr, m_debuggerMode == 1)) m_debuggerMode = 1;
        if (m_debuggerMode == 1)
        {
            ImGui::Separator();
            ImGui::TextDisabled("VEH watchpoint method:");
            if (ImGui::MenuItem("  Hardware (DR0-DR3)", nullptr, m_veh.Method() == 0)) m_veh.SetMethod(0);
            if (ImGui::MenuItem("  Page-guard (no debug registers)", nullptr, m_veh.Method() == 1)) m_veh.SetMethod(1);
        }
        ImGui::EndDisabled();
        if (!canSwitch) ImGui::TextDisabled("Close trace windows to switch");
        ImGui::Separator();
        if (m_debuggerMode == 1)
            ImGui::TextDisabled(m_veh.Method() == 1
                                    ? "Page-guard: no debug registers - beats DR-scanning anti-debug. 64-bit."
                                    : "Hardware DR: fast/exact, but visible to DR-scanning anti-debug. 64-bit.");
        else
            ImGui::TextDisabled("Windows: DebugActiveProcess + DR0-DR3. Works on 32/64-bit.");
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Help"))
    {
        ImGui::MenuItem("Expressions & shortcuts", nullptr, &m_showAbout);
        ImGui::EndMenu();
    }
    cap.solid.push_back(ImVec4(menusX0, barMin.y, ImGui::GetItemRectMax().x, barMax.y));

    // Window buttons, flush right like the system ones. Maximize is answered by the window
    // procedure (HTMAXBUTTON) so Windows 11 can show snap layouts; the UI only draws it.
    HWND hwnd = (HWND)m_hwnd;
    const float capW = Px(46);
    const float capX = barMax.x - capW * 3;
    auto captionButton = [&](int i, const char* icon, const char* id, bool danger) {
        ImVec2 b0(capX + capW * i, barMin.y), b1(b0.x + capW, barMax.y);
        bool pressed = false, hovered, held = false;
        if (id)
        {
            ImGui::SetCursorScreenPos(b0);
            pressed = ImGui::InvisibleButton(id, ImVec2(capW, b1.y - b0.y));
            hovered = ImGui::IsItemHovered();
            held = ImGui::IsItemActive();
            cap.solid.push_back(ImVec4(b0.x, b0.y, b1.x, b1.y));
        }
        else
        {
            hovered = !cap.blocked && ImGui::IsMouseHoveringRect(b0, b1, false);
            cap.maxMin = b0;
            cap.maxMax = b1;
        }
        if (hovered)
            bar->AddRectFilled(b0, b1, danger ? IM_COL32(196, 43, 28, held ? 190 : 230) : IM_COL32(255, 255, 255, held ? 14 : 24));
        ImVec2 ts = ImGui::CalcTextSize(icon);
        bar->AddText(ImVec2(b0.x + (capW - ts.x) * 0.5f, b0.y + (b1.y - b0.y - ts.y) * 0.5f),
                     ImGui::GetColorU32(ImGuiCol_Text, hovered ? 1.f : 0.8f), icon);
        return pressed;
    };
    if (captionButton(0, ICON_WIN_MIN, "##capmin", false)) ShowWindow(hwnd, SW_MINIMIZE);
    captionButton(1, IsZoomed(hwnd) ? ICON_WIN_RESTORE : ICON_WIN_MAX, nullptr, false);
    if (captionButton(2, ICON_WIN_CLOSE, "##capclose", true)) m_quit = true;

    // Quick attach pill left of the window buttons, with a status light that pulses while attached.
    const char* label = m_proc.IsOpen() ? m_proc.Name().c_str() : "No process";
    const float dotGap = Px(22);
    float w = ImGui::CalcTextSize(label).x + dotGap + Px(44);
    ImGui::SetCursorScreenPos(ImVec2(capX - w + Px(4), barMin.y));
    ImGui::AlignTextToFramePadding();
    ImVec2 pill0 = ImGui::GetCursorScreenPos();
    ImVec2 pillSize(w - Px(16), ImGui::GetFrameHeight() - Px(4));
    pill0.y = ImGui::GetWindowPos().y + (ImGui::GetWindowHeight() - pillSize.y) * 0.5f;
    ImVec2 pill1(pill0.x + pillSize.x, pill0.y + pillSize.y);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(pill0, pill1, IM_COL32(255, 255, 255, 14), pillSize.y * 0.5f);
    dl->AddRect(pill0, pill1, IM_COL32(255, 255, 255, 34), pillSize.y * 0.5f);
    ImVec2 dot(pill0.x + Px(14), (pill0.y + pill1.y) * 0.5f);
    ImVec4 dotCol = m_proc.IsOpen() ? kColOk : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    if (m_proc.IsOpen())
    {
        float pulse = 0.5f + 0.5f * sinf((float)ImGui::GetTime() * 2.4f);
        Glass::Glow(dl, dot, Px(9 + 3 * pulse), ImVec4(dotCol.x, dotCol.y, dotCol.z, 0.35f + 0.25f * pulse));
    }
    dl->AddCircleFilled(dot, Px(3.5f), ImGui::ColorConvertFloat4ToU32(dotCol));

    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + dotGap);
    ImGui::PushStyleColor(ImGuiCol_Text, m_proc.IsOpen() ? ImGui::GetStyleColorVec4(ImGuiCol_Text)
                                                         : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
    if (ImGui::Selectable(label, false, 0, ImVec2(w - dotGap - Px(28), 0))) m_openPicker = true;
    bool pillHovered = ImGui::IsItemHovered();
    ImGui::PopStyleColor(3);
    if (pillHovered) dl->AddRect(pill0, pill1, ImGui::GetColorU32(ImGuiCol_SliderGrab), pillSize.y * 0.5f, 0, 1.5f);
    cap.solid.push_back(ImVec4(pill0.x, pill0.y, pill1.x, pill1.y));
    ImGui::SetItemTooltip("Click to choose a process (Ctrl+O)");
    ImGui::EndMainMenuBar();
}

void App::DrawStatusBar()
{
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_MenuBar;
    float h = ImGui::GetFrameHeight();
    if (ImGui::BeginViewportSideBar("##statusbar", ImGui::GetMainViewport(), ImGuiDir_Down, h, flags))
    {
        if (ImGui::BeginMenuBar())
        {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            const ImVec2 wp = ImGui::GetWindowPos();
            dl->AddLine(wp, ImVec2(wp.x + ImGui::GetWindowWidth(), wp.y), IM_COL32(255, 255, 255, 18));
            const float midY = wp.y + ImGui::GetWindowHeight() * 0.5f;

            // Connection light, then process facts.
            ImVec4 dotCol = m_proc.IsOpen() ? kColOk : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
            ImVec2 dot(ImGui::GetCursorScreenPos().x + Px(5), midY);
            if (m_proc.IsOpen()) Glass::Glow(dl, dot, Px(9), ImVec4(dotCol.x, dotCol.y, dotCol.z, 0.35f));
            dl->AddCircleFilled(dot, Px(3.5f), ImGui::ColorConvertFloat4ToU32(dotCol));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + Px(16));
            if (m_proc.IsOpen())
            {
                ImGui::TextUnformatted(m_proc.Name().c_str());
                ImGui::TextDisabled("PID %lu", m_proc.Pid());
                ImGui::TextDisabled(ICON_CHIP " %s", m_proc.Is64() ? "x64" : "x86");
                if (m_proc.IsSuspended()) ImGui::TextColored(kColChanged, ICON_PAUSE " Suspended");
            }
            else ImGui::TextDisabled("Not attached");

            // Scan state: a slim progress track while scanning.
            if (m_scanner.Busy())
            {
                ImGui::Separator();
                ImGui::TextColored(kColAccent, ICON_SEARCH " Scanning");
                ImVec2 t0(ImGui::GetCursorScreenPos().x, midY - Px(2)), t1(t0.x + Px(120), midY + Px(2));
                dl->AddRectFilled(t0, t1, IM_COL32(255, 255, 255, 22), Px(2));
                dl->AddRectFilled(t0, ImVec2(t0.x + (t1.x - t0.x) * m_scanner.Progress(), t1.y),
                                  ImGui::GetColorU32(Glass::kAccent), Px(2));
                ImGui::Dummy(ImVec2(Px(120), 0));
                ImGui::TextDisabled("%.0f%%", m_scanner.Progress() * 100.f);
            }
            else if (m_scanner.HasResults())
            {
                ImGui::Separator();
                ImGui::TextDisabled(ICON_LIST " Scan #%llu: %zu results", (unsigned long long)m_scanner.State().scanNumber,
                                    m_scanner.State().Count());
            }

            // Right side: privilege and frame rate.
            char fps[32];
            snprintf(fps, sizeof(fps), "%.0f FPS", ImGui::GetIO().Framerate);
            const char* priv = m_elevated ? ICON_SHIELD_FILL " Administrator" : ICON_SHIELD " Not elevated";
            const ImGuiStyle& st = ImGui::GetStyle();
            float rightW = ImGui::CalcTextSize(priv).x + ImGui::CalcTextSize(fps).x + st.ItemSpacing.x * 4 + Px(8);
            ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(), ImGui::GetWindowWidth() - rightW));
            if (m_elevated) ImGui::TextColored(kColOk, "%s", priv);
            else ImGui::TextDisabled("%s", priv);
            ImGui::Separator();
            ImGui::TextDisabled("%s", fps);
            ImGui::EndMenuBar();
        }
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------

void App::DrawProcessPicker()
{
    if (m_openPicker)
    {
        m_openPicker = false;
        m_procList = Process::Enumerate();
        ImGui::OpenPopup("Attach to Process");
    }
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(Px(560), Px(520)), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("Attach to Process", nullptr)) return;

    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(Px(-200));
    ImGui::InputTextWithHint("##pfilter", "Filter by name or PID", m_procFilter, sizeof(m_procFilter));
    ImGui::SameLine();
    ImGui::Checkbox("Hide inaccessible", &m_hideInaccessible);
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) m_procList = Process::Enumerate();

    DWORD chosen = 0;
    static DWORD selected = 0;
    float footer = ImGui::GetFrameHeightWithSpacing() + 4;
    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##procs", 4, tf, ImVec2(0, -footer)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending, Px(70));
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_DefaultSort);
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, Px(45));
        ImGui::TableSetupColumn("Threads", ImGuiTableColumnFlags_WidthFixed, Px(60));
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* ss = ImGui::TableGetSortSpecs())
        {
            if (ss->SpecsDirty && ss->SpecsCount > 0)
            {
                auto spec = ss->Specs[0];
                std::sort(m_procList.begin(), m_procList.end(), [&](const ProcessInfo& a, const ProcessInfo& b) {
                    int c = 0;
                    switch (spec.ColumnIndex)
                    {
                    case 0: c = a.pid < b.pid ? -1 : a.pid > b.pid; break;
                    case 1: c = _stricmp(a.name.c_str(), b.name.c_str()); break;
                    case 2: c = (int)a.is64 - (int)b.is64; break;
                    case 3: c = a.threads < b.threads ? -1 : a.threads > b.threads; break;
                    }
                    return spec.SortDirection == ImGuiSortDirection_Ascending ? c < 0 : c > 0;
                });
                ss->SpecsDirty = false;
            }
        }

        for (const auto& p : m_procList)
        {
            if (m_hideInaccessible && !p.accessible) continue;
            if (m_procFilter[0] && !Contains(p.name, m_procFilter) && std::to_string(p.pid).find(m_procFilter) == std::string::npos)
                continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (!p.accessible) ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
            char id[32];
            snprintf(id, sizeof(id), "%lu", p.pid);
            if (ImGui::Selectable(id, selected == p.pid, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
            {
                selected = p.pid;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) chosen = p.pid;
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(p.name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(p.accessible ? (p.is64 ? "x64" : "x86") : "-");
            ImGui::TableNextColumn();
            ImGui::Text("%lu", p.threads);
            if (!p.accessible) ImGui::PopStyleColor();
        }
        ImGui::EndTable();
    }

    ImGui::BeginDisabled(selected == 0);
    if (ImGui::Button("Attach", ImVec2(Px(120), 0)) || (selected && ImGui::IsKeyPressed(ImGuiKey_Enter))) chosen = selected;
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(Px(120), 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    if (chosen)
    {
        Attach(chosen);
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

// ---------------------------------------------------------------------------

void App::DrawScanner()
{
    Glass::PrepareWindow(kWinScanner);
    if (!ImGui::Begin(kWinScanner, &m_showScanner))
    {
        ImGui::End();
        return;
    }
    bool attached = m_proc.IsOpen();
    bool busy = m_scanner.Busy();
    bool hasResults = m_scanner.HasResults();
    ImGui::BeginDisabled(!attached || busy);

    bool doFirst = false, doNext = false;
    float bw = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * 2) / 3.f;
    // The step you'd take next gets the filled accent button.
    if (!hasResults)
    {
        if (Glass::AccentButton(ICON_SEARCH "  First Scan", ImVec2(bw, 0))) doFirst = true;
    }
    else if (ImGui::Button(ICON_REFRESH "  New Scan", ImVec2(bw, 0)))
    {
        m_scanner.Reset();
        m_resSel.Clear();
        if (!CompareAllowed(m_opts.compare, m_opts.type, true)) m_opts.compare = ScanCompare::Exact;
        hasResults = false;
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!hasResults);
    if (hasResults ? Glass::AccentButton(ICON_FORWARD "  Next Scan", ImVec2(bw, 0))
                   : ImGui::Button(ICON_FORWARD "  Next Scan", ImVec2(bw, 0)))
        doNext = true;
    ImGui::SameLine();
    ImGui::BeginDisabled(!m_scanner.CanUndo());
    if (ImGui::Button(ICON_UNDO "  Undo Scan", ImVec2(bw, 0))) { m_scanner.Undo(); m_resSel.Clear(); }
    ImGui::EndDisabled();
    ImGui::EndDisabled();

    ImGui::Spacing();
    const float labelW = Px(90);

    // Value type
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Value type");
    ImGui::SameLine(labelW);
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::BeginDisabled(hasResults);
    if (ImGui::BeginCombo("##vtype", ValueTypeName(m_opts.type)))
    {
        for (int t = 0; t < (int)ValueType::Count; t++)
        {
            if (ImGui::Selectable(ValueTypeName((ValueType)t), (int)m_opts.type == t))
            {
                m_opts.type = (ValueType)t;
                size_t s = ValueTypeSize(m_opts.type);
                m_opts.alignment = s ? (int)std::min<size_t>(s, 4) : 1;
                if (!CompareAllowed(m_opts.compare, m_opts.type, true)) m_opts.compare = ScanCompare::Exact;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::EndDisabled();

    // Scan type
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Scan type");
    ImGui::SameLine(labelW);
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (!CompareAllowed(m_opts.compare, m_opts.type, !hasResults)) m_opts.compare = ScanCompare::Exact;
    if (ImGui::BeginCombo("##ctype", ScanCompareName(m_opts.compare)))
    {
        for (int c = 0; c < (int)ScanCompare::Count; c++)
        {
            if (!CompareAllowed((ScanCompare)c, m_opts.type, !hasResults)) continue;
            if (ImGui::Selectable(ScanCompareName((ScanCompare)c), (int)m_opts.compare == c)) m_opts.compare = (ScanCompare)c;
        }
        ImGui::EndCombo();
    }

    // Values
    bool enter = false;
    if (CompareNeedsValue(m_opts.compare))
    {
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(CompareNeedsTwoValues(m_opts.compare) ? "From" : "Value");
        ImGui::SameLine(labelW);
        ImGui::SetNextItemWidth(-FLT_MIN);
        const char* hint = m_opts.type == ValueType::ByteArray ? "48 8B ?? ?? 89" : IsFloat(m_opts.type) ? "100.5" : "100";
        if (m_mono) ImGui::PushFont(m_mono);
        enter |= ImGui::InputTextWithHint("##v1", hint, m_value1, sizeof(m_value1), ImGuiInputTextFlags_EnterReturnsTrue);
        if (m_mono) ImGui::PopFont();
        if (CompareNeedsTwoValues(m_opts.compare))
        {
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("To");
            ImGui::SameLine(labelW);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (m_mono) ImGui::PushFont(m_mono);
            enter |= ImGui::InputText("##v2", m_value2, sizeof(m_value2), ImGuiInputTextFlags_EnterReturnsTrue);
            if (m_mono) ImGui::PopFont();
        }
        ImGui::SetCursorPosX(labelW);
        if (IsNumeric(m_opts.type) && !IsFloat(m_opts.type)) ImGui::Checkbox("Hex", &m_opts.hexInput);
        if (m_opts.type == ValueType::String || m_opts.type == ValueType::WString)
            ImGui::Checkbox("Case sensitive", &m_opts.caseSensitive);
    }
    if (enter) (hasResults ? doNext : doFirst) = true;

    ImGui::Spacing();
    if (ImGui::CollapsingHeader("Memory scan options", ImGuiTreeNodeFlags_DefaultOpen))
    {
        ImGui::BeginDisabled(hasResults);
        // Region checkboxes in a three-column grid sized from the panel, so labels never collide.
        if (ImGui::BeginTable("##regionkinds", 3, ImGuiTableFlags_SizingStretchSame))
        {
            ImGui::TableNextColumn();
            ImGui::Checkbox("Writable only", &m_opts.requireWritable);
            ImGui::TableNextColumn();
            ImGui::Checkbox("Include executable", &m_opts.includeExecutable);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Checkbox("Image", &m_opts.includeImage);
            ImGui::SetItemTooltip("Memory backed by loaded modules (.exe/.dll sections)");
            ImGui::TableNextColumn();
            ImGui::Checkbox("Private", &m_opts.includePrivate);
            ImGui::SetItemTooltip("Heap / stack / VirtualAlloc memory");
            ImGui::TableNextColumn();
            ImGui::Checkbox("Mapped", &m_opts.includeMapped);
            ImGui::SetItemTooltip("File mappings and shared sections");
            ImGui::EndTable();
        }

        if (IsNumeric(m_opts.type))
        {
            ImGui::Checkbox("Fast scan, alignment", &m_opts.fastScan);
            ImGui::SameLine();
            ImGui::BeginDisabled(!m_opts.fastScan);
            ImGui::SetNextItemWidth(StepperWidth(40));
            ImGui::InputInt("##align", &m_opts.alignment, 1, 4);
            m_opts.alignment = std::clamp(m_opts.alignment, 1, 64);
            ImGui::EndDisabled();
        }

        // Start [....] Stop [....] [All]: the two address fields share whatever width is left.
        const ImGuiStyle& st = ImGui::GetStyle();
        float allW = ImGui::CalcTextSize("All").x + st.FramePadding.x * 2;
        float fieldW = (ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Start").x - ImGui::CalcTextSize("Stop").x -
                        allW - st.ItemSpacing.x * 4) / 2.f;
        fieldW = std::max(fieldW, Px(90));
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Start");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(fieldW);
        if (m_mono) ImGui::PushFont(m_mono);
        ImGui::InputText("##rs", m_rangeStart, sizeof(m_rangeStart), ImGuiInputTextFlags_CharsHexadecimal);
        if (m_mono) ImGui::PopFont();
        ImGui::SameLine();
        ImGui::TextUnformatted("Stop");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(fieldW);
        if (m_mono) ImGui::PushFont(m_mono);
        ImGui::InputText("##re", m_rangeEnd, sizeof(m_rangeEnd), ImGuiInputTextFlags_CharsHexadecimal);
        if (m_mono) ImGui::PopFont();
        ImGui::SameLine();
        if (ImGui::Button("All", ImVec2(allW, 0)))
        {
            snprintf(m_rangeStart, sizeof(m_rangeStart), "0");
            snprintf(m_rangeEnd, sizeof(m_rangeEnd), "%llX", (unsigned long long)m_proc.MaxAddress());
        }
        ImGui::EndDisabled();
    }
    ImGui::EndDisabled(); // !attached || busy

    if (busy)
    {
        ImGui::Spacing();
        char overlay[64];
        snprintf(overlay, sizeof(overlay), "Scanning %.0f%%", m_scanner.Progress() * 100.f);
        ImGui::ProgressBar(m_scanner.Progress(), ImVec2(-Px(80), 0), overlay);
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(-FLT_MIN, 0))) m_scanner.Cancel();
    }
    else if (hasResults)
    {
        ImGui::Spacing();
        const ScanState& st = m_scanner.State();
        ImGui::TextColored(kColAccent, "Found %zu", st.Count());
        ImGui::SameLine();
        ImGui::TextDisabled("(scan #%llu, %s, %.0f ms)", (unsigned long long)st.scanNumber, ValueTypeName(st.type),
                            m_scanner.LastDurationMs());
    }
    if (!m_scanError.empty()) ImGui::TextColored(kColErr, "%s", m_scanError.c_str());
    if (!attached) ImGui::TextDisabled("Attach to a process first (Ctrl+O).");

    if ((doFirst || doNext) && attached && !busy)
    {
        m_opts.value1 = m_value1;
        m_opts.value2 = m_value2;
        uint64_t s = 0, e = 0;
        ParseHexU64(m_rangeStart, s);
        if (!ParseHexU64(m_rangeEnd, e) || e == 0) e = m_proc.MaxAddress();
        m_opts.startAddress = s;
        m_opts.endAddress = e;
        m_scanError.clear();
        if (!m_scanner.Start(m_proc, m_opts, doFirst, m_scanError)) Log("Scan error: " + m_scanError);
        m_resSel.Clear();
    }
    ImGui::End();
}

void App::DrawResults()
{
    Glass::PrepareWindow(kWinResults);
    if (!ImGui::Begin(kWinResults, &m_showResults))
    {
        ImGui::End();
        return;
    }
    const ScanState& st = m_scanner.State();
    if (m_scanner.Busy())
    {
        char hint[64];
        snprintf(hint, sizeof(hint), "%.0f%% done. Results appear here when it finishes.", m_scanner.Progress() * 100.f);
        Glass::EmptyState(ICON_SEARCH, "Scanning", hint);
        ImGui::End();
        return;
    }
    if (!st.valid)
    {
        if (!m_proc.IsOpen())
        {
            if (Glass::EmptyState(ICON_LIST, "No results yet", "Attach to a process, then run a First Scan.",
                                  ICON_LINK "  Attach to process"))
                m_openPicker = true;
        }
        else Glass::EmptyState(ICON_LIST, "No results yet", "Run a First Scan in the Scanner to find addresses.");
        ImGui::End();
        return;
    }
    if (st.snapshot)
    {
        uint64_t bytes = 0;
        for (const auto& r : st.regions) bytes += r.data.size();
        ImGui::TextWrapped("Captured %s of memory (%llu candidate addresses) for an unknown initial value.",
                           HumanSize(bytes).c_str(), (unsigned long long)st.snapshotCandidates);
        ImGui::TextDisabled("Change the value in the target, then Next Scan with\nChanged / Unchanged / Increased / Decreased.");
        ImGui::End();
        return;
    }

    const size_t count = st.addresses.size();
    const size_t vs = st.valueSize;
    m_resSel.Resize(count);

    // Selected results -> address list (capped so a stray Ctrl+A on millions can't hang the UI).
    auto addSelected = [&] {
        size_t added = 0;
        m_resSel.ForEach([&](size_t k) {
            if (added++ < 5000) AddWatch(st.addresses[k], st.type, (int)vs);
        });
        if (added > 5000) Log("Added the first 5000 of " + std::to_string(added) + " selected results");
    };
    auto copySelected = [&] {
        std::string text;
        size_t n = 0;
        m_resSel.ForEach([&](size_t k) {
            if (n++ < 100000) text += ToHex(st.addresses[k]) + "\n";
        });
        ImGui::SetClipboardText(text.c_str());
    };
    auto editSelected = [&] {
        m_editWatch = -2;
        m_editBuf[0] = 0;
        m_openEditPopup = true;
    };

    // Toolbar: counts plus actions on the selection.
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("%zu %s", count, count == 1 ? "result" : "results");
    if (m_resSel.Count())
    {
        ImGui::SameLine();
        ImGui::TextColored(kColAccent, "%zu selected", m_resSel.Count());
        ImGui::SameLine();
        if (ImGui::SmallButton(ICON_ADD " Add to list")) addSelected();
        ImGui::SetItemTooltip("Add the selected results to the address list (Enter)");
        ImGui::SameLine();
        if (ImGui::SmallButton(ICON_EDIT " Set value")) editSelected();
        ImGui::SameLine();
        if (ImGui::SmallButton(ICON_COPY " Copy")) copySelected();
        ImGui::SetItemTooltip("Copy the selected addresses (Ctrl+C)");
    }
    else
    {
        ImGui::SameLine();
        ImGui::TextDisabled(" -  Ctrl/Shift+click to select several");
    }

    // Keyboard, while this panel has focus and no text field is being edited.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput)
    {
        const bool ctrl = ImGui::GetIO().KeyCtrl;
        if (ctrl && ImGui::IsKeyPressed(ImGuiKey_A, false)) m_resSel.SelectAll();
        if (ctrl && ImGui::IsKeyPressed(ImGuiKey_C, false) && m_resSel.Count()) copySelected();
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) && m_resSel.Count()) addSelected();
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) m_resSel.Clear();
    }

    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##results", 3, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Previous", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();

        if (m_mono) ImGui::PushFont(m_mono);
        ImGuiListClipper clipper;
        clipper.Begin((int)std::min<size_t>(count, INT_MAX));
        std::vector<uint8_t> cur(vs);
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                uint64_t a = st.addresses[i];
                const uint8_t* prev = st.values.data() + (size_t)i * vs;
                bool ok = m_proc.ReadExact(a, cur.data(), vs);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                bool selected = m_resSel.Get(i);
                ModuleInfo m;
                bool isStatic = m_proc.ModuleFromAddress(a, m);
                std::string label = isStatic ? m_proc.Symbolize(a) : AddrText(a);
                if (isStatic) ImGui::PushStyleColor(ImGuiCol_Text, kColOk);
                if (ImGui::Selectable(label.c_str(), selected,
                                      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
                {
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) AddWatch(a, st.type, (int)vs);
                    else m_resSel.Click(i);
                }
                if (isStatic) ImGui::PopStyleColor();
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) m_resSel.SelectForContextMenu(i);
                if (ImGui::BeginPopupContextItem("##rctx"))
                {
                    if (m_mono) ImGui::PopFont(); // the menu uses the normal UI face, not the table's mono one
                    const size_t n = m_resSel.Count();
                    std::string addLabel = n > 1 ? "Add " + std::to_string(n) + " selected to address list" : "Add to address list";
                    if (ImGui::MenuItem((ICON_ADD "  " + addLabel).c_str(), "Enter")) addSelected();
                    if (ImGui::MenuItem(n > 1 ? ICON_EDIT "  Change value of selected..." : ICON_EDIT "  Change value..."))
                    {
                        editSelected();
                        snprintf(m_editBuf, sizeof(m_editBuf), "%s", ok ? FormatValue(st.type, cur.data(), vs, false).c_str() : "");
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_CHIP "  Browse memory here")) { m_hex.GoTo(a); m_showHex = true; ImGui::SetWindowFocus(kWinHex); }
                    if (ImGui::MenuItem(ICON_SEARCH "  Pointer scan for this address")) OpenPointerScan(a);
                    ImGui::Separator();
                    if (ImGui::MenuItem(n > 1 ? ICON_COPY "  Copy selected addresses" : ICON_COPY "  Copy address", "Ctrl+C"))
                        copySelected();
                    if (ImGui::MenuItem(ICON_COPY "  Copy value", nullptr, false, ok))
                        ImGui::SetClipboardText(FormatValue(st.type, cur.data(), vs, false).c_str());
                    ImGui::Separator();
                    if (ImGui::MenuItem("Select all", "Ctrl+A")) m_resSel.SelectAll();
                    if (ImGui::MenuItem("Clear selection", "Esc", false, n > 0)) m_resSel.Clear();
                    if (m_mono) ImGui::PushFont(m_mono);
                    ImGui::EndPopup();
                }
                ImGui::PopID();
                if (isStatic) ImGui::SetItemTooltip("Static address inside %s", m.name.c_str());

                ImGui::TableNextColumn();
                if (ok)
                {
                    bool changed = memcmp(cur.data(), prev, vs) != 0;
                    std::string v = FormatValue(st.type, cur.data(), vs, false);
                    ImGui::TextColored(changed ? kColChanged : Syntax::TypeColor(st.type), "%s", v.c_str());
                }
                else
                {
                    ImGui::TextDisabled("??");
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", FormatValue(st.type, prev, vs, false).c_str());
            }
        }
        if (m_mono) ImGui::PopFont();
        ImGui::EndTable();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------

void App::DrawEditValuePopup()
{
    if (m_openEditPopup)
    {
        m_openEditPopup = false;
        ImGui::OpenPopup("Change value");
    }
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("Change value", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    ValueType type = ValueType::Int32;
    bool hex = false;
    if (m_editWatch >= 0 && m_editWatch < (int)m_watches.size())
    {
        type = m_watches[m_editWatch].type;
        hex = m_watches[m_editWatch].hex;
        ImGui::Text("%s", m_watches[m_editWatch].description.c_str());
    }
    else if (m_editWatch == -2)
    {
        type = m_scanner.State().type;
        ImGui::Text("Set %zu selected result(s)", m_resSel.Count());
    }
    else if (m_editWatch == -3)
    {
        // Several address-list entries: each is written with its own type.
        size_t n = 0;
        for (const auto& w : m_watches)
            if (w.selected && !n++) type = w.type, hex = w.hex;
        ImGui::Text("Set %zu selected entries", n);
    }
    ImGui::TextDisabled("Type: %s%s", ValueTypeName(type), hex ? " (hex)" : "");

    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(Px(320));
    if (m_mono) ImGui::PushFont(m_mono);
    bool enter = ImGui::InputText("##editval", m_editBuf, sizeof(m_editBuf), ImGuiInputTextFlags_EnterReturnsTrue);
    if (m_mono) ImGui::PopFont();

    bool apply = ImGui::Button("OK", ImVec2(Px(100), 0)) || enter;
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(Px(100), 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();

    if (apply)
    {
        ParsedValue pv = ParseValue(type, m_editBuf, hex);
        if (!pv.ok)
        {
            Log(std::string("Invalid value for ") + ValueTypeName(type));
        }
        else if (m_editWatch >= 0 && m_editWatch < (int)m_watches.size())
        {
            WatchEntry& w = m_watches[m_editWatch];
            if (w.type == ValueType::String || w.type == ValueType::WString)
            {
                pv.bytes.push_back(0);
                if (w.type == ValueType::WString) pv.bytes.push_back(0);
            }
            if (!w.resolved || !m_proc.Write(w.address, pv.bytes.data(), pv.bytes.size())) Log("Write failed: " + w.expression);
            if (w.frozen) w.frozenBytes = pv.bytes;
        }
        else if (m_editWatch == -2)
        {
            const ScanState& st = m_scanner.State();
            int fails = 0;
            m_resSel.ForEach([&](size_t k) {
                if (k < st.addresses.size() && !m_proc.Write(st.addresses[k], pv.bytes.data(), pv.bytes.size())) fails++;
            });
            if (fails) Log(std::to_string(fails) + " writes failed");
        }
        else if (m_editWatch == -3)
        {
            int fails = 0;
            for (auto& w : m_watches)
            {
                if (!w.selected) continue;
                ParsedValue v = ParseValue(w.type, m_editBuf, w.hex);
                if (!v.ok) { fails++; continue; }
                if (w.type == ValueType::String || w.type == ValueType::WString)
                {
                    v.bytes.push_back(0);
                    if (w.type == ValueType::WString) v.bytes.push_back(0);
                }
                if (!w.resolved || !m_proc.Write(w.address, v.bytes.data(), v.bytes.size())) fails++;
                else if (w.frozen) w.frozenBytes = v.bytes;
            }
            if (fails) Log(std::to_string(fails) + " of the selected entries could not be written");
        }
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void App::DrawAddressList()
{
    Glass::PrepareWindow(kWinWatch);
    if (!ImGui::Begin(kWinWatch, &m_showWatch))
    {
        ImGui::End();
        return;
    }
    if (ImGui::Button("Add address"))
    {
        WatchEntry e;
        e.expression = m_proc.IsOpen() ? m_proc.Symbolize(m_hex.Cursor()) : "0";
        m_watches.push_back(e);
    }
    ImGui::SetItemTooltip("Adds the memory view's cursor address. Edit the address cell to change it.");
    ImGui::SameLine();
    if (ImGui::Button("Load...")) LoadTable();
    ImGui::SameLine();
    ImGui::BeginDisabled(m_watches.empty());
    if (ImGui::Button("Save...")) SaveTable();
    ImGui::SameLine();
    if (ImGui::Button("Clear")) m_watches.clear();
    ImGui::EndDisabled();
    const int selCount = (int)std::count_if(m_watches.begin(), m_watches.end(), [](const WatchEntry& w) { return w.selected; });
    ImGui::SameLine();
    ImGui::TextDisabled("%zu %s", m_watches.size(), m_watches.size() == 1 ? "entry" : "entries");
    if (selCount)
    {
        ImGui::SameLine();
        ImGui::TextColored(kColAccent, "%d selected", selCount);
    }

    // Reads the live value of an entry (also used for sorting and freezing).
    auto readValue = [&](const WatchEntry& w, std::vector<uint8_t>& buf) {
        buf.resize(WatchSize(w));
        return w.resolved && m_proc.ReadExact(w.address, buf.data(), buf.size());
    };
    auto setFrozen = [&](WatchEntry& w, bool on) {
        std::vector<uint8_t> buf;
        if (!on || !readValue(w, buf)) { w.frozen = false; return; }
        w.frozen = true;
        w.frozenBytes = buf;
        if (w.type == ValueType::String) // freeze only up to the terminator
        {
            auto z = std::find(w.frozenBytes.begin(), w.frozenBytes.end(), 0);
            if (z != w.frozenBytes.end()) w.frozenBytes.erase(z + 1, w.frozenBytes.end());
        }
    };
    auto forSelected = [&](auto fn) {
        for (auto& w : m_watches)
            if (w.selected) fn(w);
    };
    auto deleteSelected = [&] {
        m_watches.erase(std::remove_if(m_watches.begin(), m_watches.end(), [](const WatchEntry& w) { return w.selected; }),
                        m_watches.end());
        m_watchAnchor = -1;
    };
    auto toggleFreezeSelected = [&] {
        bool anyThawed = false;
        forSelected([&](WatchEntry& w) { anyThawed |= !w.frozen; });
        forSelected([&](WatchEntry& w) { setFrozen(w, anyThawed); });
    };
    auto copySelected = [&] {
        std::string text;
        forSelected([&](WatchEntry& w) {
            std::vector<uint8_t> buf;
            bool ok = readValue(w, buf);
            text += w.description + "\t" + w.expression + "\t" + (w.resolved ? ToHex(w.address) : "?") + "\t" +
                    (ok ? FormatValue(w.type, buf.data(), buf.size(), w.hex) : "??") + "\n";
        });
        ImGui::SetClipboardText(text.c_str());
    };
    auto duplicateSelected = [&] {
        std::vector<WatchEntry> out;
        out.reserve(m_watches.size() * 2);
        for (auto& w : m_watches)
        {
            out.push_back(w);
            out.back().selected = false;
            if (w.selected)
            {
                WatchEntry copy = w;
                copy.frozen = false;
                out.push_back(std::move(copy)); // the copies become the selection
            }
        }
        m_watches = std::move(out);
    };
    auto editSelected = [&] {
        m_editWatch = -3;
        m_editBuf[0] = 0;
        m_openEditPopup = true;
    };

    // Keyboard, while this panel has focus and no text field is being edited.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput)
    {
        const bool ctrl = ImGui::GetIO().KeyCtrl;
        if (ctrl && ImGui::IsKeyPressed(ImGuiKey_A, false)) for (auto& w : m_watches) w.selected = true;
        if (selCount)
        {
            if (ImGui::IsKeyPressed(ImGuiKey_Delete, false)) deleteSelected();
            else if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) toggleFreezeSelected();
            else if (ImGui::IsKeyPressed(ImGuiKey_Enter, false)) editSelected();
            else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) copySelected();
            else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_D, false)) duplicateSelected();
            else if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) for (auto& w : m_watches) w.selected = false;
        }
    }

    int removeIdx = -1, dupIdx = -1, moveFrom = -1, moveTo = -1, clickRow = -1;
    bool bulkDelete = false;
    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Sortable |
                         ImGuiTableFlags_SortTristate;
    if (ImGui::BeginTable("##watch", 6, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Freeze", ImGuiTableColumnFlags_WidthFixed, Px(56));
        ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.6f);
        ImGui::TableSetupColumn("Resolved", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, Px(130));
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableHeadersRow();

        // Clicking a header sorts the list in place (once - values that change later don't reshuffle rows).
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs())
        {
            if (specs->SpecsDirty && specs->SpecsCount > 0)
            {
                const ImGuiTableColumnSortSpecs& s = specs->Specs[0];
                const bool desc = s.SortDirection == ImGuiSortDirection_Descending;
                // Numeric key for the Value column; text values fall back to string order.
                std::vector<std::pair<double, std::string>> keys(m_watches.size());
                std::vector<uint8_t> buf;
                for (size_t k = 0; k < m_watches.size(); k++)
                {
                    const WatchEntry& w = m_watches[k];
                    bool ok = readValue(w, buf);
                    keys[k].second = ok ? FormatValue(w.type, buf.data(), buf.size(), false) : "";
                    keys[k].first = ok && IsNumeric(w.type) ? strtod(keys[k].second.c_str(), nullptr) : -HUGE_VAL;
                }
                std::vector<size_t> order(m_watches.size());
                for (size_t k = 0; k < order.size(); k++) order[k] = k;
                std::stable_sort(order.begin(), order.end(), [&](size_t x, size_t y) {
                    const WatchEntry& a = m_watches[x];
                    const WatchEntry& b = m_watches[y];
                    int c = 0;
                    switch (s.ColumnIndex)
                    {
                    case 0: c = (int)b.frozen - (int)a.frozen; break;
                    case 1: c = Lower(a.description).compare(Lower(b.description)); break;
                    case 2: c = Lower(a.expression).compare(Lower(b.expression)); break;
                    case 3: c = a.resolved != b.resolved ? (a.resolved ? -1 : 1) : a.address < b.address ? -1 : a.address > b.address; break;
                    case 4: c = (int)a.type - (int)b.type; break;
                    case 5:
                        c = keys[x].first < keys[y].first ? -1 : keys[x].first > keys[y].first;
                        if (!c) c = keys[x].second.compare(keys[y].second);
                        break;
                    }
                    return desc ? c > 0 : c < 0;
                });
                std::vector<WatchEntry> sorted;
                sorted.reserve(m_watches.size());
                for (size_t k : order) sorted.push_back(std::move(m_watches[k]));
                m_watches = std::move(sorted);
                m_watchAnchor = -1;
                specs->SpecsDirty = false;
            }
        }

        for (int i = 0; i < (int)m_watches.size(); i++)
        {
            WatchEntry& w = m_watches[i];
            ImGui::PushID(i);
            ImGui::TableNextRow(0, ImGui::GetFrameHeight());

            size_t sz = WatchSize(w);
            std::vector<uint8_t> buf(sz);
            bool readOk = w.resolved && m_proc.ReadExact(w.address, buf.data(), sz);

            // Right-click anywhere on the row: select it (unless it's already part of the selection), open the menu.
            auto rowContext = [&] {
                if (!ImGui::IsItemClicked(ImGuiMouseButton_Right)) return;
                if (!w.selected)
                {
                    for (auto& o : m_watches) o.selected = false;
                    w.selected = true;
                    m_watchAnchor = i;
                }
                ImGui::OpenPopup("##wctx");
            };

            // Whole-row selectable underneath the cells; the widgets on top still get their clicks.
            ImGui::TableNextColumn();
            ImVec2 cell = ImGui::GetCursorPos();
            if (ImGui::Selectable("##row", w.selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                                  ImVec2(0, ImGui::GetFrameHeight())))
                clickRow = i;
            rowContext();
            ImGui::SetCursorPos(cell);

            bool frozen = w.frozen;
            if (ImGui::Checkbox("##frz", &frozen))
            {
                // Toggling a selected row's box applies to the whole selection.
                if (w.selected && selCount > 1) forSelected([&](WatchEntry& o) { setFrozen(o, frozen); });
                else setFrozen(w, frozen);
            }

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("##desc", &w.description);
            if (ImGui::IsItemActivated() && !w.selected) clickRow = i;
            rowContext();

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (m_mono) ImGui::PushFont(m_mono);
            if (!w.resolved) ImGui::PushStyleColor(ImGuiCol_Text, kColErr);
            ImGui::InputText("##expr", &w.expression);
            if (!w.resolved) ImGui::PopStyleColor();
            if (m_mono) ImGui::PopFont();
            if (ImGui::IsItemActivated() && !w.selected) clickRow = i;
            rowContext();
            if (!w.error.empty()) ImGui::SetItemTooltip("%s", w.error.c_str());

            ImGui::TableNextColumn();
            if (m_mono) ImGui::PushFont(m_mono);
            if (w.resolved) ImGui::TextDisabled("%s", AddrText(w.address).c_str());
            else ImGui::TextDisabled("-");
            if (m_mono) ImGui::PopFont();

            // Type: picking one on a selected row retypes the whole selection.
            const bool multi = w.selected && selCount > 1;
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::PushStyleColor(ImGuiCol_Text, Syntax::TypeColor(w.type));
            const bool typeOpen = ImGui::BeginCombo("##type", ValueTypeName(w.type));
            ImGui::PopStyleColor(); // the list itself keeps normal text
            if (typeOpen)
            {
                for (int t = 0; t < (int)ValueType::Count; t++)
                    if (ImGui::Selectable(ValueTypeName((ValueType)t), (int)w.type == t))
                    {
                        auto retype = [&](WatchEntry& o) { o.type = (ValueType)t; o.frozen = false; };
                        if (multi) forSelected(retype);
                        else retype(w);
                    }
                if (ValueTypeSize(w.type) == 0)
                {
                    ImGui::Separator();
                    ImGui::SetNextItemWidth(StepperWidth(50));
                    ImGui::InputInt("Length", &w.length);
                    w.length = std::clamp(w.length, 1, 4096);
                }
                ImGui::Checkbox("Show as hex", &w.hex);
                ImGui::EndCombo();
            }
            if (ImGui::IsItemActivated() && !w.selected) clickRow = i;
            rowContext();

            ImGui::TableNextColumn();
            if (m_mono) ImGui::PushFont(m_mono);
            std::string val = readOk ? FormatValue(w.type, buf.data(), sz, w.hex) : "??";
            // Frozen values glow in the accent; others take their type's colour.
            ImGui::PushStyleColor(ImGuiCol_Text, w.frozen ? kColAccent : readOk ? Syntax::TypeColor(w.type) : Syntax::kDim);
            if (ImGui::Selectable((val + "##val").c_str(), false, ImGuiSelectableFlags_AllowDoubleClick))
            {
                if (!ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) clickRow = i;
                else if (multi) editSelected();
                else if (readOk)
                {
                    m_editWatch = i;
                    snprintf(m_editBuf, sizeof(m_editBuf), "%s", val.c_str());
                    m_openEditPopup = true;
                }
            }
            ImGui::PopStyleColor();
            if (m_mono) ImGui::PopFont();
            rowContext();
            ImGui::SetItemTooltip("Double-click to change the value");

            if (ImGui::BeginPopup("##wctx"))
            {
                const int n = selCount > 0 ? selCount : 1;
                if (n > 1)
                {
                    ImGui::TextDisabled("%d entries selected", n);
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_EDIT "  Change value of selected...", "Enter")) editSelected();
                    if (ImGui::MenuItem(ICON_PIN "  Freeze / unfreeze selected", "Space")) toggleFreezeSelected();
                    if (ImGui::BeginMenu(ICON_SETTINGS "  Set type"))
                    {
                        for (int t = 0; t < (int)ValueType::Count; t++)
                            if (ImGui::MenuItem(ValueTypeName((ValueType)t)))
                                forSelected([&](WatchEntry& o) { o.type = (ValueType)t; o.frozen = false; });
                        ImGui::EndMenu();
                    }
                    if (ImGui::MenuItem("Show as hex", nullptr, w.hex)) { bool h = !w.hex; forSelected([&](WatchEntry& o) { o.hex = h; }); }
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_COPY "  Copy selected", "Ctrl+C")) copySelected();
                    if (ImGui::MenuItem(ICON_ADD "  Duplicate selected", "Ctrl+D")) duplicateSelected();
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_DELETE "  Delete selected", "Del")) bulkDelete = true;
                }
                else
                {
                    if (ImGui::MenuItem(ICON_EDIT "  Change value...", "Enter", false, readOk))
                    {
                        m_editWatch = i;
                        snprintf(m_editBuf, sizeof(m_editBuf), "%s", val.c_str());
                        m_openEditPopup = true;
                    }
                    if (ImGui::MenuItem(ICON_PIN "  Freeze", "Space", w.frozen)) setFrozen(w, !w.frozen);
                    if (ImGui::MenuItem(ICON_CHIP "  Browse memory here", nullptr, false, w.resolved))
                    {
                        m_hex.GoTo(w.address);
                        m_showHex = true;
                        ImGui::SetWindowFocus(kWinHex);
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("Find out what writes to this address", nullptr, false, w.resolved))
                        StartTrace(w.address, (int)std::min<size_t>(sz, 8), TraceKind::Writes);
                    if (ImGui::MenuItem("Find out what accesses this address", nullptr, false, w.resolved))
                        StartTrace(w.address, (int)std::min<size_t>(sz, 8), TraceKind::Accesses);
                    if (ImGui::MenuItem(ICON_CODE "  Decompile function here", nullptr, false, w.resolved))
                        StartDecompile(w.address);
                    if (ImGui::MenuItem(ICON_SEARCH "  Pointer scan for this address", nullptr, false, w.resolved))
                        OpenPointerScan(w.address);
                    if (ImGui::MenuItem(ICON_FLASH "  Make AOB signature here", nullptr, false, w.resolved))
                        OpenSigMaker(w.address);
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_COPY "  Copy address", nullptr, false, w.resolved))
                        ImGui::SetClipboardText(ToHex(w.address).c_str());
                    if (ImGui::MenuItem(ICON_COPY "  Copy value")) ImGui::SetClipboardText(val.c_str());
                    ImGui::MenuItem("Show as hex", nullptr, &w.hex);
                    if (ImGui::MenuItem("Dereference (wrap in [ ])")) w.expression = "[" + w.expression + "]";
                    if (ImGui::MenuItem(ICON_ADD "  Duplicate", "Ctrl+D")) dupIdx = i;
                    ImGui::Separator();
                    if (ImGui::MenuItem("Move up", nullptr, false, i > 0)) { moveFrom = i; moveTo = i - 1; }
                    if (ImGui::MenuItem("Move down", nullptr, false, i + 1 < (int)m_watches.size())) { moveFrom = i; moveTo = i + 1; }
                    if (ImGui::MenuItem(ICON_DELETE "  Delete", "Del")) removeIdx = i;
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    // Structural changes after the loop, so indices stayed valid while drawing.
    if (clickRow >= 0 && clickRow < (int)m_watches.size())
        ClickSelect(clickRow, (int)m_watches.size(), m_watchAnchor, [&](int k) { return m_watches[k].selected; },
                    [&](int k, bool on) { m_watches[k].selected = on; });
    if (bulkDelete) deleteSelected();
    if (dupIdx >= 0)
    {
        WatchEntry copy = m_watches[dupIdx];
        copy.frozen = false;
        copy.selected = false;
        m_watches.insert(m_watches.begin() + dupIdx + 1, std::move(copy));
    }
    if (removeIdx >= 0) m_watches.erase(m_watches.begin() + removeIdx);
    if (moveFrom >= 0) std::swap(m_watches[moveFrom], m_watches[moveTo]);
    ImGui::End();
}

// ---------------------------------------------------------------------------

void App::DrawRegions()
{
    Glass::PrepareWindow(kWinRegions);
    if (!ImGui::Begin(kWinRegions, &m_showRegions))
    {
        ImGui::End();
        return;
    }
    if (!m_proc.IsOpen())
    {
        if (Glass::EmptyState(ICON_GRID, "No process", "Attach to a process to list its memory regions.",
                              ICON_LINK "  Attach to process"))
            m_openPicker = true;
        ImGui::End();
        return;
    }
    double now = ImGui::GetTime();
    bool refresh = ImGui::Button("Refresh");
    ImGui::SameLine();
    refresh |= ImGui::Checkbox("Committed only", &m_regionsCommittedOnly);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Px(220));
    ImGui::InputTextWithHint("##rfilter", "Filter (module, RWX, Private...)", m_regionFilter, sizeof(m_regionFilter));
    if (refresh || now - m_regionsRefreshed > 3.0)
    {
        m_regions = m_proc.QueryRegions(m_regionsCommittedOnly);
        m_regionsRefreshed = now;
    }

    // Build the filtered view.
    struct Row
    {
        const RegionInfo* r;
        std::string owner;
    };
    std::vector<Row> rows;
    rows.reserve(m_regions.size());
    uint64_t totalCommit = 0;
    for (const auto& r : m_regions)
    {
        ModuleInfo m;
        std::string owner;
        if (m_proc.ModuleFromAddress(r.base, m)) owner = m.name;
        if (m_regionFilter[0])
        {
            std::string hay = owner + " " + ProtectToString(r.protect) + " " + StateToString(r.state) + " " +
                              TypeToString(r.type) + " " + ToHex(r.base);
            if (!Contains(hay, m_regionFilter)) continue;
        }
        if (r.state == MEM_COMMIT) totalCommit += r.size;
        rows.push_back({ &r, std::move(owner) });
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%zu regions, %s committed", rows.size(), HumanSize(totalCommit).c_str());

    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable;
    if (ImGui::BeginTable("##regions", 6, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort, Px(150));
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending, Px(90));
        ImGui::TableSetupColumn("Protect", ImGuiTableColumnFlags_WidthFixed, Px(70));
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, Px(65));
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, Px(65));
        ImGui::TableSetupColumn("Owner", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // The row list is rebuilt every frame, so sorting it every frame keeps the order live.
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsCount > 0)
        {
            const ImGuiTableColumnSortSpecs s = specs->Specs[0];
            const bool desc = s.SortDirection == ImGuiSortDirection_Descending;
            std::stable_sort(rows.begin(), rows.end(), [&](const auto& x, const auto& y) {
                const RegionInfo& a = *x.r;
                const RegionInfo& b = *y.r;
                int c = 0;
                switch (s.ColumnIndex)
                {
                case 0: c = a.base < b.base ? -1 : a.base > b.base; break;
                case 1: c = a.size < b.size ? -1 : a.size > b.size; break;
                case 2: c = ProtectToString(a.protect).compare(ProtectToString(b.protect)); break;
                case 3: c = (int)a.state - (int)b.state; break;
                case 4: c = (int)a.type - (int)b.type; break;
                case 5: c = Lower(x.owner).compare(Lower(y.owner)); break;
                }
                return desc ? c > 0 : c < 0;
            });
            specs->SpecsDirty = false;
        }

        ImGuiListClipper clipper;
        clipper.Begin((int)rows.size());
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                const RegionInfo& r = *rows[i].r;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                if (m_mono) ImGui::PushFont(m_mono);
                if (ImGui::Selectable(AddrText(r.base).c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                {
                    m_hex.GoTo(r.base);
                    m_showHex = true;
                }
                if (m_mono) ImGui::PopFont();
                if (ImGui::BeginPopupContextItem("##regctx"))
                {
                    if (ImGui::MenuItem("Browse memory")) m_hex.GoTo(r.base);
                    if (ImGui::MenuItem("Scan only this region"))
                    {
                        snprintf(m_rangeStart, sizeof(m_rangeStart), "%llX", (unsigned long long)r.base);
                        snprintf(m_rangeEnd, sizeof(m_rangeEnd), "%llX", (unsigned long long)(r.base + r.size));
                        Log("Scan range set to " + ToHex(r.base) + "-" + ToHex(r.base + r.size));
                    }
                    if (ImGui::MenuItem("Dump to file...", nullptr, false, r.state == MEM_COMMIT))
                        DumpMemory(r.base, r.size, ToHex(r.base) + ".bin");
                    if (ImGui::MenuItem("Copy base address")) ImGui::SetClipboardText(ToHex(r.base).c_str());
                    ImGui::EndPopup();
                }
                ImGui::PopID();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(HumanSize(r.size).c_str());
                ImGui::TableNextColumn();
                // Protection: RWX stands out (code you can patch in place), code is amber, data sky,
                // read-only dim, inaccessible red.
                std::string prot = ProtectToString(r.protect);
                ImVec4 protCol = !IsReadable(r.protect)                            ? Syntax::kSystem
                                 : IsExecutable(r.protect) && IsWritable(r.protect) ? Syntax::kJump
                                 : IsExecutable(r.protect)                          ? Syntax::kCall
                                 : IsWritable(r.protect)                            ? Syntax::kMove
                                                                                    : Syntax::kDim;
                if (r.state != MEM_COMMIT) protCol = Syntax::kDim;
                ImGui::TextColored(protCol, "%s", prot.c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(r.state == MEM_COMMIT ? ImGui::GetStyleColorVec4(ImGuiCol_Text) : Syntax::kDim, "%s",
                                   StateToString(r.state).c_str());
                ImGui::TableNextColumn();
                // Type: module images green (like static addresses), heap/stack sky, file mappings orchid.
                ImVec4 typeCol = r.type == MEM_IMAGE ? Syntax::kModule : r.type == MEM_MAPPED ? Syntax::kSimd : Syntax::kMove;
                ImGui::TextColored(typeCol, "%s", TypeToString(r.type).c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(rows[i].owner.empty() ? Syntax::kDim : Syntax::kModule, "%s", rows[i].owner.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

void App::DrawModules()
{
    Glass::PrepareWindow(kWinModules);
    if (!ImGui::Begin(kWinModules, &m_showModules))
    {
        ImGui::End();
        return;
    }
    if (!m_proc.IsOpen())
    {
        if (Glass::EmptyState(ICON_PUZZLE, "No process", "Attach to a process to list its loaded modules.",
                              ICON_LINK "  Attach to process"))
            m_openPicker = true;
        ImGui::End();
        return;
    }
    if (ImGui::Button("Refresh")) m_proc.RefreshModules();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Px(220));
    ImGui::InputTextWithHint("##mfilter", "Filter modules", m_moduleFilter, sizeof(m_moduleFilter));
    auto mods = m_proc.Modules();
    ImGui::SameLine();
    ImGui::TextDisabled("%zu modules", mods.size());

    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable | ImGuiTableFlags_SortTristate;
    if (ImGui::BeginTable("##mods", 4, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, Px(180));
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, Px(150));
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending, Px(90));
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // `mods` is a fresh copy each frame; with no sort column it keeps the load order.
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsCount > 0)
        {
            const ImGuiTableColumnSortSpecs s = specs->Specs[0];
            const bool desc = s.SortDirection == ImGuiSortDirection_Descending;
            std::stable_sort(mods.begin(), mods.end(), [&](const ModuleInfo& a, const ModuleInfo& b) {
                int c = 0;
                switch (s.ColumnIndex)
                {
                case 0: c = Lower(a.name).compare(Lower(b.name)); break;
                case 1: c = a.base < b.base ? -1 : a.base > b.base; break;
                case 2: c = a.size < b.size ? -1 : a.size > b.size; break;
                case 3: c = Lower(a.path).compare(Lower(b.path)); break;
                }
                return desc ? c > 0 : c < 0;
            });
            specs->SpecsDirty = false;
        }
        int i = 0;
        for (const auto& m : mods)
        {
            if (!Contains(m.name, m_moduleFilter) && !Contains(m.path, m_moduleFilter)) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i++);
            // The program's own modules in green; Windows' system DLLs dimmed so they recede.
            const bool system = Contains(m.path, "\\windows\\");
            const bool mainExe = Lower(m.name) == Lower(m_proc.Name());
            ImGui::PushStyleColor(ImGuiCol_Text, mainExe ? kColAccent : system ? Syntax::kDim : Syntax::kModule);
            bool picked = ImGui::Selectable(m.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::PopStyleColor();
            if (picked)
            {
                m_hex.GoTo(m.base);
                m_showHex = true;
            }
            if (ImGui::BeginPopupContextItem("##modctx"))
            {
                if (ImGui::MenuItem("Browse memory")) m_hex.GoTo(m.base);
                if (ImGui::MenuItem("Scan only this module"))
                {
                    snprintf(m_rangeStart, sizeof(m_rangeStart), "%llX", (unsigned long long)m.base);
                    snprintf(m_rangeEnd, sizeof(m_rangeEnd), "%llX", (unsigned long long)(m.base + m.size));
                    m_opts.includeImage = true;
                    Log("Scan range set to " + m.name + " (enable/disable 'Writable only' as needed)");
                }
                if (ImGui::MenuItem("Dump module to file...")) DumpMemory(m.base, m.size, m.name);
                if (ImGui::MenuItem("Copy base address")) ImGui::SetClipboardText(ToHex(m.base).c_str());
                if (ImGui::MenuItem("Copy path")) ImGui::SetClipboardText(m.path.c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            if (m_mono) ImGui::PushFont(m_mono);
            ImGui::TextUnformatted(AddrText(m.base).c_str());
            if (m_mono) ImGui::PopFont();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(HumanSize(m.size).c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", m.path.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

void App::DrawLog()
{
    Glass::PrepareWindow(kWinLog);
    if (!ImGui::Begin(kWinLog, &m_showLog))
    {
        ImGui::End();
        return;
    }
    if (ImGui::SmallButton("Clear")) m_log.clear();
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy all"))
    {
        std::string all;
        for (const auto& l : m_log) all += l + "\n";
        ImGui::SetClipboardText(all.c_str());
    }
    ImGui::Separator();
    ImGui::BeginChild("##logscroll");
    for (const auto& l : m_log) Syntax::LogLine(l);
    if (m_logScroll)
    {
        ImGui::SetScrollHereY(1.0f);
        m_logScroll = false;
    }
    ImGui::EndChild();
    ImGui::End();
}

void App::DrawAbout()
{
    ImGui::SetNextWindowSize(ImVec2(Px(520), Px(420)), ImGuiCond_FirstUseEver);
    Glass::PrepareWindow("Help");
    if (!ImGui::Begin("Help", &m_showAbout))
    {
        ImGui::End();
        return;
    }
    ImGui::TextColored(kColAccent, "Address expressions");
    ImGui::BulletText("Numbers are hexadecimal: 7FF6A0001000, 0x1F0");
    ImGui::BulletText("Decimal with #: base+#100");
    ImGui::BulletText("Module names resolve to their base: game.exe+1F0");
    ImGui::BulletText("Quote names with spaces: \"My Game.exe\"+10");
    ImGui::BulletText("[ ] dereferences a pointer: [[game.exe+1F0]+18]+4");
    ImGui::BulletText("Operators: + - * and parentheses");
    ImGui::Spacing();
    ImGui::TextColored(kColAccent, "Scanning");
    ImGui::BulletText("First Scan with a known value, change it in the target, Next Scan.");
    ImGui::BulletText("Unknown initial value snapshots memory; filter with Changed/Increased...");
    ImGui::BulletText("Array of Bytes accepts wildcards: 48 8B ?? ?? 89");
    ImGui::BulletText("Green results are static (inside a module) - they survive restarts.");
    ImGui::BulletText("Double-click a result to add it to the address list.");
    ImGui::Spacing();
    ImGui::TextColored(kColAccent, "AOB scan (array of bytes)");
    ImGui::BulletText("48 8B 05 ?? ?? ?? ??  -  ?? or ? is any byte; 4? and ?8 match half a byte.");
    ImGui::BulletText("A | marks where results point: E8 | ?? ?? ?? ?? points at the call's offset.");
    ImGui::BulletText("Code style works too: \\x48\\x8B\\x05 with a mask like xx?");
    ImGui::BulletText("Right-click an instruction > Make AOB signature here for a pattern that survives updates.");
    ImGui::BulletText("Save signatures in the Signature list and Scan all after the program updates.");
    ImGui::Spacing();
    ImGui::TextColored(kColAccent, "Lists (Scan Results, Address List)");
    ImGui::BulletText("Click selects, Ctrl+click adds/removes a row, Shift+click selects a range.");
    ImGui::BulletText("Ctrl+A select all, Ctrl+C copy, Esc clear selection.");
    ImGui::BulletText("Results: Enter adds the selection to the address list.");
    ImGui::BulletText("Address list: Enter changes values, Space freezes, Del deletes, Ctrl+D duplicates.");
    ImGui::BulletText("Right-click acts on the whole selection. Click a column header to sort.");
    ImGui::Spacing();
    ImGui::TextColored(kColAccent, "Memory view");
    ImGui::BulletText("Type hex digits to edit, Tab to edit ASCII.");
    ImGui::BulletText("Recently changed bytes flash red.");
    ImGui::BulletText("Right-click: follow pointer, copy, fill, add to list.");
    ImGui::Spacing();
    ImGui::TextColored(kColAccent, "Find out what writes / accesses an address");
    ImGui::BulletText("Right-click an address list entry (or bytes in the memory view).");
    ImGui::BulletText("Uses hardware breakpoints: up to 4 watches at once, 1/2/4/8 bytes each.");
    ImGui::BulletText("Attaches as a debugger; closing the last window detaches safely.");
    ImGui::BulletText("Select an instruction to see registers, NOP it out, or restore it.");
    ImGui::Spacing();
    ImGui::TextDisabled("Run as administrator to attach to elevated processes.");
    ImGui::End();
}

// ---------------------------------------------------------------------------

void App::StartTrace(uint64_t address, int size, TraceKind kind)
{
    if (!m_proc.IsOpen()) return;
    for (auto& t : m_traces)
    {
        if (t.address == address && t.kind == kind)
        {
            ImGui::SetWindowFocus(("###trace" + std::to_string(t.slot)).c_str());
            return;
        }
    }
    std::string err;
    int slot = Dbg()->Add(m_proc.Pid(), m_proc.Is64(), address, size, kind, err);
    if (slot < 0)
    {
        Log("Trace: " + err);
        return;
    }
    TraceWindow t;
    t.slot = slot;
    t.kind = kind;
    t.address = address;
    t.size = size;
    t.label = m_proc.Symbolize(address);
    m_traces.push_back(t);
    Log(std::string("Watching ") + (kind == TraceKind::Writes ? "writes to " : "accesses to ") + t.label +
        " with hardware breakpoint DR" + std::to_string(slot));
}

void App::DrawTraceWindows()
{
    for (auto& t : m_traces)
    {
        std::string title = std::string(t.kind == TraceKind::Writes ? "Writes to " : "Accesses to ") + t.label +
                            "###trace" + std::to_string(t.slot);
        ImGui::SetNextWindowSize(ImVec2(Px(720), Px(460)), ImGuiCond_FirstUseEver);
        Glass::PrepareWindow(title.c_str());
        if (!ImGui::Begin(title.c_str(), &t.open))
        {
            ImGui::End();
            continue;
        }

        std::vector<TraceHit> hits = Dbg()->Hits(t.slot);
        std::string err = Dbg()->Error();
        const char* dbgName = m_debuggerMode == 1 ? "VEH debugger (injected)" : "Windows debugger";
        if (!err.empty()) ImGui::TextColored(kColErr, "%s", err.c_str());
        else if (Dbg()->Attached())
            ImGui::TextColored(kColOk, "%s - watching %d byte(s) at %s (DR%d)", dbgName, t.size,
                               AddrText(t.address).c_str(), t.slot);
        else ImGui::TextDisabled("Starting debugger...");

        if (ImGui::Button("Clear")) Dbg()->Clear(t.slot);
        ImGui::SameLine();
        if (ImGui::Button("Stop")) t.open = false;
        ImGui::SameLine();
        ImGui::TextDisabled("%zu instruction(s). The target is paused briefly on every hit.", hits.size());

        const TraceHit* sel = nullptr;
        float detailsH = Px(150);
        ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                             ImGuiTableFlags_Resizable;
        if (ImGui::BeginTable("##hits", 4, tf, ImVec2(0, -detailsH)))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, Px(60));
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 1.6f);
            ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthStretch, 0.9f);
            ImGui::TableHeadersRow();
            if (m_mono) ImGui::PushFont(m_mono);
            for (const auto& h : hits)
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID((void*)(uintptr_t)h.address);
                bool selected = t.selected == h.address;
                if (selected) sel = &h;
                char cnt[32];
                snprintf(cnt, sizeof(cnt), "%llu", (unsigned long long)h.count);
                if (ImGui::Selectable(cnt, selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
                {
                    t.selected = h.address;
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                    {
                        m_hex.GoTo(h.address);
                        m_showHex = true;
                    }
                }
                if (ImGui::BeginPopupContextItem("##hitctx"))
                {
                    t.selected = h.address;
                    if (ImGui::MenuItem("Decompile this function")) StartDecompile(h.address);
                    if (ImGui::MenuItem("Show in memory view")) { m_hex.GoTo(h.address); m_showHex = true; }
                    if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText((m_proc.Symbolize(h.address) + " - " + h.text).c_str());
                    ImGui::EndPopup();
                }
                ImGui::PopID();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(m_proc.Symbolize(h.address).c_str());
                ImGui::TableNextColumn();
                if (m_patches.count(h.address)) ImGui::TextColored(kColChanged, "%s  [NOPed]", h.text.c_str());
                else Syntax::Instruction(h.text.c_str());
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", BytesToHex(h.bytes.data(), h.bytes.size()).c_str());
            }
            if (m_mono) ImGui::PopFont();
            ImGui::EndTable();
        }

        // Details for the selected instruction
        ImGui::BeginChild("##details", ImVec2(0, 0), ImGuiChildFlags_Borders);
        if (!sel)
        {
            ImGui::TextDisabled("Select an instruction to see the registers when it last ran.\n"
                                "Double-click to open it in the memory view.");
        }
        else
        {
            bool patched = m_patches.count(sel->address) != 0;
            if (ImGui::Button("Show in memory view"))
            {
                m_hex.GoTo(sel->address);
                m_showHex = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Decompile function")) StartDecompile(sel->address);
            ImGui::SameLine();
            ImGui::BeginDisabled(sel->length == 0);
            if (!patched)
            {
                if (ImGui::Button("Replace with NOPs"))
                {
                    std::vector<uint8_t> orig(sel->length);
                    std::vector<uint8_t> nops(sel->length, 0x90);
                    if (m_proc.ReadExact(sel->address, orig.data(), orig.size()) &&
                        m_proc.Write(sel->address, nops.data(), nops.size()))
                    {
                        m_patches[sel->address] = orig;
                        Log("NOPed " + std::to_string(sel->length) + " bytes at " + m_proc.Symbolize(sel->address) +
                            " (" + sel->text + ")");
                    }
                    else Log("Patch failed at " + m_proc.Symbolize(sel->address));
                }
                ImGui::SetItemTooltip("Overwrites this instruction with NOPs so it no longer runs.");
            }
            else if (ImGui::Button("Restore original"))
            {
                auto& orig = m_patches[sel->address];
                if (m_proc.Write(sel->address, orig.data(), orig.size()))
                {
                    Log("Restored " + m_proc.Symbolize(sel->address));
                    m_patches.erase(sel->address);
                }
                else Log("Restore failed at " + m_proc.Symbolize(sel->address));
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Button("Copy")) ImGui::SetClipboardText((m_proc.Symbolize(sel->address) + " - " + sel->text).c_str());

            if (m_mono) ImGui::PushFont(m_mono);
            const TraceRegs& r = sel->regs;
            int n = r.is64 ? 16 : 8;
            if (ImGui::BeginTable("##regs", 4, ImGuiTableFlags_SizingStretchSame))
            {
                for (int i = 0; i < n; i++)
                {
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%-3s", AccessTracer::RegName(i, r.is64));
                    ImGui::SameLine();
                    ImGui::Text("%s", ToHex(r.gp[i], r.is64 ? 16 : 8).c_str());
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", r.is64 ? "RIP" : "EIP");
                ImGui::SameLine();
                ImGui::Text("%s", ToHex(r.ip, r.is64 ? 16 : 8).c_str());
                ImGui::TableNextColumn();
                ImGui::TextDisabled("FLG");
                ImGui::SameLine();
                ImGui::Text("%08llX", (unsigned long long)r.flags);
                ImGui::EndTable();
            }
            if (m_mono) ImGui::PopFont();
            ImGui::TextDisabled("RIP/EIP is the instruction after the access, as reported by the CPU.");
        }
        ImGui::EndChild();
        ImGui::End();
    }

    // Closing a window frees its hardware breakpoint.
    for (auto it = m_traces.begin(); it != m_traces.end();)
    {
        if (!it->open)
        {
            Dbg()->Remove(it->slot);
            Log("Stopped watching " + it->label);
            it = m_traces.erase(it);
        }
        else ++it;
    }
}

// ---------------------------------------------------------------------------

// Parse a user-entered number: decimal, or hex with a 0x prefix; a leading - is allowed.
static bool ParseNumber(const char* s, uint64_t& out)
{
    std::string t = s;
    size_t a = t.find_first_not_of(" \t");
    if (a == std::string::npos) return false;
    size_t b = t.find_last_not_of(" \t");
    t = t.substr(a, b - a + 1);
    const char* p = t.c_str();
    char* end = nullptr;
    errno = 0;
    if (t[0] == '-') out = (uint64_t)strtoll(p, &end, 0);
    else out = strtoull(p, &end, 0);
    return end && *end == '\0' && errno == 0;
}

// Parse space/comma separated hex byte pairs ("90 90", "DE,AD") into bytes.
static bool ParseBytes(const char* s, std::vector<uint8_t>& out)
{
    out.clear();
    int hi = -1;
    for (const char* p = s; *p; p++)
    {
        char c = *p;
        if (c == ' ' || c == '\t' || c == ',')
        {
            if (hi >= 0) { out.push_back((uint8_t)hi); hi = -1; }
            continue;
        }
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return false;
        if (hi < 0) hi = v;
        else { out.push_back((uint8_t)((hi << 4) | v)); hi = -1; }
    }
    if (hi >= 0) out.push_back((uint8_t)hi);
    return !out.empty();
}

void App::StartDecompile(uint64_t address)
{
    snprintf(m_decompileExpr, sizeof(m_decompileExpr), "%llX", (unsigned long long)address);
    m_showDecompile = true;
    RunDecompile();
    m_selectedInsn = address;
    m_scrollToSelected = true;
    m_newImm[0] = m_newBytes[0] = '\0';
    m_patchStatus.clear();
    ImGui::SetWindowFocus(kWinDecompile);
}

void App::RunDecompile()
{
    m_decompileText.clear();
    m_decompileError.clear();
    m_instructions.clear();
    if (!m_proc.IsOpen())
    {
        m_decompileError = "No process attached. Attach with Ctrl+O first.";
        return;
    }
    uint64_t address = 0;
    std::string err;
    if (!EvaluateAddress(m_proc, m_decompileExpr, address, &err))
    {
        m_decompileError = err;
        return;
    }
    m_decompileEntry = address;
    std::string code;
    if (!DecompileFunction(m_proc, address, code, err))
    {
        m_decompileError = err;
        return;
    }
    m_decompileText = code;
    if (!DisassembleFunction(m_proc, address, m_instructions, err))
    {
        m_decompileError = err;
        return;
    }
    bool have = false;
    for (const auto& r : m_instructions)
        if (r.address == m_selectedInsn) have = true;
    if (!have && !m_instructions.empty()) m_selectedInsn = m_instructions.front().address;
    Log("Decompiled " + m_proc.Symbolize(address));
}

void App::DrawPatchPanel(const InstructionRow& row)
{
    if (m_mono) ImGui::PushFont(m_mono);
    ImGui::TextColored(kColAccent, "%s", m_proc.Symbolize(row.address).c_str());
    ImGui::SameLine();
    Syntax::Instruction(row.text.c_str());
    if (m_mono) ImGui::PopFont();

    const CodePatch* existing = m_patchmgr.Find(row.address);

    if (row.hasImmediate)
    {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("value");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(Px(150));
        bool go = ImGui::InputText("##imm", m_newImm, sizeof(m_newImm), ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        if (ImGui::Button("Set value") || go)
        {
            uint64_t v = 0;
            std::string perr;
            if (!ParseNumber(m_newImm, v)) m_patchStatus = "Enter a number: decimal 28 or hex 0x1C.";
            else if (!m_patchmgr.SetImmediate(m_proc, row, v, perr))
            {
                m_patchStatus = perr;
                Log("Patch failed at " + m_proc.Symbolize(row.address) + ": " + perr);
            }
            else
            {
                m_patchStatus = "Set value to " + std::to_string(v);
                Log(m_patchStatus + " at " + m_proc.Symbolize(row.address));
                RunDecompile();
            }
        }
        ImGui::SameLine();
        ImGui::TextDisabled("(now %llu / 0x%llX)", (unsigned long long)row.immediate, (unsigned long long)row.immediate);
    }
    else ImGui::TextDisabled("No immediate value in this instruction - use NOP or raw bytes.");

    if (ImGui::Button("NOP out"))
    {
        std::string perr;
        if (!m_patchmgr.Nop(m_proc, row, perr)) m_patchStatus = perr;
        else
        {
            m_patchStatus = "Replaced with " + std::to_string(row.bytes.size()) + " NOP(s)";
            Log("NOPed " + m_proc.Symbolize(row.address) + " (" + row.text + ")");
            RunDecompile();
        }
    }
    if (row.isBranch) ImGui::SetItemTooltip("This is a call/jump - NOPing it removes the control flow.");
    ImGui::SameLine();

    ImGui::SetNextItemWidth(Px(220));
    bool goBytes = ImGui::InputText("##bytes", m_newBytes, sizeof(m_newBytes), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Write bytes") || goBytes)
    {
        std::vector<uint8_t> bytes;
        std::string perr;
        if (!ParseBytes(m_newBytes, bytes)) m_patchStatus = "Enter hex bytes like 90 90 90.";
        else if (!m_patchmgr.SetBytes(m_proc, row, bytes, perr)) m_patchStatus = perr;
        else
        {
            m_patchStatus = "Wrote " + std::to_string(bytes.size()) + " bytes";
            Log(m_patchStatus + " at " + m_proc.Symbolize(row.address));
            RunDecompile();
        }
    }
    ImGui::SetItemTooltip("Overwrite this instruction with raw hex, same length (%zu bytes).", row.bytes.size());

    if (existing)
    {
        ImGui::SameLine();
        if (ImGui::Button("Restore"))
        {
            m_patchmgr.Remove(m_proc, row.address);
            m_patchStatus = "Restored original bytes";
            Log("Restored " + m_proc.Symbolize(row.address));
            RunDecompile();
        }
    }

    if (!m_patchStatus.empty()) ImGui::TextColored(kColAccent, "%s", m_patchStatus.c_str());
}

void App::DrawDisasm()
{
    if (m_instructions.empty())
    {
        ImGui::TextDisabled("Decompile a function to see its instructions.");
        return;
    }

    const InstructionRow* sel = nullptr;
    for (const auto& r : m_instructions)
        if (r.address == m_selectedInsn) sel = &r;

    float panelH = Px(sel ? 118 : 36);
    ImGui::BeginChild("##patchpanel", ImVec2(0, panelH), ImGuiChildFlags_Borders);
    if (sel) DrawPatchPanel(*sel);
    else ImGui::TextDisabled("Click an instruction below to patch it.");
    ImGui::EndChild();

    if (m_mono) ImGui::PushFont(m_mono);
    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##insns", 3, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, Px(190));
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthStretch, 0.7f);
        ImGui::TableHeadersRow();
        for (const auto& r : m_instructions)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID((void*)(uintptr_t)r.address);
            bool selected = r.address == m_selectedInsn;
            if (ImGui::Selectable(m_proc.Symbolize(r.address).c_str(), selected,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
            {
                m_selectedInsn = r.address;
                snprintf(m_newImm, sizeof(m_newImm), "%llu", (unsigned long long)r.immediate);
                std::string hex = BytesToHex(r.bytes.data(), r.bytes.size());
                snprintf(m_newBytes, sizeof(m_newBytes), "%s", hex.c_str());
                m_patchStatus.clear();
                // Double-click jumps to this instruction in the Memory View to edit/assemble it.
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                {
                    m_hex.FocusDisasm(r.address);
                    m_showHex = true;
                    ImGui::SetWindowFocus(kWinHex);
                }
            }
            ImGui::SetItemTooltip("Double-click to edit this instruction in the Memory View");
            if (ImGui::BeginPopupContextItem("##insctx"))
            {
                if (m_mono) ImGui::PopFont(); // the menu uses the normal UI face, not the table's mono one
                if (ImGui::MenuItem(ICON_FLASH "  Make AOB signature here")) OpenSigMaker(r.address);
                DrawDetourMenu(r.address);
                if (ImGui::MenuItem(ICON_HELP "  Explain this instruction")) OpenOpcodes(r.text);
                if (ImGui::MenuItem(ICON_CHIP "  Edit in Memory View"))
                {
                    m_hex.FocusDisasm(r.address);
                    m_showHex = true;
                    ImGui::SetWindowFocus(kWinHex);
                }
                if (ImGui::MenuItem(ICON_COPY "  Copy address")) ImGui::SetClipboardText(ToHex(r.address).c_str());
                if (m_mono) ImGui::PushFont(m_mono);
                ImGui::EndPopup();
            }
            if (selected && m_scrollToSelected)
            {
                ImGui::SetScrollHereY(0.4f);
                m_scrollToSelected = false;
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            const CodePatch* p = m_patchmgr.Find(r.address);
            if (p && p->enabled) ImGui::TextColored(kColChanged, "%s", r.text.c_str());
            else if (p) ImGui::TextDisabled("%s  (patch off)", r.text.c_str());
            else Syntax::Instruction(r.text.c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", BytesToHex(r.bytes.data(), r.bytes.size()).c_str());
        }
        ImGui::EndTable();
    }
    if (m_mono) ImGui::PopFont();
}

void App::DrawActivePatches()
{
    if (m_patchmgr.Empty())
    {
        ImGui::TextDisabled("No patches yet. Select an instruction in the Disassembly tab to make one.");
        return;
    }

    if (ImGui::Button("Disable all"))
    {
        m_patchmgr.RestoreAll(m_proc);
        RunDecompile();
    }
    ImGui::SameLine();
    if (ImGui::Button("Remove all"))
    {
        std::vector<uint64_t> addrs;
        for (const auto& p : m_patchmgr.All()) addrs.push_back(p.address);
        for (uint64_t a : addrs) m_patchmgr.Remove(m_proc, a);
        RunDecompile();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%zu patch(es). Patches live in the target's memory only.", m_patchmgr.All().size());

    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
    if (ImGui::BeginTable("##patches", 4, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, Px(30));
        ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthFixed, Px(190));
        ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, SmallButtonWidth("Remove"));
        ImGui::TableHeadersRow();

        uint64_t toRemove = 0;
        bool remove = false;
        for (const auto& p : m_patchmgr.All())
        {
            ImGui::TableNextRow();
            ImGui::PushID((void*)(uintptr_t)p.address);
            ImGui::TableNextColumn();
            bool on = p.enabled;
            if (ImGui::Checkbox("##on", &on)) m_patchmgr.SetEnabled(m_proc, p.address, on);
            ImGui::TableNextColumn();
            if (ImGui::Selectable(p.location.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
            {
                m_selectedInsn = p.address;
                m_scrollToSelected = true;
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(p.label.c_str());
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Remove")) { toRemove = p.address; remove = true; }
            ImGui::PopID();
        }
        ImGui::EndTable();
        if (remove)
        {
            m_patchmgr.Remove(m_proc, toRemove);
            RunDecompile();
        }
    }
}

void App::DrawDecompile()
{
    ImGui::SetNextWindowSize(ImVec2(Px(780), Px(600)), ImGuiCond_FirstUseEver);
    Glass::PrepareWindow(kWinDecompile);
    if (!ImGui::Begin(kWinDecompile, &m_showDecompile))
    {
        ImGui::End();
        return;
    }

    ImGui::SetNextItemWidth(Px(240));
    bool enter = ImGui::InputText("Function address", m_decompileExpr, sizeof(m_decompileExpr),
                                  ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Decompile") || enter) RunDecompile();
    ImGui::SameLine();
    ImGui::BeginDisabled(m_decompileText.empty());
    if (ImGui::Button("Copy C")) ImGui::SetClipboardText(m_decompileText.c_str());
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Copy the pseudo-C to the clipboard");

    if (!m_decompileError.empty()) ImGui::TextColored(kColErr, "%s", m_decompileError.c_str());

    if (ImGui::BeginTabBar("##decompile_tabs"))
    {
        if (ImGui::BeginTabItem("Pseudo-C"))
        {
            if (m_mono) ImGui::PushFont(m_mono);
            ImGui::InputTextMultiline("##decompiled", &m_decompileText, ImGui::GetContentRegionAvail(),
                                      ImGuiInputTextFlags_ReadOnly);
            if (m_mono) ImGui::PopFont();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Disassembly"))
        {
            DrawDisasm();
            ImGui::EndTabItem();
        }
        const char* patchTab = m_patchmgr.Empty() ? "Patches" : "Patches *";
        if (ImGui::BeginTabItem(patchTab))
        {
            DrawActivePatches();
            ImGui::EndTabItem();
        }
        // "###Detours" keeps the tab's identity while the label gains a '*'.
        const char* detourTab = m_detours.Empty() ? "Detours###Detours" : "Detours *###Detours";
        if (ImGui::BeginTabItem(detourTab, nullptr, m_decompileTabRequest == 3 ? ImGuiTabItemFlags_SetSelected : 0))
        {
            DrawDetours();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    m_decompileTabRequest = -1;
    ImGui::End();
}

void App::OpenDetours(uint64_t entry)
{
    StartDecompile(entry); // loads the function and selects `entry`, which the Detours tab acts on
    m_decompileTabRequest = 3;
    m_detourStatus.clear();
}

void App::InstallCaveAt(uint64_t entry)
{
    OpenDetours(entry);
    std::string e;
    const int bytes = RecommendCaveBytes();
    if (!m_detours.InstallTrampoline(m_proc, entry, (size_t)bytes, e))
    {
        m_detourStatus = e;
        Log("Detour failed at " + m_proc.Symbolize(entry) + ": " + e);
        return;
    }
    const Detour* d = m_detours.Find(entry);
    const uint64_t cave = d ? d->cave : 0;
    m_detourStatus = "Cave at " + ToHex(cave) + " with " + std::to_string(bytes) +
                     " free bytes - the original still runs; write your code into the cave.";
    Log("Installed trampoline on " + m_proc.Symbolize(entry) + ", cave at " + ToHex(cave));
    RunDecompile();
    // Straight to the cave, where the new code goes.
    if (cave)
    {
        m_hex.FocusDisasm(cave);
        m_showHex = true;
    }
}

void App::DrawDetourMenu(uint64_t a)
{
    if (!m_proc.IsOpen()) return;
    RegionInfo region;
    if (!m_proc.QueryRegion(a, region) || !IsExecutable(region.protect)) return; // only code can be detoured
    if (const Detour* d = m_detours.Find(a))
    {
        // Already hooked: manage it instead of offering a second detour.
        const uint64_t cave = d->cave;
        if (ImGui::MenuItem(ICON_EDIT "  Edit detour cave", nullptr, false, cave != 0))
        {
            m_hex.FocusDisasm(cave);
            m_showHex = true;
        }
        if (ImGui::MenuItem(ICON_FORWARD "  Show in Detours tab")) OpenDetours(a);
        if (ImGui::MenuItem(ICON_DELETE "  Remove detour"))
        {
            m_detours.Remove(m_proc, a);
            Log("Removed detour on " + m_proc.Symbolize(a));
            if (m_showDecompile) RunDecompile();
        }
        return;
    }
    if (ImGui::BeginMenu(ICON_FLASH "  Detour this function"))
    {
        if (ImGui::MenuItem(ICON_ADD "  Trampoline cave (original still runs)")) InstallCaveAt(a);
        ImGui::SetItemTooltip("Hooks this entry with a jump to a new code cave sized for it, then opens the cave\n"
                              "in the Memory View so you can write your own code there.");
        if (ImGui::MenuItem(ICON_FORWARD "  Redirect to another function..."))
        {
            OpenDetours(a);
            m_focusDetourTarget = true;
        }
        ImGui::SetItemTooltip("Opens the Detours tab with this entry selected; type where it should jump to.");
        if (m_proc.Is64() && ImGui::MenuItem(ICON_CODE "  Hook with C++..."))
            OpenCppHooks(a);
        ImGui::SetItemTooltip("Opens the C++ Hooks window: write C++ that runs on every call to this\n"
                              "function (or on demand) and recompile it live.");
        if (ImGui::MenuItem(ICON_SETTINGS "  Open in Detours tab...")) OpenDetours(a);
        ImGui::EndMenu();
    }
}

void App::OpenCppHooks(uint64_t entry)
{
    m_showCppHook = true;
    ImGui::SetWindowFocus(kWinCppHook);
    if (entry) snprintf(m_cppEntry, sizeof(m_cppEntry), "%llX", (unsigned long long)entry);
}

std::string App::CppStarter() const
{
    return
        "#include \"memhook.h\"\n"
        "using namespace memhook;\n"
        "\n"
        "// Runs on EVERY call to the hooked function, inside the target. rcx/rdx/r8/r9 are the\n"
        "// first four integer/pointer arguments (Windows x64 calling convention).\n"
        "void OnCall(Regs* r)\n"
        "{\n"
        "    Print(\"called: arg1=%llu arg2=%llu\\n\", r->rcx, r->rdx);\n"
        "    // r->rcx = 999;          // change an argument before the original runs\n"
        "    // r->skipOriginal = 1;   // or stop the original from running at all\n"
        "}\n"
        "\n"
        "// Runs when you press Run, with the Params box passed as `args`.\n"
        "void OnRun(const char* args)\n"
        "{\n"
        "    Print(\"Run with: %s\\n\", args);\n"
        "    // Call the real function yourself with custom parameters:\n"
        "    // auto fn = Fn<long long(long long, long long)>(Original);\n"
        "    // Print(\"result = %lld\\n\", fn(2, 3));\n"
        "}\n";
}

std::string App::CppTemplateFor(uint64_t entry) const
{
    std::string sym = m_proc.Symbolize(entry);
    std::string decomp, err;
    bool ok = entry && DecompileFunction(m_proc, entry, decomp, err);

    std::string ref = "// ---- Original function at " + sym + " (decompiled, for reference) ----\n";
    if (ok)
    {
        // Comment out every line of the pseudo-C so it sits in the file as a guide.
        size_t start = 0;
        while (start < decomp.size())
        {
            size_t nl = decomp.find('\n', start);
            std::string line = decomp.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
            while (!line.empty() && (line.back() == '\r')) line.pop_back();
            ref += "//   " + line + "\n";
            if (nl == std::string::npos) break;
            start = nl + 1;
        }
    }
    else
    {
        ref += "//   (could not decompile: " + (err.empty() ? std::string("unknown") : err) + ")\n";
    }
    ref += "// ------------------------------------------------------------------\n\n";

    return "#include \"memhook.h\"\n"
           "using namespace memhook;\n\n" +
           ref +
           "// rcx/rdx/r8/r9 = first four integer/pointer arguments (Windows x64).\n"
           "void OnCall(Regs* r)\n"
           "{\n"
           "    // Reproduce or tweak the behaviour above. Edit r->rcx etc., or:\n"
           "    // auto orig = Fn<long long(long long, long long)>(Original);\n"
           "    // r->skipOriginal = 1;   // replace the original entirely\n"
           "}\n\n"
           "void OnRun(const char* args)\n"
           "{\n"
           "}\n";
}

void App::DrawCppHooks()
{
    if (!m_cppInit) { m_cppSource = CppStarter(); m_cppInit = true; }

    Glass::PrepareWindow(kWinCppHook);
    ImGui::SetNextWindowSize(ImVec2(680, 620), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(kWinCppHook, &m_showCppHook)) { ImGui::End(); return; }

    if (!m_proc.IsOpen())
    {
        Glass::EmptyState(ICON_CODE, "No process", "Attach to a 64-bit process to hook and run C++ in it.", nullptr);
        ImGui::End();
        return;
    }

    std::string whyNot;
    if (!m_cpp.Available(whyNot))
        ImGui::TextColored(kColErr, ICON_WARNING "  %s", whyNot.c_str());

    // --- Target function + hook controls ---
    ImGui::TextUnformatted("Function");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260);
    ImGui::InputTextWithHint("##cppentry", "address or module.exe+1F0", m_cppEntry, sizeof(m_cppEntry));

    uint64_t entry = 0;
    bool haveEntry = EvaluateAddress(m_proc, m_cppEntry, entry);
    const bool hooked = m_cppHookedEntry && m_detours.Find(m_cppHookedEntry);
    if (!hooked) m_cppHookedEntry = 0;

    ImGui::SameLine();
    if (!hooked)
    {
        if (Glass::AccentButton(ICON_FLASH "  Install hook") && haveEntry)
        {
            std::string err;
            uint64_t tramp = 0;
            if (m_detours.InstallHook(m_proc, entry, 0, tramp, err))
            {
                m_cppHookedEntry = entry;
                m_cpp.Attach(m_proc, err);
                m_cpp.SetTrampoline(tramp);
                // Seed the editor with the original function (decompiled) unless you've edited it.
                if (m_cppSource.empty() || m_cppSource == CppStarter())
                    m_cppSource = CppTemplateFor(entry);
                m_cppLog = "Hooked " + m_proc.Symbolize(entry) + " (passthrough). Compile & Apply to run your code.";
                Log("C++ hook installed on " + m_proc.Symbolize(entry));
            }
            else { m_cppLog = err; Log("C++ hook failed: " + err); }
        }
    }
    else
    {
        if (ImGui::Button(ICON_DELETE "  Remove hook"))
        {
            m_detours.Remove(m_proc, m_cppHookedEntry);
            Log("Removed C++ hook on " + m_proc.Symbolize(m_cppHookedEntry));
            m_cppHookedEntry = 0;
        }
    }

    if (hooked)
        ImGui::TextColored(ImVec4(0.45f, 0.85f, 0.5f, 1), ICON_SHIELD_FILL "  Hooked at %s",
                           m_proc.Symbolize(m_cppHookedEntry).c_str());
    else
        ImGui::TextDisabled("Not hooked - you can still write OnRun and press Run without hooking.");

    // Pull the original function in as a starting point, and toggle colouring.
    if (ImGui::Button(ICON_CODE "  Load original as template") && (haveEntry || hooked))
        m_cppSource = CppTemplateFor(hooked ? m_cppHookedEntry : entry);
    ImGui::SetItemTooltip("Replaces the editor with the hooked function decompiled to pseudo-C,\n"
                          "so you can rebuild or tweak its behaviour in your hook.");
    ImGui::SameLine();
    ImGui::Checkbox("Syntax highlight", &m_cppHighlight);

    ImGui::Separator();

    // --- Code editor ---
    float footer = ImGui::GetFrameHeightWithSpacing() * 2 + 150;
    float editH = ImGui::GetContentRegionAvail().y - footer;
    if (editH < 80) editH = 80;
    if (m_mono) ImGui::PushFont(m_mono);
    if (m_cppHighlight && m_mono)
    {
        // Colour the code by drawing it under a transparent, content-sized InputTextMultiline. Both
        // live in one scrolling child, so they move together; editing happens in the (invisible) input.
        ImGui::BeginChild("##cppeditor", ImVec2(-FLT_MIN, editH), true, ImGuiWindowFlags_HorizontalScrollbar);
        ImVec2 origin = ImGui::GetCursorScreenPos();
        ImVec2 content = Syntax::DrawCppCode(ImGui::GetWindowDrawList(), origin, m_cppSource.c_str());
        float w = content.x + 40 > ImGui::GetContentRegionAvail().x ? content.x + 40 : ImGui::GetContentRegionAvail().x;
        float h = content.y > ImGui::GetContentRegionAvail().y ? content.y : ImGui::GetContentRegionAvail().y;
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0, 0, 0, 0));          // typed glyphs invisible
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
        ImGui::SetCursorScreenPos(origin);
        ImGui::InputTextMultiline("##cppsrc", &m_cppSource, ImVec2(w, h), ImGuiInputTextFlags_AllowTabInput);
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);

        // The transparent text hides ImGui's own caret, so draw one where the cursor is.
        if (ImGuiInputTextState* st = ImGui::GetInputTextState(ImGui::GetItemID()))
        {
            int cur = st->GetCursorPos();
            if (cur < 0) cur = 0;
            if (cur > (int)m_cppSource.size()) cur = (int)m_cppSource.size();
            int row = 0, lineStart = 0;
            for (int i = 0; i < cur; i++) if (m_cppSource[i] == '\n') { row++; lineStart = i + 1; }
            float cx = origin.x + ImGui::CalcTextSize(m_cppSource.c_str() + lineStart, m_cppSource.c_str() + cur).x;
            float cy = origin.y + row * ImGui::GetTextLineHeight();
            if (fmodf((float)ImGui::GetTime(), 1.0f) < 0.6f)
                ImGui::GetWindowDrawList()->AddLine(ImVec2(cx, cy), ImVec2(cx, cy + ImGui::GetTextLineHeight()),
                                                    ImGui::GetColorU32(ImGuiCol_Text));
        }
        ImGui::EndChild();
    }
    else
    {
        ImGui::InputTextMultiline("##cppsrc", &m_cppSource, ImVec2(-FLT_MIN, editH),
                                  ImGuiInputTextFlags_AllowTabInput);
    }
    if (m_mono) ImGui::PopFont();

    // --- Actions ---
    if (Glass::AccentButton(ICON_REFRESH "  Compile & Apply"))
    {
        std::string log;
        bool ok = m_cpp.Apply(m_proc, m_detours, m_cppHookedEntry, m_cppSource, log);
        m_cppLog = log;
        Log(ok ? "C++ build applied." : "C++ build failed.");
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(240);
    ImGui::InputTextWithHint("##cppargs", "params for OnRun", m_cppRunArgs, sizeof(m_cppRunArgs));
    ImGui::SameLine();
    if (ImGui::Button(ICON_PLAY "  Run"))
    {
        std::string out, err;
        if (m_cpp.Run(m_cppRunArgs, out, err)) m_cppLog = out.empty() ? "(no output)" : out;
        else m_cppLog = err;
    }
    ImGui::SameLine();
    if (ImGui::Button(ICON_DELETE "  Clear output")) m_cppLog.clear();

    ImGui::TextDisabled("Output");
    if (m_mono) ImGui::PushFont(m_mono);
    ImGui::InputTextMultiline("##cpplog", &m_cppLog, ImVec2(-FLT_MIN, -FLT_MIN),
                              ImGuiInputTextFlags_ReadOnly);
    if (m_mono) ImGui::PopFont();

    ImGui::End();
}

int App::RecommendCaveBytes() const
{
    const size_t jsz = m_proc.Is64() ? 14 : 5; // bytes stolen for the entry jump

    size_t idx = (size_t)-1;
    for (size_t i = 0; i < m_instructions.size(); i++)
        if (m_instructions[i].address == m_selectedInsn) { idx = i; break; }
    if (idx == (size_t)-1) return 32;

    // How many whole instructions get stolen (and thus relocated) into the cave.
    size_t stolen = 0;
    for (size_t i = idx; i < m_instructions.size() && stolen < jsz; i++)
        stolen += m_instructions[i].bytes.size();
    if (stolen < jsz) stolen = jsz;

    // Free room for your own code: enough to reproduce the stolen logic plus headroom,
    // rounded up to 16 so the number stays tidy.
    size_t rec = stolen + 32;
    rec = (rec + 15) & ~size_t(15);
    return (int)rec;
}

void App::DrawDetours()
{
    if (!m_proc.IsOpen())
    {
        ImGui::TextDisabled("Attach to a process first.");
        return;
    }

    // Install controls operate on the instruction selected in the Disassembly tab.
    const InstructionRow* sel = nullptr;
    for (const auto& r : m_instructions)
        if (r.address == m_selectedInsn) sel = &r;

    // Pre-fill the cave's free-byte count with a size suggestion when the selection
    // changes; the user can still override it with the stepper afterwards.
    if (sel && m_caveRecForInsn != sel->address)
    {
        m_caveUserBytes = RecommendCaveBytes();
        m_caveRecForInsn = sel->address;
    }

    ImGui::TextDisabled("A detour redirects a function's entry. Pick the entry in the Disassembly tab.");
    if (sel)
    {
        if (m_mono) ImGui::PushFont(m_mono);
        ImGui::TextColored(kColAccent, "entry %s", m_proc.Symbolize(sel->address).c_str());
        ImGui::SameLine();
        ImGui::TextUnformatted(sel->text.c_str());
        if (m_mono) ImGui::PopFont();

        bool already = m_detours.Find(sel->address) != nullptr;
        ImGui::BeginDisabled(already);

        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("redirect to");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(Px(200));
        if (m_focusDetourTarget && !already)
        {
            ImGui::SetKeyboardFocusHere();
            m_focusDetourTarget = false;
        }
        ImGui::InputText("##dtarget", m_detourTarget, sizeof(m_detourTarget));
        ImGui::SetItemTooltip("Address expression, e.g. game.exe+1F00 or another function.");
        ImGui::SameLine();
        if (ImGui::Button("Redirect"))
        {
            uint64_t target = 0;
            std::string e;
            if (!EvaluateAddress(m_proc, m_detourTarget, target, &e)) m_detourStatus = "Target: " + e;
            else if (!m_detours.Redirect(m_proc, sel->address, target, e)) m_detourStatus = e;
            else
            {
                m_detourStatus = "Redirected " + m_proc.Symbolize(sel->address) + " to " + m_proc.Symbolize(target);
                Log(m_detourStatus);
                RunDecompile();
            }
        }

        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("or trampoline cave with");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(StepperWidth(50));
        ImGui::InputInt("##cavebytes", &m_caveUserBytes);
        if (m_caveUserBytes < 0) m_caveUserBytes = 0;
        if (m_caveUserBytes > 4096) m_caveUserBytes = 4096;
        ImGui::SameLine();
        int rec = RecommendCaveBytes();
        ImGui::TextDisabled("free bytes (rec %d)", rec);
        if (m_caveUserBytes != rec)
        {
            ImGui::SameLine();
            if (ImGui::SmallButton("Reset")) m_caveUserBytes = rec;
        }
        ImGui::SameLine();
        if (ImGui::Button("Install cave"))
        {
            std::string e;
            if (!m_detours.InstallTrampoline(m_proc, sel->address, (size_t)m_caveUserBytes, e)) m_detourStatus = e;
            else
            {
                const Detour* d = m_detours.Find(sel->address);
                m_detourStatus = "Cave at " + ToHex(d ? d->cave : 0) + " - original runs; edit the cave to add code.";
                Log("Installed trampoline on " + m_proc.Symbolize(sel->address));
                RunDecompile();
            }
        }
        ImGui::SetItemTooltip("Allocates a code cave: [original instructions][your free bytes][jump back].\n"
                              "If the stolen code ends in a jmp/ret, the free bytes go just before it so\n"
                              "they still run. Your code runs AFTER the original, so a store you write wins.\n"
                              "Free bytes defaults to a size for this instruction; raise it if you need more.");
        ImGui::EndDisabled();
        if (already) ImGui::TextDisabled("This entry is already detoured - see the list below.");
    }
    else ImGui::TextDisabled("No instruction selected.");

    if (!m_detourStatus.empty()) ImGui::TextColored(kColAccent, "%s", m_detourStatus.c_str());

    ImGui::Separator();
    if (m_detours.Empty())
    {
        ImGui::TextDisabled("No detours installed.");
        return;
    }

    if (ImGui::Button("Disable all")) { m_detours.RestoreAll(m_proc); RunDecompile(); }
    ImGui::SameLine();
    if (ImGui::Button("Remove all"))
    {
        std::vector<uint64_t> es;
        for (const auto& d : m_detours.All()) es.push_back(d.entry);
        for (uint64_t e : es) m_detours.Remove(m_proc, e);
        RunDecompile();
    }

    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
    if (ImGui::BeginTable("##detours", 5, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, Px(30));
        ImGui::TableSetupColumn("Entry", ImGuiTableColumnFlags_WidthFixed, Px(170));
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, Px(90));
        ImGui::TableSetupColumn("Target / cave", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed,
                                SmallButtonWidth("Edit cave") + ImGui::GetStyle().ItemSpacing.x + SmallButtonWidth("Remove"));
        ImGui::TableHeadersRow();

        uint64_t toRemove = 0;
        bool remove = false;
        for (const auto& d : m_detours.All())
        {
            ImGui::TableNextRow();
            ImGui::PushID((void*)(uintptr_t)d.entry);
            ImGui::TableNextColumn();
            bool on = d.enabled;
            if (ImGui::Checkbox("##on", &on)) m_detours.SetEnabled(m_proc, d.entry, on);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(d.location.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(d.kind.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(m_proc.Symbolize(d.target).c_str());
            ImGui::TableNextColumn();
            if (d.cave)
            {
                if (ImGui::SmallButton("Edit cave"))
                {
                    // Land on the first byte of the cave - the original (stolen) instructions -
                    // so you see the function first, with your free bytes below them.
                    m_hex.FocusDisasm(d.cave);
                    m_showHex = true;
                    ImGui::SetWindowFocus(kWinHex);
                }
                ImGui::SetItemTooltip("Jumps to the cave's free bytes (the highlighted NOP block) in the Memory View.\n"
                                      "Type hex there to add your code; the stolen instructions run right after it.");
                ImGui::SameLine();
            }
            if (ImGui::SmallButton("Remove")) { toRemove = d.entry; remove = true; }
            ImGui::PopID();
        }
        ImGui::EndTable();
        if (remove) { m_detours.Remove(m_proc, toRemove); RunDecompile(); }
    }

    // Reference: the instructions each cave stole from its entry, so you can rebuild the
    // original behaviour in the cave (or just see what you're replacing) while you edit.
    bool anyCave = false;
    for (const auto& d : m_detours.All())
        if (d.cave) { anyCave = true; break; }
    if (anyCave)
    {
        ImGui::Spacing();
        if (ImGui::CollapsingHeader("Original code (before cave)", ImGuiTreeNodeFlags_DefaultOpen))
        {
            ImGui::TextDisabled("What the entry ran before the detour. Your cave's free bytes start as NOPs -\n"
                                "write your new version here, using this as the reference.");
            for (const auto& d : m_detours.All())
            {
                if (!d.cave) continue;
                ImGui::PushID((void*)(uintptr_t)d.entry);
                ImGui::SeparatorText(m_proc.Symbolize(d.entry).c_str());

                std::vector<InstructionRow> rows;
                DisassembleBytes(d.original, d.entry, m_proc.Is64(), rows);
                if (m_mono) ImGui::PushFont(m_mono);
                for (const auto& r : rows)
                {
                    std::string hex = BytesToHex(r.bytes.data(), r.bytes.size());
                    ImGui::TextDisabled("%-18s %-21s ", m_proc.Symbolize(r.address).c_str(), hex.c_str());
                    ImGui::SameLine(0, 0);
                    Syntax::Instruction(r.text.c_str());
                }
                if (m_mono) ImGui::PopFont();

                if (ImGui::SmallButton("Copy original bytes"))
                    ImGui::SetClipboardText(BytesToHex(d.original.data(), d.original.size()).c_str());
                ImGui::SameLine();
                ImGui::TextDisabled("cave %s  |  %zu free bytes", ToHex(d.cave).c_str(), d.caveUserSize);

                // Set the immediate (e.g. the +25) to any value, even one too big for the original
                // width - it's re-encoded wider and written into the cave's free bytes.
                ImGui::AlignTextToFramePadding();
                ImGui::TextDisabled("set value");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(Px(120));
                ImGui::InputText("##caveimm", m_caveImmInput, sizeof(m_caveImmInput));
                ImGui::SetItemTooltip("Hex by default (3E8 = 1000); prefix 0n for decimal.");
                ImGui::SameLine();
                if (ImGui::SmallButton("Apply"))
                {
                    const char* s = m_caveImmInput;
                    uint64_t v = 0;
                    if (s[0] == '0' && (s[1] == 'n' || s[1] == 'N')) v = strtoull(s + 2, nullptr, 10);
                    else if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) v = strtoull(s + 2, nullptr, 16);
                    else v = strtoull(s, nullptr, 16);
                    std::string e;
                    if (!m_detours.SetCaveImmediate(m_proc, d.entry, v, e)) m_detourStatus = e;
                    else { m_detourStatus = "Cave at " + ToHex(d.cave) + " now uses value " + ToHex(v); Log(m_detourStatus); }
                }
                ImGui::PopID();
            }
        }
    }
}

void App::OpenOpcodes(const std::string& query)
{
    // Given a whole instruction ("lock cmpxchg [rcx], edx"), search for its mnemonic.
    std::istringstream in(query);
    std::string word, pick;
    static const char* kPrefixes[] = { "lock", "rep", "repe", "repz", "repne", "repnz", "bnd", "notrack" };
    while (in >> word)
    {
        bool prefix = false;
        for (const char* p : kPrefixes)
            if (word == p) prefix = true;
        pick = word;
        if (!prefix) break;
    }
    snprintf(m_opcSearch, sizeof(m_opcSearch), "%s", pick.empty() ? query.c_str() : pick.c_str());
    m_opcCategory = 0;
    m_opcPickBest = true;
    m_showOpcodes = true;
    ImGui::SetWindowFocus(kWinOpcodes);
}

void App::DrawOpcodes()
{
    ImGui::SetNextWindowSize(ImVec2(Px(1000), Px(640)), ImGuiCond_FirstUseEver);
    Glass::PrepareWindow(kWinOpcodes);
    if (!ImGui::Begin(kWinOpcodes, &m_showOpcodes))
    {
        ImGui::End();
        return;
    }
    const auto& ref = OpcodeReference();
    const auto& cats = OpcodeCategories();

    // Search row: text or raw bytes, plus a category filter.
    const float catW = Px(210);
    if (ImGui::IsWindowAppearing() || m_opcFocusSearch)
    {
        ImGui::SetKeyboardFocusHere();
        m_opcFocusSearch = false;
    }
    ImGui::SetNextItemWidth(-catW - ImGui::GetStyle().ItemSpacing.x);
    if (ImGui::InputTextWithHint("##opcsearch", "Search: jne, flags, float, return, 0F 84, 48 8B 05 10 00 00 00 ...",
                                 m_opcSearch, sizeof(m_opcSearch)))
        m_opcPickBest = true;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (ImGui::BeginCombo("##opccat", m_opcCategory == 0 ? "All categories" : cats[m_opcCategory - 1].c_str()))
    {
        if (ImGui::Selectable("All categories", m_opcCategory == 0)) m_opcCategory = 0, m_opcPickBest = true;
        for (size_t c = 0; c < cats.size(); c++)
            if (ImGui::Selectable(cats[c].c_str(), m_opcCategory == (int)c + 1)) m_opcCategory = (int)c + 1, m_opcPickBest = true;
        ImGui::EndCombo();
    }

    // Understand the query: words to match, and whether it is a run of hex bytes to decode.
    std::string q = Lower(m_opcSearch);
    while (!q.empty() && isspace((unsigned char)q.back())) q.pop_back();
    while (!q.empty() && isspace((unsigned char)q.front())) q.erase(q.begin());
    std::vector<std::string> words;
    {
        std::istringstream ws(q);
        for (std::string w; ws >> w;) words.push_back(w);
    }
    std::string hexDigits;
    bool hexOnly = !q.empty(), hasDigit = false;
    for (char c : q)
    {
        if (isspace((unsigned char)c)) continue;
        if (!isxdigit((unsigned char)c)) hexOnly = false;
        if (isdigit((unsigned char)c)) hasDigit = true;
        hexDigits += (char)toupper((unsigned char)c);
    }
    const bool bytesQuery = hexOnly && hasDigit && hexDigits.size() >= 2 && hexDigits.size() % 2 == 0;
    std::vector<InstructionRow> decoded;
    std::vector<std::string> decodedMnemonics;
    if (bytesQuery)
    {
        std::vector<uint8_t> bytes;
        for (size_t k = 0; k + 1 < hexDigits.size(); k += 2) bytes.push_back((uint8_t)strtoul(hexDigits.substr(k, 2).c_str(), nullptr, 16));
        DisassembleBytes(bytes, 0, m_proc.IsOpen() ? m_proc.Is64() : true, decoded);
        for (const auto& r : decoded)
        {
            std::istringstream ts(r.text);
            std::string m;
            while (ts >> m && (m == "lock" || m == "rep" || m == "repe" || m == "repne" || m == "repz" || m == "repnz")) {}
            decodedMnemonics.push_back(m);
        }
    }

    // Score every entry. Exact mnemonic / alias matches first, then prefixes, then text matches.
    auto wordIn = [](const std::string& list, const std::string& w) {
        std::istringstream ls(list);
        for (std::string x; ls >> x;)
            if (x == w) return true;
        return false;
    };
    struct Hit { int idx; int score; };
    std::vector<Hit> hits;
    for (int i = 0; i < (int)ref.size(); i++)
    {
        const OpcodeRef& e = ref[i];
        if (m_opcCategory > 0 && e.category != cats[m_opcCategory - 1]) continue;
        if (q.empty())
        {
            hits.push_back({ i, 0 });
            continue;
        }
        const std::string mn = Lower(e.mnemonic), al = Lower(e.aliases);
        int score = 0;
        if (bytesQuery)
        {
            for (const auto& m : decodedMnemonics)
                if (m == mn || wordIn(al, m)) score = std::max(score, 1000);
            std::string enc = e.encodings + " " + e.exampleBytes;
            std::string compact;
            for (char c : enc)
                if (!isspace((unsigned char)c)) compact += (char)toupper((unsigned char)c);
            if (compact.find(hexDigits) != std::string::npos) score = std::max(score, 300);
        }
        else
        {
            const std::string hay = mn + " " + al + " " + Lower(e.category) + " " + Lower(e.summary) + " " +
                                    Lower(e.details) + " " + Lower(e.encodings) + " " + Lower(e.example) + " " +
                                    Lower(e.exampleBytes) + " " + Lower(e.tip) + " " + Lower(e.flags);
            bool all = true;
            for (const auto& w : words)
                if (hay.find(w) == std::string::npos) all = false;
            if (all)
            {
                score = 100;
                if (Lower(e.summary).find(q) != std::string::npos) score = 250;
                if (mn.rfind(q, 0) == 0) score = 500;
                if (wordIn(al, q)) score = 900;
                if (mn == q) score = 1000;
            }
            // cmovge / setnz / jnae -> the family entry
            if (!score && ((q.rfind("cmov", 0) == 0 && mn == "cmovcc") || (q.rfind("set", 0) == 0 && mn == "setcc")))
                score = 800;
        }
        if (score) hits.push_back({ i, score });
    }
    if (!q.empty())
        std::stable_sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.score > b.score; });

    // Keep a valid selection: the best hit after the search changes.
    bool selVisible = false;
    for (const Hit& h : hits) selVisible |= h.idx == m_opcSelected;
    if (!hits.empty() && (m_opcPickBest || !selVisible)) m_opcSelected = hits.front().idx;
    m_opcPickBest = false;

    // Bytes typed in: show what they decode to.
    if (bytesQuery)
    {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(Glass::kAccent.x, Glass::kAccent.y, Glass::kAccent.z, 0.08f));
        ImGui::BeginChild("##opcdecode", ImVec2(0, 0), ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY);
        ImGui::TextDisabled("These bytes decode as (placed at address 0, so relative targets are offsets):");
        if (m_mono) ImGui::PushFont(m_mono);
        if (decoded.empty()) ImGui::TextColored(kColErr, "(not a valid instruction)");
        for (const auto& r : decoded)
        {
            ImGui::TextDisabled("%-24s", BytesToHex(r.bytes.data(), r.bytes.size()).c_str());
            ImGui::SameLine(0, 0);
            Syntax::Instruction(r.text.c_str());
        }
        if (m_mono) ImGui::PopFont();
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    // Up / Down walk the list even while typing in the search box.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !hits.empty())
    {
        int pos = 0;
        for (int k = 0; k < (int)hits.size(); k++)
            if (hits[k].idx == m_opcSelected) pos = k;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) pos = std::min(pos + 1, (int)hits.size() - 1);
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) pos = std::max(pos - 1, 0);
        m_opcSelected = hits[pos].idx;
    }

    // Left: the list. Right: the selected entry.
    const float listW = std::max(Px(300), ImGui::GetContentRegionAvail().x * 0.36f);
    ImGui::BeginChild("##opclist", ImVec2(listW, 0), ImGuiChildFlags_Borders);
    if (hits.empty())
        ImGui::TextDisabled(bytesQuery ? "No entry for these bytes." : "Nothing matches. Try fewer words.");
    std::string lastCat;
    const float mnW = Px(118);
    for (const Hit& h : hits)
    {
        const OpcodeRef& e = ref[h.idx];
        if (q.empty() && e.category != lastCat)
        {
            ImGui::SeparatorText(e.category.c_str());
            lastCat = e.category;
        }
        ImGui::PushID(h.idx);
        const bool sel = h.idx == m_opcSelected;
        ImVec2 rowPos = ImGui::GetCursorScreenPos();
        if (ImGui::Selectable("##row", sel, 0, ImVec2(0, ImGui::GetTextLineHeight()))) m_opcSelected = h.idx;
        if (sel && ImGui::IsWindowAppearing()) ImGui::SetScrollHereY(0.3f);
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const bool topic = e.category == "Encoding" || e.category == "Modding recipes";
        ImVec4 mc = topic ? Glass::kAccentHi : Syntax::MnemonicColor(e.mnemonic);
        if (m_mono && !topic) ImGui::PushFont(m_mono);
        dl->AddText(rowPos, ImGui::ColorConvertFloat4ToU32(mc), e.mnemonic.c_str());
        const float nameW = ImGui::CalcTextSize(e.mnemonic.c_str()).x;
        if (m_mono && !topic) ImGui::PopFont();
        if (!topic)
        {
            // Summaries line up in a column, pushed right only past an unusually long name.
            ImVec2 sp(rowPos.x + std::max(mnW, nameW + Px(12)), rowPos.y);
            ImVec4 clip(sp.x, sp.y, ImGui::GetWindowPos().x + ImGui::GetWindowWidth() - Px(8), sp.y + ImGui::GetTextLineHeight());
            dl->AddText(nullptr, 0.f, sp, ImGui::GetColorU32(ImGuiCol_TextDisabled), e.summary.c_str(), nullptr, 0.f, &clip);
        }
        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("##opcdetail", ImVec2(0, 0), ImGuiChildFlags_Borders);
    if (m_opcSelected >= 0 && m_opcSelected < (int)ref.size())
    {
        const OpcodeRef& e = ref[m_opcSelected];
        const bool topic = e.category == "Encoding" || e.category == "Modding recipes";
        const float wrap = ImGui::GetContentRegionAvail().x;

        // Heading.
        if (Glass::GetFonts().title) ImGui::PushFont(Glass::GetFonts().title);
        ImGui::TextColored(topic ? Glass::kAccentHi : Syntax::MnemonicColor(e.mnemonic), "%s", e.mnemonic.c_str());
        if (Glass::GetFonts().title) ImGui::PopFont();
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s", e.category.c_str());
        if (!e.aliases.empty() && !topic) // topics use aliases only as search keywords
        {
            ImGui::SameLine();
            ImGui::TextDisabled("- also: %s", e.aliases.c_str());
        }
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap);
        if (Glass::GetFonts().bold) ImGui::PushFont(Glass::GetFonts().bold);
        ImGui::TextUnformatted(e.summary.c_str());
        if (Glass::GetFonts().bold) ImGui::PopFont();

        if (!e.encodings.empty())
        {
            ImGui::SeparatorText(topic ? "Form" : "Encoding");
            if (m_mono) ImGui::PushFont(m_mono);
            ImGui::TextColored(Syntax::kNumber, "%s", e.encodings.c_str());
            if (m_mono) ImGui::PopFont();
        }
        if (!e.details.empty())
        {
            ImGui::SeparatorText(topic ? "How it works" : "What it does");
            // Multi-line details (tables, step lists) keep their layout in the mono font.
            const bool table = e.details.find('\n') != std::string::npos;
            size_t split = table ? e.details.find('\n') : std::string::npos;
            ImGui::TextUnformatted(e.details.substr(0, split).c_str());
            if (table)
            {
                if (m_mono) ImGui::PushFont(m_mono);
                ImGui::TextUnformatted(e.details.substr(split + 1).c_str());
                if (m_mono) ImGui::PopFont();
            }
        }
        if (!topic)
        {
            ImGui::SeparatorText("Flags");
            if (e.flags.empty()) ImGui::TextDisabled("No flags changed.");
            else ImGui::TextColored(Syntax::kCompare, "%s", e.flags.c_str());
        }
        if (!e.example.empty())
        {
            ImGui::SeparatorText("Example");
            if (m_mono) ImGui::PushFont(m_mono);
            if (!e.exampleBytes.empty())
            {
                ImGui::TextDisabled("%-26s", e.exampleBytes.c_str());
                ImGui::SameLine(0, 0);
            }
            Syntax::Instruction(e.example.c_str());
            if (m_mono) ImGui::PopFont();
            if (!e.exampleBytes.empty() && ImGui::SmallButton(ICON_COPY " Copy bytes"))
                ImGui::SetClipboardText(e.exampleBytes.c_str());
        }
        ImGui::PopTextWrapPos();

        if (!e.tip.empty())
        {
            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(Syntax::kCall.x, Syntax::kCall.y, Syntax::kCall.z, 0.08f));
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(Syntax::kCall.x, Syntax::kCall.y, Syntax::kCall.z, 0.35f));
            ImGui::BeginChild("##tip", ImVec2(0, 0), ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY);
            ImGui::TextColored(Syntax::kCall, ICON_FLASH "  Modding tip");
            ImGui::PushTextWrapPos(0.f);
            ImGui::TextUnformatted(e.tip.c_str());
            ImGui::PopTextWrapPos();
            ImGui::EndChild();
            ImGui::PopStyleColor(2);
        }

        // Neighbours in the same category, one click away.
        ImGui::SeparatorText("Related");
        int shown = 0;
        for (int i = 0; i < (int)ref.size() && shown < 14; i++)
        {
            if (i == m_opcSelected || ref[i].category != e.category) continue;
            if (shown++ && ImGui::GetContentRegionAvail().x > ImGui::CalcTextSize(ref[i].mnemonic.c_str()).x + Px(40))
                ImGui::SameLine();
            ImGui::PushID(i);
            if (ImGui::SmallButton(ref[i].mnemonic.c_str())) m_opcSelected = i;
            ImGui::PopID();
            ImGui::SetItemTooltip("%s", ref[i].summary.c_str());
        }
    }
    ImGui::EndChild();
    ImGui::End();
}

void App::DrawCalculator()
{
    ImGui::SetNextWindowSize(ImVec2(Px(440), Px(330)), ImGuiCond_FirstUseEver);
    Glass::PrepareWindow("Calculator");
    if (!ImGui::Begin("Calculator", &m_showCalc))
    {
        ImGui::End();
        return;
    }

    ImGui::Checkbox("Hex input", &m_calcHex);
    ImGui::SameLine();
    ImGui::TextDisabled(m_calcHex ? "typing 1C = 0x1C; prefix with 0n for decimal" : "typing 28 = decimal; prefix 0x for hex");

    // Parse A/B honouring the hex-input toggle. 0x forces hex, 0n forces decimal, '-' negates.
    auto parse = [&](const char* s, uint64_t& v) -> bool {
        std::string t = s;
        size_t a = t.find_first_not_of(" \t");
        if (a == std::string::npos) return false;
        t = t.substr(a, t.find_last_not_of(" \t") - a + 1);
        bool neg = t[0] == '-';
        if (neg) t = t.substr(1);
        int base = m_calcHex ? 16 : 10;
        if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) { base = 16; t = t.substr(2); }
        else if (t.rfind("0n", 0) == 0 || t.rfind("0N", 0) == 0) { base = 10; t = t.substr(2); }
        if (t.empty()) return false;
        char* end = nullptr;
        errno = 0;
        unsigned long long u = strtoull(t.c_str(), &end, base);
        if (end == t.c_str() || *end != '\0' || errno != 0) return false;
        v = neg ? (uint64_t)(-(int64_t)u) : u;
        return true;
    };

    ImGui::SetNextItemWidth(Px(170));
    ImGui::InputText("A", m_calcA, sizeof(m_calcA));
    const char* ops[] = { "A + B", "A - B", "A * B", "A / B", "A AND B", "A OR B", "A XOR B", "A << B", "A >> B", "~A" };
    ImGui::SetNextItemWidth(Px(120));
    ImGui::Combo("op", &m_calcOp, ops, IM_ARRAYSIZE(ops));
    bool unary = m_calcOp == 9;
    ImGui::BeginDisabled(unary);
    ImGui::SetNextItemWidth(Px(170));
    ImGui::InputText("B", m_calcB, sizeof(m_calcB));
    ImGui::EndDisabled();

    uint64_t a = 0, b = 0;
    bool okA = parse(m_calcA, a);
    bool okB = unary ? true : parse(m_calcB, b);
    ImGui::Separator();
    if (!okA || !okB)
    {
        ImGui::TextColored(kColErr, "Enter valid numbers.");
        ImGui::End();
        return;
    }

    uint64_t r = 0;
    switch (m_calcOp)
    {
    case 0: r = a + b; break;
    case 1: r = a - b; break;
    case 2: r = a * b; break;
    case 3:
        if (b == 0) { ImGui::TextColored(kColErr, "Divide by zero."); ImGui::End(); return; }
        r = a / b;
        break;
    case 4: r = a & b; break;
    case 5: r = a | b; break;
    case 6: r = a ^ b; break;
    case 7: r = a << (b & 63); break;
    case 8: r = a >> (b & 63); break;
    case 9: r = ~a; break;
    }

    // Smallest natural width that holds the result, for the little-endian byte view.
    int width = 1;
    if (r > 0xFFFFFFFFull) width = 8;
    else if (r > 0xFFFFull) width = 4;
    else if (r > 0xFFull) width = 2;

    // Label | value | Copy, with every Copy button lined up on the right edge.
    const float copyW = ImGui::CalcTextSize("Copy").x + ImGui::GetStyle().FramePadding.x * 2;
    auto row = [&](const char* label, const std::string& value) {
        ImGui::TextDisabled("%-10s", label);
        ImGui::SameLine();
        ImGui::TextUnformatted(value.c_str());
        ImGui::SameLine(std::max(ImGui::GetCursorPosX(), ImGui::GetContentRegionMax().x - copyW));
        ImGui::SmallButton((std::string("Copy##") + label).c_str());
        if (ImGui::IsItemClicked()) ImGui::SetClipboardText(value.c_str());
    };

    char hexs[32];
    snprintf(hexs, sizeof(hexs), "0x%llX", (unsigned long long)r);
    std::string bytesLE;
    for (int i = 0; i < width; i++)
    {
        char bb[4];
        snprintf(bb, sizeof(bb), "%02X ", (unsigned)((r >> (i * 8)) & 0xFF));
        bytesLE += bb;
    }
    if (!bytesLE.empty()) bytesLE.pop_back();

    std::string bin;
    int topBit = 0;
    for (int i = 63; i >= 0; i--)
        if (r & (1ull << i)) { topBit = i; break; }
    for (int i = topBit; i >= 0; i--)
    {
        bin += (r & (1ull << i)) ? '1' : '0';
        if (i && i % 4 == 0) bin += ' ';
    }
    if (bin.empty()) bin = "0";

    if (m_mono) ImGui::PushFont(m_mono);
    row("hex", hexs);
    row("unsigned", std::to_string((unsigned long long)r));
    row("signed", std::to_string((long long)r));
    row("bytes LE", bytesLE);
    row("binary", bin);
    if (m_mono) ImGui::PopFont();

    ImGui::End();
}

void App::OpenPointerScan(uint64_t target)
{
    m_showPtrScan = true;
    snprintf(m_ptrTarget, sizeof(m_ptrTarget), "%llX", (unsigned long long)target);
    m_ptrOpts.target = target;
    ImGui::SetWindowFocus("Pointer scan");
}

void App::DrawPointerScan()
{
    ImGui::SetNextWindowSize(ImVec2(Px(640), Px(460)), ImGuiCond_FirstUseEver);
    Glass::PrepareWindow("Pointer scan");
    if (!ImGui::Begin("Pointer scan", &m_showPtrScan))
    {
        ImGui::End();
        return;
    }

    ImGui::TextDisabled("Finds static pointer paths (module+offset -> ... -> address) that survive a restart.");
    ImGui::Spacing();

    ImGui::SetNextItemWidth(Px(200));
    ImGui::InputText("target", m_ptrTarget, sizeof(m_ptrTarget));
    ImGui::SameLine();
    ImGui::TextDisabled("hex, or an expression");

    ImGui::SetNextItemWidth(Px(120));
    ImGui::SliderInt("max depth", &m_ptrMaxDepth, 1, 7);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Px(100));
    ImGui::InputText("max offset", m_ptrMaxOffset, sizeof(m_ptrMaxOffset));
    ImGui::SameLine();
    ImGui::Checkbox("negative offsets", &m_ptrAllowNeg);

    const bool busy = m_ptrScan.Busy();
    ImGui::BeginDisabled(busy || !m_proc.IsOpen());
    if (ImGui::Button("Scan"))
    {
        uint64_t target = 0;
        std::string err;
        uint64_t maxOff = 0x800;
        ParseHexU64(m_ptrMaxOffset, maxOff);
        if (!EvaluateAddress(m_proc, m_ptrTarget, target, &err))
            m_ptrStatus = "Bad target: " + err;
        else
        {
            m_ptrOpts.target = target;
            m_ptrOpts.maxDepth = m_ptrMaxDepth;
            m_ptrOpts.maxOffset = maxOff ? maxOff : 0x800;
            m_ptrOpts.allowNegative = m_ptrAllowNeg;
            m_ptrOpts.staticOnly = true;
            if (!m_ptrScan.Start(m_proc, m_ptrOpts, err)) m_ptrStatus = err;
            else m_ptrStatus = "Scanning...";
        }
    }
    ImGui::EndDisabled();
    if (busy)
    {
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) m_ptrScan.Cancel();
        ImGui::SameLine();
        ImGui::ProgressBar(m_ptrScan.Progress(), ImVec2(Px(160), 0), m_ptrScan.Phase());
    }

    if (!m_ptrStatus.empty())
    {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", m_ptrStatus.c_str());
    }

    const auto& results = m_ptrScan.Results();

    // Keep the selection / display-order arrays in step with the current results.
    bool resultsChanged = false;
    if (m_ptrSelected.size() != results.size())
    {
        m_ptrSelected.assign(results.size(), 0);
        m_ptrOrder.resize(results.size());
        for (int i = 0; i < (int)results.size(); i++) m_ptrOrder[i] = i;
        m_ptrAnchor = -1;
        resultsChanged = true;
    }

    auto addWatchFor = [&](const PointerChain& ch) {
        WatchEntry e;
        e.expression = ch.Expression();
        e.type = ValueType::Int32;
        e.description = "Pointer";
        m_watches.push_back(std::move(e));
    };
    auto selectedCount = [&]() {
        int n = 0;
        for (char c : m_ptrSelected) n += c ? 1 : 0;
        return n;
    };

    ImGui::Separator();
    ImGui::TextColored(kColAccent, "%zu paths", results.size());
    ImGui::SameLine();
    ImGui::TextDisabled("from %llu pointers", (unsigned long long)m_ptrScan.PointerMapSize());

    // Rescan after a restart: keep only paths that still resolve to a (new) target.
    ImGui::SameLine(0, Px(20));
    ImGui::SetNextItemWidth(Px(150));
    ImGui::InputText("new target", m_ptrNewTarget, sizeof(m_ptrNewTarget));
    ImGui::SameLine();
    ImGui::BeginDisabled(results.empty() || !m_proc.IsOpen());
    if (ImGui::Button("Filter to still-valid"))
    {
        uint64_t nt = 0;
        std::string err;
        if (!EvaluateAddress(m_proc, m_ptrNewTarget, nt, &err)) m_ptrStatus = "Bad new target: " + err;
        else
        {
            size_t left = m_ptrScan.Filter(m_proc, nt);
            m_ptrStatus = std::to_string(left) + " paths still resolve to the new target";
        }
    }
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("After the game restarts, attach again, find the value's new address, type it here,\n"
                          "and keep only the paths that still reach it.");

    // Selection toolbar.
    int selN = selectedCount();
    ImGui::BeginDisabled(selN == 0);
    if (ImGui::Button(selN > 1 ? "Add selected to list" : "Add to list"))
        for (size_t ri = 0; ri < results.size(); ri++) if (m_ptrSelected[ri]) addWatchFor(results[ri]);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(results.empty());
    if (ImGui::Button("Select all")) std::fill(m_ptrSelected.begin(), m_ptrSelected.end(), (char)1);
    ImGui::SameLine();
    if (ImGui::Button("Clear")) { std::fill(m_ptrSelected.begin(), m_ptrSelected.end(), (char)0); m_ptrAnchor = -1; }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("%d selected  -  shift/ctrl-click to multi-select", selN);

    if (ImGui::BeginTable("##ptrres", 3,
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Sortable | ImGuiTableFlags_SortTristate))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort, Px(180), 0);
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 0, 1);
        ImGui::TableSetupColumn("Resolves to", ImGuiTableColumnFlags_WidthFixed, Px(130), 2);
        ImGui::TableHeadersRow();

        // (Re)sort the display order when the user clicks a header or the results change.
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs())
        {
            if (specs->SpecsDirty || resultsChanged)
            {
                int col = specs->SpecsCount > 0 ? specs->Specs[0].ColumnUserID : 0;
                bool asc = specs->SpecsCount == 0 || specs->Specs[0].SortDirection != ImGuiSortDirection_Descending;
                std::sort(m_ptrOrder.begin(), m_ptrOrder.end(), [&](int a, int b) {
                    const PointerChain& x = results[a];
                    const PointerChain& y = results[b];
                    bool less;
                    if (col == 1) // Path: by depth then text
                        less = x.offsets.size() != y.offsets.size() ? x.offsets.size() < y.offsets.size()
                                                                    : x.Expression() < y.Expression();
                    else if (col == 2) // Resolves to
                        less = x.resolved < y.resolved;
                    else // Base: static first, then module+offset / address
                        less = x.base < y.base;
                    return asc ? less : !less;
                });
                specs->SpecsDirty = false;
            }
        }

        if (m_mono) ImGui::PushFont(m_mono);
        ImGuiListClipper clip;
        clip.Begin((int)m_ptrOrder.size());
        while (clip.Step())
        {
            for (int d = clip.DisplayStart; d < clip.DisplayEnd; d++)
            {
                int ri = m_ptrOrder[d];
                const PointerChain& ch = results[ri];
                ImGui::TableNextRow();
                ImGui::PushID(ri);

                ImGui::TableNextColumn();
                std::string baseText = ch.staticBase ? (ch.module + "+" + ToHex(ch.baseOffset)) : ToHex(ch.base);
                if (ch.staticBase) ImGui::PushStyleColor(ImGuiCol_Text, kColOk);
                bool sel = m_ptrSelected[ri] != 0;
                // Render for visuals/hover only; drive selection from IsItemClicked so Ctrl/Shift
                // clicks register reliably (Selectable's return value can swallow modified clicks).
                ImGui::Selectable(baseText.c_str(), sel, ImGuiSelectableFlags_SpanAllColumns);
                if (ch.staticBase) ImGui::PopStyleColor();

                if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
                {
                    ImGuiIO& io = ImGui::GetIO();
                    if (io.KeyShift && m_ptrAnchor >= 0 && m_ptrAnchor < (int)m_ptrOrder.size())
                    {
                        int a = std::min(m_ptrAnchor, d), b = std::max(m_ptrAnchor, d);
                        if (!io.KeyCtrl) std::fill(m_ptrSelected.begin(), m_ptrSelected.end(), (char)0);
                        for (int k = a; k <= b; k++) m_ptrSelected[m_ptrOrder[k]] = 1;
                    }
                    else if (io.KeyCtrl)
                    {
                        m_ptrSelected[ri] = m_ptrSelected[ri] ? 0 : 1;
                        m_ptrAnchor = d;
                    }
                    else
                    {
                        std::fill(m_ptrSelected.begin(), m_ptrSelected.end(), (char)0);
                        m_ptrSelected[ri] = 1;
                        m_ptrAnchor = d;
                    }
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right) && !sel)
                {
                    std::fill(m_ptrSelected.begin(), m_ptrSelected.end(), (char)0);
                    m_ptrSelected[ri] = 1;
                    m_ptrAnchor = d;
                }
                std::string expr = ch.Expression();
                if (ImGui::BeginPopupContextItem("##pctx"))
                {
                    int sc = selectedCount();
                    if (ImGui::MenuItem(sc > 1 ? "Add selected to address list" : "Add to address list"))
                    {
                        if (sc > 1) { for (size_t k = 0; k < results.size(); k++) if (m_ptrSelected[k]) addWatchFor(results[k]); }
                        else addWatchFor(ch);
                    }
                    if (ImGui::MenuItem("Copy path")) ImGui::SetClipboardText(expr.c_str());
                    if (ImGui::MenuItem("Browse memory here")) { m_hex.GoTo(ch.resolved); m_showHex = true; }
                    ImGui::EndPopup();
                }

                ImGui::TableNextColumn();
                Syntax::Expression(expr.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(ToHex(ch.resolved).c_str());

                ImGui::PopID();
            }
        }
        if (m_mono) ImGui::PopFont();
        ImGui::EndTable();
    }

    ImGui::End();
}

// ---------------------------------------------------------------------------
// AOB scan: pattern search, signature maker, signature list

AobScanOptions App::AobOptions() const
{
    AobScanOptions o;
    o.executableOnly = m_aobExecOnly;
    o.writableOnly = m_aobWritableOnly;
    o.includeMapped = m_aobIncludeMapped;
    if (m_aobScope > 0 && m_aobScope <= (int)m_aobModules.size())
    {
        const ModuleInfo& m = m_aobModules[m_aobScope - 1];
        o.start = m.base;
        o.end = m.base + m.size;
    }
    return o;
}

void App::StartAobScan()
{
    AobPattern p;
    std::string err;
    if (!p.Parse(m_aobPattern, err) || !m_aob.Start(m_proc, p, AobOptions(), err)) m_aobStatus = err;
    else m_aobStatus.clear();
}

void App::OpenAobScan(const std::string& pattern, bool run)
{
    snprintf(m_aobPattern, sizeof(m_aobPattern), "%s", pattern.c_str());
    m_showAob = true;
    m_aobTabRequest = 0;
    ImGui::SetWindowFocus(kWinAob);
    if (run && m_proc.IsOpen() && !m_aob.Busy()) StartAobScan();
}

void App::OpenSigMaker(uint64_t address)
{
    snprintf(m_sigAddress, sizeof(m_sigAddress), "%s", m_proc.Symbolize(address).c_str());
    m_showAob = true;
    m_aobTabRequest = 1;
    ImGui::SetWindowFocus(kWinAob);
    auto t0 = std::chrono::steady_clock::now();
    m_sigResult = MakeSignature(m_proc, address, m_sigOpts);
    m_sigMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    m_sigAt = address;
    m_sigHave = true;
}

void App::DrawAobScan()
{
    ImGui::SetNextWindowSize(ImVec2(Px(900), Px(580)), ImGuiCond_FirstUseEver);
    Glass::PrepareWindow(kWinAob);
    if (!ImGui::Begin(kWinAob, &m_showAob))
    {
        ImGui::End();
        return;
    }
    if (!m_proc.IsOpen())
    {
        if (Glass::EmptyState(ICON_FLASH, "No process", "Attach to a process to search its memory for byte patterns.",
                              ICON_LINK "  Attach to process"))
            m_openPicker = true;
        ImGui::End();
        return;
    }
    if (ImGui::BeginTabBar("##aobtabs"))
    {
        auto tab = [&](const char* label, int idx) {
            return ImGui::BeginTabItem(label, nullptr, m_aobTabRequest == idx ? ImGuiTabItemFlags_SetSelected : 0);
        };
        if (tab(ICON_SEARCH "  Scan", 0))
        {
            DrawAobScanTab();
            ImGui::EndTabItem();
        }
        if (tab(ICON_EDIT "  Signature maker", 1))
        {
            DrawSigMakerTab();
            ImGui::EndTabItem();
        }
        if (tab(ICON_LIST "  Signature list", 2))
        {
            DrawSigListTab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    m_aobTabRequest = -1;
    ImGui::End();
}

void App::DrawAobScanTab()
{
    const bool busy = m_aob.Busy();
    AobPattern parsed;
    std::string perr;
    const bool valid = m_aobPattern[0] && parsed.Parse(m_aobPattern, perr);

    // Pattern + Scan.
    const float btnW = Px(112);
    ImGui::SetNextItemWidth(-btnW - ImGui::GetStyle().ItemSpacing.x);
    if (m_mono) ImGui::PushFont(m_mono);
    bool enter = ImGui::InputTextWithHint("##aobpat", "48 8B 05 ?? ?? ?? ??   or   \\x48\\x8B\\x05 xxx", m_aobPattern,
                                          sizeof(m_aobPattern), ImGuiInputTextFlags_EnterReturnsTrue);
    if (m_mono) ImGui::PopFont();
    ImGui::SameLine();
    if (busy)
    {
        if (ImGui::Button(ICON_STOP "  Cancel", ImVec2(btnW, 0))) m_aob.Cancel();
    }
    else
    {
        ImGui::BeginDisabled(!valid);
        if (Glass::AccentButton(ICON_SEARCH "  Scan", ImVec2(btnW, 0)) || (enter && valid)) StartAobScan();
        ImGui::EndDisabled();
    }

    // What the pattern parsed to.
    if (!m_aobPattern[0])
        ImGui::TextDisabled("?? any byte   4? / ?8 half a byte   | where results point   \\x48\\x8B + xx? mask also works");
    else if (!valid) ImGui::TextColored(kColErr, ICON_WARNING " %s", perr.c_str());
    else
    {
        const int wild = (int)parsed.Size() - parsed.SolidBytes();
        ImGui::TextDisabled("%zu bytes, %d with wildcards", parsed.Size(), wild);
        if (parsed.resultOffset)
        {
            ImGui::SameLine();
            ImGui::TextDisabled("- results point %d bytes in", parsed.resultOffset);
        }
        if (strstr(m_aobPattern, "\\x") || strstr(m_aobPattern, "\\X"))
        {
            ImGui::SameLine();
            if (m_mono) ImGui::PushFont(m_mono);
            ImGui::TextColored(kColAccent, "%s", parsed.ToIda().c_str());
            if (m_mono) ImGui::PopFont();
        }
    }

    // Where to look.
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("In");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Px(230));
    const bool scoped = m_aobScope > 0 && m_aobScope <= (int)m_aobModules.size();
    if (ImGui::BeginCombo("##aobscope", scoped ? m_aobModules[m_aobScope - 1].name.c_str() : "All memory"))
    {
        if (ImGui::IsWindowAppearing())
        {
            // Refresh the module list, keeping the current choice by name.
            std::string keep = scoped ? m_aobModules[m_aobScope - 1].name : "";
            m_aobModules = m_proc.Modules();
            m_aobScope = 0;
            for (size_t k = 0; k < m_aobModules.size(); k++)
                if (m_aobModules[k].name == keep) m_aobScope = (int)k + 1;
        }
        if (ImGui::Selectable("All memory", m_aobScope == 0)) m_aobScope = 0;
        ImGui::Separator();
        for (size_t k = 0; k < m_aobModules.size(); k++)
            if (ImGui::Selectable(m_aobModules[k].name.c_str(), m_aobScope == (int)k + 1)) m_aobScope = (int)k + 1;
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Executable only", &m_aobExecOnly);
    ImGui::SetItemTooltip("Search code only - where signatures normally live. Turn off to search data too.");
    ImGui::SameLine();
    ImGui::Checkbox("Writable only", &m_aobWritableOnly);
    ImGui::SameLine();
    ImGui::Checkbox("Mapped", &m_aobIncludeMapped);
    ImGui::SetItemTooltip("Also search file mappings and shared sections");

    // Status.
    const auto& res = m_aob.Results();
    const AobPattern& pat = m_aob.Pattern();
    const bool scanned = !pat.Empty();
    if (busy)
    {
        char overlay[48];
        snprintf(overlay, sizeof(overlay), "Searching %.0f%%", m_aob.Progress() * 100.f);
        ImGui::ProgressBar(m_aob.Progress(), ImVec2(-FLT_MIN, 0), overlay);
        return;
    }
    if (!m_aobStatus.empty()) ImGui::TextColored(kColErr, ICON_WARNING " %s", m_aobStatus.c_str());
    else if (scanned)
    {
        ImGui::TextColored(res.size() == 1 ? kColOk : kColAccent, "%zu%s %s", res.size(), m_aob.Truncated() ? "+" : "",
                           res.size() == 1 ? "match (unique)" : "matches");
        ImGui::SameLine();
        ImGui::TextDisabled("in %.0f ms, %s searched", m_aob.LastDurationMs(), HumanSize(m_aob.BytesScanned()).c_str());
        if (m_aob.Truncated())
        {
            ImGui::SameLine();
            ImGui::TextColored(kColChanged, "- stopped at the result limit");
        }
        if (!m_aob.LastError().empty())
        {
            ImGui::SameLine();
            ImGui::TextDisabled("(%s)", m_aob.LastError().c_str());
        }
    }

    if (res.empty())
    {
        if (scanned)
            Glass::EmptyState(ICON_SEARCH, "No matches",
                              "Nothing in the chosen memory matches. Try fewer bytes, more wildcards, All memory, or "
                              "turning off Executable only.");
        else
            Glass::EmptyState(ICON_FLASH, "Find code by its bytes",
                              "Type a pattern and press Enter. To make one that survives updates, right-click an "
                              "instruction and choose Make AOB signature here.");
        return;
    }

    // Selection actions.
    m_aobSel.Resize(res.size());
    auto copySelected = [&](bool symbolic) {
        std::string text;
        m_aobSel.ForEach([&](size_t k) { text += (symbolic ? m_proc.Symbolize(res[k]) : ToHex(res[k])) + "\n"; });
        ImGui::SetClipboardText(text.c_str());
    };
    auto addSelected = [&] {
        size_t n = 0;
        m_aobSel.ForEach([&](size_t k) {
            if (n++ < 5000) AddWatch(res[k], ValueType::ByteArray, (int)std::max<size_t>(pat.Size(), 8));
        });
    };
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput)
    {
        const bool ctrl = ImGui::GetIO().KeyCtrl;
        if (ctrl && ImGui::IsKeyPressed(ImGuiKey_A, false)) m_aobSel.SelectAll();
        if (ctrl && ImGui::IsKeyPressed(ImGuiKey_C, false) && m_aobSel.Count()) copySelected(false);
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) m_aobSel.Clear();
    }

    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##aobres", 4, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 1.5f);
        ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 0.9f);
        ImGui::TableHeadersRow();

        if (m_mono) ImGui::PushFont(m_mono);
        const float space = ImGui::CalcTextSize(" ").x;
        ImGuiListClipper clipper;
        clipper.Begin((int)res.size());
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                const uint64_t a = res[i];
                const uint64_t start = a - (uint64_t)(int64_t)pat.resultOffset;
                const AobInsn insn = AobDecode(m_proc, start);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                ModuleInfo mod;
                const bool isStatic = m_proc.ModuleFromAddress(a, mod);
                if (isStatic) ImGui::PushStyleColor(ImGuiCol_Text, kColOk);
                if (ImGui::Selectable(m_proc.Symbolize(a).c_str(), m_aobSel.Get(i),
                                      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
                {
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                    {
                        m_hex.FocusDisasm(start);
                        m_showHex = true;
                        ImGui::SetWindowFocus(kWinHex);
                    }
                    else m_aobSel.Click(i);
                }
                if (isStatic) ImGui::PopStyleColor();
                ImGui::SetItemTooltip("Double-click to open in the Memory View's disassembly");
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) m_aobSel.SelectForContextMenu(i);
                if (ImGui::BeginPopupContextItem("##aobctx"))
                {
                    if (m_mono) ImGui::PopFont();
                    const size_t n = m_aobSel.Count();
                    if (ImGui::MenuItem(ICON_CHIP "  Disassemble here")) { m_hex.FocusDisasm(start); m_showHex = true; ImGui::SetWindowFocus(kWinHex); }
                    if (ImGui::MenuItem(ICON_CHIP "  Browse memory here")) { m_hex.GoTo(a); m_showHex = true; ImGui::SetWindowFocus(kWinHex); }
                    if (ImGui::MenuItem(ICON_FORWARD "  Follow target", nullptr, false, insn.hasTarget))
                    {
                        m_hex.GoTo(insn.target);
                        m_showHex = true;
                        ImGui::SetWindowFocus(kWinHex);
                    }
                    if (ImGui::MenuItem(ICON_CODE "  Decompile function here")) StartDecompile(start);
                    if (ImGui::MenuItem(ICON_FLASH "  Make AOB signature here")) OpenSigMaker(start);
                    ImGui::Separator();
                    if (ImGui::MenuItem(n > 1 ? (ICON_ADD "  Add " + std::to_string(n) + " selected to address list").c_str()
                                              : ICON_ADD "  Add to address list"))
                        addSelected();
                    if (ImGui::MenuItem(n > 1 ? ICON_COPY "  Copy selected addresses" : ICON_COPY "  Copy address", "Ctrl+C"))
                        copySelected(false);
                    if (ImGui::MenuItem(ICON_COPY "  Copy as module+offset")) copySelected(true);
                    if (ImGui::MenuItem(ICON_COPY "  Copy target", nullptr, false, insn.hasTarget))
                        ImGui::SetClipboardText(ToHex(insn.target).c_str());
                    ImGui::Separator();
                    if (ImGui::MenuItem("Select all", "Ctrl+A")) m_aobSel.SelectAll();
                    ImGui::EndPopup();
                    if (m_mono) ImGui::PushFont(m_mono);
                }
                ImGui::PopID();

                // The matched bytes; the pattern's wildcard positions are dimmed.
                ImGui::TableNextColumn();
                uint8_t bytes[24] = {};
                const size_t show = std::min<size_t>(pat.Size(), sizeof(bytes));
                const size_t got = m_proc.Read(start, bytes, show);
                for (size_t k = 0; k < show; k++)
                {
                    if (k) ImGui::SameLine(0, space);
                    char hx[4];
                    snprintf(hx, sizeof(hx), "%02X", bytes[k]);
                    if (k >= got) ImGui::TextDisabled("??");
                    else if (pat.mask[k] != 0xFF) ImGui::TextDisabled("%s", hx);
                    else ImGui::TextUnformatted(hx);
                }
                if (pat.Size() > show)
                {
                    ImGui::SameLine(0, space);
                    ImGui::TextDisabled("...");
                }

                ImGui::TableNextColumn();
                if (insn.ok) Syntax::Instruction(insn.text.c_str());
                else ImGui::TextDisabled("(not code)");

                ImGui::TableNextColumn();
                if (insn.hasTarget) ImGui::TextUnformatted(m_proc.Symbolize(insn.target).c_str());
                else ImGui::TextDisabled("-");
            }
        }
        if (m_mono) ImGui::PopFont();
        ImGui::EndTable();
    }
}

void App::DrawSigMakerTab()
{
    ImGui::TextDisabled("Builds the shortest byte pattern that finds this code again after the program restarts or updates.");

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Address");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Px(280));
    if (m_mono) ImGui::PushFont(m_mono);
    bool enter = ImGui::InputTextWithHint("##sigaddr", "game.exe+1F00", m_sigAddress, sizeof(m_sigAddress),
                                          ImGuiInputTextFlags_EnterReturnsTrue);
    if (m_mono) ImGui::PopFont();
    ImGui::SameLine();
    if (Glass::AccentButton(ICON_FLASH "  Generate") || enter)
    {
        uint64_t a = 0;
        std::string err;
        if (EvaluateAddress(m_proc, m_sigAddress, a, &err)) OpenSigMaker(a);
        else
        {
            m_sigResult = SigMakerResult();
            m_sigResult.error = "Address: " + err;
            m_sigHave = true;
        }
    }

    ImGui::Checkbox("Wildcard relative addresses", &m_sigOpts.wildcardRelative);
    ImGui::SetItemTooltip("Call/jump targets, RIP-relative operands and absolute pointers into modules.\n"
                          "These change whenever the code moves, so leave this on.");
    ImGui::SameLine();
    ImGui::Checkbox("Also 32-bit offsets and constants", &m_sigOpts.wildcardWide);
    ImGui::SetItemTooltip("Wildcards large struct offsets and immediates too. Survives more updates but\n"
                          "needs more bytes to be unique.");
    ImGui::Checkbox("Unique across all executable memory", &m_sigOpts.wholeProcess);
    ImGui::SetItemTooltip("Off: unique within the module the address belongs to (what you normally want).");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(StepperWidth(40));
    ImGui::InputInt("Max bytes", &m_sigOpts.maxBytes, 8, 32);
    m_sigOpts.maxBytes = std::clamp(m_sigOpts.maxBytes, 8, 512);
    ImGui::Separator();

    if (!m_sigHave)
    {
        Glass::EmptyState(ICON_EDIT, "Make a signature",
                          "Right-click an instruction in the Memory View, the Disassembly tab or a scan result and "
                          "choose Make AOB signature here - or type an address above.");
        return;
    }
    const SigMakerResult& r = m_sigResult;
    if (!r.ok)
    {
        ImGui::TextColored(kColErr, ICON_WARNING " %s", r.error.c_str());
        return;
    }

    const AobPattern& p = r.pattern;
    const int wild = (int)p.Size() - p.SolidBytes();
    if (r.unique) ImGui::TextColored(kColOk, ICON_SHIELD_FILL " Unique in %s", r.scope.c_str());
    else ImGui::TextColored(kColChanged, ICON_WARNING " %s", r.error.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("%zu bytes, %d instructions, %d wildcarded, %.0f ms", p.Size(), r.instructions, wild, m_sigMs);

    // Copyable forms.
    std::string ida = p.ToIda(), code = p.ToCodeBytes(), mask = p.ToCodeMask();
    auto field = [&](const char* label, std::string& value, const char* id) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s", label);
        ImGui::SameLine(Px(70));
        ImGui::SetNextItemWidth(-Px(80));
        if (m_mono) ImGui::PushFont(m_mono);
        ImGui::InputText(id, &value, ImGuiInputTextFlags_ReadOnly);
        if (m_mono) ImGui::PopFont();
        ImGui::SameLine();
        ImGui::PushID(id);
        if (ImGui::Button(ICON_COPY " Copy", ImVec2(-FLT_MIN, 0))) ImGui::SetClipboardText(value.c_str());
        ImGui::PopID();
    };
    field("Pattern", ida, "##sigida");
    field("Bytes", code, "##sigcode");
    field("Mask", mask, "##sigmask");

    if (Glass::AccentButton(ICON_SEARCH "  Scan for it")) OpenAobScan(ida, true);
    ImGui::SameLine();
    if (ImGui::Button(ICON_ADD "  Add to signature list"))
    {
        SigEntry e;
        e.name = m_proc.Symbolize(m_sigAt);
        e.pattern = ida;
        m_sigList.push_back(e);
        m_aobTabRequest = 2;
    }
    ImGui::Spacing();

    // The instructions the pattern covers, with wildcarded bytes dimmed.
    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
    if (ImGui::BeginTable("##siginsns", 3, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 0.8f);
        ImGui::TableSetupColumn("Pattern bytes", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableHeadersRow();
        if (m_mono) ImGui::PushFont(m_mono);
        const float space = ImGui::CalcTextSize(" ").x;
        uint64_t at = m_sigAt;
        size_t pos = 0;
        for (int n = 0; n < r.instructions && pos < p.Size(); n++)
        {
            AobInsn insn = AobDecode(m_proc, at);
            if (!insn.ok || insn.length <= 0) break;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", m_proc.Symbolize(at).c_str());
            ImGui::TableNextColumn();
            for (int k = 0; k < insn.length && pos < p.Size(); k++, pos++)
            {
                if (k) ImGui::SameLine(0, space);
                if (p.mask[pos] == 0xFF) ImGui::Text("%02X", p.bytes[pos]);
                else ImGui::TextDisabled("??");
            }
            ImGui::TableNextColumn();
            Syntax::Instruction(insn.text.c_str());
            at += insn.length;
        }
        if (m_mono) ImGui::PopFont();
        ImGui::EndTable();
    }
}

void App::DrawSigListTab()
{
    auto scanOne = [&](SigEntry& e) {
        AobPattern p;
        e.scanned = true;
        e.matches = 0;
        e.first = 0;
        if (!p.Parse(e.pattern, e.error)) return;
        auto hits = AobFind(m_proc, p, AobOptions(), 1000);
        e.matches = hits.size();
        e.first = hits.empty() ? 0 : hits.front();
    };

    // New entry row.
    ImGui::SetNextItemWidth(Px(170));
    ImGui::InputTextWithHint("##signame", "Name", m_sigNewName, sizeof(m_sigNewName));
    ImGui::SameLine();
    const float addW = Px(90);
    ImGui::SetNextItemWidth(-addW - ImGui::GetStyle().ItemSpacing.x);
    if (m_mono) ImGui::PushFont(m_mono);
    bool enter = ImGui::InputTextWithHint("##sigpat", "Pattern, e.g. 48 8B 05 ?? ?? ?? ??", m_sigNewPattern,
                                          sizeof(m_sigNewPattern), ImGuiInputTextFlags_EnterReturnsTrue);
    if (m_mono) ImGui::PopFont();
    ImGui::SameLine();
    if ((ImGui::Button(ICON_ADD " Add", ImVec2(addW, 0)) || enter) && m_sigNewPattern[0])
    {
        SigEntry e;
        e.name = m_sigNewName[0] ? m_sigNewName : "Signature " + std::to_string(m_sigList.size() + 1);
        e.pattern = m_sigNewPattern;
        m_sigList.push_back(e);
        m_sigNewName[0] = m_sigNewPattern[0] = 0;
    }

    ImGui::BeginDisabled(m_sigList.empty());
    if (Glass::AccentButton(ICON_PLAY "  Scan all"))
        for (auto& e : m_sigList) scanOne(e);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Load...")) LoadSigList();
    ImGui::SameLine();
    ImGui::BeginDisabled(m_sigList.empty());
    if (ImGui::Button("Save...")) SaveSigList();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("%zu signatures - searched with the Scan tab's memory options", m_sigList.size());

    if (m_sigList.empty())
    {
        Glass::EmptyState(ICON_LIST, "No signatures yet",
                          "Add patterns here or from the Signature maker, then save the list. After the program "
                          "updates, load it and Scan all to find everything again.");
        return;
    }

    int remove = -1;
    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##siglist", 5, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.8f);
        ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch, 2.0f);
        ImGui::TableSetupColumn("Matches", ImGuiTableColumnFlags_WidthFixed, Px(80));
        ImGui::TableSetupColumn("First match", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed,
                                SmallButtonWidth("Scan") + ImGui::GetStyle().ItemSpacing.x + SmallButtonWidth(ICON_DELETE));
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)m_sigList.size(); i++)
        {
            SigEntry& e = m_sigList[i];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("##n", &e.name);
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (m_mono) ImGui::PushFont(m_mono);
            if (ImGui::InputText("##p", &e.pattern)) e.scanned = false;
            if (m_mono) ImGui::PopFont();

            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            if (!e.scanned) ImGui::TextDisabled("-");
            else if (!e.error.empty())
            {
                ImGui::TextColored(kColErr, "error");
                ImGui::SetItemTooltip("%s", e.error.c_str());
            }
            else if (e.matches == 0) ImGui::TextColored(kColErr, "none");
            else if (e.matches == 1) ImGui::TextColored(kColOk, "unique");
            else ImGui::TextColored(kColChanged, "%zu%s", e.matches, e.matches >= 1000 ? "+" : "");

            ImGui::TableNextColumn();
            if (e.scanned && e.matches)
            {
                if (m_mono) ImGui::PushFont(m_mono);
                if (ImGui::Selectable(m_proc.Symbolize(e.first).c_str()))
                {
                    m_hex.FocusDisasm(e.first);
                    m_showHex = true;
                    ImGui::SetWindowFocus(kWinHex);
                }
                if (m_mono) ImGui::PopFont();
                ImGui::SetItemTooltip("Open in the Memory View's disassembly");
            }

            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Scan")) scanOne(e);
            ImGui::SameLine();
            if (ImGui::SmallButton(ICON_DELETE)) remove = i;
            ImGui::SetItemTooltip("Remove from the list");
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (remove >= 0) m_sigList.erase(m_sigList.begin() + remove);
}

// Signature lists are plain text: one "name = pattern" per line, # starts a comment.
void App::SaveSigList()
{
    std::wstring path = L"signatures.sig";
    if (!FileDialog((HWND)m_hwnd, true, L"Signature list (*.sig)\0*.sig\0Text files\0*.txt\0All files\0*.*\0", L"sig", path))
        return;
    std::ofstream f(path, std::ios::binary);
    if (!f)
    {
        Log("Could not write the signature list");
        return;
    }
    f << "# Memory Browser signatures: name = pattern\n";
    for (const auto& e : m_sigList)
    {
        std::string n = e.name;
        std::replace(n.begin(), n.end(), '=', '-');
        f << n << " = " << e.pattern << "\n";
    }
    Log("Saved " + std::to_string(m_sigList.size()) + " signatures");
}

void App::LoadSigList()
{
    std::wstring path;
    if (!FileDialog((HWND)m_hwnd, false, L"Signature list (*.sig)\0*.sig\0Text files\0*.txt\0All files\0*.*\0", L"sig", path))
        return;
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        Log("Could not open the signature list");
        return;
    }
    auto trim = [](std::string s) {
        size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
        return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
    };
    size_t added = 0;
    std::string line;
    while (std::getline(f, line))
    {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        SigEntry e;
        size_t eq = line.find('=');
        if (eq == std::string::npos) e.pattern = line;
        else
        {
            e.name = trim(line.substr(0, eq));
            e.pattern = trim(line.substr(eq + 1));
        }
        if (e.name.empty()) e.name = "Signature " + std::to_string(m_sigList.size() + 1);
        if (e.pattern.empty()) continue;
        m_sigList.push_back(e);
        added++;
    }
    Log("Loaded " + std::to_string(added) + " signatures");
}

void App::SaveTable()
{
    std::wstring path = L"table.mtbl";
    if (!FileDialog((HWND)m_hwnd, true, L"Memory table (*.mtbl)\0*.mtbl\0All files\0*.*\0", L"mtbl", path)) return;
    std::ofstream f(path, std::ios::binary);
    if (!f)
    {
        Log("Could not write table");
        return;
    }
    f << "MTBL1\n";
    for (const auto& w : m_watches)
    {
        std::string d = w.description, e = w.expression;
        std::replace(d.begin(), d.end(), '\t', ' ');
        std::replace(e.begin(), e.end(), '\t', ' ');
        f << (int)w.type << '\t' << w.length << '\t' << (w.hex ? 1 : 0) << '\t' << d << '\t' << e << '\n';
    }
    Log("Saved " + std::to_string(m_watches.size()) + " entries");
}

void App::LoadTable()
{
    std::wstring path;
    if (!FileDialog((HWND)m_hwnd, false, L"Memory table (*.mtbl)\0*.mtbl\0All files\0*.*\0", L"mtbl", path)) return;
    std::ifstream f(path, std::ios::binary);
    std::string line;
    if (!f || !std::getline(f, line) || line.rfind("MTBL1", 0) != 0)
    {
        Log("Not a memory table file");
        return;
    }
    int n = 0;
    while (std::getline(f, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string p;
        while (std::getline(ss, p, '\t')) parts.push_back(p);
        if (parts.size() < 5) continue;
        WatchEntry w;
        int t = atoi(parts[0].c_str());
        if (t < 0 || t >= (int)ValueType::Count) continue;
        w.type = (ValueType)t;
        w.length = std::clamp(atoi(parts[1].c_str()), 1, 4096);
        w.hex = parts[2] == "1";
        w.description = parts[3];
        w.expression = parts[4];
        m_watches.push_back(std::move(w));
        n++;
    }
    Log("Loaded " + std::to_string(n) + " entries");
}

void App::DumpMemory(uint64_t base, uint64_t size, const std::string& suggestedName)
{
    std::wstring path = Utf8ToWide(suggestedName);
    for (auto& c : path)
        if (c == L'"' || c == L':' || c == L'\\' || c == L'/') c = L'_';
    if (!FileDialog((HWND)m_hwnd, true, L"Binary (*.bin)\0*.bin\0All files\0*.*\0", L"bin", path)) return;
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f)
    {
        Log("Could not open dump file");
        return;
    }
    std::vector<uint8_t> buf(1 << 20);
    uint64_t readTotal = 0;
    for (uint64_t off = 0; off < size; off += buf.size())
    {
        size_t n = (size_t)std::min<uint64_t>(buf.size(), size - off);
        readTotal += m_proc.Read(base + off, buf.data(), n);
        fwrite(buf.data(), 1, n, f);
    }
    fclose(f);
    Log("Dumped " + HumanSize(size) + " from " + ToHex(base) + " (" + HumanSize(readTotal) + " readable)");
}
