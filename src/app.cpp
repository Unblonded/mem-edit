#include "app.h"

#include "decompiler.h"
#include "imgui.h"
#include "ui.h"
#include "imgui_internal.h"
#include "misc/cpp/imgui_stdlib.h"

#include <windows.h>
#include <commdlg.h>
#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sstream>

namespace
{
const char* kWinScanner = "Scanner";
const char* kWinResults = "Scan Results";
const char* kWinHex = "Memory View";
const char* kWinWatch = "Address List";
const char* kWinRegions = "Memory Regions";
const char* kWinModules = "Modules";
const char* kWinLog = "Log";
const char* kWinDecompile = "Decompile";

const ImVec4 kColErr(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kColOk(0.45f, 0.85f, 0.55f, 1.0f);
const ImVec4 kColChanged(1.0f, 0.38f, 0.32f, 1.0f);
const ImVec4 kColAccent(0.40f, 0.62f, 1.0f, 1.0f);

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
    m_traces.clear();
    m_patches.clear();
    m_proc.Close();
    m_scanner.Reset();
    m_regions.clear();
    m_resSelA = m_resSelB = -1;
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
    UpdateWatches();

    ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) m_openPicker = true;

    DrawMenuBar();
    DrawStatusBar();

    ImGuiID dock = ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
    if (!m_layoutInit)
    {
        m_layoutInit = true;
        ImGuiDockNode* node = ImGui::DockBuilderGetNode(dock);
        if (m_forceLayout || !node || !node->IsSplitNode()) SetupDefaultLayout(dock);
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
    DrawTraceWindows();
    DrawProcessPicker();
    DrawEditValuePopup();
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
    if (!ImGui::BeginMainMenuBar()) return;
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
        ImGui::Separator();
        if (ImGui::MenuItem("Reset layout"))
        {
            m_showScanner = m_showResults = m_showHex = m_showWatch = m_showRegions = m_showModules = m_showLog = true;
            m_layoutInit = false;
            m_forceLayout = true;
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Help"))
    {
        ImGui::MenuItem("Expressions & shortcuts", nullptr, &m_showAbout);
        ImGui::EndMenu();
    }

    // Quick attach button on the right of the menu bar.
    const char* label = m_proc.IsOpen() ? m_proc.Name().c_str() : "No process";
    float w = ImGui::CalcTextSize(label).x + Px(60);
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - w);
    ImGui::PushStyleColor(ImGuiCol_Text, m_proc.IsOpen() ? kColOk : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    if (ImGui::Selectable(label, false, 0, ImVec2(w - Px(16), 0))) m_openPicker = true;
    ImGui::PopStyleColor();
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
            if (m_proc.IsOpen())
            {
                ImGui::TextColored(kColOk, "%s", m_proc.Name().c_str());
                ImGui::TextDisabled("PID %lu  %s", m_proc.Pid(), m_proc.Is64() ? "x64" : "x86");
                if (m_proc.IsSuspended()) ImGui::TextColored(kColChanged, "SUSPENDED");
            }
            else
            {
                ImGui::TextDisabled("Not attached");
            }
            ImGui::Separator();
            if (m_scanner.Busy()) ImGui::Text("Scanning... %.0f%%", m_scanner.Progress() * 100.f);
            else if (m_scanner.HasResults())
                ImGui::TextDisabled("Scan #%llu: %zu results", (unsigned long long)m_scanner.State().scanNumber,
                                    m_scanner.State().Count());
            ImGui::Separator();
            if (m_elevated) ImGui::TextColored(kColOk, "Administrator");
            else ImGui::TextDisabled("Not elevated");
            ImGui::Separator();
            ImGui::TextDisabled("%.0f FPS", ImGui::GetIO().Framerate);
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
    if (!hasResults)
    {
        if (ImGui::Button("First Scan", ImVec2(bw, 0))) doFirst = true;
    }
    else if (ImGui::Button("New Scan", ImVec2(bw, 0)))
    {
        m_scanner.Reset();
        m_resSelA = m_resSelB = -1;
        if (!CompareAllowed(m_opts.compare, m_opts.type, true)) m_opts.compare = ScanCompare::Exact;
        hasResults = false;
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!hasResults);
    if (ImGui::Button("Next Scan", ImVec2(bw, 0))) doNext = true;
    ImGui::SameLine();
    ImGui::BeginDisabled(!m_scanner.CanUndo());
    if (ImGui::Button("Undo Scan", ImVec2(bw, 0))) { m_scanner.Undo(); m_resSelA = m_resSelB = -1; }
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
        ImGui::Checkbox("Writable only", &m_opts.requireWritable);
        ImGui::SameLine(Px(180));
        ImGui::Checkbox("Include executable", &m_opts.includeExecutable);
        ImGui::Checkbox("Image", &m_opts.includeImage);
        ImGui::SetItemTooltip("Memory backed by loaded modules (.exe/.dll sections)");
        ImGui::SameLine(Px(90));
        ImGui::Checkbox("Private", &m_opts.includePrivate);
        ImGui::SetItemTooltip("Heap / stack / VirtualAlloc memory");
        ImGui::SameLine(Px(180));
        ImGui::Checkbox("Mapped", &m_opts.includeMapped);
        ImGui::SetItemTooltip("File mappings and shared sections");

        if (IsNumeric(m_opts.type))
        {
            ImGui::Checkbox("Fast scan, alignment", &m_opts.fastScan);
            ImGui::SameLine();
            ImGui::BeginDisabled(!m_opts.fastScan);
            ImGui::SetNextItemWidth(Px(80));
            ImGui::InputInt("##align", &m_opts.alignment, 1, 4);
            m_opts.alignment = std::clamp(m_opts.alignment, 1, 64);
            ImGui::EndDisabled();
        }

        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Start");
        ImGui::SameLine(Px(50));
        ImGui::SetNextItemWidth(Px(150));
        if (m_mono) ImGui::PushFont(m_mono);
        ImGui::InputText("##rs", m_rangeStart, sizeof(m_rangeStart), ImGuiInputTextFlags_CharsHexadecimal);
        if (m_mono) ImGui::PopFont();
        ImGui::SameLine();
        ImGui::TextUnformatted("Stop");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(Px(150));
        if (m_mono) ImGui::PushFont(m_mono);
        ImGui::InputText("##re", m_rangeEnd, sizeof(m_rangeEnd), ImGuiInputTextFlags_CharsHexadecimal);
        if (m_mono) ImGui::PopFont();
        ImGui::SameLine();
        if (ImGui::SmallButton("All"))
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
        m_resSelA = m_resSelB = -1;
    }
    ImGui::End();
}

void App::DrawResults()
{
    if (!ImGui::Begin(kWinResults, &m_showResults))
    {
        ImGui::End();
        return;
    }
    const ScanState& st = m_scanner.State();
    if (m_scanner.Busy())
    {
        ImGui::TextDisabled("Scan in progress...");
        ImGui::End();
        return;
    }
    if (!st.valid)
    {
        ImGui::TextDisabled("No scan results yet.");
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
    int64_t selMin = std::min(m_resSelA, m_resSelB), selMax = std::max(m_resSelA, m_resSelB);

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
                bool selected = i >= selMin && i <= selMax;
                ModuleInfo m;
                bool isStatic = m_proc.ModuleFromAddress(a, m);
                std::string label = isStatic ? m_proc.Symbolize(a) : AddrText(a);
                if (isStatic) ImGui::PushStyleColor(ImGuiCol_Text, kColOk);
                if (ImGui::Selectable(label.c_str(), selected,
                                      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
                {
                    if (ImGui::GetIO().KeyShift && m_resSelA >= 0) m_resSelB = i;
                    else m_resSelA = m_resSelB = i;
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) AddWatch(a, st.type, (int)vs);
                }
                if (isStatic) ImGui::PopStyleColor();
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right) && !selected) m_resSelA = m_resSelB = i;
                if (ImGui::BeginPopupContextItem("##rctx"))
                {
                    int64_t a0 = std::min(m_resSelA, m_resSelB), a1 = std::max(m_resSelA, m_resSelB);
                    int64_t n = a1 - a0 + 1;
                    if (ImGui::MenuItem(n > 1 ? "Add selected to address list" : "Add to address list"))
                    {
                        for (int64_t k = a0; k <= a1 && k < a0 + 5000; k++) AddWatch(st.addresses[k], st.type, (int)vs);
                    }
                    if (ImGui::MenuItem("Browse memory here")) { m_hex.GoTo(a); m_showHex = true; ImGui::SetWindowFocus(kWinHex); }
                    if (ImGui::MenuItem("Change value of selected..."))
                    {
                        m_editWatch = -2;
                        snprintf(m_editBuf, sizeof(m_editBuf), "%s", ok ? FormatValue(st.type, cur.data(), vs, false).c_str() : "");
                        m_openEditPopup = true;
                    }
                    if (ImGui::MenuItem("Copy address")) ImGui::SetClipboardText(ToHex(a).c_str());
                    ImGui::EndPopup();
                }
                ImGui::PopID();
                if (isStatic) ImGui::SetItemTooltip("Static address inside %s", m.name.c_str());

                ImGui::TableNextColumn();
                if (ok)
                {
                    bool changed = memcmp(cur.data(), prev, vs) != 0;
                    std::string v = FormatValue(st.type, cur.data(), vs, false);
                    if (changed) ImGui::TextColored(kColChanged, "%s", v.c_str());
                    else ImGui::TextUnformatted(v.c_str());
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
        int64_t n = std::abs(m_resSelB - m_resSelA) + 1;
        ImGui::Text("Set %lld selected result(s)", (long long)n);
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
            int64_t a0 = std::min(m_resSelA, m_resSelB), a1 = std::max(m_resSelA, m_resSelB);
            int fails = 0;
            for (int64_t k = std::max<int64_t>(a0, 0); k <= a1 && k < (int64_t)st.addresses.size(); k++)
                if (!m_proc.Write(st.addresses[k], pv.bytes.data(), pv.bytes.size())) fails++;
            if (fails) Log(std::to_string(fails) + " writes failed");
        }
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void App::DrawAddressList()
{
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
    ImGui::SameLine();
    ImGui::TextDisabled("%zu entries", m_watches.size());

    int removeIdx = -1, dupIdx = -1, moveFrom = -1, moveTo = -1;
    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                         ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable;
    if (ImGui::BeginTable("##watch", 6, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Freeze", ImGuiTableColumnFlags_WidthFixed, Px(50));
        ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.6f);
        ImGui::TableSetupColumn("Resolved", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, Px(130));
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)m_watches.size(); i++)
        {
            WatchEntry& w = m_watches[i];
            ImGui::PushID(i);
            ImGui::TableNextRow();

            size_t sz = WatchSize(w);
            std::vector<uint8_t> buf(sz);
            bool readOk = w.resolved && m_proc.ReadExact(w.address, buf.data(), sz);

            ImGui::TableNextColumn();
            if (ImGui::Checkbox("##frz", &w.frozen))
            {
                if (w.frozen && readOk)
                {
                    w.frozenBytes = buf;
                    if (w.type == ValueType::String) // freeze only up to the terminator
                    {
                        auto z = std::find(w.frozenBytes.begin(), w.frozenBytes.end(), 0);
                        if (z != w.frozenBytes.end()) w.frozenBytes.erase(z + 1, w.frozenBytes.end());
                    }
                }
                else if (w.frozen) w.frozen = false;
            }

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("##desc", &w.description);

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (m_mono) ImGui::PushFont(m_mono);
            if (!w.resolved) ImGui::PushStyleColor(ImGuiCol_Text, kColErr);
            ImGui::InputText("##expr", &w.expression);
            if (!w.resolved) ImGui::PopStyleColor();
            if (m_mono) ImGui::PopFont();
            if (!w.error.empty()) ImGui::SetItemTooltip("%s", w.error.c_str());

            ImGui::TableNextColumn();
            if (m_mono) ImGui::PushFont(m_mono);
            if (w.resolved) ImGui::TextDisabled("%s", AddrText(w.address).c_str());
            else ImGui::TextDisabled("-");
            if (m_mono) ImGui::PopFont();

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::BeginCombo("##type", ValueTypeName(w.type)))
            {
                for (int t = 0; t < (int)ValueType::Count; t++)
                    if (ImGui::Selectable(ValueTypeName((ValueType)t), (int)w.type == t))
                    {
                        w.type = (ValueType)t;
                        w.frozen = false;
                    }
                if (ValueTypeSize(w.type) == 0)
                {
                    ImGui::Separator();
                    ImGui::SetNextItemWidth(Px(100));
                    ImGui::InputInt("Length", &w.length);
                    w.length = std::clamp(w.length, 1, 4096);
                }
                ImGui::Checkbox("Show as hex", &w.hex);
                ImGui::EndCombo();
            }

            ImGui::TableNextColumn();
            if (m_mono) ImGui::PushFont(m_mono);
            std::string val = readOk ? FormatValue(w.type, buf.data(), sz, w.hex) : "??";
            if (w.frozen) ImGui::PushStyleColor(ImGuiCol_Text, kColAccent);
            if (ImGui::Selectable((val + "##val").c_str(), false, ImGuiSelectableFlags_AllowDoubleClick) &&
                ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && readOk)
            {
                m_editWatch = i;
                snprintf(m_editBuf, sizeof(m_editBuf), "%s", val.c_str());
                m_openEditPopup = true;
            }
            if (w.frozen) ImGui::PopStyleColor();
            if (m_mono) ImGui::PopFont();
            ImGui::SetItemTooltip("Double-click to change the value");

            if (ImGui::BeginPopupContextItem("##wctx"))
            {
                if (ImGui::MenuItem("Change value...", nullptr, false, readOk))
                {
                    m_editWatch = i;
                    snprintf(m_editBuf, sizeof(m_editBuf), "%s", val.c_str());
                    m_openEditPopup = true;
                }
                if (ImGui::MenuItem("Browse memory here", nullptr, false, w.resolved))
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
                if (ImGui::MenuItem("Decompile function here", nullptr, false, w.resolved))
                    StartDecompile(w.address);
                ImGui::Separator();
                if (ImGui::MenuItem("Copy address", nullptr, false, w.resolved)) ImGui::SetClipboardText(ToHex(w.address).c_str());
                if (ImGui::MenuItem("Copy value")) ImGui::SetClipboardText(val.c_str());
                ImGui::MenuItem("Show as hex", nullptr, &w.hex);
                if (ImGui::MenuItem("Dereference (wrap in [ ])")) w.expression = "[" + w.expression + "]";
                if (ImGui::MenuItem("Duplicate")) dupIdx = i;
                ImGui::Separator();
                if (ImGui::MenuItem("Move up", nullptr, false, i > 0)) { moveFrom = i; moveTo = i - 1; }
                if (ImGui::MenuItem("Move down", nullptr, false, i + 1 < (int)m_watches.size())) { moveFrom = i; moveTo = i + 1; }
                if (ImGui::MenuItem("Delete")) removeIdx = i;
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (dupIdx >= 0)
    {
        WatchEntry copy = m_watches[dupIdx];
        copy.frozen = false;
        m_watches.insert(m_watches.begin() + dupIdx + 1, std::move(copy));
    }
    if (removeIdx >= 0) m_watches.erase(m_watches.begin() + removeIdx);
    if (moveFrom >= 0) std::swap(m_watches[moveFrom], m_watches[moveTo]);
    ImGui::End();
}

// ---------------------------------------------------------------------------

void App::DrawRegions()
{
    if (!ImGui::Begin(kWinRegions, &m_showRegions))
    {
        ImGui::End();
        return;
    }
    if (!m_proc.IsOpen())
    {
        ImGui::TextDisabled("Not attached.");
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
                         ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##regions", 6, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, Px(150));
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, Px(90));
        ImGui::TableSetupColumn("Protect", ImGuiTableColumnFlags_WidthFixed, Px(70));
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, Px(65));
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, Px(65));
        ImGui::TableSetupColumn("Owner", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

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
                std::string prot = ProtectToString(r.protect);
                if (IsExecutable(r.protect) && IsWritable(r.protect)) ImGui::TextColored(kColChanged, "%s", prot.c_str());
                else if (IsExecutable(r.protect)) ImGui::TextColored(kColAccent, "%s", prot.c_str());
                else ImGui::TextUnformatted(prot.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(StateToString(r.state).c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(TypeToString(r.type).c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(rows[i].owner.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

void App::DrawModules()
{
    if (!ImGui::Begin(kWinModules, &m_showModules))
    {
        ImGui::End();
        return;
    }
    if (!m_proc.IsOpen())
    {
        ImGui::TextDisabled("Not attached.");
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
                         ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##mods", 4, tf))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, Px(180));
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, Px(150));
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, Px(90));
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int i = 0;
        for (const auto& m : mods)
        {
            if (!Contains(m.name, m_moduleFilter) && !Contains(m.path, m_moduleFilter)) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i++);
            if (ImGui::Selectable(m.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
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
    for (const auto& l : m_log) ImGui::TextUnformatted(l.c_str());
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
    int slot = m_tracer.Add(m_proc.Pid(), m_proc.Is64(), address, size, kind, err);
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
        if (!ImGui::Begin(title.c_str(), &t.open))
        {
            ImGui::End();
            continue;
        }

        std::vector<TraceHit> hits = m_tracer.Hits(t.slot);
        std::string err = m_tracer.Error();
        if (!err.empty()) ImGui::TextColored(kColErr, "%s", err.c_str());
        else if (m_tracer.Attached())
            ImGui::TextColored(kColOk, "Debugger attached - watching %d byte(s) at %s (DR%d)", t.size,
                               AddrText(t.address).c_str(), t.slot);
        else ImGui::TextDisabled("Starting debugger...");

        if (ImGui::Button("Clear")) m_tracer.Clear(t.slot);
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
                else ImGui::TextUnformatted(h.text.c_str());
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
            m_tracer.Remove(it->slot);
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
    ImGui::TextUnformatted(row.text.c_str());
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
            if (ImGui::Selectable(m_proc.Symbolize(r.address).c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
            {
                m_selectedInsn = r.address;
                snprintf(m_newImm, sizeof(m_newImm), "%llu", (unsigned long long)r.immediate);
                std::string hex = BytesToHex(r.bytes.data(), r.bytes.size());
                snprintf(m_newBytes, sizeof(m_newBytes), "%s", hex.c_str());
                m_patchStatus.clear();
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
            else ImGui::TextUnformatted(r.text.c_str());
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
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, Px(70));
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
        ImGui::EndTabBar();
    }
    ImGui::End();
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
