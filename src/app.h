#pragma once
#include "decompiler.h"
#include "detour.h"
#include "hexview.h"
#include "patches.h"
#include "target.h"
#include "scanner.h"
#include "tracer.h"
#include "values.h"

#include <map>
#include <string>
#include <vector>

struct ImFont;

struct WatchEntry
{
    std::string description = "No description";
    std::string expression;
    ValueType type = ValueType::Int32;
    int length = 32;          // for strings / byte arrays
    bool hex = false;
    bool frozen = false;
    std::vector<uint8_t> frozenBytes;

    // Runtime
    uint64_t address = 0;
    bool resolved = false;
    std::string error;
};

// One "find out what writes/accesses this address" window.
struct TraceWindow
{
    int slot = -1;
    TraceKind kind = TraceKind::Writes;
    uint64_t address = 0;
    int size = 4;
    std::string label;
    bool open = true;
    uint64_t selected = 0; // instruction address of the selected row
};

class App
{
public:
    void Init(void* hwnd, ImFont* uiFont, ImFont* monoFont);
    void Frame();
    bool WantsQuit() const { return m_quit; }

private:
    void DrawMenuBar();
    void DrawStatusBar();
    void DrawProcessPicker();
    void DrawScanner();
    void DrawResults();
    void DrawAddressList();
    void DrawRegions();
    void DrawModules();
    void DrawLog();
    void DrawAbout();
    void DrawEditValuePopup();
    void DrawTraceWindows();
    void StartTrace(uint64_t address, int size, TraceKind kind);
    void DrawDecompile();
    void DrawCalculator();
    void StartDecompile(uint64_t address);
    void RunDecompile();
    void DrawDisasm();
    void DrawPatchPanel(const InstructionRow& row);
    void DrawActivePatches();
    void DrawDetours();
    int RecommendCaveBytes() const; // free-byte suggestion sized to the selected instruction
    void SetupDefaultLayout(unsigned int dockId);

    void Attach(DWORD pid);
    void Detach();
    void UpdateWatches();
    void AddWatch(uint64_t address, ValueType type, int length = 32);
    void SaveTable();
    void LoadTable();
    void DumpMemory(uint64_t base, uint64_t size, const std::string& suggestedName);
    void Log(const std::string& msg);
    std::string AddrText(uint64_t a) const;

    void* m_hwnd = nullptr;
    ImFont* m_mono = nullptr;
    bool m_quit = false;
    bool m_layoutInit = false;
    bool m_forceLayout = false;
    bool m_elevated = false;

    Process m_proc;
    Scanner m_scanner;
    HexView m_hex;

    // Windows
    bool m_showScanner = true, m_showResults = true, m_showHex = true, m_showWatch = true;
    bool m_showRegions = true, m_showModules = true, m_showLog = true, m_showAbout = false;
    bool m_openPicker = false;

    // Process picker
    std::vector<ProcessInfo> m_procList;
    char m_procFilter[128] = "";
    bool m_hideInaccessible = true;

    // Scanner UI
    ScanOptions m_opts;
    char m_value1[512] = "";
    char m_value2[512] = "";
    char m_rangeStart[32] = "0";
    char m_rangeEnd[32] = "7FFFFFFFFFFF";
    std::string m_scanError;

    // Results
    int64_t m_resSelA = -1, m_resSelB = -1;

    // Address list
    std::vector<WatchEntry> m_watches;
    int m_editWatch = -1;
    char m_editBuf[512] = "";
    bool m_openEditPopup = false;

    // Regions / modules
    std::vector<RegionInfo> m_regions;
    char m_regionFilter[64] = "";
    bool m_regionsCommittedOnly = true;
    double m_regionsRefreshed = -100;
    char m_moduleFilter[64] = "";

    std::vector<std::string> m_log;
    bool m_logScroll = false;

    // Access tracing (hardware breakpoints)
    AccessTracer m_tracer;
    std::vector<TraceWindow> m_traces;
    std::map<uint64_t, std::vector<uint8_t>> m_patches; // instruction address -> original bytes

    // Decompile view
    bool m_showDecompile = false;
    char m_decompileExpr[256] = "";
    std::string m_decompileText;
    std::string m_decompileError;
    uint64_t m_decompileEntry = 0;
    std::vector<InstructionRow> m_instructions;
    uint64_t m_selectedInsn = 0;
    bool m_scrollToSelected = false;
    char m_newImm[64] = "";
    char m_newBytes[128] = "";
    std::string m_patchStatus;
    PatchManager m_patchmgr;

    // Detours
    DetourManager m_detours;
    char m_detourTarget[256] = "";
    int m_caveUserBytes = 32;
    uint64_t m_caveRecForInsn = 0; // which instruction m_caveUserBytes was auto-sized for
    char m_caveImmInput[32] = "";  // new value to write into a cave's immediate instruction
    std::string m_detourStatus;

    // Hex calculator
    bool m_showCalc = false;
    bool m_calcHex = true;
    int m_calcOp = 0;
    char m_calcA[40] = "0";
    char m_calcB[40] = "0";
};
