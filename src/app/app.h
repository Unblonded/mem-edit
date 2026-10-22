#pragma once
#include "code/decompiler.h"
#include "code/detour.h"
#include "ui/hexview.h"
#include "code/patches.h"
#include "scan/aobscan.h"
#include "scan/pointerscan.h"
#include "core/target.h"
#include "scan/scanner.h"
#include "ui/selection.h"
#include "code/tracer.h"
#include "code/vehtracer.h"
#include "core/values.h"

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
    bool selected = false; // row selection in the address list; follows the entry when sorted
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
    void DrawOpcodes();
    void DrawPointerScan();
    void OpenPointerScan(uint64_t target);
    void OpenOpcodes(const std::string& query); // Opcodes window searching for `query`
    void DrawDetourMenu(uint64_t address);   // right-click "Detour this function" items
    void OpenDetours(uint64_t entry);        // Decompile window, Detours tab, entry selected
    void InstallCaveAt(uint64_t entry);      // one-click trampoline with the recommended size
    void DrawAobScan();
    void DrawAobScanTab();
    void DrawSigMakerTab();
    void DrawSigListTab();
    void StartAobScan();
    AobScanOptions AobOptions() const;
    void OpenAobScan(const std::string& pattern, bool run); // show the AOB window with a pattern
    void OpenSigMaker(uint64_t address);                     // "Make AOB signature here"
    void SaveSigList();
    void LoadSigList();
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
    RowSelection m_resSel;   // scan results (Ctrl/Shift multi-select)
    int m_watchAnchor = -1;  // address list: last clicked row, for Shift ranges

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

    // Access tracing (hardware breakpoints). Two interchangeable backends: the Windows debugger and
    // the injected VEH debugger; m_debuggerMode picks which Dbg() returns.
    AccessTracer m_tracer;
    VehTracer m_veh;
    int m_debuggerMode = 0; // 0 = Windows debugger, 1 = VEH (injected)
    ITracer* Dbg() { return m_debuggerMode == 1 ? (ITracer*)&m_veh : (ITracer*)&m_tracer; }
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
    int m_decompileTabRequest = -1;  // select this Decompile tab on the next frame (3 = Detours)
    bool m_focusDetourTarget = false; // put the cursor in "redirect to" when the Detours tab opens

    // Pointer scan
    PointerScanner m_ptrScan;
    PointerScanOptions m_ptrOpts;
    bool m_showPtrScan = false;
    char m_ptrTarget[64] = "";
    char m_ptrMaxOffset[16] = "800";
    int m_ptrMaxDepth = 4;
    bool m_ptrAllowNeg = false;
    char m_ptrNewTarget[64] = "";   // "rescan after restart" target
    std::string m_ptrStatus;
    std::vector<char> m_ptrSelected; // per-result selection flag (index-aligned to results)
    std::vector<int> m_ptrOrder;     // display order (sorted) into results
    int m_ptrAnchor = -1;            // last-clicked display row, for shift-range select

    // AOB (array of bytes) scan, signature maker and signature list
    AobScanner m_aob;
    bool m_showAob = false;
    int m_aobTabRequest = -1;            // switch to this tab on the next frame
    char m_aobPattern[2048] = "";
    int m_aobScope = 0;                  // 0 = all memory, otherwise index+1 into m_aobModules
    std::vector<ModuleInfo> m_aobModules;
    bool m_aobExecOnly = true;
    bool m_aobWritableOnly = false;
    bool m_aobIncludeMapped = false;
    RowSelection m_aobSel;
    std::string m_aobStatus;
    char m_sigAddress[128] = "";
    SigMakerOptions m_sigOpts;
    SigMakerResult m_sigResult;
    bool m_sigHave = false;
    uint64_t m_sigAt = 0;                // address the current signature was made for
    double m_sigMs = 0;
    struct SigEntry
    {
        std::string name;
        std::string pattern;
        bool scanned = false;
        size_t matches = 0;
        uint64_t first = 0;
        std::string error;
    };
    std::vector<SigEntry> m_sigList;
    char m_sigNewName[64] = "";
    char m_sigNewPattern[1024] = "";

    // Hex calculator
    bool m_showCalc = false;
    bool m_showOpcodes = false;
    char m_opcSearch[128] = "";
    int m_opcCategory = 0;        // 0 = all, otherwise index+1 into OpcodeCategories()
    int m_opcSelected = 0;        // index into OpcodeReference()
    bool m_opcPickBest = false;   // select the top hit after the search changes
    bool m_opcFocusSearch = false;
    bool m_calcHex = true;
    int m_calcOp = 0;
    char m_calcA[40] = "0";
    char m_calcB[40] = "0";
};
