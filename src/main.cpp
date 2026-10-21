// Memory Browser - Dear ImGui + DirectX 11 front end.
#include "app.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include <d3d11.h>
#include <dwmapi.h>
#include <windows.h>

#pragma comment(lib, "dwmapi.lib")
#include <algorithm>
#include <cstring>
#include <string>

static ID3D11Device* g_device = nullptr;
static ID3D11DeviceContext* g_context = nullptr;
static IDXGISwapChain* g_swapChain = nullptr;
static bool g_swapChainOccluded = false;
static UINT g_resizeWidth = 0, g_resizeHeight = 0;
static ID3D11RenderTargetView* g_rtv = nullptr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void CreateRenderTarget()
{
    ID3D11Texture2D* back = nullptr;
    g_swapChain->GetBuffer(0, IID_PPV_ARGS(&back));
    g_device->CreateRenderTargetView(back, nullptr, &g_rtv);
    back->Release();
}

static void CleanupRenderTarget()
{
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

static bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL got;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
                                               D3D11_SDK_VERSION, &sd, &g_swapChain, &g_device, &got, &g_context);
    if (hr == DXGI_ERROR_UNSUPPORTED) // no GPU: fall back to WARP
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION,
                                           &sd, &g_swapChain, &g_device, &got, &g_context);
    if (hr != S_OK) return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_swapChain) { g_swapChain->Release(); g_swapChain = nullptr; }
    if (g_context) { g_context->Release(); g_context = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_resizeWidth = (UINT)LOWORD(lParam);
        g_resizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0; // disable ALT application menu
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// Modern dark theme: a cohesive near-neutral palette with a single vivid accent,
// generous spacing, soft rounding and thin rounded scrollbars.
static void ApplyTheme(float scale)
{
    ImGuiStyle& s = ImGui::GetStyle();
    ImGui::StyleColorsDark();

    // Shape
    s.WindowRounding = 9.f;
    s.ChildRounding = 8.f;
    s.FrameRounding = 7.f;
    s.PopupRounding = 8.f;
    s.ScrollbarRounding = 10.f;
    s.GrabRounding = 7.f;
    s.TabRounding = 7.f;

    // Spacing - roomier and more even, for a calmer, less cramped layout.
    s.WindowPadding = ImVec2(14, 12);
    s.FramePadding = ImVec2(11, 6);
    s.ItemSpacing = ImVec2(10, 8);
    s.ItemInnerSpacing = ImVec2(8, 6);
    s.CellPadding = ImVec2(8, 5);
    s.IndentSpacing = 22.f;
    s.ScrollbarSize = 13.f;
    s.GrabMinSize = 11.f;

    // Borders - hairline, used sparingly for depth.
    s.WindowBorderSize = 1.f;
    s.ChildBorderSize = 1.f;
    s.FrameBorderSize = 0.f;
    s.PopupBorderSize = 1.f;
    s.TabBarBorderSize = 2.f;
    s.SeparatorTextBorderSize = 2.f;
    s.DockingSeparatorSize = 2.f;

    // Alignment
    s.WindowTitleAlign = ImVec2(0.0f, 0.5f);
    s.WindowMenuButtonPosition = ImGuiDir_None;
    s.ButtonTextAlign = ImVec2(0.5f, 0.5f);

    // Palette ------------------------------------------------------------
    auto rgb = [](int r, int g, int b, float a = 1.f) {
        return ImVec4(r / 255.f, g / 255.f, b / 255.f, a);
    };
    const ImVec4 base    = rgb(13, 15, 20);    // app backdrop / docking space
    const ImVec4 surface = rgb(20, 23, 30);    // window body
    const ImVec4 raised  = rgb(27, 31, 40);    // inputs, buttons, table header
    const ImVec4 raised2 = rgb(35, 40, 51);    // hovered input
    const ImVec4 raised3 = rgb(44, 50, 64);    // active input
    const ImVec4 line    = rgb(45, 51, 64);    // borders / separators
    const ImVec4 text    = rgb(226, 230, 240);
    const ImVec4 textDim = rgb(120, 128, 146);
    const ImVec4 accent  = rgb(88, 140, 251);  // vivid indigo-blue
    const ImVec4 accentHi= rgb(120, 165, 255);
    auto A = [](ImVec4 col, float a) { col.w = a; return col; };

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = text;
    c[ImGuiCol_TextDisabled] = textDim;
    c[ImGuiCol_WindowBg] = surface;
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg] = rgb(23, 26, 34, 0.99f);
    c[ImGuiCol_Border] = A(line, 0.70f);
    c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = raised;
    c[ImGuiCol_FrameBgHovered] = raised2;
    c[ImGuiCol_FrameBgActive] = raised3;
    c[ImGuiCol_TitleBg] = base;
    c[ImGuiCol_TitleBgActive] = base;
    c[ImGuiCol_TitleBgCollapsed] = base;
    c[ImGuiCol_MenuBarBg] = base;
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = A(rgb(70, 78, 96), 0.75f);
    c[ImGuiCol_ScrollbarGrabHovered] = A(rgb(92, 102, 124), 0.9f);
    c[ImGuiCol_ScrollbarGrabActive] = accent;
    c[ImGuiCol_CheckMark] = accentHi;
    c[ImGuiCol_SliderGrab] = accent;
    c[ImGuiCol_SliderGrabActive] = accentHi;
    c[ImGuiCol_Button] = A(raised, 0.0f);          // flat by default
    c[ImGuiCol_ButtonHovered] = A(accent, 0.22f);
    c[ImGuiCol_ButtonActive] = A(accent, 0.38f);
    c[ImGuiCol_Header] = A(accent, 0.22f);
    c[ImGuiCol_HeaderHovered] = A(accent, 0.34f);
    c[ImGuiCol_HeaderActive] = A(accent, 0.48f);
    c[ImGuiCol_Separator] = A(line, 0.60f);
    c[ImGuiCol_SeparatorHovered] = A(accent, 0.6f);
    c[ImGuiCol_SeparatorActive] = accent;
    c[ImGuiCol_ResizeGrip] = A(rgb(70, 78, 96), 0.0f);
    c[ImGuiCol_ResizeGripHovered] = A(accent, 0.5f);
    c[ImGuiCol_ResizeGripActive] = A(accent, 0.8f);
    c[ImGuiCol_Tab] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabHovered] = A(accent, 0.28f);
    c[ImGuiCol_TabSelected] = A(accent, 0.16f);
    c[ImGuiCol_TabSelectedOverline] = accent;
    c[ImGuiCol_TabDimmed] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabDimmedSelected] = A(raised, 0.6f);
    c[ImGuiCol_TabDimmedSelectedOverline] = A(accent, 0.4f);
    c[ImGuiCol_DockingPreview] = A(accent, 0.45f);
    c[ImGuiCol_DockingEmptyBg] = base;
    c[ImGuiCol_TableHeaderBg] = raised;
    c[ImGuiCol_TableBorderStrong] = A(line, 0.6f);
    c[ImGuiCol_TableBorderLight] = A(line, 0.32f);
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.022f);
    c[ImGuiCol_TextSelectedBg] = A(accent, 0.35f);
    c[ImGuiCol_DragDropTarget] = accentHi;
    c[ImGuiCol_PlotHistogram] = accent;
    c[ImGuiCol_PlotHistogramHovered] = accentHi;
    c[ImGuiCol_PlotLines] = accentHi;
    c[ImGuiCol_NavCursor] = accent;
    c[ImGuiCol_NavWindowingHighlight] = accentHi;
    c[ImGuiCol_NavWindowingDimBg] = ImVec4(0.02f, 0.02f, 0.03f, 0.55f);
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0.02f, 0.02f, 0.03f, 0.55f);

    s.ScaleAllSizes(scale);
    s.HoverStationaryDelay = 0.25f;
    s.Colors[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int)
{
    ImGui_ImplWin32_EnableDpiAwareness();
    float dpi = ImGui_ImplWin32_GetDpiScaleForMonitor(MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW wc{ sizeof(wc), CS_CLASSDC, WndProc, 0, 0, hInstance, LoadIconW(nullptr, IDI_APPLICATION),
                    LoadCursorW(nullptr, IDC_ARROW), nullptr, nullptr, L"MemoryBrowserClass", nullptr };
    RegisterClassExW(&wc);
    // Fit the window inside the primary monitor's work area and center it.
    RECT work{ 0, 0, 1920, 1080 };
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    int workW = work.right - work.left, workH = work.bottom - work.top;
    int winW = (int)std::min(1600 * dpi, workW * 0.92f), winH = (int)std::min(950 * dpi, workH * 0.92f);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Memory Browser", WS_OVERLAPPEDWINDOW, work.left + (workW - winW) / 2,
                              work.top + (workH - winH) / 2, winW, winH, nullptr, nullptr, wc.hInstance, nullptr);

    // Dark title bar that matches the interface (Windows 10 20H1+ / 11; ignored on older builds).
    BOOL darkTitle = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkTitle, sizeof(darkTitle));
    COLORREF captionColor = RGB(13, 15, 20);
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));
    COLORREF textColor = RGB(226, 230, 240);
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &textColor, sizeof(textColor));
    // Rounded window corners on Windows 11.
    DWM_WINDOW_CORNER_PREFERENCE corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        MessageBoxW(nullptr, L"Failed to create a Direct3D 11 device.", L"Memory Browser", MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
    io.IniFilename = "memory_browser.ini";

    ApplyTheme(dpi);

    // Fonts: Segoe UI for the interface, Cascadia Code / Consolas for addresses and hex.
    // Oversampling keeps text crisp at fractional DPI scales.
    ImFont* uiFont = nullptr;
    ImFont* monoFont = nullptr;
    const float uiSize = 16.f * dpi, monoSize = 15.f * dpi;

    ImFontConfig ui;
    ui.OversampleH = 3;
    ui.OversampleV = 2;
    ui.PixelSnapH = false;
    ui.RasterizerMultiply = 1.08f; // a touch heavier so light text reads well on dark
    if (GetFileAttributesW(L"C:\\Windows\\Fonts\\segoeui.ttf") != INVALID_FILE_ATTRIBUTES)
        uiFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", uiSize, &ui);
    if (!uiFont)
    {
        ImFontConfig cfg;
        cfg.SizePixels = 13.f * dpi;
        uiFont = io.Fonts->AddFontDefault(&cfg);
    }

    ImFontConfig mono;
    mono.OversampleH = 3;
    mono.OversampleV = 2;
    mono.RasterizerMultiply = 1.05f;
    const char* monoPaths[] = { "C:\\Windows\\Fonts\\CascadiaCode.ttf", "C:\\Windows\\Fonts\\CascadiaMono.ttf",
                                "C:\\Windows\\Fonts\\consola.ttf" };
    for (const char* path : monoPaths)
    {
        std::wstring w(path, path + strlen(path));
        if (GetFileAttributesW(w.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            monoFont = io.Fonts->AddFontFromFileTTF(path, monoSize, &mono);
            if (monoFont) break;
        }
    }
    if (!monoFont)
    {
        ImFontConfig cfg;
        cfg.SizePixels = 13.f * dpi;
        monoFont = io.Fonts->AddFontDefault(&cfg);
    }

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);

    App app;
    app.Init(hwnd, uiFont, monoFont);

    const float clear[4] = { 0.051f, 0.059f, 0.078f, 1.f };
    bool done = false;
    while (!done)
    {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (g_swapChainOccluded && g_swapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            Sleep(10);
            continue;
        }
        g_swapChainOccluded = false;

        if (g_resizeWidth != 0 && g_resizeHeight != 0)
        {
            CleanupRenderTarget();
            g_swapChain->ResizeBuffers(0, g_resizeWidth, g_resizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_resizeWidth = g_resizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        app.Frame();
        if (app.WantsQuit()) PostMessageW(hwnd, WM_CLOSE, 0, 0);

        ImGui::Render();
        g_context->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_context->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT hr = g_swapChain->Present(1, 0); // vsync
        g_swapChainOccluded = hr == DXGI_STATUS_OCCLUDED;
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}
