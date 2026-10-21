// Memory Browser - Dear ImGui + DirectX 11 front end.
#include "app.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "glass.h"

#include <d3d11.h>
#include <dcomp.h>
#include <dwmapi.h>
#include <dxgi1_2.h>
#include <windows.h>

#pragma comment(lib, "dcomp.lib")
#pragma comment(lib, "dwmapi.lib")
#include <algorithm>
#include <cstring>
#include <string>

static ID3D11Device* g_device = nullptr;
static ID3D11DeviceContext* g_context = nullptr;
static IDXGISwapChain1* g_swapChain = nullptr;
static bool g_swapChainOccluded = false;
static UINT g_resizeWidth = 0, g_resizeHeight = 0;
static ID3D11RenderTargetView* g_rtv = nullptr;

// Glass mode: a premultiplied-alpha swap chain presented through DirectComposition,
// so the Windows 11 acrylic backdrop shows through wherever the UI is translucent.
static bool g_glass = false;
static IDCompositionDevice* g_dcomp = nullptr;
static IDCompositionTarget* g_dcompTarget = nullptr;
static IDCompositionVisual* g_dcompVisual = nullptr;

template <class T> static void SafeRelease(T*& p)
{
    if (p) { p->Release(); p = nullptr; }
}

// The system backdrop attribute needs Windows 11 22H2 (build 22621).
static bool SupportsSystemBackdrop()
{
    using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
    auto rtlGetVersion = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    OSVERSIONINFOW v{ sizeof(v) };
    return rtlGetVersion && rtlGetVersion(&v) == 0 && v.dwBuildNumber >= 22621;
}

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

static bool CreateCompositionSwapChain(HWND hWnd, IDXGIFactory2* factory, IDXGIDevice* dxgiDevice,
                                       const DXGI_SWAP_CHAIN_DESC1& desc)
{
    DXGI_SWAP_CHAIN_DESC1 sd = desc;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    sd.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;
    if (FAILED(factory->CreateSwapChainForComposition(g_device, &sd, nullptr, &g_swapChain))) return false;
    if (SUCCEEDED(DCompositionCreateDevice(dxgiDevice, IID_PPV_ARGS(&g_dcomp))) &&
        SUCCEEDED(g_dcomp->CreateTargetForHwnd(hWnd, TRUE, &g_dcompTarget)) &&
        SUCCEEDED(g_dcomp->CreateVisual(&g_dcompVisual)) && SUCCEEDED(g_dcompVisual->SetContent(g_swapChain)) &&
        SUCCEEDED(g_dcompTarget->SetRoot(g_dcompVisual)) && SUCCEEDED(g_dcomp->Commit()))
        return true;
    SafeRelease(g_dcompVisual);
    SafeRelease(g_dcompTarget);
    SafeRelease(g_dcomp);
    SafeRelease(g_swapChain);
    return false;
}

static bool CreateDeviceD3D(HWND hWnd, bool wantGlass)
{
    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    const UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT; // required by DirectComposition
    D3D_FEATURE_LEVEL got;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags, levels, 2, D3D11_SDK_VERSION,
                                   &g_device, &got, &g_context);
    if (FAILED(hr)) // no GPU: fall back to WARP
        hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, flags, levels, 2, D3D11_SDK_VERSION, &g_device,
                               &got, &g_context);
    if (FAILED(hr)) return false;

    IDXGIDevice* dxgiDevice = nullptr;
    IDXGIAdapter* adapter = nullptr;
    IDXGIFactory2* factory = nullptr;
    g_device->QueryInterface(IID_PPV_ARGS(&dxgiDevice));
    if (dxgiDevice) dxgiDevice->GetAdapter(&adapter);
    if (adapter) adapter->GetParent(IID_PPV_ARGS(&factory));

    RECT rc;
    GetClientRect(hWnd, &rc);
    DXGI_SWAP_CHAIN_DESC1 sd{};
    sd.Width = (UINT)std::max<LONG>(1, rc.right - rc.left);
    sd.Height = (UINT)std::max<LONG>(1, rc.bottom - rc.top);
    sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.Scaling = DXGI_SCALING_STRETCH;

    g_glass = factory && wantGlass && CreateCompositionSwapChain(hWnd, factory, dxgiDevice, sd);
    if (factory && !g_glass)
    {
        sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        sd.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        factory->CreateSwapChainForHwnd(g_device, hWnd, &sd, nullptr, nullptr, &g_swapChain);
    }
    SafeRelease(factory);
    SafeRelease(adapter);
    SafeRelease(dxgiDevice);
    if (!g_swapChain) return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    SafeRelease(g_dcompVisual);
    SafeRelease(g_dcompTarget);
    SafeRelease(g_dcomp);
    SafeRelease(g_swapChain);
    SafeRelease(g_context);
    SafeRelease(g_device);
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

// Liquid-glass theme: translucent tinted panes over the backdrop, hairline white
// borders, frosted inputs, generous rounding and a duotone ink / steel-blue palette.
static void ApplyTheme(float scale)
{
    ImGuiStyle& s = ImGui::GetStyle();
    ImGui::StyleColorsDark();

    // Shape
    s.WindowRounding = 14.f;
    s.ChildRounding = 11.f;
    s.FrameRounding = 9.f;
    s.PopupRounding = 12.f;
    s.ScrollbarRounding = 12.f;
    s.GrabRounding = 9.f;
    s.TabRounding = 9.f;

    // Spacing
    s.WindowPadding = ImVec2(14, 12);
    s.FramePadding = ImVec2(11, 6);
    s.ItemSpacing = ImVec2(10, 8);
    s.ItemInnerSpacing = ImVec2(8, 6);
    s.CellPadding = ImVec2(8, 5);
    s.IndentSpacing = 22.f;
    s.ScrollbarSize = 11.f;
    s.GrabMinSize = 11.f;

    // Borders - hairlines that catch the light like a glass edge.
    s.WindowBorderSize = 1.f;
    s.ChildBorderSize = 1.f;
    s.FrameBorderSize = 1.f;
    s.PopupBorderSize = 1.f;
    s.TabBorderSize = 0.f;
    s.TabBarBorderSize = 1.f;
    s.TabBarOverlineSize = 2.f;
    s.SeparatorTextBorderSize = 1.f;
    s.DockingSeparatorSize = 5.f; // gaps between docked panes let the backdrop through

    // Alignment
    s.WindowTitleAlign = ImVec2(0.0f, 0.5f);
    s.WindowMenuButtonPosition = ImGuiDir_None;
    s.ButtonTextAlign = ImVec2(0.5f, 0.5f);

    // Palette ------------------------------------------------------------
    auto rgb = [](int r, int g, int b, float a = 1.f) {
        return ImVec4(r / 255.f, g / 255.f, b / 255.f, a);
    };
    auto white = [](float a) { return ImVec4(1, 1, 1, a); };
    auto A = [](ImVec4 col, float a) { col.w = a; return col; };
    const ImVec4 tint    = rgb(16, 20, 34);     // the glass's own colour
    const ImVec4 text    = rgb(236, 240, 250);
    const ImVec4 textDim = rgb(140, 150, 175);
    const ImVec4 accent  = Glass::kAccent;
    const ImVec4 accentHi= Glass::kAccentHi;
    const ImVec4 deep    = Glass::kAccentDeep;

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = text;
    c[ImGuiCol_TextDisabled] = textDim;
    c[ImGuiCol_WindowBg] = A(tint, 0.48f);
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg] = rgb(20, 24, 40, 0.94f);
    c[ImGuiCol_Border] = white(0.10f);
    c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = white(0.055f);
    c[ImGuiCol_FrameBgHovered] = white(0.09f);
    c[ImGuiCol_FrameBgActive] = A(accent, 0.18f);
    c[ImGuiCol_TitleBg] = A(tint, 0.35f);
    c[ImGuiCol_TitleBgActive] = A(tint, 0.50f);
    c[ImGuiCol_TitleBgCollapsed] = A(tint, 0.35f);
    c[ImGuiCol_MenuBarBg] = A(tint, 0.30f);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = white(0.14f);
    c[ImGuiCol_ScrollbarGrabHovered] = white(0.24f);
    c[ImGuiCol_ScrollbarGrabActive] = A(accent, 0.85f);
    c[ImGuiCol_CheckMark] = accentHi;
    c[ImGuiCol_SliderGrab] = accent;
    c[ImGuiCol_SliderGrabActive] = accentHi;
    c[ImGuiCol_Button] = white(0.07f);
    c[ImGuiCol_ButtonHovered] = A(accent, 0.32f);
    c[ImGuiCol_ButtonActive] = A(deep, 0.45f);
    c[ImGuiCol_Header] = A(accent, 0.20f);
    c[ImGuiCol_HeaderHovered] = A(accent, 0.30f);
    c[ImGuiCol_HeaderActive] = A(deep, 0.40f);
    c[ImGuiCol_Separator] = white(0.09f);
    c[ImGuiCol_SeparatorHovered] = A(accent, 0.6f);
    c[ImGuiCol_SeparatorActive] = accent;
    c[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ResizeGripHovered] = A(accent, 0.5f);
    c[ImGuiCol_ResizeGripActive] = A(accent, 0.8f);
    c[ImGuiCol_Tab] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabHovered] = white(0.10f);
    c[ImGuiCol_TabSelected] = white(0.09f);
    c[ImGuiCol_TabSelectedOverline] = accent;
    c[ImGuiCol_TabDimmed] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabDimmedSelected] = white(0.05f);
    c[ImGuiCol_TabDimmedSelectedOverline] = A(accent, 0.35f);
    c[ImGuiCol_DockingPreview] = A(accent, 0.40f);
    c[ImGuiCol_DockingEmptyBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableHeaderBg] = white(0.05f);
    c[ImGuiCol_TableBorderStrong] = white(0.09f);
    c[ImGuiCol_TableBorderLight] = white(0.05f);
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = white(0.025f);
    c[ImGuiCol_TextLink] = accentHi;
    c[ImGuiCol_TextSelectedBg] = A(accent, 0.35f);
    c[ImGuiCol_DragDropTarget] = accentHi;
    c[ImGuiCol_PlotHistogram] = accent;
    c[ImGuiCol_PlotHistogramHovered] = accentHi;
    c[ImGuiCol_PlotLines] = accentHi;
    c[ImGuiCol_NavCursor] = accent;
    c[ImGuiCol_NavWindowingHighlight] = accentHi;
    c[ImGuiCol_NavWindowingDimBg] = rgb(4, 6, 14, 0.45f);
    c[ImGuiCol_ModalWindowDimBg] = rgb(4, 6, 14, 0.45f);

    s.ScaleAllSizes(scale);
    s.HoverStationaryDelay = 0.25f;
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
    // Without a redirection bitmap the window's pixels come only from DirectComposition.
    const bool wantGlass = SupportsSystemBackdrop();
    HWND hwnd = CreateWindowExW(wantGlass ? WS_EX_NOREDIRECTIONBITMAP : 0, wc.lpszClassName, L"Memory Browser",
                                WS_OVERLAPPEDWINDOW, work.left + (workW - winW) / 2, work.top + (workH - winH) / 2, winW,
                                winH, nullptr, nullptr, wc.hInstance, nullptr);

    // Dark title bar that matches the interface (Windows 10 20H1+ / 11; ignored on older builds).
    BOOL darkTitle = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkTitle, sizeof(darkTitle));
    // Rounded window corners on Windows 11.
    DWM_WINDOW_CORNER_PREFERENCE corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));

    if (!CreateDeviceD3D(hwnd, wantGlass))
    {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        MessageBoxW(nullptr, L"Failed to create a Direct3D 11 device.", L"Memory Browser", MB_ICONERROR);
        return 1;
    }
    if (g_glass)
    {
        // Acrylic blur of whatever is behind the window, across caption and client area.
        MARGINS margins{ -1, -1, -1, -1 };
        DwmExtendFrameIntoClientArea(hwnd, &margins);
        const DWORD kSystemBackdropType = 38, kBackdropAcrylic = 3; // DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_TRANSIENTWINDOW
        DwmSetWindowAttribute(hwnd, kSystemBackdropType, &kBackdropAcrylic, sizeof(kBackdropAcrylic));
    }
    else
    {
        COLORREF captionColor = RGB(10, 12, 22);
        DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));
        COLORREF textColor = RGB(236, 240, 250);
        DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &textColor, sizeof(textColor));
    }
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    // Viewports let panels be dragged out of the main window into their own OS windows.
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable | ImGuiConfigFlags_ViewportsEnable;
    io.ConfigViewportsNoTaskBarIcon = true;
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

    // Panels torn out into their own windows get Windows 11 rounded corners and a soft shadow.
    static void (*createPlatformWindow)(ImGuiViewport*) = nullptr;
    ImGuiPlatformIO& pio = ImGui::GetPlatformIO();
    createPlatformWindow = pio.Platform_CreateWindow;
    pio.Platform_CreateWindow = [](ImGuiViewport* vp) {
        createPlatformWindow(vp);
        HWND h = (HWND)vp->PlatformHandleRaw;
        if (!h) return;
        BOOL dark = TRUE;
        DwmSetWindowAttribute(h, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
        DWM_WINDOW_CORNER_PREFERENCE round = DWMWCP_ROUND;
        DwmSetWindowAttribute(h, DWMWA_WINDOW_CORNER_PREFERENCE, &round, sizeof(round));
    };

    App app;
    app.Init(hwnd, uiFont, monoFont);

    // Glass: a premultiplied, partly transparent tint over the acrylic. Otherwise opaque.
    const float glassAlpha = 0.42f;
    const float clearGlass[4] = { 0.035f * glassAlpha, 0.043f * glassAlpha, 0.085f * glassAlpha, glassAlpha };
    const float clearSolid[4] = { 0.035f, 0.043f, 0.085f, 1.f };
    const float* clear = g_glass ? clearGlass : clearSolid;
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

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

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
