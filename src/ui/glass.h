#pragma once
#include "imgui.h"

// "Liquid glass" look: a slowly drifting colour field behind the interface, and
// specular rims plus a soft top sheen on every panel so translucent windows read
// as panes of glass over it.
namespace Glass
{
// Duotone: deep ink plus a single pale steel-blue tone, in three strengths.
// Shared by the theme and custom-drawn widgets.
inline const ImVec4 kInk(0.055f, 0.066f, 0.100f, 1.0f);
inline const ImVec4 kAccent(0.56f, 0.67f, 0.86f, 1.0f);
inline const ImVec4 kAccentHi(0.78f, 0.85f, 0.97f, 1.0f);
inline const ImVec4 kAccentDeep(0.33f, 0.41f, 0.58f, 1.0f);

// Soft radial falloff: `col` at the centre easing out to transparent at `radius`.
void Glow(ImDrawList* dl, ImVec2 center, float radius, ImVec4 col);

// Per-monitor DPI. Fonts are rasterised once at the highest DPI of any monitor (`atlasDpi`) and the
// style is designed at the main window's DPI; call after ApplyTheme and the font setup.
void InitDpi(float mainDpi, float atlasDpi);
// Call right before ImGui::Begin(name). Scales style and fonts to the monitor the window was on last
// frame, so a panel dragged to a screen with a different DPI keeps the same physical size. A window
// floating over other panes (not docked) also gets a near-opaque background; docked panes keep the glass.
void PrepareWindow(const char* name);
// Back to the main window's scale, for things not tied to one window (modal popups, end of frame).
void PrepareMain();
// A font's pixel size at the current scale (use instead of font->FontSize).
float FontPx(const ImFont* font);

// Call once per frame before any windows are submitted.
void DrawBackdrop();
// Call after every window has been submitted, before ImGui::Render().
void DecorateWindows();

// Extra faces loaded next to the regular UI font. Any of them may be null (fallback: current font).
struct Fonts
{
    ImFont* bold = nullptr;      // semibold UI text, icons merged
    ImFont* title = nullptr;     // larger semibold for headings
    ImFont* iconLarge = nullptr; // Segoe Fluent Icons alone, for empty-state art
};
Fonts& GetFonts();

// The brand mark (same design as res/app.ico): a RAM stick on a dark glass tile, `size` square.
void RamLogo(ImDrawList* dl, ImVec2 p0, float size);

// Filled steel-blue button for a panel's primary action. Honours BeginDisabled().
bool AccentButton(const char* label, const ImVec2& size = ImVec2(0, 0));

// Centred placeholder for a panel with nothing to show: icon badge, title, hint and an
// optional call-to-action button. Fills the remaining content region; returns true when clicked.
bool EmptyState(const char* icon, const char* title, const char* hint, const char* action = nullptr);

// The custom title bar (the main menu bar doubles as the window caption). The UI writes this
// each frame, in screen pixels; the window procedure reads it to answer WM_NCHITTEST.
struct Caption
{
    ImVec2 barMin, barMax;      // whole bar
    ImVec2 maxMin, maxMax;      // maximize button (HTMAXBUTTON, for Windows 11 snap layouts)
    ImVector<ImVec4> solid;     // interactive spans that must stay client area (x0, y0, x1, y1)
    bool blocked = false;       // a popup is open or another window covers the bar: clicks go to the UI
};
Caption& GetCaption();
// 0 = client, 1 = caption (drag), 2 = maximize button.
int HitTestCaption(float x, float y);
} // namespace Glass
