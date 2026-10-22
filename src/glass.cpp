#include "glass.h"

#include "imgui_internal.h"

#include <cmath>
#include <cstring>

namespace
{
ImU32 Col(ImVec4 c, float a) { c.w = a; return ImGui::ColorConvertFloat4ToU32(c); }

// Horizontal hairline that fades in from the left and out to the right.
void SpecularLine(ImDrawList* dl, float x0, float x1, float y, ImU32 mid)
{
    const ImU32 clear = mid & ~IM_COL32_A_MASK;
    float q = (x1 - x0) * 0.22f;
    dl->AddRectFilledMultiColor(ImVec2(x0, y), ImVec2(x0 + q, y + 1), clear, mid, mid, clear);
    dl->AddRectFilled(ImVec2(x0 + q, y), ImVec2(x1 - q, y + 1), mid);
    dl->AddRectFilledMultiColor(ImVec2(x1 - q, y), ImVec2(x1, y + 1), mid, clear, clear, mid);
}

// Light catching the top of the pane. Drawn as stacked bands rather than a
// multi-colour rect so it respects the window's rounded corners.
void Sheen(ImDrawList* dl, ImVec2 p0, ImVec2 p1, float rounding, float height, float alpha)
{
    const int bands = 10;
    height = ImMin(height, p1.y - p0.y);
    for (int i = 0; i < bands; i++)
    {
        float y = p0.y + height * i / bands;
        dl->AddRectFilled(ImVec2(p0.x, y), ImVec2(p1.x, p0.y + height), IM_COL32(255, 255, 255, (int)(255 * alpha / bands)),
                          rounding, ImDrawFlags_RoundCornersTop);
    }
}

// Soft outer halo around a rounded rect: concentric outlines fading out over `spread` pixels.
void Halo(ImDrawList* dl, ImVec2 p0, ImVec2 p1, float rounding, ImVec4 col, float spread)
{
    const int steps = 8;
    for (int i = 1; i <= steps; i++)
    {
        float t = (float)i / steps, d = spread * t;
        float a = col.w * (1.f - t) * (1.f - t);
        dl->AddRect(ImVec2(p0.x - d, p0.y - d), ImVec2(p1.x + d, p1.y + d), Col(col, a), rounding + d, 0,
                    spread / steps + 0.5f);
    }
}

void DecoratePane(ImDrawList* dl, ImVec2 p0, ImVec2 p1, float rounding, bool focused, bool drawBorder)
{
    dl->PushClipRect(p0, p1, false);
    Sheen(dl, p0, p1, rounding, ImGui::GetFontSize() * 3.2f, 0.055f);
    if (drawBorder)
        dl->AddRect(ImVec2(p0.x + 0.5f, p0.y + 0.5f), ImVec2(p1.x - 0.5f, p1.y - 0.5f), IM_COL32(255, 255, 255, 20), rounding);
    // Specular rim: brighter, accent-tinted on the focused pane.
    float inset = ImMax(rounding, 1.f);
    ImU32 rim = focused ? Col(Glass::kAccentHi, 0.85f) : IM_COL32(255, 255, 255, 70);
    SpecularLine(dl, p0.x + inset, p1.x - inset, p0.y + 0.5f, rim);
    // Faint secondary reflection along the bottom edge.
    SpecularLine(dl, p0.x + inset * 2, p1.x - inset * 2, p1.y - 1.5f, IM_COL32(255, 255, 255, 14));
    dl->PopClipRect();
}
} // namespace

namespace Glass
{
void Glow(ImDrawList* dl, ImVec2 center, float radius, ImVec4 col)
{
    // A centre vertex plus concentric rings; alpha follows an inverted smoothstep.
    const int seg = 64, rings = 6;
    const int vtxCount = 1 + rings * seg;
    const int idxCount = seg * 3 + (rings - 1) * seg * 6;
    dl->PrimReserve(idxCount, vtxCount);
    const ImVec2 uv = dl->_Data->TexUvWhitePixel;
    const ImDrawIdx base = (ImDrawIdx)dl->_VtxCurrentIdx;

    dl->PrimWriteVtx(center, uv, ImGui::ColorConvertFloat4ToU32(col));
    for (int r = 1; r <= rings; r++)
    {
        float t = (float)r / rings;
        float a = col.w * (1.f - t * t * (3.f - 2.f * t));
        ImU32 c = Col(col, a);
        for (int i = 0; i < seg; i++)
        {
            float ang = IM_PI * 2.f * i / seg;
            dl->PrimWriteVtx(ImVec2(center.x + cosf(ang) * radius * t, center.y + sinf(ang) * radius * t), uv, c);
        }
    }
    for (int i = 0; i < seg; i++)
    {
        int j = (i + 1) % seg;
        dl->PrimWriteIdx(base);
        dl->PrimWriteIdx((ImDrawIdx)(base + 1 + i));
        dl->PrimWriteIdx((ImDrawIdx)(base + 1 + j));
    }
    for (int r = 0; r < rings - 1; r++)
    {
        ImDrawIdx in = (ImDrawIdx)(base + 1 + r * seg), out = (ImDrawIdx)(in + seg);
        for (int i = 0; i < seg; i++)
        {
            int j = (i + 1) % seg;
            dl->PrimWriteIdx((ImDrawIdx)(in + i));
            dl->PrimWriteIdx((ImDrawIdx)(out + i));
            dl->PrimWriteIdx((ImDrawIdx)(out + j));
            dl->PrimWriteIdx((ImDrawIdx)(in + i));
            dl->PrimWriteIdx((ImDrawIdx)(out + j));
            dl->PrimWriteIdx((ImDrawIdx)(in + j));
        }
    }
}

static void DrawBackdrop(ImGuiViewport* vp)
{
    ImDrawList* dl = ImGui::GetBackgroundDrawList(vp);
    const ImVec2 p0 = vp->Pos, sz = vp->Size;
    const float t = (float)ImGui::GetTime();
    const float diag = sqrtf(sz.x * sz.x + sz.y * sz.y);

    // Base wash: ink, lifting slightly toward the steel tone at the top-left.
    dl->AddRectFilledMultiColor(p0, ImVec2(p0.x + sz.x, p0.y + sz.y), IM_COL32(46, 56, 80, 70), IM_COL32(22, 26, 38, 60),
                                IM_COL32(12, 14, 22, 70), IM_COL32(22, 26, 38, 60));

    // Drifting light pools on slow Lissajous paths, all in the one steel tone so the
    // field stays duotone; the translucent panels refract them.
    struct Orb { ImVec4 col; float r, sx, sy, px, py, ax, ay, cx, cy; };
    const ImVec4 tone = kAccent;
    const Orb orbs[] = {
        { ImVec4(tone.x, tone.y, tone.z, 0.30f), 0.45f, 0.050f, 0.071f, 0.0f, 1.3f, 0.32f, 0.30f, 0.30f, 0.35f },
        { ImVec4(tone.x, tone.y, tone.z, 0.20f), 0.36f, 0.043f, 0.057f, 2.1f, 0.4f, 0.30f, 0.34f, 0.72f, 0.40f },
        { ImVec4(kAccentDeep.x, kAccentDeep.y, kAccentDeep.z, 0.35f), 0.32f, 0.061f, 0.039f, 4.0f, 2.6f, 0.36f, 0.28f, 0.55f, 0.75f },
    };
    for (const Orb& o : orbs)
    {
        ImVec2 c(p0.x + sz.x * (o.cx + o.ax * sinf(t * o.sx + o.px)), p0.y + sz.y * (o.cy + o.ay * cosf(t * o.sy + o.py)));
        float breathe = 1.f + 0.08f * sinf(t * 0.21f + o.px);
        Glow(dl, c, diag * o.r * breathe, o.col);
    }
}

void DrawBackdrop()
{
    // Every viewport, so panels dragged out into their own OS windows keep the look.
    for (ImGuiViewport* vp : ImGui::GetPlatformIO().Viewports) DrawBackdrop(vp);
}

void DecorateWindows()
{
    ImGuiContext& g = *GImGui;
    ImGuiWindow* focusedRoot = g.NavWindow ? g.NavWindow->RootWindowDockTree : nullptr;
    for (ImGuiWindow* w : g.Windows)
    {
        if (!w->Active || w->Hidden || (w->Flags & ImGuiWindowFlags_NoBackground)) continue;
        if (w->Flags & ImGuiWindowFlags_Tooltip) continue;
        if (strncmp(w->Name, "WindowOverViewport_", 19) == 0) continue; // the transparent dockspace host

        if (w->DockIsActive && w->DockNode)
        {
            // A docked window and its tab bar form one pane: decorate the node once.
            ImGuiDockNode* n = w->DockNode;
            if (n->VisibleWindow != w) continue;
            bool focused = g.NavWindow && g.NavWindow->RootWindow == w;
            DecoratePane(w->DrawList, n->Pos, ImVec2(n->Pos.x + n->Size.x, n->Pos.y + n->Size.y), 0.f, focused, true);
        }
        else if (!(w->Flags & ImGuiWindowFlags_ChildWindow))
        {
            bool focused = w == focusedRoot && !(w->Flags & (ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_Popup));
            DecoratePane(w->DrawList, w->Pos, ImVec2(w->Pos.x + w->Size.x, w->Pos.y + w->Size.y), w->WindowRounding, focused,
                         false);
        }
    }
}

Fonts& GetFonts()
{
    static Fonts fonts;
    return fonts;
}

void RamLogo(ImDrawList* dl, ImVec2 p0, float s)
{
    const ImVec2 p1(p0.x + s, p0.y + s);
    const float r = s * 0.23f;
    dl->AddRectFilled(p0, p1, IM_COL32(24, 30, 46, 255), r);
    Sheen(dl, p0, p1, r, s * 0.5f, 0.10f);
    dl->AddRect(p0, p1, Col(kAccentHi, 0.40f), r);

    // Board.
    const float sw = s * 0.84f, sh = s * 0.44f;
    const ImVec2 a(IM_ROUND(p0.x + (s - sw) * 0.5f), IM_ROUND(p0.y + (s - sh) * 0.5f + s * 0.02f));
    const ImVec2 b(a.x + IM_ROUND(sw), a.y + IM_ROUND(sh));
    dl->AddRectFilledMultiColor(a, b, IM_COL32(205, 222, 250, 255), IM_COL32(205, 222, 250, 255),
                                IM_COL32(120, 145, 196, 255), IM_COL32(120, 145, 196, 255));

    // Chips across the top.
    const int n = s >= 28 ? 4 : 3;
    const float padX = (b.x - a.x) * 0.08f, gap = ImMax(1.f, (b.x - a.x) * 0.05f);
    const float cw = ((b.x - a.x) - 2 * padX - (n - 1) * gap) / n;
    const float cy0 = a.y + (b.y - a.y) * 0.14f, cy1 = a.y + (b.y - a.y) * 0.60f;
    for (int i = 0; i < n; i++)
    {
        float x = a.x + padX + i * (cw + gap);
        dl->AddRectFilled(ImVec2(x, cy0), ImVec2(x + cw, cy1), IM_COL32(20, 24, 36, 255), s * 0.03f);
    }

    // Contact strip with the off-centre key notch.
    const float py0 = a.y + (b.y - a.y) * 0.72f, py1 = a.y + (b.y - a.y) * 0.92f;
    dl->AddRectFilled(ImVec2(a.x + padX * 0.6f, py0), ImVec2(b.x - padX * 0.6f, py1), IM_COL32(236, 242, 252, 255));
    const float nx = a.x + (b.x - a.x) * 0.40f, nw = ImMax(1.f, (b.x - a.x) * 0.06f);
    dl->AddRectFilled(ImVec2(nx, py0 - 1), ImVec2(nx + nw, b.y), IM_COL32(24, 30, 46, 255));
}

bool AccentButton(const char* label, const ImVec2& sizeArg)
{
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& st = ImGui::GetStyle();
    ImFont* bold = GetFonts().bold;
    if (bold) ImGui::PushFont(bold);

    // The fill is drawn under the button, so work out its rect and state up front.
    ImVec2 labelSize = ImGui::CalcTextSize(label, nullptr, true);
    ImVec2 size = ImGui::CalcItemSize(sizeArg, labelSize.x + st.FramePadding.x * 2, labelSize.y + st.FramePadding.y * 2);
    ImVec2 p0 = ImGui::GetCursorScreenPos(), p1(p0.x + size.x, p0.y + size.y);
    const bool disabled = (g.CurrentItemFlags & ImGuiItemFlags_Disabled) != 0;
    const bool hovered = !disabled && ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(p0, p1);
    const bool held = hovered && ImGui::IsMouseDown(ImGuiMouseButton_Left);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float r = st.FrameRounding;
    if (hovered) Halo(dl, p0, p1, r, ImVec4(kAccent.x, kAccent.y, kAccent.z, 0.30f), ImGui::GetFontSize() * 0.6f);
    ImVec4 fill = held ? kAccentDeep : hovered ? kAccentHi : kAccent;
    dl->AddRectFilled(p0, p1, ImGui::GetColorU32(fill), r);
    // Glassy highlight over the upper half, and a crisp light rim.
    Sheen(dl, p0, ImVec2(p1.x, (p0.y + p1.y) * 0.5f), r, size.y * 0.5f, held ? 0.05f : 0.22f);
    dl->AddRect(p0, p1, ImGui::GetColorU32(ImVec4(1, 1, 1, 0.28f)), r);

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Text, kInk);
    bool pressed = ImGui::Button(label, size);
    ImGui::PopStyleColor(5);
    if (bold) ImGui::PopFont();
    return pressed;
}

bool EmptyState(const char* icon, const char* title, const char* hint, const char* action)
{
    const Fonts& f = GetFonts();
    ImFont* titleFont = f.title ? f.title : ImGui::GetFont();
    ImFont* iconFont = f.iconLarge ? f.iconLarge : ImGui::GetFont();
    const float em = ImGui::GetFontSize();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const ImVec2 origin = ImGui::GetCursorScreenPos();

    const float badge = em * 4.6f;
    const float wrap = ImMin(avail.x - em * 2, em * 26);
    ImVec2 titleSize = titleFont->CalcTextSizeA(titleFont->FontSize, FLT_MAX, 0, title);
    ImVec2 hintSize = ImGui::CalcTextSize(hint, nullptr, false, wrap);
    float actionH = action ? ImGui::GetFrameHeight() + em * 1.2f : 0.f;
    float total = badge + em * 1.3f + titleSize.y + em * 0.5f + hintSize.y + actionH;
    float y = origin.y + ImMax(em, (avail.y - total) * 0.45f);
    const float cx = origin.x + avail.x * 0.5f;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float t = (float)ImGui::GetTime();
    ImVec2 c(cx, y + badge * 0.5f);
    Glow(dl, c, badge * (1.15f + 0.05f * sinf(t * 1.3f)), ImVec4(kAccent.x, kAccent.y, kAccent.z, 0.16f));
    dl->AddCircleFilled(c, badge * 0.5f, IM_COL32(255, 255, 255, 12), 64);
    dl->AddCircle(c, badge * 0.5f, IM_COL32(255, 255, 255, 34), 64, 1.f);
    dl->AddCircle(c, badge * 0.5f - em * 0.45f, Col(kAccent, 0.18f), 64, 1.f);
    ImVec2 iconSize = iconFont->CalcTextSizeA(iconFont->FontSize, FLT_MAX, 0, icon);
    dl->AddText(iconFont, iconFont->FontSize, ImVec2(c.x - iconSize.x * 0.5f, c.y - iconSize.y * 0.5f), Col(kAccentHi, 1.f),
                icon);
    y += badge + em * 1.3f;

    dl->AddText(titleFont, titleFont->FontSize, ImVec2(cx - titleSize.x * 0.5f, y), ImGui::GetColorU32(ImGuiCol_Text), title);
    y += titleSize.y + em * 0.5f;

    // Hint lines centred individually.
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::SetCursorScreenPos(ImVec2(cx - hintSize.x * 0.5f, y));
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap);
    ImGui::TextUnformatted(hint);
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
    y += hintSize.y;

    bool clicked = false;
    if (action)
    {
        y += em * 1.2f;
        ImFont* bold = f.bold ? f.bold : ImGui::GetFont();
        float w = bold->CalcTextSizeA(em, FLT_MAX, 0, action).x + ImGui::GetStyle().FramePadding.x * 4;
        ImGui::SetCursorScreenPos(ImVec2(cx - w * 0.5f, y));
        clicked = AccentButton(action, ImVec2(w, 0));
    }
    // Claim the rest of the region so the window's content size stays put.
    ImGui::SetCursorScreenPos(origin);
    ImGui::Dummy(ImVec2(avail.x, ImMax(avail.y, total)));
    return clicked;
}

Caption& GetCaption()
{
    static Caption caption;
    return caption;
}

int HitTestCaption(float x, float y)
{
    const Caption& c = GetCaption();
    if (x < c.barMin.x || x >= c.barMax.x || y < c.barMin.y || y >= c.barMax.y) return 0;
    if (x >= c.maxMin.x && x < c.maxMax.x && y >= c.maxMin.y && y < c.maxMax.y) return 2;
    if (c.blocked) return 0;
    for (const ImVec4& r : c.solid)
        if (x >= r.x && x < r.z && y >= r.y && y < r.w) return 0;
    return 1;
}
} // namespace Glass
