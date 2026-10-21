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
} // namespace Glass
