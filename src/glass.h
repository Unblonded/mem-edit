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

// Call once per frame before any windows are submitted.
void DrawBackdrop();
// Call after every window has been submitted, before ImGui::Render().
void DecorateWindows();
} // namespace Glass
