#pragma once
#include "imgui.h"

// Scales a layout size designed at a 16px font to the current (DPI-scaled) font size.
inline float Px(float v) { return v * ImGui::GetFontSize() / 16.f; }

// Width for an InputInt whose text field should be `field` wide (at 16px) once its -/+ buttons are added.
inline float StepperWidth(float field)
{
    return Px(field) + 2.f * (ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x);
}

// Exact width of ImGui::SmallButton(label), for sizing fixed table columns that hold buttons.
inline float SmallButtonWidth(const char* label)
{
    return ImGui::CalcTextSize(label, nullptr, true).x + 2.f * ImGui::GetStyle().FramePadding.x;
}
