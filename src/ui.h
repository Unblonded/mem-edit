#pragma once
#include "imgui.h"

// Scales a layout size designed at a 16px font to the current (DPI-scaled) font size.
inline float Px(float v) { return v * ImGui::GetFontSize() / 16.f; }
