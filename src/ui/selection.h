#pragma once
#include "imgui.h"

#include <algorithm>
#include <cstddef>
#include <vector>

// Explorer-style click handling shared by the lists: a click selects just that row, Ctrl+click
// toggles it, Shift+click selects the range from the last clicked row (Ctrl+Shift adds the range).
template <class IsSel, class SetSel>
void ClickSelect(int row, int count, int& anchor, IsSel isSel, SetSel setSel)
{
    const ImGuiIO& io = ImGui::GetIO();
    if (io.KeyShift && anchor >= 0 && anchor < count)
    {
        if (!io.KeyCtrl)
            for (int k = 0; k < count; k++) setSel(k, false);
        for (int k = std::min(anchor, row); k <= std::max(anchor, row); k++) setSel(k, true);
        return; // the anchor stays put so the range can be adjusted
    }
    if (io.KeyCtrl) setSel(row, !isSel(row));
    else
    {
        for (int k = 0; k < count; k++) setSel(k, false);
        setSel(row, true);
    }
    anchor = row;
}

// Per-row flags for a list that can hold millions of rows (scan results). Keeps a running count so
// "N selected" costs nothing per frame, and clears with a fill instead of a per-row loop.
class RowSelection
{
public:
    void Resize(size_t n)
    {
        if (m_on.size() == n) return;
        m_on.assign(n, 0);
        m_count = 0;
        m_anchor = -1;
    }
    void Clear()
    {
        std::fill(m_on.begin(), m_on.end(), (char)0);
        m_count = 0;
        m_anchor = -1;
    }
    void SelectAll()
    {
        std::fill(m_on.begin(), m_on.end(), (char)1);
        m_count = m_on.size();
    }
    bool Get(size_t i) const { return i < m_on.size() && m_on[i]; }
    void Set(size_t i, bool on)
    {
        if (i >= m_on.size() || (m_on[i] != 0) == on) return;
        m_on[i] = on;
        if (on) m_count++;
        else m_count--;
    }
    // Same rules as ClickSelect.
    void Click(int row)
    {
        const ImGuiIO& io = ImGui::GetIO();
        if (io.KeyShift && m_anchor >= 0 && m_anchor < (int)m_on.size())
        {
            const int anchor = m_anchor; // Clear() forgets it; the range keeps growing from the same row
            if (!io.KeyCtrl) Clear();
            for (int k = std::min(anchor, row); k <= std::max(anchor, row); k++) Set(k, true);
            m_anchor = anchor;
            return;
        }
        if (io.KeyCtrl) Set(row, !Get(row));
        else
        {
            Clear();
            Set(row, true);
        }
        m_anchor = row;
    }
    // Right-click on a row outside the selection makes it the selection, like Explorer.
    void SelectForContextMenu(int row)
    {
        if (Get(row)) return;
        Clear();
        Set(row, true);
        m_anchor = row;
    }
    size_t Count() const { return m_count; }
    template <class F> void ForEach(F f) const
    {
        if (!m_count) return;
        for (size_t i = 0, seen = 0; i < m_on.size() && seen < m_count; i++)
            if (m_on[i]) f(i), seen++;
    }

private:
    std::vector<char> m_on;
    size_t m_count = 0;
    int m_anchor = -1;
};
