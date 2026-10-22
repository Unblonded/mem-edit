# Memory Browser

[![Build](https://github.com/Unblonded/mem-edit/actions/workflows/build.yml/badge.svg)](https://github.com/Unblonded/mem-edit/actions/workflows/build.yml)

A process memory browser / scanner / editor for Windows, built with C++20, Dear ImGui (docking branch) and DirectX 11.

**Download:** the latest build of `main` is always on the [Nightly release](https://github.com/Unblonded/mem-edit/releases/tag/nightly); tagged versions are under [Releases](https://github.com/Unblonded/mem-edit/releases).

## Build

Open `MemoryBrowser.sln` in Visual Studio 2026 (toolset v145, Windows 10/11 SDK) and build **Release | x64**.
The exe lands in `bin\Release\mem-edit.exe`. Run it as administrator to attach to elevated processes.

Command line alternative (Developer PowerShell):

```
msbuild MemoryBrowser.sln /p:Configuration=Release /p:Platform=x64 /m
```

Dear ImGui v1.91.9-docking is vendored in `third_party/imgui`, and Zydis v4.1.1 (with Zycore) in `third_party/zydis`.

## Features

- **Process picker** – sortable/filterable list with architecture, hides inaccessible processes; suspend/resume.
- **Value scanner** (multi-threaded) – Int8..UInt64, Float, Double, ASCII/UTF-16 strings, byte arrays with `??` wildcards.
  First scans: exact, not equal, bigger, smaller, between, unknown initial value (memory snapshot).
  Next scans: changed, unchanged, increased, decreased, increased by, decreased by, plus all the above. Undo last scan.
  Filters: writable / executable, image / private / mapped memory, address range, fast-scan alignment.
- **Scan results** – virtualised list for millions of hits, live values (red when changed), static addresses shown as
  `module+offset`, multi-select, bulk value change.
- **Memory view** – hex + ASCII editor with live refresh, red flash on changed bytes, selection, in-place editing,
  pointer following, back/forward history, fill/NOP, copy as hex or C array, and a data inspector (all integer widths,
  float, double, pointer, strings, binary) whose fields are editable.
- **Address list** – descriptions, address expressions with pointer chains, any value type, freeze, hex display,
  save/load (`.mtbl`).
- **Find out what writes / accesses an address** – right-click an address list entry (or bytes in the memory view).
  Attaches as a debugger and sets a hardware breakpoint (DR0–DR3, so up to 4 at once) on every thread. Each instruction
  that touches the address is listed with a hit count, Zydis disassembly, and the registers at that moment. You can NOP
  an instruction out and restore it later. Closing the last window detaches without stopping the target.
- **Memory regions** & **Modules** – full VirtualQueryEx map with protection highlighting, filters, jump, dump to file,
  "scan only this region/module".
- **Decompile & patch** – *Decompile function here* (memory view, address list, or a trace window button) opens the
  Decompile window on the whole function (bounds from the x64 exception table).
  - **Pseudo-C** – registers become locals, flags come from the last compare, and control flow is recovered into
    `if` / `else` / `while` / `do-while` where the shape allows, falling back to `goto` only when it can't be
    proven structurable. Dead arguments, casts and a trailing `return` are trimmed. It is still a lifter, not a
    full decompiler: no type recovery, calls aren't analysed, and `/* asm */` marks anything not modelled.
  - **Disassembly** – pick an instruction and change its immediate (decimal `28` or hex `0x1C`), NOP it out, or
    overwrite it with raw bytes. Edits are re-encoded with Zydis and verified before they are written, and never
    grow the instruction.
  - **Patches** – every change is tracked here with the original bytes kept, so each can be toggled off/on or
    removed, individually or all at once. Patches live only in the target's memory.

## Practice target

The solution also builds `bin\Release\TestTarget.exe`, a console "game" to practise on. Start it, then attach to it
from Memory Browser (Ctrl+O). Press **A** in TestTarget to reveal the answers.

1. **Exact value** – scan Int32 `100` (Health), press **D** in the target, Next Scan `93`. One green
   `TestTarget.exe+...` result remains. Double-click it, then tick *Freeze* and press **D** again: health no longer drops.
2. **Unknown initial value** – First Scan *Unknown initial value*, press **P** (poison), Next Scan *Decreased value*
   a few times.
3. **Float / Double** – Speed is a Float (`1.5`, change with **+/-**); Pos X/Y are Doubles that change constantly
   (try *Changed value*).
4. **Strings** – scan String `Hero` or UTF-16 `Knight`; edit them in the memory view.
5. **Byte pattern** – Array of Bytes `DE AD BE EF ?? 37 C0 DE` finds the player object.
6. **Pointer chain** – Ammo lives in a heap object. Find it, then press **M**: the object moves and the old address
   goes stale. Add `[TestTarget.exe+<pointer offset>]+24` to the address list (the offset is shown with **A**);
   it keeps working after every **M**.
7. **What writes to this address** – right-click Health in the address list → *Find out what writes to this
   address*, then press **D** and **H** in the target. Select the `sub` instruction and click *Replace with NOPs*:
   **D** no longer does damage.

## Address expressions

```
7FF6A0001000            hex number
game.exe+1F0            module base + offset
"My Game.exe"+10        quoted module name
[[game.exe+1F0]+18]+4   pointer chain ([ ] dereferences)
base+#100               decimal literal
```
