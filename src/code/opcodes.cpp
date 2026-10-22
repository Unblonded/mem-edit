#include "code/opcodes.h"

#include <cstdio>
#include <cstring>

// Notation used in the encodings column (Intel manual style):
//   /r     a ModRM byte follows, its reg field names a register
//   /0../7 a ModRM byte follows, its reg field is that digit (picks the operation inside a group)
//   +r     the register number is added to the opcode byte (B8+r: B8 eax, B9 ecx ... BF edi)
//   ib iw id io   an 8 / 16 / 32 / 64-bit immediate follows
//   cb cd         an 8 / 32-bit relative branch offset follows

namespace
{
std::vector<std::string> g_categories = {
    "Data movement", "Arithmetic", "Logic & bits", "Shifts & rotates", "Compare & test", "Jumps & calls",
    "Conditional jumps", "Stack & flags", "Strings", "Floating point (SSE)", "x87 & AVX", "System & misc",
    "Encoding", "Modding recipes",
};

void Add(std::vector<OpcodeRef>& v, const char* cat, const char* mn, const char* aliases, const char* enc,
         const char* summary, const char* details, const char* flags, const char* ex, const char* exBytes,
         const char* tip)
{
    v.push_back({ mn, aliases, cat, enc, summary, details, flags, ex, exBytes, tip });
}

const char* kArithFlags = "OF SF ZF AF CF PF";
const char* kLogicFlags = "SF ZF PF set from the result; OF CF cleared; AF undefined";

// Condition codes shared by jcc / setcc / cmovcc.
struct Cond
{
    int cc;
    const char* name;      // primary suffix
    const char* aliases;   // other suffixes
    const char* meaning;
    const char* test;      // flag test
    const char* kind;      // signed / unsigned / flag
};
const Cond kConds[] = {
    { 0x0, "o", "", "overflow", "OF = 1", "flag" },
    { 0x1, "no", "", "no overflow", "OF = 0", "flag" },
    { 0x2, "b", "jnae jc", "below (unsigned <)", "CF = 1", "unsigned" },
    { 0x3, "ae", "jnb jnc", "above or equal (unsigned >=)", "CF = 0", "unsigned" },
    { 0x4, "e", "jz", "equal / zero", "ZF = 1", "either" },
    { 0x5, "ne", "jnz", "not equal / not zero", "ZF = 0", "either" },
    { 0x6, "be", "jna", "below or equal (unsigned <=)", "CF = 1 or ZF = 1", "unsigned" },
    { 0x7, "a", "jnbe", "above (unsigned >)", "CF = 0 and ZF = 0", "unsigned" },
    { 0x8, "s", "", "sign (result negative)", "SF = 1", "flag" },
    { 0x9, "ns", "", "not sign (result >= 0)", "SF = 0", "flag" },
    { 0xA, "p", "jpe", "parity even", "PF = 1", "flag" },
    { 0xB, "np", "jpo", "parity odd", "PF = 0", "flag" },
    { 0xC, "l", "jnge", "less (signed <)", "SF != OF", "signed" },
    { 0xD, "ge", "jnl", "greater or equal (signed >=)", "SF = OF", "signed" },
    { 0xE, "le", "jng", "less or equal (signed <=)", "ZF = 1 or SF != OF", "signed" },
    { 0xF, "g", "jnle", "greater (signed >)", "ZF = 0 and SF = OF", "signed" },
};

std::string CondTable()
{
    std::string t;
    for (const Cond& c : kConds)
    {
        char line[128];
        snprintf(line, sizeof(line), "  %X  %-3s %-30s %s\n", c.cc, c.name, c.meaning, c.test);
        t += line;
    }
    return t;
}

std::vector<OpcodeRef> Build()
{
    std::vector<OpcodeRef> v;
    v.reserve(200);

    // ---------------------------------------------------------------- Data movement
    const char* D = "Data movement";
    Add(v, D, "mov", "movabs", "88 /r  89 /r  8A /r  8B /r  B0+r ib  B8+r id/io  C6 /0 ib  C7 /0 id",
        "Copy a value from the source to the destination.",
        "The workhorse: register to register, memory to register (load, 8A/8B) or register to memory (store, "
        "88/89), or an immediate into either (B8+r, C7). It never changes flags. There is no memory-to-memory "
        "form, so copies go through a register. Writing a 32-bit register (eax) zeroes the upper half of the "
        "64-bit register (rax); 8- and 16-bit writes leave the rest alone. With REX.W, B8+r takes a full 64-bit "
        "immediate (often shown as movabs).",
        "", "mov eax, dword ptr [rcx+0x24]", "8B 41 24",
        "A store such as 89 41 24 (mov [rcx+0x24], eax) is what 'Find out what writes' usually lands on. NOP it "
        "to stop the game updating the value, or change the source register.");
    Add(v, D, "movzx", "", "0F B6 /r (from byte)  0F B7 /r (from word)",
        "Load a smaller value and zero-extend it.",
        "Reads an 8- or 16-bit value and fills the upper bits with zeros, so a byte of 0xFF becomes 255. Used "
        "for unsigned bytes and shorts: bools, small counters, enum values, characters.",
        "", "movzx eax, byte ptr [rcx]", "0F B6 01",
        "If a scan finds a 1-byte value, the code reading it is usually a movzx.");
    Add(v, D, "movsx", "movsxd", "0F BE /r (byte)  0F BF /r (word)  REX.W 63 /r (movsxd, dword)",
        "Load a smaller value and sign-extend it.",
        "Like movzx but copies the sign bit upward, so a byte of 0xFF becomes -1. movsxd widens a signed 32-bit "
        "int to 64 bits, typically right before using it as an array index.",
        "", "movsxd rax, ecx", "48 63 C1",
        "movsxd rax, ecx followed by [base+rax*8] is a classic array access: ecx is the index.");
    Add(v, D, "lea", "", "8D /r",
        "Compute an address without touching memory.",
        "Load Effective Address evaluates the bracket expression ([base + index*scale + disp]) and stores the "
        "address itself, not what it points at. No flags change. Compilers also use it as a fast multiply-add: "
        "lea eax, [rcx+rcx*2] is ecx*3. With RIP-relative addressing it loads the address of a global or "
        "string.",
        "", "lea rcx, [rip+0x1234]", "48 8D 0D 34 12 00 00",
        "lea reg, [rip+disp32] points at a global. The four disp32 bytes change every build, so wildcard them in "
        "AOB signatures, then resolve the result to find the global.");
    Add(v, D, "xchg", "", "86 /r  87 /r  90+r (with eax/rax)",
        "Swap two values.",
        "Exchanges a register with a register or memory. With a memory operand it is implicitly atomic (locked), "
        "so it doubles as a spin-lock primitive. 90 is xchg eax, eax, which is why it is the one-byte NOP.",
        "", "xchg eax, ecx", "91", "");
    Add(v, D, "cmovcc", "cmove cmovne cmovl cmovg cmovb cmova cmovz cmovnz", "0F 40+cc /r",
        "Move only if a condition holds.",
        "Copies the source into the destination when the condition (same codes as jcc) is true; otherwise does "
        "nothing. Compilers use it to avoid a branch, for example min/max or clamping a value.\n\nCondition "
        "codes:\n" ,
        "", "cmovl eax, ecx", "0F 4C C1",
        "To always take the value, replace cmovcc with a plain mov of the same operands (8B /r), NOP-padding the "
        "spare byte.");
    v.back().details += CondTable();
    Add(v, D, "setcc", "sete setne setl setg setb seta setz setnz", "0F 90+cc /0",
        "Set a byte to 1 or 0 from a condition.",
        "Writes 1 into an 8-bit register or memory byte if the condition is true, else 0. This is how a "
        "comparison becomes a bool: cmp then sete al. Usually followed by movzx eax, al to widen it.\n\nCondition "
        "codes:\n",
        "", "sete al", "0F 94 C0",
        "To force a bool result, replace the 3-byte setcc with mov al, 1 (B0 01) plus a NOP (90).");
    v.back().details += CondTable();
    Add(v, D, "bswap", "", "0F C8+r",
        "Reverse the byte order of a register.",
        "Turns 0x11223344 into 0x44332211. Used for big-endian data such as network packets and some file "
        "formats.",
        "", "bswap eax", "0F C8", "");
    Add(v, D, "cbw / cwde / cdqe", "cbw cwde cdqe", "66 98 (cbw)  98 (cwde)  REX.W 98 (cdqe)",
        "Sign-extend the accumulator in place.",
        "cbw widens al into ax, cwde widens ax into eax, cdqe widens eax into rax. Used before arithmetic on a "
        "value that was loaded narrower.",
        "", "cdqe", "48 98", "");
    Add(v, D, "cwd / cdq / cqo", "cwd cdq cqo", "66 99 (cwd)  99 (cdq)  REX.W 99 (cqo)",
        "Sign-extend the accumulator into the d register.",
        "Fills edx (rdx) with copies of eax's (rax's) sign bit, making edx:eax a 64-bit (rdx:rax 128-bit) signed "
        "value. You almost always see it immediately before idiv.",
        "", "cdq", "99", "");
    Add(v, D, "movd / movq", "movd movq", "66 0F 6E /r (to xmm)  66 0F 7E /r (from xmm)  F3 0F 7E (movq xmm)",
        "Move between general registers and XMM registers.",
        "Copies 32 (movd) or 64 (movq) bits between a general-purpose register or memory and the low part of an "
        "XMM register, without converting. It is a bit copy, so 1.0f moves as 0x3F800000.",
        "", "movd xmm0, eax", "66 0F 6E C0", "");

    // ---------------------------------------------------------------- Arithmetic
    const char* A = "Arithmetic";
    Add(v, A, "add", "", "00-05  80 /0 ib  81 /0 id  83 /0 ib",
        "Add the source to the destination.",
        "dest = dest + src. 83 /0 takes a sign-extended 8-bit immediate (the short, common form); 81 /0 a "
        "32-bit one. 05 id is the short form for eax/rax. CF signals unsigned overflow, OF signed overflow.",
        kArithFlags, "add dword ptr [rcx+0x24], 0x5", "83 41 24 05",
        "Changing the immediate (05 to 64) makes a pickup worth 100 instead of 5. Changing the opcode to sub "
        "(83 /5) reverses it.");
    Add(v, A, "sub", "", "28-2D  80 /5 ib  81 /5 id  83 /5 ib",
        "Subtract the source from the destination.",
        "dest = dest - src, setting flags exactly like cmp does. Damage, ammo use and cooldown timers are usually "
        "a sub.",
        kArithFlags, "sub dword ptr [rcx+0x24], eax", "29 41 24",
        "NOP a sub to make something never decrease. Make sure it's the right one with 'Find out what writes', "
        "since the same code may also handle enemies.");
    Add(v, A, "adc", "", "10-15  80 /2  81 /2  83 /2",
        "Add with carry.",
        "dest = dest + src + CF. Chains additions wider than a register (64-bit math on x86, 128-bit on x64).",
        kArithFlags, "adc edx, 0x0", "83 D2 00", "");
    Add(v, A, "sbb", "", "18-1D  80 /3  81 /3  83 /3",
        "Subtract with borrow.",
        "dest = dest - (src + CF). Besides wide subtraction, compilers use sbb eax, eax to turn the carry flag "
        "into 0 or -1 without a branch.",
        kArithFlags, "sbb eax, eax", "1B C0", "");
    Add(v, A, "inc", "", "FE /0  FF /0  (40+r in 32-bit code only)",
        "Add one.",
        "dest = dest + 1. Unlike add it leaves CF alone. In 64-bit code bytes 40-4F are REX prefixes, so inc "
        "always uses FF /0 there.",
        "OF SF ZF AF PF (CF unchanged)", "inc dword ptr [rax]", "FF 00", "");
    Add(v, A, "dec", "", "FE /1  FF /1  (48+r in 32-bit code only)",
        "Subtract one.",
        "dest = dest - 1, leaving CF alone. Loops counting down often end with dec + jnz.",
        "OF SF ZF AF PF (CF unchanged)", "dec ecx", "FF C9",
        "A dec on a counter (lives, ammo) can be NOPed with 90 90.");
    Add(v, A, "neg", "", "F6 /3  F7 /3",
        "Negate (two's complement).",
        "dest = 0 - dest. CF is set unless the value was zero.",
        kArithFlags, "neg eax", "F7 D8", "");
    Add(v, A, "mul", "", "F6 /4  F7 /4",
        "Unsigned multiply into rdx:rax.",
        "Multiplies rax (eax, al) by the operand. The double-width result goes into rdx:rax (edx:eax, ax). CF and "
        "OF are set when the high half is non-zero.",
        "OF CF (others undefined)", "mul ecx", "F7 E1", "");
    Add(v, A, "imul", "", "F6 /5  F7 /5  0F AF /r  6B /r ib  69 /r id",
        "Signed multiply.",
        "Three forms: one operand (like mul, into rdx:rax), two operands (dest *= src) and three operands (dest = "
        "src * imm). The two- and three-operand forms are what compilers emit for ordinary multiplication; the "
        "high half is discarded.",
        "OF CF (others undefined)", "imul eax, ecx, 0x64", "6B C1 64",
        "The immediate in 6B /r ib is a multiplier you can change (damage x100, score x2 ...).");
    Add(v, A, "div", "", "F6 /6  F7 /6",
        "Unsigned divide.",
        "Divides rdx:rax by the operand: quotient to rax, remainder to rdx. Dividing by zero or overflowing the "
        "quotient raises #DE (a crash).",
        "undefined", "div ecx", "F7 F1", "");
    Add(v, A, "idiv", "", "F6 /7  F7 /7",
        "Signed divide.",
        "Like div but signed; preceded by cdq/cqo to sign-extend the dividend. Compilers replace division by a "
        "constant with a multiply-and-shift, so an idiv usually means the divisor is a variable.",
        "undefined", "idiv ecx", "F7 F9", "");
    Add(v, A, "xadd", "", "0F C0 /r  0F C1 /r",
        "Exchange and add.",
        "Stores dest + src into dest and the old dest into src. With lock it is an atomic fetch-and-add "
        "(reference counts, InterlockedIncrement).",
        kArithFlags, "lock xadd dword ptr [rcx], eax", "F0 0F C1 01", "");
    Add(v, A, "cmpxchg", "", "0F B0 /r  0F B1 /r",
        "Compare and exchange.",
        "If dest equals eax (rax), dest = src and ZF = 1; otherwise eax = dest and ZF = 0. With lock this is the "
        "atomic compare-and-swap behind most lock-free code.",
        kArithFlags, "lock cmpxchg dword ptr [rcx], edx", "F0 0F B1 11", "");

    // ---------------------------------------------------------------- Logic & bits
    const char* L = "Logic & bits";
    Add(v, L, "and", "", "20-25  80 /4  81 /4  83 /4",
        "Bitwise AND.",
        "Keeps only the bits set in both operands: masking flags, aligning (and rsp, -16) and taking a remainder "
        "by a power of two (and eax, 0xF is eax % 16).",
        kLogicFlags, "and ecx, 0xF", "83 E1 0F", "");
    Add(v, L, "or", "", "08-0D  80 /1  81 /1  83 /1",
        "Bitwise OR.",
        "Sets every bit set in either operand, for example turning on a flag bit. or eax, -1 (83 C8 FF) is a "
        "short way to load -1.",
        kLogicFlags, "or eax, 0xFFFFFFFF", "83 C8 FF", "");
    Add(v, L, "xor", "", "30-35  80 /6  81 /6  83 /6",
        "Bitwise exclusive OR.",
        "Flips the bits set in the source. xor eax, eax is the standard way to zero a register (shorter than mov "
        "eax, 0 and it also clears flags). Also used for toggles, hashing and simple obfuscation.",
        kLogicFlags, "xor eax, eax", "31 C0",
        "31 C0 C3 (xor eax, eax / ret) is the shortest 'return 0' patch.");
    Add(v, L, "not", "", "F6 /2  F7 /2",
        "Flip every bit.",
        "One's complement: dest = ~dest. No flags change.",
        "", "not eax", "F7 D0", "");
    Add(v, L, "bt / bts / btr / btc", "bt bts btr btc", "0F A3 /r  0F AB /r  0F B3 /r  0F BB /r  0F BA /4 /5 /6 /7 ib",
        "Test (and set / reset / complement) one bit.",
        "Copies the selected bit into CF; bts also sets it, btr clears it, btc flips it. Common for bitfields of "
        "flags such as unlocked items or status effects.",
        "CF = the bit (others undefined)", "bt eax, 0x3", "0F BA E0 03", "");
    Add(v, L, "bsf / bsr", "bsf bsr", "0F BC /r  0F BD /r",
        "Find the lowest / highest set bit.",
        "Writes the index of the first set bit from the bottom (bsf) or top (bsr). ZF = 1 and the destination is "
        "undefined when the source is zero.",
        "ZF (others undefined)", "bsf eax, ecx", "0F BC C1", "");
    Add(v, L, "tzcnt / lzcnt", "tzcnt lzcnt", "F3 0F BC /r  F3 0F BD /r",
        "Count trailing / leading zero bits.",
        "Newer replacements for bsf/bsr that are defined for zero (the result is the operand width). The F3 "
        "prefix makes the difference; on old CPUs they silently run as bsf/bsr.",
        "CF ZF", "tzcnt eax, ecx", "F3 0F BC C1", "");
    Add(v, L, "popcnt", "", "F3 0F B8 /r",
        "Count the set bits.",
        "Number of 1 bits in the source, for example how many flags in a bitmask are on.",
        "ZF (others cleared)", "popcnt eax, ecx", "F3 0F B8 C1", "");

    // ---------------------------------------------------------------- Shifts & rotates
    const char* S = "Shifts & rotates";
    Add(v, S, "shl / sal", "shl sal", "D0 /4  D1 /4 (by 1)  D2 /4  D3 /4 (by cl)  C0 /4 ib  C1 /4 ib",
        "Shift left.",
        "Moves bits toward the top, filling with zeros; each step multiplies by 2. The last bit shifted out goes "
        "to CF. sal is the same instruction.",
        "CF OF SF ZF PF", "shl eax, 0x4", "C1 E0 04", "");
    Add(v, S, "shr", "", "D0 /5  D1 /5  D2 /5  D3 /5  C0 /5 ib  C1 /5 ib",
        "Logical shift right.",
        "Moves bits toward the bottom, filling with zeros: unsigned divide by a power of two.",
        "CF OF SF ZF PF", "shr eax, 1", "D1 E8", "");
    Add(v, S, "sar", "", "D0 /7  D1 /7  D2 /7  D3 /7  C0 /7 ib  C1 /7 ib",
        "Arithmetic shift right.",
        "Like shr but copies the sign bit in from the top, so it divides signed values (rounding toward minus "
        "infinity). sar eax, 31 gives 0 or -1 depending on the sign.",
        "CF OF SF ZF PF", "sar eax, 0x1F", "C1 F8 1F", "");
    Add(v, S, "rol / ror", "rol ror", "D0-D3 /0 /1  C0 /0 /1 ib  C1 /0 /1 ib",
        "Rotate left / right.",
        "Bits shifted out of one end come back in the other. Common in hashes, checksums and decryption "
        "routines.",
        "CF OF", "rol eax, 0x8", "C1 C0 08", "");
    Add(v, S, "rcl / rcr", "rcl rcr", "D0-D3 /2 /3  C0 /2 /3 ib  C1 /2 /3 ib",
        "Rotate through carry.",
        "Rotates with CF as an extra 33rd (65th) bit. Rare outside multi-word arithmetic.",
        "CF OF", "rcl eax, 1", "D1 D0", "");
    Add(v, S, "shld / shrd", "shld shrd", "0F A4 /r ib  0F A5 /r (cl)  0F AC /r ib  0F AD /r (cl)",
        "Double-precision shift.",
        "Shifts the destination while feeding in bits from a second register, used to shift values wider than "
        "one register.",
        "CF SF ZF PF (OF undefined)", "shld eax, ecx, 0x4", "0F A4 C8 04", "");

    // ---------------------------------------------------------------- Compare & test
    const char* C = "Compare & test";
    Add(v, C, "cmp", "", "38-3D  80 /7 ib  81 /7 id  83 /7 ib",
        "Compare two values (subtract and keep only the flags).",
        "Computes dest - src, sets the flags and throws the result away. The next instruction is almost always a "
        "jcc, setcc or cmovcc that reads those flags. Signed comparisons use jl/jg/jle/jge; unsigned use "
        "jb/ja/jbe/jae.",
        kArithFlags, "cmp eax, 0x64", "83 F8 64",
        "Change the immediate to move a threshold (level cap, price check), or patch the jump that follows "
        "instead.");
    Add(v, C, "test", "", "84 /r  85 /r  A8 ib  A9 id  F6 /0 ib  F7 /0 id",
        "AND two values and keep only the flags.",
        "test eax, eax is how compilers check for zero or a null pointer (then je/jne). test al, 1 checks a "
        "single bit, such as a bool.",
        kLogicFlags, "test eax, eax", "85 C0",
        "test eax, eax / je skip guards an 'if (ptr)' or 'if (alive)': force or remove the je to change the "
        "outcome.");
    Add(v, C, "ucomiss / comiss", "ucomiss comiss ucomisd comisd",
        "0F 2E /r (ucomiss)  0F 2F /r (comiss)  66 0F 2E /r (ucomisd)  66 0F 2F /r (comisd)",
        "Compare floats and set the integer flags.",
        "Compares the low float (ss) or double (sd) of two XMM operands and sets ZF, PF and CF like an "
        "unsigned compare, so the branches that follow are ja/jb/jae/jbe. PF = 1 means one side was NaN.",
        "ZF PF CF (OF SF AF cleared)", "ucomiss xmm0, xmm1", "0F 2E C1",
        "Float checks such as 'if (health <= 0.0f)' compile to ucomiss/comiss followed by jbe or jae.");

    // ---------------------------------------------------------------- Jumps & calls
    const char* J = "Jumps & calls";
    Add(v, J, "jmp", "", "EB cb (short)  E9 cd (near)  FF /4 (indirect)  FF /5 (far)",
        "Jump unconditionally.",
        "EB jumps -128..+127 bytes, E9 anywhere within 2 GB, both relative to the end of the instruction. FF /4 "
        "jumps to an address held in a register or memory (switch tables, thunks, import stubs: FF 25 is jmp "
        "[rip+disp]).",
        "", "jmp 0x1005 (from 0x1000)", "EB 03",
        "Target = address of the next instruction + offset. To skip a block, overwrite its first bytes with EB "
        "and the distance to jump.");
    Add(v, J, "call", "", "E8 cd  FF /2 (indirect)",
        "Call a function.",
        "Pushes the address of the next instruction, then jumps. E8 is relative (like E9); FF 15 calls through a "
        "pointer in memory (imported functions), FF D0 calls rax (virtual functions, callbacks).",
        "", "call qword ptr [rip+0x7DA7]", "FF 15 A7 7D 00 00",
        "NOP the whole call (5 bytes for E8: 0F 1F 44 00 00) to stop a function running, as long as nothing "
        "afterwards needs its return value in rax.");
    Add(v, J, "ret", "retn retf", "C3  C2 iw (pop extra bytes)  CB / CA (far)",
        "Return from a function.",
        "Pops the return address and jumps there. C2 iw also removes iw bytes of arguments (32-bit stdcall). The "
        "return value is already in eax/rax (or xmm0 for floats).",
        "", "ret", "C3",
        "Writing C3 at a function's first byte makes it do nothing (void functions). For a return value, put it "
        "in eax first: 31 C0 C3 returns 0, B0 01 C3 returns true.");
    Add(v, J, "loop", "loope loopne", "E2 cb  E1 cb (loope)  E0 cb (loopne)",
        "Decrement rcx and jump if it is not zero.",
        "loop decrements rcx (ecx) without touching flags and jumps while it is non-zero. Rare in compiled code "
        "(dec + jnz is faster) but common in hand-written assembly and packers.",
        "", "loop -0x7 (back to 5 bytes before itself)", "E2 F9", "");
    Add(v, J, "jrcxz", "jecxz jcxz", "E3 cb",
        "Jump if rcx (ecx) is zero.",
        "Tests the count register directly, without flags. Usually guards a loop that should run zero times.",
        "", "jrcxz +0x10", "E3 10", "");

    // ---------------------------------------------------------------- Conditional jumps (one per condition)
    for (const Cond& c : kConds)
    {
        char mn[8], enc[64], summary[96], ex[64], exb[16], tip[256];
        snprintf(mn, sizeof(mn), "j%s", c.name);
        snprintf(enc, sizeof(enc), "%X cb (short)  0F %X cd (near)", 0x70 + c.cc, 0x80 + c.cc);
        snprintf(summary, sizeof(summary), "Jump if %s.", c.meaning);
        snprintf(ex, sizeof(ex), "%s +0x10", mn);
        snprintf(exb, sizeof(exb), "%X 10", 0x70 + c.cc);
        const Cond& inv = kConds[c.cc ^ 1];
        snprintf(tip, sizeof(tip),
                 "Invert it with j%s (%X / 0F %X: flip the lowest bit). Always jump: EB; never jump: 66 90 for the "
                 "short form, 66 0F 1F 44 00 00 for the 6-byte near form.",
                 inv.name, 0x70 + inv.cc, 0x80 + inv.cc);
        std::string details = std::string("Jumps when ") + c.test + ". ";
        if (!strcmp(c.kind, "signed"))
            details += "This is a SIGNED comparison: after cmp a, b it jumps when a is " + std::string(c.meaning) +
                       " b treating both as signed integers. Health, positions and deltas are usually signed.";
        else if (!strcmp(c.kind, "unsigned"))
            details += "This is an UNSIGNED comparison: after cmp a, b it jumps when a is " +
                       std::string(c.meaning) +
                       " b treating both as unsigned. Also used after float compares (ucomiss), pointer and size "
                       "checks.";
        else if (!strcmp(c.kind, "either"))
            details += "After cmp it means the operands were equal (or, for jne, different); after test eax, eax "
                       "it means the value was zero (non-zero). Works for signed and unsigned alike.";
        else
            details += "It reads a single flag directly, usually after arithmetic rather than cmp.";
        details += " The short form reaches -128..+127 bytes, the near form +-2 GB; both are relative to the end "
                   "of the jump.";
        v.push_back({ mn, c.aliases, "Conditional jumps", enc, summary, details, "", ex, exb, tip });
    }

    // ---------------------------------------------------------------- Stack & flags
    const char* K = "Stack & flags";
    Add(v, K, "push", "", "50+r  FF /6  6A ib  68 id",
        "Push a value onto the stack.",
        "Decrements rsp by 8 (esp by 4) and stores the value. Function prologues push the non-volatile "
        "registers they use (rbx, rbp, rdi, rsi, r12-r15); 32-bit code also pushes arguments.",
        "", "push rbx", "53", "");
    Add(v, K, "pop", "", "58+r  8F /0",
        "Pop a value off the stack.",
        "Loads from [rsp] and adds 8 (4). Epilogues pop saved registers in reverse order before ret.",
        "", "pop rbx", "5B", "");
    Add(v, K, "enter / leave", "enter leave", "C8 iw ib  C9",
        "Set up / tear down a stack frame.",
        "leave is mov rsp, rbp then pop rbp, undoing push rbp / mov rbp, rsp. enter does the setup but is slow "
        "and rarely emitted.",
        "", "leave", "C9", "");
    Add(v, K, "pushf / popf", "pushfq popfq pushfd popfd", "9C  9D",
        "Save / restore the flags register.",
        "Copies rflags to or from the stack. Hooks and code caves use pushfq / popfq to preserve flags around "
        "injected code.",
        "popf writes all flags", "pushfq", "9C",
        "In a cave, wrap code that changes flags with pushfq ... popfq if the original code tests flags right "
        "after the hook.");
    Add(v, K, "clc / stc / cmc", "clc stc cmc", "F8  F9  F5",
        "Clear / set / complement the carry flag.",
        "Direct control of CF; some routines return success or failure in CF.",
        "CF", "stc", "F9", "");
    Add(v, K, "cld / std", "cld std", "FC  FD",
        "Clear / set the direction flag.",
        "DF controls whether string instructions (movs, stos ...) walk forward (cld) or backward (std). The "
        "Windows ABI requires DF = 0 on function entry and exit.",
        "DF", "cld", "FC", "");
    Add(v, K, "lahf / sahf", "lahf sahf", "9F  9E",
        "Copy flags to / from ah.",
        "Moves SF ZF AF PF CF between the flags and ah. Mostly seen in old x87 floating point code.",
        "sahf writes SF ZF AF PF CF", "lahf", "9F", "");

    // ---------------------------------------------------------------- Strings
    const char* T = "Strings";
    Add(v, T, "rep", "repe repz repne repnz", "F3 (rep / repe)  F2 (repne)",
        "Repeat the following string instruction rcx times.",
        "rep movs is an inline memcpy, rep stos an inline memset. repe / repne also stop early on a compare "
        "result (cmps, scas). On SSE instructions F3 and F2 are not repeats but part of the opcode (F3 = ss, "
        "F2 = sd).",
        "", "rep movsb", "F3 A4", "");
    Add(v, T, "movs", "movsb movsw movsd movsq", "A4 (byte)  A5 (word/dword/qword)",
        "Copy from [rsi] to [rdi] and advance both.",
        "With rep it copies rcx elements: memcpy. Note movsd here is the string move, not the SSE double move "
        "(F2 0F 10).",
        "", "rep movsb", "F3 A4", "");
    Add(v, T, "stos", "stosb stosw stosd stosq", "AA (byte)  AB (word/dword/qword)",
        "Store al/ax/eax/rax to [rdi] and advance.",
        "With rep it fills rcx elements: memset. rep stosd with eax = 0 clears a struct.",
        "", "rep stosb", "F3 AA", "");
    Add(v, T, "lods", "lodsb lodsw lodsd lodsq", "AC  AD",
        "Load from [rsi] into al/ax/eax/rax and advance.",
        "Steps through a buffer one element at a time; rarely used with rep.",
        "", "lodsb", "AC", "");
    Add(v, T, "scas", "scasb scasw scasd scasq", "AE  AF",
        "Compare al/ax/eax/rax with [rdi] and advance.",
        "repne scasb with al = 0 finds a string's terminator: an inline strlen.",
        kArithFlags, "repne scasb", "F2 AE", "");
    Add(v, T, "cmps", "cmpsb cmpsw cmpsd cmpsq", "A6  A7",
        "Compare [rsi] with [rdi] and advance both.",
        "repe cmpsb compares two buffers until they differ: memcmp.",
        kArithFlags, "repe cmpsb", "F3 A6", "");

    // ---------------------------------------------------------------- SSE floating point
    const char* F = "Floating point (SSE)";
    Add(v, F, "movss", "", "F3 0F 10 /r (load)  F3 0F 11 /r (store)",
        "Move a single float.",
        "Loads or stores a 32-bit float through the low lane of an XMM register. Games keep positions, health "
        "and speeds as floats, so these are the loads and stores you find with 'what accesses'.",
        "", "movss xmm0, dword ptr [rcx+0x20]", "F3 0F 10 41 20",
        "The store form (F3 0F 11) writing a float field can be NOPed (5 bytes here: 0F 1F 44 00 00) to freeze "
        "it.");
    Add(v, F, "movsd (SSE)", "movsd", "F2 0F 10 /r (load)  F2 0F 11 /r (store)",
        "Move a double.",
        "The 64-bit floating point version of movss. Not the same as the string movsd (A5).",
        "", "movsd xmm0, qword ptr [rcx+0x28]", "F2 0F 10 41 28", "");
    Add(v, F, "movaps / movups", "movaps movups movapd movupd movdqa movdqu", "0F 28 /r  0F 29 /r  0F 10 /r  0F 11 /r",
        "Move 16 bytes (four floats).",
        "Copies a whole XMM register. aps requires 16-byte aligned memory (else it crashes); ups does not. "
        "Compilers use these to copy vectors, matrices and small structs.",
        "", "movaps xmm1, xmm0", "0F 28 C8", "");
    Add(v, F, "addss / addsd", "addss addsd addps addpd", "F3 0F 58 /r  F2 0F 58 /r  0F 58 /r  66 0F 58 /r",
        "Add floats.",
        "ss = one float, sd = one double, ps = four floats, pd = two doubles.",
        "", "addss xmm0, xmm1", "F3 0F 58 C1", "");
    Add(v, F, "subss / subsd", "subss subsd subps subpd", "F3 0F 5C /r  F2 0F 5C /r  0F 5C /r",
        "Subtract floats.",
        "Float damage, stamina drain and timers usually end in a subss followed by a movss store.",
        "", "subss xmm0, xmm1", "F3 0F 5C C1",
        "NOP the store after the subss rather than the subss itself, so the register stays consistent.");
    Add(v, F, "mulss / mulsd", "mulss mulsd mulps mulpd", "F3 0F 59 /r  F2 0F 59 /r  0F 59 /r",
        "Multiply floats.",
        "Scaling: speed * deltaTime, damage * multiplier.",
        "", "mulss xmm0, xmm1", "F3 0F 59 C1",
        "A multiplier read from a constant (mulss xmm0, [rip+disp]) can be changed by editing that constant in "
        "memory.");
    Add(v, F, "divss / divsd", "divss divsd divps divpd", "F3 0F 5E /r  F2 0F 5E /r  0F 5E /r",
        "Divide floats.",
        "", "", "divss xmm0, xmm1", "F3 0F 5E C1", "");
    Add(v, F, "sqrtss / sqrtsd", "sqrtss sqrtsd sqrtps", "F3 0F 51 /r  F2 0F 51 /r  0F 51 /r",
        "Square root.",
        "Usually part of a distance or vector-length calculation: sqrt(x*x + y*y + z*z).",
        "", "sqrtss xmm0, xmm0", "F3 0F 51 C0", "");
    Add(v, F, "minss / maxss", "minss maxss minsd maxsd minps maxps", "F3 0F 5D /r  F3 0F 5F /r",
        "Minimum / maximum.",
        "Clamping, for example health = min(health, maxHealth).",
        "", "minss xmm0, xmm1", "F3 0F 5D C1",
        "Swapping a minss for a maxss (5D to 5F) turns a cap into a floor.");
    Add(v, F, "cvtsi2ss / cvtsi2sd", "cvtsi2ss cvtsi2sd", "F3 0F 2A /r  F2 0F 2A /r",
        "Convert an integer to a float / double.",
        "", "", "cvtsi2ss xmm0, eax", "F3 0F 2A C0", "");
    Add(v, F, "cvttss2si / cvttsd2si", "cvttss2si cvttsd2si cvtss2si", "F3 0F 2C /r  F2 0F 2C /r",
        "Convert a float to an integer, truncating.",
        "This is what (int)someFloat compiles to. The non-t versions round instead.",
        "", "cvttss2si eax, xmm0", "F3 0F 2C C0", "");
    Add(v, F, "cvtss2sd / cvtsd2ss", "cvtss2sd cvtsd2ss", "F3 0F 5A /r  F2 0F 5A /r",
        "Convert between float and double.",
        "", "", "cvtss2sd xmm0, xmm0", "F3 0F 5A C0", "");
    Add(v, F, "xorps / andps / orps", "xorps andps orps xorpd andpd pxor pand por",
        "0F 57 /r  0F 54 /r  0F 56 /r  66 0F EF /r (pxor)",
        "Bitwise operations on XMM registers.",
        "xorps xmm0, xmm0 zeroes a register (0.0f). xorps with a sign-bit mask negates floats; andps with the "
        "inverse mask is fabs().",
        "", "xorps xmm0, xmm0", "0F 57 C0", "");
    Add(v, F, "shufps / unpcklps", "shufps unpcklps unpckhps pshufd", "0F C6 /r ib  0F 14 /r  66 0F 70 /r ib",
        "Rearrange lanes in an XMM register.",
        "Moves floats between the four lanes, typically to build or split vectors (x, y, z, w).",
        "", "shufps xmm0, xmm0, 0x0", "0F C6 C0 00", "");

    // ---------------------------------------------------------------- x87 & AVX
    const char* X = "x87 & AVX";
    Add(v, X, "VEX / AVX forms", "vmovss vmovaps vaddss vmulss vxorps vmovups", "C5 (2-byte VEX)  C4 (3-byte VEX)  62 (EVEX, AVX-512)",
        "AVX versions of SSE instructions, prefixed with v.",
        "vaddss xmm0, xmm1, xmm2 does the same maths as addss but takes a separate destination, and the ymm "
        "forms work on 256 bits. The VEX prefix (C5 or C4) replaces the 66/F2/F3 and REX prefixes, so the bytes "
        "look different even though the operation matches.",
        "", "vmovss xmm0, dword ptr [rcx]", "C5 FA 10 01",
        "A VEX instruction is a single unit: NOP all of its bytes, never just part of it.");
    Add(v, X, "fld / fstp", "fld fst fstp fild fistp", "D9 /0 (fld m32)  DD /0 (fld m64)  D9 /3 (fstp m32)  DD /3",
        "x87 floating point load / store.",
        "The pre-SSE floating point unit, a stack of eight 80-bit registers st(0)..st(7). Still common in 32-bit "
        "games and code built with old compilers.",
        "", "fld dword ptr [rcx]", "D9 01", "");
    Add(v, X, "fadd / fsub / fmul / fdiv", "fadd faddp fsub fsubp fmul fmulp fdiv fdivp", "D8 /0 /4 /1 /6  DC ...  DE ...",
        "x87 arithmetic.",
        "Operates on st(0) and a memory operand or another stack register; the p forms also pop.",
        "", "fadd dword ptr [rcx]", "D8 01", "");

    // ---------------------------------------------------------------- System & misc
    const char* M = "System & misc";
    Add(v, M, "nop", "", "90  0F 1F /0 (multi-byte)",
        "Do nothing.",
        "90 is one byte. 0F 1F /0 is a family of longer NOPs that compilers use to align code and that patchers "
        "use to erase an instruction in one piece (see Modding recipes > NOP widths).",
        "", "nop dword ptr [rax+rax*1+0x0]", "0F 1F 44 00 00",
        "Prefer one multi-byte NOP over several 90s: the disassembly stays clean and it is a single instruction.");
    Add(v, M, "int3", "", "CC",
        "Breakpoint.",
        "Raises a breakpoint exception; debuggers write CC to set software breakpoints. Compilers pad the gaps "
        "between functions with CC, so a run of CCs marks where a function ends and the next begins.",
        "", "int3", "CC", "If code you patched shows CC where an instruction should be, a debugger may have a breakpoint there.");
    Add(v, M, "int", "", "CD ib",
        "Software interrupt.",
        "int 0x2E and int 0x80 were old system-call gates; int 0x29 is __fastfail (instant termination), often "
        "after a security check fails.",
        "", "int 0x29", "CD 29", "");
    Add(v, M, "ud2", "", "0F 0B",
        "Undefined instruction: always crashes.",
        "Deliberately raises #UD. Compilers place it after code that must not be reached (unreachable switch "
        "cases, failed asserts).",
        "", "ud2", "0F 0B", "");
    Add(v, M, "hlt", "", "F4",
        "Halt.",
        "Privileged; in user mode it simply crashes. Seen in kernel idle loops.",
        "", "hlt", "F4", "");
    Add(v, M, "syscall", "sysenter", "0F 05  0F 34",
        "Call the kernel.",
        "Enters the operating system with the call number in eax. In Windows user code it lives inside ntdll's "
        "Nt* stubs: mov r10, rcx / mov eax, N / syscall. A syscall elsewhere in a game usually means anti-cheat or "
        "DRM making direct calls.",
        "", "syscall", "0F 05", "");
    Add(v, M, "cpuid", "", "0F A2",
        "Query the processor.",
        "Returns CPU vendor and feature bits in eax..edx. Also used by anti-debug and virtual machine checks.",
        "", "cpuid", "0F A2", "");
    Add(v, M, "rdtsc", "rdtscp", "0F 31  0F 01 F9",
        "Read the time-stamp counter.",
        "Puts the CPU cycle counter in edx:eax. Used for timing, and by anti-debug code that measures how long a "
        "stretch of code took (a breakpoint makes it far longer).",
        "", "rdtsc", "0F 31", "");
    Add(v, M, "pause", "", "F3 90",
        "Spin-wait hint.",
        "A NOP that tells the CPU it is in a spin loop waiting for a lock.",
        "", "pause", "F3 90", "");
    Add(v, M, "endbr64", "endbr32", "F3 0F 1E FA  F3 0F 1E FB",
        "Indirect branch target marker (CET).",
        "Marks a valid target for indirect jumps and calls under Control-flow Enforcement. On CPUs without CET it "
        "is a NOP. Often the first instruction of a function.",
        "", "endbr64", "F3 0F 1E FA", "Hook after an endbr64, not over it, if the game has CET enabled.");
    Add(v, M, "lock", "", "F0",
        "Make the next read-modify-write atomic.",
        "A prefix for add, sub, inc, dec, xadd, cmpxchg, and so on with a memory operand, so other threads can't "
        "interleave. Reference counts and thread-safe counters use it.",
        "", "lock inc dword ptr [rcx]", "F0 FF 01", "");
    Add(v, M, "mfence / lfence / sfence", "mfence lfence sfence", "0F AE F0  0F AE E8  0F AE F8",
        "Memory ordering barriers.",
        "Stop loads and/or stores being reordered across them. lfence also appears as a speculation barrier "
        "(Spectre mitigations).",
        "", "mfence", "0F AE F0", "");
    Add(v, M, "prefetch", "prefetcht0 prefetcht1 prefetcht2 prefetchnta", "0F 18 /1 /2 /3 /0",
        "Hint that memory will be needed soon.",
        "Brings a cache line closer without changing anything visible. Safe to NOP.",
        "", "prefetcht0 byte ptr [rcx]", "0F 18 09", "");

    // ---------------------------------------------------------------- Encoding
    const char* E = "Encoding";
    Add(v, E, "Instruction layout", "format layout bytes", "[prefixes] [REX] opcode [ModRM] [SIB] [disp] [imm]",
        "How the bytes of one instruction fit together.",
        "Up to 15 bytes: optional legacy prefixes (66, 67, F0, F2, F3, segment), an optional REX (40-4F) in "
        "64-bit code, the opcode (1-3 bytes, starting with 0F for the extended maps), a ModRM byte choosing the "
        "operands, an optional SIB byte for scaled-index addressing, then a displacement and/or immediate stored "
        "little-endian.",
        "", "mov dword ptr [rcx+rax*4+0x10], 0x64", "C7 44 81 10 64 00 00 00",
        "Patch whole instructions. Writing only part of one leaves the leftover bytes to be decoded as garbage.");
    Add(v, E, "REX prefix", "rex rex.w rex.r rex.x rex.b 48 49 4c", "40-4F  (0100 W R X B)",
        "64-bit operand size and access to r8-r15.",
        "W = 64-bit operands (48 = REX.W). R, X and B add a fourth bit to the ModRM reg, SIB index and base/rm "
        "fields, which is how r8-r15 are reached: 49 8B 01 is mov rax, [r9]. Must come right before the opcode.",
        "", "mov rax, qword ptr [rcx]", "48 8B 01",
        "That's why so many x64 instructions start with 48: drop it and the same bytes operate on 32 bits.");
    Add(v, E, "ModRM byte", "modrm mod reg rm", "mod(2) reg(3) rm(3)",
        "Chooses the operands.",
        "mod = 11 means rm is a register; 00 / 01 / 10 mean memory with no / 8-bit / 32-bit displacement. reg is "
        "a register or, for group opcodes (the /digit notation), an extension of the opcode. rm = 100 means a "
        "SIB byte follows. mod 00 + rm 101 means RIP-relative in 64-bit code.\n\nRegister numbers: 0 eax, 1 ecx, "
        "2 edx, 3 ebx, 4 esp, 5 ebp, 6 esi, 7 edi (8-15 r8-r15 with REX).",
        "", "mov eax, dword ptr [rcx+0x24]   (ModRM 41 = 01 000 001)", "8B 41 24", "");
    Add(v, E, "SIB byte", "sib scale index base", "scale(2) index(3) base(3)",
        "Scaled-index addressing.",
        "Encodes [base + index * scale]; scale is 1, 2, 4 or 8. Array accesses look like [rcx+rax*4] where rax is "
        "the index and 4 the element size.",
        "", "mov eax, dword ptr [rcx+rax*4]", "8B 04 81",
        "The scale tells you the element size: *4 int/float, *8 pointer or double.");
    Add(v, E, "RIP-relative addressing", "rip relative disp32 global", "ModRM mod=00 rm=101 + disp32",
        "Address = next instruction's address + disp32.",
        "How x64 code reaches globals, constants and imported function pointers. The disp32 changes whenever "
        "code or data move between builds, but the target stays the same object.",
        "", "mov eax, dword ptr [rip+0x5BA5]", "8B 05 A5 5B 00 00",
        "In AOB signatures wildcard the four disp bytes; the AOB Scan window resolves the absolute target for "
        "you.");
    Add(v, E, "Operand-size and address prefixes", "66 67 prefix", "66 (16-bit operand)  67 (32-bit address)",
        "Change the operand or address size.",
        "66 switches a 32-bit operation to 16 bits (66 89 01 is mov word ptr [rcx], ax) and selects the double / "
        "integer variants of SSE instructions. 67 makes addresses 32-bit in 64-bit code.",
        "", "mov word ptr [rcx], ax", "66 89 01", "");
    Add(v, E, "Segment prefixes (fs / gs)", "fs gs teb peb segment 64 65", "2E CS  36 SS  3E DS  26 ES  64 FS  65 GS",
        "Thread-local and process structures.",
        "On x64 Windows gs points at the TEB (thread block): gs:[0x30] is the TEB itself, gs:[0x58] the TLS array "
        "and gs:[0x60] the PEB. On x86 the same lives in fs (fs:[0x30] = PEB). gs:[0x60] -> PEB+2 is "
        "BeingDebugged, a classic anti-debug check.",
        "", "mov rax, qword ptr gs:[0x60]", "65 48 8B 04 25 60 00 00 00", "");
    Add(v, E, "Two- and three-byte opcodes", "0f escape 0f38 0f3a", "0F xx  0F 38 xx  0F 3A xx",
        "The extended opcode maps.",
        "0F introduces the second opcode map (movzx, jcc near, setcc, cmovcc, SSE). 0F 38 and 0F 3A hold newer SSE "
        "and AVX instructions.",
        "", "je near +0x100", "0F 84 00 01 00 00", "");
    Add(v, E, "Little-endian immediates", "endian immediate byte order", "least significant byte first",
        "Multi-byte numbers are stored backwards.",
        "100 (0x64) as a 32-bit immediate is 64 00 00 00; 0x12345678 is 78 56 34 12. The same goes for "
        "displacements, branch offsets and everything in memory.",
        "", "mov eax, 0x12345678", "B8 78 56 34 12", "");

    // ---------------------------------------------------------------- Modding recipes
    const char* R = "Modding recipes";
    Add(v, R, "NOP widths", "nop multibyte fill erase", "1-9 bytes",
        "Single-instruction NOPs of every length.",
        "1: 90\n2: 66 90\n3: 0F 1F 00\n4: 0F 1F 40 00\n5: 0F 1F 44 00 00\n6: 66 0F 1F 44 00 00\n7: 0F 1F 80 00 "
        "00 00 00\n8: 0F 1F 84 00 00 00 00 00\n9: 66 0F 1F 84 00 00 00 00 00\nCombine them for longer runs.",
        "", "nop word ptr [rax+rax*1+0x0]", "66 0F 1F 44 00 00",
        "The Patches tab and the Memory View assembler already pick the right width for you.");
    Add(v, R, "Freeze a value by NOPing its write", "freeze infinite health god mode", "",
        "Stop the game changing a value.",
        "1. Find the value with the Scanner.\n2. Right-click it in the Address List: 'Find out what writes to this "
        "address'.\n3. Take damage; the instruction that ran shows up (often sub, mov or movss).\n4. NOP it, or "
        "use 'Find out what accesses' if it's computed elsewhere.\nCheck the same code doesn't also update "
        "enemies: if it does, use a code cave that compares the object first.",
        "", "sub dword ptr [rcx+0x24], eax  ->  nop", "29 41 24  ->  0F 1F 00", "");
    Add(v, R, "Force a jump", "always jump je to jmp", "74 xx -> EB xx   0F 84 xx xx xx xx -> 90 E9 xx xx xx xx",
        "Make a conditional jump always taken.",
        "For a short jcc, replace the opcode with EB and keep the offset. For a near jcc (0F 8x + rel32), "
        "replace the two opcode bytes with 90 E9; the offset still lines up because the jump still ends at the "
        "same address.",
        "", "je +0x10  ->  jmp +0x10", "74 10  ->  EB 10", "");
    Add(v, R, "Never jump", "skip branch remove check", "short: 66 90   near: 66 0F 1F 44 00 00",
        "Make a conditional jump never taken.",
        "Overwrite the whole jump with a NOP of the same length, so execution always falls through to the next "
        "instruction.",
        "", "jne +0x10  ->  nop", "75 10  ->  66 90", "");
    Add(v, R, "Invert a condition", "flip reverse condition", "flip bit 0 of the opcode",
        "Swap je/jne, jl/jge, jb/jae ...",
        "Condition codes come in pairs that differ only in the lowest bit: 74 <-> 75, 7C <-> 7D, 0F 84 <-> 0F 85. "
        "Same for setcc (0F 94 <-> 0F 95) and cmovcc.",
        "", "je +0x10  ->  jne +0x10", "74 10  ->  75 10", "");
    Add(v, R, "Return early with a value", "return true false zero one stub", "",
        "Make a function exit immediately.",
        "At the function's first instruction:\nreturn (void): C3\nreturn 0 / false: 31 C0 C3\nreturn true "
        "(bool): B0 01 C3\nreturn 1: B8 01 00 00 00 C3\nreturn a float 0.0: 0F 57 C0 C3 (xorps xmm0, xmm0)\nOn "
        "32-bit stdcall functions use C2 nn 00 to remove the arguments.",
        "", "xor eax, eax ; ret", "31 C0 C3", "");
    Add(v, R, "Change a constant", "immediate value edit multiplier", "",
        "Edit the number baked into an instruction.",
        "Find the immediate (the last bytes, little-endian) and overwrite it. Short forms like 83 /0 ib hold "
        "only -128..127; for bigger values the instruction has to be re-encoded. The cave 'set value' box "
        "does that for you.",
        "", "add eax, 0x5  ->  add eax, 0x64", "83 C0 05  ->  83 C0 64", "");
    Add(v, R, "Code cave basics", "cave trampoline hook detour inject", "",
        "Run your own code at a hook point.",
        "A detour overwrites the entry with a jump (5 bytes E9 rel32 or 14 bytes FF 25 + absolute address) to "
        "newly allocated memory. There you run the stolen original instructions plus your own code, then jump "
        "back. Right-click a function in the Memory View > Detour this function > Trampoline cave sets all of "
        "this up.",
        "", "jmp qword ptr [rip+0x0] ; <8-byte address>", "FF 25 00 00 00 00 ...", "");
    Add(v, R, "Calling conventions (x64 Windows)", "abi arguments registers rcx rdx r8 r9 shadow space volatile", "",
        "Where arguments and return values live.",
        "Arguments 1-4: rcx, rdx, r8, r9 (xmm0-xmm3 for floats); the rest on the stack. Return: rax or xmm0. "
        "The caller reserves 32 bytes of shadow space. Volatile (may be clobbered): rax rcx rdx r8-r11 "
        "xmm0-xmm5. Non-volatile (callee must preserve): rbx rbp rdi rsi rsp r12-r15 xmm6-xmm15. A member "
        "function receives 'this' in rcx.",
        "", "mov rcx, rbx ; call ...   (rcx = this)", "48 8B CB E8 ...",
        "In a hook, rcx at the entry is usually the object pointer: [rcx+offset] is a field of the player or "
        "entity.");
    Add(v, R, "Calling conventions (x86)", "cdecl stdcall thiscall fastcall 32-bit", "",
        "32-bit argument passing.",
        "cdecl: arguments pushed right to left, caller cleans up (add esp, n after the call). stdcall (WinAPI): "
        "callee cleans up with ret n. thiscall (MSVC member functions): 'this' in ecx. fastcall: first two in ecx, "
        "edx. Return value in eax (edx:eax for 64-bit), floats in st(0).",
        "", "push 0x1 ; push eax ; call ... ; add esp, 0x8", "6A 01 50 E8 ... 83 C4 08", "");
    Add(v, R, "Find a function's start", "prologue epilogue function start", "",
        "Recognise prologues and epilogues.",
        "Functions usually start after a run of CC padding with something like push rbx / sub rsp, 0x20 (40 53 "
        "48 83 EC 20), mov [rsp+8], rbx (48 89 5C 24 08) or push rbp / mov rbp, rsp (55 48 8B EC). They end "
        "with add rsp, n / pop ... / ret.",
        "", "sub rsp, 0x28", "48 83 EC 28", "");
    Add(v, R, "Relative jump maths", "rel32 offset target compute branch", "target = next instruction + rel",
        "Work out where a call or jump goes.",
        "For E8/E9 the 4-byte offset is signed and counted from the end of the 5-byte instruction: target = "
        "address + 5 + rel32. For 0F 8x it's address + 6 + rel32; for short jumps address + 2 + rel8. To write a "
        "jump from A to B: rel32 = B - (A + 5).",
        "", "call +0x100 at 0x1000 -> 0x1105", "E8 00 01 00 00",
        "When you move an instruction (as caves do) every relative offset in it must be recomputed. The detour "
        "code does this automatically.");
    Add(v, R, "Find what reads a pointer", "pointer chain multilevel base address", "",
        "Turn a heap address into a stable pointer path.",
        "Heap addresses change every run. Use 'Find out what accesses' on the value: an instruction like mov "
        "eax, [rcx+0x24] tells you the offset (0x24) and that rcx holds the object. Then find what holds rcx, and "
        "repeat until you reach a static (green) address. Or let the Pointer scan window do the search.",
        "", "mov eax, dword ptr [rcx+0x24]", "8B 41 24", "");
    return v;
}
} // namespace

const std::vector<OpcodeRef>& OpcodeReference()
{
    static const std::vector<OpcodeRef> ref = Build();
    return ref;
}

const std::vector<std::string>& OpcodeCategories() { return g_categories; }
