#include "decompiler.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace
{
constexpr size_t kMaxInstructions = 6000;
constexpr uint64_t kUnboundedRange = 0x10000;

struct RuntimeFunction
{
    DWORD begin;
    DWORD end;
    DWORD unwind;
};

// Reads [begin, end) of the function containing `address` from the x64 exception directory.
bool FindFunctionBounds(const Process& proc, uint64_t address, uint64_t& begin, uint64_t& end)
{
    if (!proc.Is64()) return false;
    ModuleInfo mod;
    if (!proc.ModuleFromAddress(address, mod)) return false;

    DWORD lfanew = 0;
    if (!proc.ReadExact(mod.base + 0x3C, &lfanew, sizeof(lfanew))) return false;
    IMAGE_NT_HEADERS64 nt{};
    if (!proc.ReadExact(mod.base + lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_DATA_DIRECTORY dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || dir.Size < sizeof(RuntimeFunction)) return false;

    std::vector<RuntimeFunction> table(dir.Size / sizeof(RuntimeFunction));
    if (!proc.ReadExact(mod.base + dir.VirtualAddress, table.data(), table.size() * sizeof(RuntimeFunction)))
        return false;

    DWORD rva = (DWORD)(address - mod.base);
    auto it = std::upper_bound(table.begin(), table.end(), rva,
                               [](DWORD v, const RuntimeFunction& f) { return v < f.begin; });
    if (it == table.begin()) return false;
    --it;
    if (rva < it->begin || rva >= it->end) return false;
    begin = mod.base + it->begin;
    end = mod.base + it->end;
    return true;
}

std::string Hex(uint64_t v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
    return buf;
}

std::string UIntType(int bits)
{
    switch (bits)
    {
    case 8: return "uint8_t";
    case 16: return "uint16_t";
    case 32: return "uint32_t";
    default: return "uint64_t";
    }
}

// True for a bare identifier, number, deref or parenthesised/cast expression - something that
// does not need extra parentheses before a prefix cast binds to it.
bool IsSimpleExpr(const std::string& e)
{
    if (e.empty()) return true;
    if (e[0] == '(' || e[0] == '*' || e[0] == '~' || e[0] == '-') return true;
    for (char c : e)
        if (!(isalnum((unsigned char)c) || c == '_')) return false;
    return true;
}

bool IsLiteral(const std::string& e)
{
    if (e.empty()) return false;
    size_t i = (e[0] == '-') ? 1 : 0;
    if (i >= e.size()) return false;
    for (; i < e.size(); i++)
        if (!(isalnum((unsigned char)e[i]))) return false;
    return true;
}

std::string Paren(const std::string& e) { return IsSimpleExpr(e) ? e : "(" + e + ")"; }

// Cast `e` to `type`, parenthesising when needed and collapsing a redundant leading cast so we
// never emit (uint32_t)(uint32_t)x or let a cast bind to only the first operand of an expression.
std::string Cast(const std::string& type, const std::string& e)
{
    std::string c = "(" + type + ")";
    if (e.rfind(c, 0) == 0)
    {
        std::string rest = e.substr(c.size());
        return IsSimpleExpr(rest) ? e : c + "(" + rest + ")";
    }
    return c + Paren(e);
}

// Reinterpret an unsigned expression as signed of the same width. Literals and a matching
// unsigned cast are handled so we get (int32_t)x, not (int32_t)((uint32_t)x) or (int32_t)0xA.
std::string Signed(const std::string& e, int bits)
{
    if (bits != 8 && bits != 16 && bits != 32) bits = 64;
    std::string st = "int" + std::to_string(bits) + "_t";
    if (IsLiteral(e)) return e;
    // (int32_t)(uint32_t)x is just (int32_t)x - the signed cast already takes the low bits.
    std::string u = "(" + UIntType(bits) + ")";
    if (e.rfind(u, 0) == 0) return Cast(st, e.substr(u.size()));
    return Cast(st, e);
}

void ReplaceAll(std::string& s, const std::string& from, const std::string& to)
{
    if (from.empty()) return;
    for (size_t p = s.find(from); p != std::string::npos; p = s.find(from, p + to.size()))
        s.replace(p, from.size(), to);
}

std::string Join(const std::vector<std::string>& v, const std::string& sep)
{
    std::string r;
    for (size_t i = 0; i < v.size(); i++) r += (i ? sep : "") + v[i];
    return r;
}

bool IsGprClass(ZydisRegister r)
{
    switch (ZydisRegisterGetClass(r))
    {
    case ZYDIS_REGCLASS_GPR8:
    case ZYDIS_REGCLASS_GPR16:
    case ZYDIS_REGCLASS_GPR32:
    case ZYDIS_REGCLASS_GPR64: return true;
    default: return false;
    }
}

struct Insn
{
    uint64_t address = 0;
    ZydisDecodedInstruction ins{};
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    std::string text;
};

// The last flag-setting instruction, so a following jcc/setcc/cmovcc reads as a condition.
struct Compare
{
    bool valid = false;
    std::string lhs;
    std::string rhs;
    int bits = 64;
};

// A basic block: a run of statements and one way out.
struct Block
{
    enum Kind
    {
        Fall,   // execution falls into the next block
        Jump,   // unconditional branch to `taken`
        Branch, // conditional: `taken` when condT, else next block
        Return, // function returns (retText, or the default)
        End     // dead end (indirect jump, int3, ...)
    };

    uint64_t start = 0;
    std::vector<std::string> stmts;
    Kind kind = Fall;
    uint64_t taken = 0;
    uint64_t fall = 0;
    std::string condT; // Branch taken when this is true
    std::string condF; // the negation, for the fall-through / inverted forms
    std::string retText;
    bool needLabel = false;
};

class Lifter
{
public:
    Lifter(const Process& proc, bool x64) : m_proc(proc), m_x64(x64)
    {
        m_mode = x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
        ZydisDecoderInit(&m_dec, m_mode, x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
        ZydisFormatterInit(&m_fmt, ZYDIS_FORMATTER_STYLE_INTEL);
        ZydisFormatterSetProperty(&m_fmt, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
    }

    bool Run(uint64_t address, std::string& out, std::string& error);

private:
    // Decoding / collection
    bool Decode(uint64_t address, Insn& out);
    bool InFunction(uint64_t a) const { return a >= m_lo && a < m_hi; }
    bool BranchTarget(const Insn& in, uint64_t& target) const;
    bool Collect(uint64_t entry, std::string& error);

    // Per-instruction lifting
    std::string ReadReg(ZydisRegister r);
    void WriteReg(ZydisRegister r, const std::string& value);
    std::string AddressOf(const ZydisDecodedOperand& op);
    std::string ReadOp(const ZydisDecodedOperand& op);
    std::string Immediate(const ZydisDecodedOperand& op) const;
    void Assign(const ZydisDecodedOperand& dst, const std::string& value);
    void SetCompare(const std::string& lhs, const std::string& rhs, int bits);
    std::string Cond(const Insn& in, bool invert) const;
    std::string BinaryExpr(ZydisMnemonic m, const std::string& a, const std::string& b, int bits) const;
    void Emit(const std::string& s) { m_cur ? (void)m_block->stmts.push_back(s) : (void)0; }
    void Unsupported(const Insn& in);
    void Lift(const Insn& in);

    // Blocks / structuring
    void BuildBlocks(uint64_t entry);
    void SetTerminator(Block& b, const Insn& in);
    std::vector<int> Succs(int i) const;
    int Idx(uint64_t a) const
    {
        auto it = m_idx.find(a);
        return it == m_idx.end() ? -1 : it->second;
    }
    bool DetectLoop(int i, int end, int& latch, int& exitIdx) const;
    bool SimpleRegion(int lo, int hi, int brk, int cont) const;
    void EmitRange(int begin, int end, int indent, int brk, int cont, int natExit, std::string& out, int noLoopAt = -1);
    void EmitLoop(int i, int latch, int exitIdx, int indent, std::string& out);
    void Finalize();

    // Naming / formatting
    std::string Ident(uint64_t a) const;
    std::string Label(int i) const { return "L_" + Hex(m_blocks[i].start).substr(2); }
    static std::string Ind(int n) { return std::string((size_t)n * 4, ' '); }

    std::string RetReg() const { return m_x64 ? "rax" : "eax"; }
    std::string RetType() const { return m_returnsValue ? (m_x64 ? "uint64_t" : "uint32_t") : "void"; }
    int RegBits(ZydisRegister r) const { return (int)ZydisRegisterGetWidth(m_mode, r); }
    std::vector<std::string> ArgRegs() const
    {
        return m_x64 ? std::vector<std::string>{ "rcx", "rdx", "r8", "r9" } : std::vector<std::string>{};
    }

    const Process& m_proc;
    bool m_x64;
    ZydisMachineMode m_mode;
    ZydisDecoder m_dec{};
    ZydisFormatter m_fmt{};

    uint64_t m_lo = 0, m_hi = 0;
    bool m_bounded = false, m_truncated = false;

    std::map<uint64_t, Insn> m_insns;
    std::vector<Block> m_blocks;
    std::map<uint64_t, int> m_idx;
    std::vector<std::vector<int>> m_preds;

    std::set<std::string> m_used;    // every register referenced
    std::set<std::string> m_written; // registers written at least once (so far, in address order)
    std::set<std::string> m_inputs;  // registers read before ever written -> look like parameters
    bool m_returnsValue = false;
    bool m_hasCall = false;

    Compare m_cmp;
    const Insn* m_cur = nullptr;
    Block* m_block = nullptr;
};

// --- decoding ---------------------------------------------------------------

bool Lifter::Decode(uint64_t address, Insn& out)
{
    uint8_t buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
    size_t got = m_proc.Read(address, buf, sizeof(buf));
    if (got == 0) return false;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_dec, buf, got, &out.ins, out.ops))) return false;
    out.address = address;
    char text[256];
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&m_fmt, &out.ins, out.ops, out.ins.operand_count_visible, text,
                                                     sizeof(text), address, nullptr)))
        out.text = text;
    return true;
}

bool Lifter::BranchTarget(const Insn& in, uint64_t& target) const
{
    if (in.ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
    return ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&in.ins, &in.ops[0], in.address, &target));
}

std::string Lifter::Ident(uint64_t a) const
{
    ModuleInfo mod;
    char buf[256];
    if (m_proc.ModuleFromAddress(a, mod))
    {
        std::string n = mod.name;
        for (char& c : n)
            if (!isalnum((unsigned char)c)) c = '_';
        snprintf(buf, sizeof(buf), "%s_sub_%llX", n.c_str(), (unsigned long long)(a - mod.base));
    }
    else snprintf(buf, sizeof(buf), "sub_%llX", (unsigned long long)a);
    return buf;
}

bool Lifter::Collect(uint64_t entry, std::string& error)
{
    std::vector<uint64_t> work{ entry };
    while (!work.empty())
    {
        uint64_t a = work.back();
        work.pop_back();
        if (m_insns.count(a) || !InFunction(a)) continue;
        if (m_insns.size() >= kMaxInstructions)
        {
            m_truncated = true;
            break;
        }

        Insn in;
        if (!Decode(a, in))
        {
            if (a == entry)
            {
                error = "Could not read or decode code at " + Hex(a);
                return false;
            }
            continue;
        }
        m_insns[a] = in;

        uint64_t next = a + in.ins.length;
        uint64_t target = 0;
        switch (in.ins.meta.category)
        {
        case ZYDIS_CATEGORY_RET: break;
        case ZYDIS_CATEGORY_UNCOND_BR:
            if (BranchTarget(in, target) && InFunction(target)) work.push_back(target);
            break;
        case ZYDIS_CATEGORY_COND_BR:
            if (BranchTarget(in, target) && InFunction(target)) work.push_back(target);
            work.push_back(next);
            break;
        default:
            if (in.ins.mnemonic == ZYDIS_MNEMONIC_UD2 || in.ins.mnemonic == ZYDIS_MNEMONIC_HLT) break;
            work.push_back(next);
            break;
        }
    }
    return !m_insns.empty();
}

// --- expressions ------------------------------------------------------------

std::string Lifter::ReadReg(ZydisRegister r)
{
    ZydisRegister full = ZydisRegisterGetLargestEnclosing(m_mode, r);
    std::string name = ZydisRegisterGetString(full);
    m_used.insert(name);
    if (!m_written.count(name)) m_inputs.insert(name);
    int bits = RegBits(r);
    if (bits == RegBits(full)) return name;
    if (r == ZYDIS_REGISTER_AH || r == ZYDIS_REGISTER_CH || r == ZYDIS_REGISTER_DH || r == ZYDIS_REGISTER_BH)
        return "(uint8_t)(" + name + " >> 8)";
    return "(" + UIntType(bits) + ")" + name;
}

void Lifter::WriteReg(ZydisRegister r, const std::string& value)
{
    ZydisRegister full = ZydisRegisterGetLargestEnclosing(m_mode, r);
    std::string name = ZydisRegisterGetString(full);
    m_used.insert(name);
    m_written.insert(name);
    if (name == RetReg()) m_returnsValue = true;
    int bits = RegBits(r);

    if (bits == RegBits(full))
    {
        Emit(name + " = " + value + ";");
        return;
    }
    if (r == ZYDIS_REGISTER_AH || r == ZYDIS_REGISTER_CH || r == ZYDIS_REGISTER_DH || r == ZYDIS_REGISTER_BH)
    {
        Emit(name + " = (" + name + " & ~0xFF00ull) | ((" + Paren(value) + " & 0xFF) << 8);");
        return;
    }
    // x64 zero-extends a 32-bit write into the whole register.
    if (bits == 32 && m_x64)
    {
        Emit(name + " = " + (IsLiteral(value) ? value : Cast("uint32_t", value)) + ";");
        return;
    }
    uint64_t mask = (1ull << bits) - 1;
    Emit(name + " = (" + name + " & " + Hex(~mask) + ") | (" + Paren(value) + " & " + Hex(mask) + ");");
}

std::string Lifter::AddressOf(const ZydisDecodedOperand& op)
{
    if (op.mem.base == ZYDIS_REGISTER_RIP)
    {
        uint64_t abs = 0;
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&m_cur->ins, &op, m_cur->address, &abs))) return Hex(abs);
    }

    std::string e;
    auto add = [&e](const std::string& term) { e = e.empty() ? term : e + " + " + term; };
    if (op.mem.segment == ZYDIS_REGISTER_FS) { add("__fs_base"); m_used.insert("__fs_base"); }
    else if (op.mem.segment == ZYDIS_REGISTER_GS) { add("__gs_base"); m_used.insert("__gs_base"); }
    if (op.mem.base != ZYDIS_REGISTER_NONE) add(ReadReg(op.mem.base));
    if (op.mem.index != ZYDIS_REGISTER_NONE)
    {
        std::string idx = ReadReg(op.mem.index);
        add(op.mem.scale > 1 ? idx + " * " + std::to_string(op.mem.scale) : idx);
    }
    if (op.mem.disp.has_displacement && op.mem.disp.value != 0)
    {
        int64_t d = op.mem.disp.value;
        if (e.empty()) add(Hex((uint64_t)d));
        else if (d < 0) e += " - " + Hex((uint64_t)(-d));
        else e += " + " + Hex((uint64_t)d);
    }
    if (e.empty()) e = "0";
    return e;
}

std::string Lifter::Immediate(const ZydisDecodedOperand& op) const
{
    if (op.imm.is_signed && op.imm.value.s < 0) return "-" + Hex(0 - op.imm.value.u);
    uint64_t v = op.imm.value.u;
    if (op.size > 0 && op.size < 64) v &= (1ull << op.size) - 1;
    return Hex(v);
}

std::string Lifter::ReadOp(const ZydisDecodedOperand& op)
{
    switch (op.type)
    {
    case ZYDIS_OPERAND_TYPE_REGISTER: return ReadReg(op.reg.value);
    case ZYDIS_OPERAND_TYPE_IMMEDIATE: return Immediate(op);
    case ZYDIS_OPERAND_TYPE_MEMORY: return "*(" + UIntType(op.size) + "*)(" + AddressOf(op) + ")";
    default: return "0";
    }
}

void Lifter::Assign(const ZydisDecodedOperand& dst, const std::string& value)
{
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) WriteReg(dst.reg.value, value);
    else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
        Emit("*(" + UIntType(dst.size) + "*)(" + AddressOf(dst) + ") = " + value + ";");
}

void Lifter::SetCompare(const std::string& lhs, const std::string& rhs, int bits)
{
    m_cmp = { true, lhs, rhs, bits };
}

std::string Lifter::Cond(const Insn& in, bool invert) const
{
    std::string name = ZydisMnemonicGetString(in.ins.mnemonic);
    std::string cc = name;
    if (cc.rfind("set", 0) == 0) cc = cc.substr(3);
    else if (cc.rfind("cmov", 0) == 0) cc = cc.substr(4);
    else if (cc.rfind("j", 0) == 0) cc = cc.substr(1);

    // Canonicalise the condition code.
    auto canon = [](std::string c) -> std::string {
        if (c == "e") return "z";
        if (c == "ne") return "nz";
        if (c == "nge") return "l";
        if (c == "nl") return "ge";
        if (c == "ng") return "le";
        if (c == "nle") return "g";
        if (c == "c" || c == "nae") return "b";
        if (c == "nb" || c == "nc") return "ae";
        if (c == "na") return "be";
        if (c == "nbe") return "a";
        return c;
    };
    cc = canon(cc);
    if (invert)
    {
        static const std::map<std::string, std::string> neg = {
            { "z", "nz" },  { "nz", "z" }, { "l", "ge" }, { "ge", "l" }, { "le", "g" }, { "g", "le" },
            { "b", "ae" },  { "ae", "b" }, { "be", "a" }, { "a", "be" }, { "s", "ns" }, { "ns", "s" },
            { "o", "no" },  { "no", "o" }, { "p", "np" }, { "np", "p" },
        };
        auto it = neg.find(cc);
        if (it != neg.end()) cc = it->second;
        else return "!(" + Cond(in, false) + ")";
    }

    if (!m_cmp.valid) return "flags_" + cc;
    const std::string& L = m_cmp.lhs;
    const std::string& R = m_cmp.rhs;
    const int b = m_cmp.bits;

    if (cc == "z") return L + " == " + R;
    if (cc == "nz") return L + " != " + R;
    if (cc == "l") return Signed(L, b) + " < " + Signed(R, b);
    if (cc == "le") return Signed(L, b) + " <= " + Signed(R, b);
    if (cc == "g") return Signed(L, b) + " > " + Signed(R, b);
    if (cc == "ge") return Signed(L, b) + " >= " + Signed(R, b);
    if (cc == "b") return L + " < " + R;
    if (cc == "be") return L + " <= " + R;
    if (cc == "a") return L + " > " + R;
    if (cc == "ae") return L + " >= " + R;
    if (cc == "s") return Signed("(" + L + ") - (" + R + ")", b) + " < 0";
    if (cc == "ns") return Signed("(" + L + ") - (" + R + ")", b) + " >= 0";
    return "flags_" + cc;
}

std::string Lifter::BinaryExpr(ZydisMnemonic m, const std::string& a, const std::string& b, int bits) const
{
    switch (m)
    {
    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_ADC: return a + " + " + b;
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_SBB: return a + " - " + b;
    case ZYDIS_MNEMONIC_AND: return a + " & " + b;
    case ZYDIS_MNEMONIC_OR: return a + " | " + b;
    case ZYDIS_MNEMONIC_XOR: return a + " ^ " + b;
    case ZYDIS_MNEMONIC_SHL: return a + " << " + b;
    case ZYDIS_MNEMONIC_SHR: return a + " >> " + b;
    case ZYDIS_MNEMONIC_SAR: return Signed(a, bits) + " >> " + b;
    case ZYDIS_MNEMONIC_ROL: return "__rotl(" + a + ", " + b + ")";
    case ZYDIS_MNEMONIC_ROR: return "__rotr(" + a + ", " + b + ")";
    default: return a;
    }
}

void Lifter::Unsupported(const Insn& in)
{
    Emit("/* " + in.text + " */");
    m_cmp.valid = false;
}

void Lifter::Lift(const Insn& in)
{
    const ZydisDecodedInstruction& ins = in.ins;
    const ZydisDecodedOperand* ops = in.ops;
    const int n = ins.operand_count_visible;

    for (int i = 0; i < n; i++)
        if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER && !IsGprClass(ops[i].reg.value)) return Unsupported(in);

    switch (ins.meta.category)
    {
    case ZYDIS_CATEGORY_CALL:
    {
        m_hasCall = true;
        std::string callee;
        uint64_t target = 0;
        if (BranchTarget(in, target)) callee = Ident(target);
        else callee = "((" + std::string(m_x64 ? "uint64_t" : "uint32_t") + "(*)(@ARGTYPES@))(" + ReadOp(ops[0]) + "))";
        m_used.insert(RetReg());
        m_written.insert(RetReg());
        m_returnsValue = true;
        Emit(RetReg() + " = " + callee + "(@ARGS@);");
        m_cmp.valid = false;
        return;
    }
    case ZYDIS_CATEGORY_SETCC: Assign(ops[0], "(" + Cond(in, false) + ")"); return;
    case ZYDIS_CATEGORY_CMOV:
        Assign(ops[0], ReadOp(ops[1]));
        if (!m_block->stmts.empty()) m_block->stmts.back().insert(0, "if (" + Cond(in, false) + ") ");
        return;
    default: break;
    }

    switch (ins.mnemonic)
    {
    case ZYDIS_MNEMONIC_NOP: return;
    case ZYDIS_MNEMONIC_INT3: Emit("__debugbreak();"); return;

    case ZYDIS_MNEMONIC_MOV:
    case ZYDIS_MNEMONIC_MOVZX: Assign(ops[0], ReadOp(ops[1])); return;

    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD: Assign(ops[0], Signed(ReadOp(ops[1]), ops[1].size)); return;

    case ZYDIS_MNEMONIC_LEA: Assign(ops[0], AddressOf(ops[1])); return;

    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_AND:
    case ZYDIS_MNEMONIC_OR:
    case ZYDIS_MNEMONIC_XOR:
    case ZYDIS_MNEMONIC_SHL:
    case ZYDIS_MNEMONIC_SHR:
    case ZYDIS_MNEMONIC_SAR:
    case ZYDIS_MNEMONIC_ADC:
    case ZYDIS_MNEMONIC_SBB:
    case ZYDIS_MNEMONIC_ROL:
    case ZYDIS_MNEMONIC_ROR:
    {
        if (n != 2) return Unsupported(in);
        int bits = ops[0].size;
        bool self = ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ops[0].reg.value == ops[1].reg.value;
        if (self && (ins.mnemonic == ZYDIS_MNEMONIC_XOR || ins.mnemonic == ZYDIS_MNEMONIC_SUB))
            Assign(ops[0], "0");
        else
            Assign(ops[0], BinaryExpr(ins.mnemonic, ReadOp(ops[0]), ReadOp(ops[1]), bits));
        SetCompare(ReadOp(ops[0]), "0", bits);
        return;
    }

    case ZYDIS_MNEMONIC_IMUL:
        if (n == 2) Assign(ops[0], ReadOp(ops[0]) + " * " + ReadOp(ops[1]));
        else if (n == 3) Assign(ops[0], ReadOp(ops[1]) + " * " + ReadOp(ops[2]));
        else return Unsupported(in);
        SetCompare(ReadOp(ops[0]), "0", ops[0].size);
        return;

    case ZYDIS_MNEMONIC_INC:
    case ZYDIS_MNEMONIC_DEC:
        Assign(ops[0], ReadOp(ops[0]) + (ins.mnemonic == ZYDIS_MNEMONIC_INC ? " + 1" : " - 1"));
        SetCompare(ReadOp(ops[0]), "0", ops[0].size);
        return;

    case ZYDIS_MNEMONIC_NEG:
        Assign(ops[0], "-" + ReadOp(ops[0]));
        SetCompare(ReadOp(ops[0]), "0", ops[0].size);
        return;

    case ZYDIS_MNEMONIC_NOT: Assign(ops[0], "~" + ReadOp(ops[0])); return;

    case ZYDIS_MNEMONIC_CMP: SetCompare(ReadOp(ops[0]), ReadOp(ops[1]), ops[0].size); return;

    case ZYDIS_MNEMONIC_TEST:
    {
        bool same = ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ops[0].reg.value == ops[1].reg.value;
        if (same) SetCompare(ReadOp(ops[0]), "0", ops[0].size);
        else SetCompare("(" + ReadOp(ops[0]) + " & " + ReadOp(ops[1]) + ")", "0", ops[0].size);
        return;
    }

    case ZYDIS_MNEMONIC_PUSH: Emit("push(" + ReadOp(ops[0]) + ");"); return;
    case ZYDIS_MNEMONIC_POP: Assign(ops[0], "pop()"); return;

    case ZYDIS_MNEMONIC_LEAVE:
        WriteReg(m_x64 ? ZYDIS_REGISTER_RSP : ZYDIS_REGISTER_ESP, ReadReg(m_x64 ? ZYDIS_REGISTER_RBP : ZYDIS_REGISTER_EBP));
        WriteReg(m_x64 ? ZYDIS_REGISTER_RBP : ZYDIS_REGISTER_EBP, "pop()");
        return;

    case ZYDIS_MNEMONIC_CDQE:
        if (!m_x64) return Unsupported(in);
        WriteReg(ZYDIS_REGISTER_RAX, "(int64_t)(int32_t)" + ReadReg(ZYDIS_REGISTER_EAX));
        return;
    case ZYDIS_MNEMONIC_CWDE: WriteReg(ZYDIS_REGISTER_EAX, "(int32_t)(int16_t)" + ReadReg(ZYDIS_REGISTER_AX)); return;
    case ZYDIS_MNEMONIC_CDQ: WriteReg(ZYDIS_REGISTER_EDX, Signed(ReadReg(ZYDIS_REGISTER_EAX), 32) + " >> 31"); return;
    case ZYDIS_MNEMONIC_CQO:
        if (!m_x64) return Unsupported(in);
        WriteReg(ZYDIS_REGISTER_RDX, Signed(ReadReg(ZYDIS_REGISTER_RAX), 64) + " >> 63");
        return;

    default: return Unsupported(in);
    }
}

// --- block building ---------------------------------------------------------

void Lifter::SetTerminator(Block& b, const Insn& in)
{
    uint64_t next = in.address + in.ins.length;
    uint64_t t = 0;
    switch (in.ins.meta.category)
    {
    case ZYDIS_CATEGORY_RET:
        b.kind = Block::Return;
        return;
    case ZYDIS_CATEGORY_UNCOND_BR:
        if (BranchTarget(in, t))
        {
            if (InFunction(t)) { b.kind = Block::Jump; b.taken = t; }
            else { b.kind = Block::Return; b.retText = "return " + Ident(t) + "(@ARGS@);"; }
        }
        else { b.stmts.push_back("/* indirect jump to " + ReadOp(in.ops[0]) + " */"); b.kind = Block::End; }
        return;
    case ZYDIS_CATEGORY_COND_BR:
        if (BranchTarget(in, t) && InFunction(t))
        {
            b.kind = Block::Branch;
            b.taken = t;
            b.fall = next;
            b.condT = Cond(in, false);
            b.condF = Cond(in, true);
        }
        else if (BranchTarget(in, t))
        {
            b.stmts.push_back("if (" + Cond(in, false) + ") return " + Ident(t) + "(@ARGS@);");
            b.kind = Block::Fall;
        }
        else
        {
            b.stmts.push_back("/* if (" + Cond(in, false) + ") jump to " + ReadOp(in.ops[0]) + " */");
            b.kind = Block::Fall;
        }
        return;
    default:
        return;
    }
}

void Lifter::BuildBlocks(uint64_t entry)
{
    std::vector<uint64_t> addrs;
    addrs.reserve(m_insns.size());
    for (auto& kv : m_insns) addrs.push_back(kv.first);
    std::sort(addrs.begin(), addrs.end());

    std::set<uint64_t> leaders;
    leaders.insert(entry);
    for (uint64_t a : addrs)
    {
        const Insn& in = m_insns[a];
        uint64_t next = a + in.ins.length;
        auto cat = in.ins.meta.category;
        uint64_t t = 0;
        if (cat == ZYDIS_CATEGORY_RET || cat == ZYDIS_CATEGORY_UNCOND_BR || cat == ZYDIS_CATEGORY_COND_BR)
            if (m_insns.count(next)) leaders.insert(next);
        if ((cat == ZYDIS_CATEGORY_UNCOND_BR || cat == ZYDIS_CATEGORY_COND_BR) && BranchTarget(in, t) &&
            InFunction(t) && m_insns.count(t))
            leaders.insert(t);
    }

    Block* cur = nullptr;
    for (uint64_t a : addrs)
    {
        if (!cur || leaders.count(a))
        {
            m_blocks.push_back(Block{});
            cur = &m_blocks.back();
            cur->start = a;
            m_idx[a] = (int)m_blocks.size() - 1;
        }
        m_block = cur;
        const Insn& in = m_insns[a];
        m_cur = &in;
        auto cat = in.ins.meta.category;
        if (cat == ZYDIS_CATEGORY_RET || cat == ZYDIS_CATEGORY_UNCOND_BR || cat == ZYDIS_CATEGORY_COND_BR)
            SetTerminator(*cur, in);
        else
            Lift(in);
    }
    m_cur = nullptr;
    m_block = nullptr;

    // A block that ran into the next leader without a terminator falls into it.
    for (int i = 0; i < (int)m_blocks.size(); i++)
    {
        Block& b = m_blocks[i];
        if (b.kind == Block::Fall && b.fall == 0)
        {
            if (i + 1 < (int)m_blocks.size()) b.fall = m_blocks[i + 1].start;
            else b.kind = Block::End;
        }
    }

    m_preds.assign(m_blocks.size(), {});
    for (int i = 0; i < (int)m_blocks.size(); i++)
        for (int s : Succs(i))
            if (s >= 0) m_preds[s].push_back(i);
}

std::vector<int> Lifter::Succs(int i) const
{
    const Block& b = m_blocks[i];
    switch (b.kind)
    {
    case Block::Jump: return { Idx(b.taken) };
    case Block::Branch: return { Idx(b.taken), Idx(b.fall) };
    case Block::Fall: return { Idx(b.fall) };
    default: return {};
    }
}

// --- structuring ------------------------------------------------------------

bool Lifter::SimpleRegion(int lo, int hi, int brk, int cont) const
{
    if (lo >= hi) return false;
    for (int j = lo; j < hi; j++)
        for (int s : Succs(j))
        {
            if (s < 0) return false; // an unresolved target: do not try to structure it
            if (s == brk || s == cont) continue;
            if (s >= lo && s <= hi) continue; // inside, or to the join (hi)
            return false;
        }
    for (int j = lo + 1; j < hi; j++)
        for (int p : m_preds[j])
            if (p < lo || p >= hi) return false; // entered from outside
    return true;
}

bool Lifter::DetectLoop(int i, int end, int& latch, int& exitIdx) const
{
    int L = -1;
    for (int k = end - 1; k >= i && L < 0; k--)
        for (int s : Succs(k))
            if (s == i) { L = k; break; }
    if (L < 0) return false;

    int exit = -2;
    for (int j = i; j <= L; j++)
        for (int s : Succs(j))
        {
            if (s < 0) return false;
            if (s >= i && s <= L) continue;
            if (exit == -2) exit = s;
            else if (exit != s) return false; // more than one way out: leave it to goto
        }
    for (int j = i + 1; j <= L; j++)
        for (int p : m_preds[j])
            if (p < i || p > L) return false; // entered somewhere other than the header

    latch = L;
    exitIdx = (exit == -2) ? -1 : exit;
    return true;
}

void Lifter::EmitLoop(int i, int L, int exitIdx, int indent, std::string& out)
{
    const int bodyEnd = L + 1;
    const int brk = exitIdx;
    const int cont = i;
    Block& head = m_blocks[i];
    Block& latch = m_blocks[L];

    bool whileSugar = head.kind == Block::Branch && Idx(head.taken) == exitIdx && head.stmts.empty();
    bool doWhile = !whileSugar && latch.kind == Block::Branch && Idx(latch.taken) == i;

    if (whileSugar)
    {
        if (head.needLabel) out += Ind(indent) + Label(i) + ":;\n";
        out += Ind(indent) + "while (" + head.condF + ")\n" + Ind(indent) + "{\n";
        EmitRange(i + 1, bodyEnd, indent + 1, brk, cont, bodyEnd, out);
        out += Ind(indent) + "}\n";
    }
    else if (doWhile)
    {
        out += Ind(indent) + "do\n" + Ind(indent) + "{\n";
        EmitRange(i, L, indent + 1, brk, cont, L, out, i);
        if (latch.needLabel) out += Ind(indent + 1) + Label(L) + ":;\n";
        for (const auto& s : latch.stmts) out += Ind(indent + 1) + s + "\n";
        out += Ind(indent) + "} while (" + latch.condT + ");\n";
    }
    else
    {
        out += Ind(indent) + "while (1)\n" + Ind(indent) + "{\n";
        EmitRange(i, bodyEnd, indent + 1, brk, cont, bodyEnd, out, i);
        out += Ind(indent) + "}\n";
    }
}

void Lifter::EmitRange(int begin, int end, int indent, int brk, int cont, int natExit, std::string& out, int noLoopAt)
{
    int i = begin;
    while (i < end)
    {
        int latch = 0, exitIdx = 0;
        if (i != noLoopAt && DetectLoop(i, end, latch, exitIdx))
        {
            EmitLoop(i, latch, exitIdx, indent, out);
            i = latch + 1;
            continue;
        }

        Block& b = m_blocks[i];
        if (b.needLabel) out += Ind(indent) + Label(i) + ":;\n";
        for (const auto& s : b.stmts) out += Ind(indent) + s + "\n";

        const bool last = (i + 1 == end);
        switch (b.kind)
        {
        case Block::Return:
            out += Ind(indent) + (b.retText.empty() ? (m_returnsValue ? "return rax;" : "return;") : b.retText) + "\n";
            i++;
            break;

        case Block::End:
            i++;
            break;

        case Block::Fall:
        {
            int f = Idx(b.fall);
            if (f == cont && !last) out += Ind(indent) + "continue;\n";
            else if (f == brk && f != i + 1) out += Ind(indent) + "break;\n";
            i++;
            break;
        }

        case Block::Jump:
        {
            int t = Idx(b.taken);
            if (t < 0) out += Ind(indent) + "goto loc_" + Hex(b.taken).substr(2) + "; /* outside */\n";
            else if (t == cont) { if (!last) out += Ind(indent) + "continue;\n"; }
            else if (t == brk) out += Ind(indent) + "break;\n";
            else if (t == i + 1) { /* natural */ }
            else if (t == natExit && last) { /* natural exit from the region */ }
            else { m_blocks[t].needLabel = true; out += Ind(indent) + "goto " + Label(t) + ";\n"; }
            i++;
            break;
        }

        case Block::Branch:
        {
            int t = Idx(b.taken), f = Idx(b.fall);
            if (t == i + 1 && f == i + 1) { i++; break; } // degenerate

            if (f == i + 1 && t > i + 1 && t <= end && SimpleRegion(i + 1, t, brk, cont))
            {
                int elseJoin = -1;
                if (t - 1 >= i + 1 && m_blocks[t - 1].kind == Block::Jump)
                {
                    int J = Idx(m_blocks[t - 1].taken);
                    if (J > t && J <= end && SimpleRegion(t, J, brk, cont)) elseJoin = J;
                }
                out += Ind(indent) + "if (" + b.condF + ")\n" + Ind(indent) + "{\n";
                EmitRange(i + 1, t, indent + 1, brk, cont, elseJoin >= 0 ? elseJoin : t, out);
                if (elseJoin >= 0)
                {
                    out += Ind(indent) + "}\n" + Ind(indent) + "else\n" + Ind(indent) + "{\n";
                    EmitRange(t, elseJoin, indent + 1, brk, cont, elseJoin, out);
                    out += Ind(indent) + "}\n";
                    i = elseJoin;
                }
                else { out += Ind(indent) + "}\n"; i = t; }
                break;
            }

            if (t < 0) out += Ind(indent) + "if (" + b.condT + ") goto loc_" + Hex(b.taken).substr(2) + "; /* outside */\n";
            else if (t == cont) out += Ind(indent) + "if (" + b.condT + ") continue;\n";
            else if (t == brk) out += Ind(indent) + "if (" + b.condT + ") break;\n";
            else if (t == i + 1) { /* taken == fall */ }
            else { m_blocks[t].needLabel = true; out += Ind(indent) + "if (" + b.condT + ") goto " + Label(t) + ";\n"; }
            i++;
            break;
        }
        }
    }
}

// --- finishing --------------------------------------------------------------

void Lifter::Finalize()
{
    // Arguments actually referenced, used both for the signature and for calls.
    std::vector<std::string> argList;
    for (const auto& r : ArgRegs())
        if (m_used.count(r)) argList.push_back(r);
    std::string args = Join(argList, ", ");
    std::string argtypes = argList.empty() ? "void" : Join(std::vector<std::string>(argList.size(), "uint64_t"), ", ");

    for (auto& b : m_blocks)
    {
        for (auto& s : b.stmts) { ReplaceAll(s, "@ARGS@", args); ReplaceAll(s, "@ARGTYPES@", argtypes); }
        ReplaceAll(b.retText, "@ARGS@", args);
        ReplaceAll(b.retText, "@ARGTYPES@", argtypes);
    }
}

bool Lifter::Run(uint64_t address, std::string& out, std::string& error)
{
    uint64_t begin = 0, end = 0;
    m_bounded = FindFunctionBounds(m_proc, address, begin, end);
    uint64_t entry = m_bounded ? begin : address;
    m_lo = m_bounded ? begin : (address > kUnboundedRange ? address - kUnboundedRange : 0);
    m_hi = m_bounded ? end : address + kUnboundedRange;

    if (!Collect(entry, error)) return false;
    BuildBlocks(entry);
    Finalize();

    const int N = (int)m_blocks.size();
    std::string scratch;
    EmitRange(0, N, 1, -1, -1, N, scratch); // first pass just marks backward goto labels
    std::string body;
    EmitRange(0, N, 1, -1, -1, N, body);

    // Signature from the arguments that are read before being written.
    std::vector<std::string> params;
    std::set<std::string> paramSet;
    for (const auto& r : ArgRegs())
        if (m_inputs.count(r)) { params.push_back("uint64_t " + r); paramSet.insert(r); }

    out = "// " + m_proc.Symbolize(entry) + "\n";
    out += RetType() + " " + Ident(entry) + "(" + (params.empty() ? "void" : Join(params, ", ")) + ")\n{\n";
    for (const auto& r : m_used)
        if (!paramSet.count(r)) out += "    uint64_t " + r + ";\n";

    // Drop a bare trailing "return;" - the closing brace already returns.
    if (!m_returnsValue)
    {
        std::string tail = Ind(1) + "return;\n";
        if (body.size() >= tail.size() && body.compare(body.size() - tail.size(), tail.size(), tail) == 0)
            body.erase(body.size() - tail.size());
    }
    out += body;
    out += "}\n";
    if (m_truncated) out += "// Truncated after " + std::to_string(kMaxInstructions) + " instructions.\n";
    return true;
}
} // namespace

bool DecompileFunction(const Process& proc, uint64_t address, std::string& out, std::string& error)
{
    if (!proc.IsOpen())
    {
        error = "No process attached";
        return false;
    }
    Lifter lifter(proc, proc.Is64());
    return lifter.Run(address, out, error);
}

// --- disassembly & patching -------------------------------------------------

namespace
{
ZydisDecoder MakeDecoder(bool x64)
{
    ZydisDecoder dec{};
    ZydisDecoderInit(&dec, x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                     x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    return dec;
}

// Operand that a patch may change: an immediate that is not a relative branch target.
int PatchableOperand(const ZydisDecodedInstruction& ins, const ZydisDecodedOperand* ops)
{
    for (int i = 0; i < ins.operand_count_visible; i++)
        if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !ops[i].imm.is_relative) return i;
    return -1;
}
} // namespace

bool DisassembleFunction(const Process& proc, uint64_t address, std::vector<InstructionRow>& out, std::string& error)
{
    if (!proc.IsOpen())
    {
        error = "No process attached";
        return false;
    }
    constexpr size_t kMaxRows = 4000;
    uint64_t begin = 0, end = 0;
    bool bounded = FindFunctionBounds(proc, address, begin, end);
    uint64_t a = bounded ? begin : address;

    ZydisDecoder dec = MakeDecoder(proc.Is64());
    ZydisFormatter fmt{};
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&fmt, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    out.clear();
    while (out.size() < kMaxRows && (!bounded || a < end))
    {
        uint8_t buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
        size_t got = proc.Read(a, buf, sizeof(buf));
        ZydisDecodedInstruction ins{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (got == 0 || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, buf, got, &ins, ops))) break;

        InstructionRow row;
        row.address = a;
        row.bytes.assign(buf, buf + ins.length);
        char text[256];
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &ins, ops, ins.operand_count_visible, text,
                                                         sizeof(text), a, nullptr)))
            row.text = text;
        int imm = PatchableOperand(ins, ops);
        if (imm >= 0)
        {
            row.hasImmediate = true;
            row.immediate = ops[imm].imm.value.u;
            if (ops[imm].size > 0 && ops[imm].size < 64) row.immediate &= (1ull << ops[imm].size) - 1;
        }
        bool branch = ins.meta.category == ZYDIS_CATEGORY_COND_BR || ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                      ins.meta.category == ZYDIS_CATEGORY_CALL;
        row.isBranch = branch;
        out.push_back(row);

        bool ret = ins.meta.category == ZYDIS_CATEGORY_RET;
        a += ins.length;
        if (!bounded && ret) break;
    }
    if (out.empty())
    {
        error = "Could not read code at " + Hex(address);
        return false;
    }
    return true;
}

bool EncodeImmediate(const std::vector<uint8_t>& insnBytes, bool x64, uint64_t value,
                     std::vector<uint8_t>& encoded, std::string& error)
{
    ZydisDecoder dec = MakeDecoder(x64);
    ZydisDecodedInstruction ins{};
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, insnBytes.data(), insnBytes.size(), &ins, ops)))
    {
        error = "Could not decode the instruction";
        return false;
    }
    int idx = PatchableOperand(ins, ops);
    if (idx < 0)
    {
        error = "This instruction has no immediate operand to change";
        return false;
    }

    ZydisEncoderRequest req{};
    if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(&ins, ops, ins.operand_count_visible, &req)))
    {
        error = "Could not turn the instruction back into an encoder request";
        return false;
    }
    req.operands[idx].imm.u = value;

    uint8_t enc[ZYDIS_MAX_INSTRUCTION_LENGTH]{};
    size_t len = sizeof(enc);
    if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, enc, &len)))
    {
        error = "That value does not fit this instruction's immediate";
        return false;
    }
    if (len > insnBytes.size())
    {
        error = "The new encoding is " + std::to_string(len) + " bytes, the original is " +
                std::to_string(insnBytes.size()) + ". Pick a value that keeps the same size.";
        return false;
    }

    // Make sure the encoding carries the value we asked for before we hand it back.
    ZydisDecodedInstruction chk{};
    ZydisDecodedOperand chkOps[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, enc, len, &chk, chkOps)))
    {
        error = "The new encoding does not decode";
        return false;
    }
    int ci = PatchableOperand(chk, chkOps);
    uint64_t mask = (ci < 0 || chkOps[ci].size >= 64) ? ~0ull : (1ull << chkOps[ci].size) - 1;
    if (ci < 0 || (chkOps[ci].imm.value.u & mask) != (value & mask))
    {
        error = "The assembler picked a different form; try another value";
        return false;
    }

    encoded.assign(enc, enc + len);
    encoded.resize(insnBytes.size(), 0x90); // pad a shorter encoding with NOPs
    return true;
}

bool PatchImmediate(const Process& proc, const InstructionRow& row, uint64_t value,
                    std::vector<uint8_t>& original, std::string& error)
{
    std::vector<uint8_t> encoded;
    if (!EncodeImmediate(row.bytes, proc.Is64(), value, encoded, error)) return false;
    original = row.bytes;
    if (!proc.Write(row.address, encoded.data(), encoded.size()))
    {
        error = "Write failed at " + Hex(row.address);
        return false;
    }
    return true;
}
