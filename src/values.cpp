#include "values.h"

#include <windows.h>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

const char* ValueTypeName(ValueType t)
{
    switch (t)
    {
    case ValueType::Int8: return "Int8";
    case ValueType::UInt8: return "Byte";
    case ValueType::Int16: return "Int16";
    case ValueType::UInt16: return "UInt16";
    case ValueType::Int32: return "Int32";
    case ValueType::UInt32: return "UInt32";
    case ValueType::Int64: return "Int64";
    case ValueType::UInt64: return "UInt64";
    case ValueType::Float: return "Float";
    case ValueType::Double: return "Double";
    case ValueType::String: return "String (ASCII)";
    case ValueType::WString: return "String (UTF-16)";
    case ValueType::ByteArray: return "Array of Bytes";
    default: return "?";
    }
}

bool IsNumeric(ValueType t) { return t <= ValueType::Double; }
bool IsFloat(ValueType t) { return t == ValueType::Float || t == ValueType::Double; }

size_t ValueTypeSize(ValueType t)
{
    switch (t)
    {
    case ValueType::Int8: case ValueType::UInt8: return 1;
    case ValueType::Int16: case ValueType::UInt16: return 2;
    case ValueType::Int32: case ValueType::UInt32: case ValueType::Float: return 4;
    case ValueType::Int64: case ValueType::UInt64: case ValueType::Double: return 8;
    default: return 0;
    }
}

static std::string Trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string ToHex(uint64_t v, int width)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%0*llX", width, (unsigned long long)v);
    return buf;
}

bool ParseHexU64(const std::string& in, uint64_t& out)
{
    std::string s = Trim(in);
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (s.empty() || s.size() > 16) return false;
    uint64_t v = 0;
    for (char c : s)
    {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | (uint64_t)d;
    }
    out = v;
    return true;
}

std::string BytesToHex(const uint8_t* data, size_t size)
{
    std::string r;
    r.reserve(size * 3);
    char buf[4];
    for (size_t i = 0; i < size; i++)
    {
        snprintf(buf, sizeof(buf), i + 1 < size ? "%02X " : "%02X", data[i]);
        r += buf;
    }
    return r;
}

template <typename T>
static void PutBytes(ParsedValue& pv, T v)
{
    pv.bytes.resize(sizeof(T));
    memcpy(pv.bytes.data(), &v, sizeof(T));
    pv.mask.assign(sizeof(T), 1);
    pv.ok = true;
}

static bool ParseInteger(const std::string& s, bool hex, bool isSigned, uint64_t& out)
{
    if (s.empty()) return false;
    const char* p = s.c_str();
    char* end = nullptr;
    bool neg = false;
    if (*p == '-') { neg = true; p++; }
    int base = hex ? 16 : 10;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
    if (*p == 0) return false;
    errno = 0;
    unsigned long long v = strtoull(p, &end, base);
    if (*end != 0 || errno == ERANGE) return false;
    if (neg)
    {
        if (!isSigned) return false;
        v = (unsigned long long)(-(long long)v);
    }
    out = v;
    return true;
}

ParsedValue ParseValue(ValueType t, const std::string& textIn, bool hexInput)
{
    ParsedValue pv;
    std::string text = (t == ValueType::String || t == ValueType::WString) ? textIn : Trim(textIn);

    switch (t)
    {
    case ValueType::Int8: case ValueType::UInt8:
    case ValueType::Int16: case ValueType::UInt16:
    case ValueType::Int32: case ValueType::UInt32:
    case ValueType::Int64: case ValueType::UInt64:
    {
        uint64_t v;
        bool sgn = t == ValueType::Int8 || t == ValueType::Int16 || t == ValueType::Int32 || t == ValueType::Int64;
        if (!ParseInteger(text, hexInput, sgn, v)) return pv;
        switch (ValueTypeSize(t))
        {
        case 1: PutBytes<uint8_t>(pv, (uint8_t)v); break;
        case 2: PutBytes<uint16_t>(pv, (uint16_t)v); break;
        case 4: PutBytes<uint32_t>(pv, (uint32_t)v); break;
        case 8: PutBytes<uint64_t>(pv, v); break;
        }
        return pv;
    }
    case ValueType::Float:
    case ValueType::Double:
    {
        if (text.empty()) return pv;
        char* end = nullptr;
        double d = strtod(text.c_str(), &end);
        if (*end != 0) return pv;
        // Tolerance follows the precision the user typed: "1.5" matches [1.45, 1.55).
        size_t dot = text.find('.');
        int decimals = dot == std::string::npos ? 0 : (int)(text.size() - dot - 1);
        pv.floatTolerance = 0.5 * std::pow(10.0, -decimals);
        if (t == ValueType::Float) PutBytes<float>(pv, (float)d);
        else PutBytes<double>(pv, d);
        return pv;
    }
    case ValueType::String:
        if (text.empty()) return pv;
        pv.bytes.assign(text.begin(), text.end());
        pv.mask.assign(pv.bytes.size(), 1);
        pv.ok = true;
        return pv;
    case ValueType::WString:
    {
        if (text.empty()) return pv;
        int n = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0);
        std::wstring w(n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), w.data(), n);
        pv.bytes.resize(w.size() * 2);
        memcpy(pv.bytes.data(), w.data(), pv.bytes.size());
        pv.mask.assign(pv.bytes.size(), 1);
        pv.ok = true;
        return pv;
    }
    case ValueType::ByteArray:
    {
        std::istringstream ss(text);
        std::string tok;
        while (ss >> tok)
        {
            if (tok.find_first_not_of('?') == std::string::npos || tok == "**")
            {
                pv.bytes.push_back(0);
                pv.mask.push_back(0);
                continue;
            }
            if (tok.size() % 2 != 0) return ParsedValue{};
            for (size_t i = 0; i < tok.size(); i += 2)
            {
                uint64_t b;
                if (!ParseHexU64(tok.substr(i, 2), b)) return ParsedValue{};
                pv.bytes.push_back((uint8_t)b);
                pv.mask.push_back(1);
            }
        }
        pv.ok = !pv.bytes.empty();
        return pv;
    }
    default:
        return pv;
    }
}

std::string FormatValue(ValueType t, const uint8_t* p, size_t size, bool hex)
{
    char buf[128];
    auto fmtInt = [&](long long sv, unsigned long long uv, int bytes, bool sgn) -> std::string {
        if (hex) snprintf(buf, sizeof(buf), "%0*llX", bytes * 2, uv);
        else if (sgn) snprintf(buf, sizeof(buf), "%lld", sv);
        else snprintf(buf, sizeof(buf), "%llu", uv);
        return buf;
    };
    size_t need = ValueTypeSize(t);
    if (need && size < need) return "??";

    switch (t)
    {
    case ValueType::Int8: { int8_t v; memcpy(&v, p, 1); return fmtInt(v, (uint8_t)v, 1, true); }
    case ValueType::UInt8: { uint8_t v; memcpy(&v, p, 1); return fmtInt(v, v, 1, false); }
    case ValueType::Int16: { int16_t v; memcpy(&v, p, 2); return fmtInt(v, (uint16_t)v, 2, true); }
    case ValueType::UInt16: { uint16_t v; memcpy(&v, p, 2); return fmtInt(v, v, 2, false); }
    case ValueType::Int32: { int32_t v; memcpy(&v, p, 4); return fmtInt(v, (uint32_t)v, 4, true); }
    case ValueType::UInt32: { uint32_t v; memcpy(&v, p, 4); return fmtInt(v, v, 4, false); }
    case ValueType::Int64: { int64_t v; memcpy(&v, p, 8); return fmtInt(v, (uint64_t)v, 8, true); }
    case ValueType::UInt64: { uint64_t v; memcpy(&v, p, 8); return fmtInt((long long)v, v, 8, false); }
    case ValueType::Float:
    {
        float v; memcpy(&v, p, 4);
        if (hex) { uint32_t u; memcpy(&u, p, 4); snprintf(buf, sizeof(buf), "%08X", u); }
        else snprintf(buf, sizeof(buf), "%.6g", v);
        return buf;
    }
    case ValueType::Double:
    {
        double v; memcpy(&v, p, 8);
        if (hex) { uint64_t u; memcpy(&u, p, 8); snprintf(buf, sizeof(buf), "%016llX", (unsigned long long)u); }
        else snprintf(buf, sizeof(buf), "%.10g", v);
        return buf;
    }
    case ValueType::String:
    {
        std::string s;
        for (size_t i = 0; i < size && p[i]; i++)
            s += (p[i] >= 32 && p[i] < 127) ? (char)p[i] : '.';
        return s;
    }
    case ValueType::WString:
    {
        size_t n = 0;
        const wchar_t* w = (const wchar_t*)p;
        while (n < size / 2 && w[n]) n++;
        if (n == 0) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w, (int)n, nullptr, 0, nullptr, nullptr);
        std::string s(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, (int)n, s.data(), len, nullptr, nullptr);
        return s;
    }
    case ValueType::ByteArray:
        return BytesToHex(p, size);
    default:
        return "?";
    }
}

double NumericAsDouble(ValueType t, const uint8_t* p)
{
    switch (t)
    {
    case ValueType::Int8: return (double)*(const int8_t*)p;
    case ValueType::UInt8: return (double)*(const uint8_t*)p;
    case ValueType::Int16: { int16_t v; memcpy(&v, p, 2); return v; }
    case ValueType::UInt16: { uint16_t v; memcpy(&v, p, 2); return v; }
    case ValueType::Int32: { int32_t v; memcpy(&v, p, 4); return v; }
    case ValueType::UInt32: { uint32_t v; memcpy(&v, p, 4); return v; }
    case ValueType::Int64: { int64_t v; memcpy(&v, p, 8); return (double)v; }
    case ValueType::UInt64: { uint64_t v; memcpy(&v, p, 8); return (double)v; }
    case ValueType::Float: { float v; memcpy(&v, p, 4); return v; }
    case ValueType::Double: { double v; memcpy(&v, p, 8); return v; }
    default: return 0.0;
    }
}
