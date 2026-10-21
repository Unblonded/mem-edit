#pragma once
#include <cstdint>
#include <string>
#include <vector>

enum class ValueType : int
{
    Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64,
    Float, Double, String, WString, ByteArray,
    Count
};

const char* ValueTypeName(ValueType t);
bool IsNumeric(ValueType t);
bool IsFloat(ValueType t);
size_t ValueTypeSize(ValueType t); // 0 for variable-length types

// A parsed scan/write value. For numeric types `bytes` holds the native
// representation. For strings and AOBs it holds the pattern and `mask`
// marks which bytes must match (0 = wildcard).
struct ParsedValue
{
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
    double floatTolerance = 0.0;
    bool ok = false;
};

ParsedValue ParseValue(ValueType t, const std::string& text, bool hexInput);
std::string FormatValue(ValueType t, const uint8_t* data, size_t size, bool hex);

// Hex helpers
std::string ToHex(uint64_t v, int width = 0);
bool ParseHexU64(const std::string& s, uint64_t& out);
std::string BytesToHex(const uint8_t* data, size_t size);

// Read a numeric value as double (for increased/decreased comparisons).
double NumericAsDouble(ValueType t, const uint8_t* p);
