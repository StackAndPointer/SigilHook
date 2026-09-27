// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "NativeBindingTest.h"

#include <cstring>
#include <cwchar>

extern "C" int32_t SHNativeAdd(int32_t left, int32_t right) {
    return left + right;
}

extern "C" double SHNativeScale(float value) {
    return static_cast<double>(value) * 3.0;
}

extern "C" const char* SHNativeText(void) {
    return "SigilHook";
}

extern "C" int32_t SHNativeTextLength(const char* text) {
    return text == nullptr ? -1 : static_cast<int32_t>(std::strlen(text));
}

extern "C" int32_t SHNativeWideLength(const wchar_t* text) {
    return text == nullptr ? -1 : static_cast<int32_t>(std::wcslen(text));
}

extern "C" void* SHNativeEchoPointer(void* value) {
    return value;
}

extern "C" int32_t SHNativeCdeclSum(int32_t left, int32_t right) {
    return left + right + 386;
}

#if defined(_MSC_VER) && defined(_M_IX86)
extern "C" __declspec(naked) int32_t SHNativeStdcallSum(int32_t, int32_t) {
    __asm {
        mov eax, dword ptr [esp + 4]
        add eax, dword ptr [esp + 8]
        add eax, 386
        ret 8
    }
}

extern "C" __declspec(naked) int32_t SHNativeFastcallSum(int32_t, int32_t) {
    __asm {
        mov eax, ecx
        add eax, edx
        add eax, 386
        ret
    }
}

extern "C" __declspec(naked) int32_t SHNativeThiscallSum(int32_t, int32_t) {
    __asm {
        mov eax, ecx
        add eax, dword ptr [esp + 4]
        add eax, 386
        ret 4
    }
}
#elif defined(_MSC_VER) && defined(_M_X64)
extern "C" int32_t __stdcall SHNativeStdcallSum(int32_t left, int32_t right) {
    return SHNativeCdeclSum(left, right);
}

extern "C" int32_t __fastcall SHNativeFastcallSum(int32_t left, int32_t right) {
    return SHNativeCdeclSum(left, right);
}

extern "C" int32_t __thiscall SHNativeThiscallSum(int32_t left, int32_t right) {
    return SHNativeCdeclSum(left, right);
}
#else
extern "C" int32_t SHNativeStdcallSum(int32_t left, int32_t right) {
    return SHNativeCdeclSum(left, right);
}

extern "C" int32_t SHNativeFastcallSum(int32_t left, int32_t right) {
    return SHNativeCdeclSum(left, right);
}

extern "C" int32_t SHNativeThiscallSum(int32_t left, int32_t right) {
    return SHNativeCdeclSum(left, right);
}
#endif

extern "C" int32_t __vectorcall SHNativeVectorcallSum(int32_t left, int32_t right) {
    return SHNativeCdeclSum(left, right);
}

extern "C" SHNativeS1 SHNativeEcho1(SHNativeS1 value) {
    ++value.value;
    return value;
}

extern "C" SHNativeS4 SHNativeEcho4(SHNativeS4 value) {
    value.value += 4;
    return value;
}

extern "C" SHNativeS8 SHNativeEcho8(SHNativeS8 value) {
    value.value += 8;
    return value;
}

extern "C" SHNativeS16 SHNativeEcho16(SHNativeS16 value) {
    value.low += 16;
    value.high += 32;
    return value;
}

extern "C" SHNativeS32 SHNativeEcho32(SHNativeS32 value) {
    value.a += 1;
    value.b += 2;
    value.c += 3;
    value.d += 4;
    return value;
}

extern "C" SHNativePacked5 SHNativeEchoPacked(SHNativePacked5 value) {
    value.tag = static_cast<uint8_t>(value.tag + 1);
    value.value += 5;
    return value;
}
