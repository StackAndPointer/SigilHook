// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

#include "sigilhook_annotations.h"

#if defined(_WIN32)
#  define SH_NATIVE_TEST_API __declspec(dllexport)
#else
#  define SH_NATIVE_TEST_API __attribute__((visibility("default")))
#endif
#if defined(_MSC_VER) && defined(_M_IX86)
#  define SH_NATIVE_TEST_STDCALL
#  define SH_NATIVE_TEST_FASTCALL
#  define SH_NATIVE_TEST_THISCALL
#else
#  define SH_NATIVE_TEST_STDCALL __stdcall
#  define SH_NATIVE_TEST_FASTCALL __fastcall
#  define SH_NATIVE_TEST_THISCALL __thiscall
#endif

typedef struct SHNativeS1 {
    uint8_t value;
} SHNativeS1;

typedef struct SHNativeS4 {
    uint32_t value;
} SHNativeS4;

typedef struct SHNativeS8 {
    uint64_t value;
} SHNativeS8;

typedef struct SHNativeS16 {
    uint64_t low;
    uint64_t high;
} SHNativeS16;

typedef struct SHNativeS32 {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
} SHNativeS32;

#pragma pack(push, 1)
typedef struct SHNativePacked5 {
    uint8_t tag;
    uint32_t value;
} SHNativePacked5;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

SH_NATIVE_TEST_API int32_t SHNativeAdd(int32_t left, int32_t right);
SH_NATIVE_TEST_API double SHNativeScale(float value);
SH_NATIVE_TEST_API const char* SHNativeText(void);
SH_NATIVE_TEST_API int32_t SHNativeTextLength(const char* text);
SH_NATIVE_TEST_API int32_t SHNativeWideLength(const wchar_t* text);
SH_NATIVE_TEST_API void* SHNativeEchoPointer(void* value);

SH_NATIVE_TEST_API int32_t __cdecl SHNativeCdeclSum(int32_t left, int32_t right);
// @sigilhook convention=stdcall
SH_NATIVE_TEST_API int32_t SH_NATIVE_TEST_STDCALL SHNativeStdcallSum(int32_t left, int32_t right);
// @sigilhook convention=fastcall
SH_NATIVE_TEST_API int32_t SH_NATIVE_TEST_FASTCALL SHNativeFastcallSum(int32_t left, int32_t right);
// @sigilhook convention=thiscall
SH_NATIVE_TEST_API int32_t SH_NATIVE_TEST_THISCALL SHNativeThiscallSum(int32_t left, int32_t right);
// @sigilhook convention=vectorcall
SH_NATIVE_TEST_API int32_t __vectorcall SHNativeVectorcallSum(int32_t left, int32_t right);

SH_NATIVE_TEST_API SHNativeS1 SHNativeEcho1(SHNativeS1 value);
SH_NATIVE_TEST_API SHNativeS4 SHNativeEcho4(SHNativeS4 value);
SH_NATIVE_TEST_API SHNativeS8 SHNativeEcho8(SHNativeS8 value);
SH_NATIVE_TEST_API SHNativeS16 SHNativeEcho16(SHNativeS16 value);
SH_NATIVE_TEST_API SHNativeS32 SHNativeEcho32(SHNativeS32 value);
SH_NATIVE_TEST_API SHNativePacked5 SHNativeEchoPacked(SHNativePacked5 value);

#ifdef __cplusplus
}
#endif
