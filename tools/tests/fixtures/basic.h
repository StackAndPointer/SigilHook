// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

#define SH_TEST_API __declspec(dllexport)

typedef struct Point {
    int32_t x;
    int32_t y;
} Point;

typedef struct Packed {
    uint8_t tag;
    uint32_t value;
} Packed;

typedef enum Mode {
    MODE_IDLE = 0,
    MODE_ACTIVE = 1
} Mode;

extern "C" {
SH_TEST_API int32_t Add(int32_t left, int32_t right);
SH_TEST_API double Scale(float value);
SH_TEST_API const char* Name(void);
SH_TEST_API Point Move(Point point, const Point* offset);
SH_TEST_API Packed PackValue(Packed input);
}

// @sigilhook convention=usercall:ret=eax;arg0=ecx;cleanup=4
SH_TEST_API int32_t UsercallAdd(int32_t left, int32_t right);
