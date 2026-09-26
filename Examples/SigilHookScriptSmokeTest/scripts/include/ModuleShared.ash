// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#pragma once

#include "Nested.ash"

const uint64 SIGILHOOK_TEST_HEADER_VALUE = 0x13579BDF;

uint64 moduleHeaderValue(uint64 value) {
    return value ^ SIGILHOOK_TEST_NESTED_VALUE ^ SIGILHOOK_TEST_HEADER_VALUE;
}
