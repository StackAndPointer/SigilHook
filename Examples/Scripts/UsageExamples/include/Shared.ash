// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Shared header for the multi-file example. Because .ash headers are expanded
// once per application, this needs no include guard.

#include "SigilHook.ash"
#include "include/SharedConstants.ash"

uint64 sharedBump(uint64 value) {
    return value + SHARED_INCREMENT;
}
