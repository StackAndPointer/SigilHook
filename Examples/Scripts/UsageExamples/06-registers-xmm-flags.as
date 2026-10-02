// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Focused register / XMM / flags access. SP is readable but never writable.

#include "SigilHook.ash"

const uint64 REGISTER_TARGET = 0x00401000;
const string REGISTER_SIGNATURE = "int:int";

// XMM register indices are plain 0..15. Use shXmmAvailable() to check.
const uint8 XMM0 = 0;
const uint8 XMM1 = 1;

uint64 g_registerHook = SH_INVALID_HANDLE;

void onRegisters() {
    // General-purpose registers.
    const uint64 eax = shReg(SH_REG_AX);
    shSetReg(SH_REG_DX, eax);          // full-width write
    shSetReg16(SH_REG_CX, 0x1234);     // keep upper bits, replace low 16

    // XMM registers: lane 0 is the low 64 bits, lane 1 the high 64 bits.
    if (shXmmAvailable(XMM0)) {
        const uint64 low = shXmm(XMM0, 0);
        shSetXmm(XMM0, low, 0);
    }

    // Arithmetic flags. Flags are restored before the original or final return.
    const uint64 flags = shFlags();
    shSetFlags((flags & ~uint64(0x40)) | 0x40);

    shKeepOriginal();
}

void setupRegistersXmmFlags() {
    g_registerHook = shHookConvention(
        REGISTER_TARGET, "void onRegisters()", REGISTER_SIGNATURE, "cdecl");
    if (!shIsValidHook(g_registerHook)) {
        shLog("register hook failed: " + shLastError());
    }
}

void unloadRegistersXmmFlags() {
    if (shIsValidHook(g_registerHook)) {
        shDestroyHook(g_registerHook);
        g_registerHook = SH_INVALID_HANDLE;
    }
}
