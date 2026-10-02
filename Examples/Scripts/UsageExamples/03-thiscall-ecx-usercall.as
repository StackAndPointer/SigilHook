// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// thiscall / ecx-based usercall. On x86, a member function receives `this` in
// ecx; express that explicitly with a usercall mapping.

#include "SigilHook.ash"

const uint64 THISCALL_TARGET = 0x00401000;
// Return type and argument list of the target function.
const string THISCALL_SIGNATURE = "void:void*";

uint64 g_thiscallHook = SH_INVALID_HANDLE;

void onThiscall() {
    // arg0 is the `this` pointer, mapped to ecx. Read it as an argument or
    // directly from the register; both refer to the same value.
    const uint64 self = shArg(0);
    if (self != shReg(SH_REG_CX)) {
        shLog("unexpected: arg0 and ecx differ");
    }
    shKeepOriginal();
}

void setupThiscallUsercall() {
    g_thiscallHook = shHookUsercall(
        THISCALL_TARGET, "void onThiscall()", THISCALL_SIGNATURE,
        "usercall:ret=none;arg0=ecx");
    if (!shIsValidHook(g_thiscallHook)) {
        shLog("thiscall hook failed: " + shLastError());
    }
}

void unloadThiscallUsercall() {
    if (shIsValidHook(g_thiscallHook)) {
        shDestroyHook(g_thiscallHook);
        g_thiscallHook = SH_INVALID_HANDLE;
    }
}
