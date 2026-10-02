// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// From one hook, call a different function inside the target process. This is
// the "hook A, call B" pattern: 0x415D40 -> call 0x41B960 with a fixed value.

#include "SigilHook.ash"

const uint64 HOOKED_FUNCTION = 0x00415D40;   // Board::Update(ecx = this)
const string HOOKED_SIGNATURE = "void:void*";
const uint64 CALLED_FUNCTION = 0x0041B960;   // Board::AddSunMoney(ecx = amount, eax = this)

// The other function uses a custom convention: amount in ecx, this in eax.
const string CALLED_MAPPING = "usercall:ret=eax;arg0=ecx;arg1=eax;cleanup=4";
const string CALLED_PARAMS = "int,void*";

uint64 g_callAnotherHook = SH_INVALID_HANDLE;

void onHookedFunction() {
    const uint64 board = shReg(SH_REG_CX);   // this pointer passed in ecx

    array<uint64> args(2);
    args[0] = 1;        // theAmount = 1
    args[1] = board;    // Board* this

    uint64 result = 0;
    const uint8 status = shCallUsercall(
        CALLED_FUNCTION, "int", CALLED_PARAMS, CALLED_MAPPING, args, result);
    if (status != SH_OK) {
        shLog("AddSunMoney call failed: " + shStatusString(status));
    }

    shKeepOriginal();
}

void setupCallAnotherFunction() {
    g_callAnotherHook = shHookUsercall(
        HOOKED_FUNCTION, "void onHookedFunction()", HOOKED_SIGNATURE,
        "usercall:ret=none;arg0=ecx");
    if (!shIsValidHook(g_callAnotherHook)) {
        shLog("call-another-function hook failed: " + shLastError());
    }
}

void unloadCallAnotherFunction() {
    if (shIsValidHook(g_callAnotherHook)) {
        shDestroyHook(g_callAnotherHook);
        g_callAnotherHook = SH_INVALID_HANDLE;
    }
}
