// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Minimal entry detour: run script code before the original function, edit one
// argument, then continue into the original body through the trampoline.

#include "SigilHook.ash"

// Replace with your target function address and its real signature:
//   returnType:arg0,arg1,...
const uint64 ENTRY_DETOUR_TARGET = 0x00401000;
const string ENTRY_DETOUR_SIGNATURE = "int:int";

uint64 g_entryDetourHook = SH_INVALID_HANDLE;

// The callback declaration is separate from the target signature. Use shArg()
// to read target arguments instead of redeclaring them here.
void onEntryDetour() {
    shLog("entry detour reached");

    const int original = int(shArg(0));
    // Change the first integer argument before the original runs.
    shSetArg(0, original + 100);

    // Continue into the original function body.
    shKeepOriginal();
}

void setupEntryDetour() {
    g_entryDetourHook = shHookScript(
        ENTRY_DETOUR_TARGET, "void onEntryDetour()", ENTRY_DETOUR_SIGNATURE);
    if (!shIsValidHook(g_entryDetourHook)) {
        shLog("entry detour failed: " + shLastError());
    }
}

void unloadEntryDetour() {
    if (shIsValidHook(g_entryDetourHook)) {
        shDestroyHook(g_entryDetourHook);
        g_entryDetourHook = SH_INVALID_HANDLE;
    }
}
