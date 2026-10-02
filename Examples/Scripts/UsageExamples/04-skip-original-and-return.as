// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Skip the original function entirely and return a value chosen by the script.

#include "SigilHook.ash"

const uint64 SKIP_TARGET = 0x00401000;
const string SKIP_SIGNATURE = "int:int";

uint64 g_skipHook = SH_INVALID_HANDLE;

void onSkip() {
    // Do not run the original body.
    shSkipOriginal();
    // Force the caller-visible return value.
    shSetReturn(shArg(0) * 2);
}

void setupSkipOriginal() {
    g_skipHook = shHookScript(SKIP_TARGET, "void onSkip()", SKIP_SIGNATURE);
    if (!shIsValidHook(g_skipHook)) {
        shLog("skip hook failed: " + shLastError());
    }
}

void unloadSkipOriginal() {
    if (shIsValidHook(g_skipHook)) {
        shDestroyHook(g_skipHook);
        g_skipHook = SH_INVALID_HANDLE;
    }
}
