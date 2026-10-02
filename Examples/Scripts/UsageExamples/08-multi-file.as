// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Cross-file functions, shared globals, and a shared .ash header. All .as files
// in the directory are one SigilHook.Application module, so no import/export is
// needed. The header is expanded once even if several files include it.

#include "SigilHook.ash"
#include "include/Shared.ash"

uint64 g_multiFileHook = SH_INVALID_HANDLE;

// This global is shared with include/Shared.ash.
uint64 g_sharedCounter = 0;

void onMultiFile() {
    // Function defined in include/Shared.ash.
    g_sharedCounter = sharedBump(g_sharedCounter);
    shKeepOriginal();
}

void setupMultiFileExamples() {
    const uint64 target = 0x00401000;
    g_multiFileHook = shHookScript(target, "void onMultiFile()", "int:int");
    if (!shIsValidHook(g_multiFileHook)) {
        shLog("multi-file hook failed: " + shLastError());
    } else {
        shLog("shared counter updated");
    }
}

void unloadMultiFileExamples() {
    if (shIsValidHook(g_multiFileHook)) {
        shDestroyHook(g_multiFileHook);
        g_multiFileHook = SH_INVALID_HANDLE;
    }
}
