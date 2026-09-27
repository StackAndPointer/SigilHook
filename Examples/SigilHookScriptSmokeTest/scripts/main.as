// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "SigilHook.ash"

void main() {
    shSetSharedU64("mainEntryCount", shSharedU64("mainEntryCount") + 1);
    verifyStatus();
    if (shSharedU64("scriptBad") != 0) return;
    verifyCrossFileSharing();
    if (recursiveMarker() != uint64(0x5ec0112233445566)) {
        shSetSharedU64("scriptBad", 900);
        return;
    }
    verifyNativeBinding();
}

void unload() {
    cleanupTestHooks();
    shSetSharedU64("unloadCount", shSharedU64("unloadCount") + 1);
}
