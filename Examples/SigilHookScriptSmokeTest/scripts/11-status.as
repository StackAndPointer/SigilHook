// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "SigilHook.ash"

void onStatusJit() {
    shSetReturn(shArg(0) + 1);
    shSkipOriginal();
}

void statusEntry() {
    shSetSharedU64Status("statusEntry", 1);
}

void testStatusDetour() {
    uint64 detour = 0;
    uint64 trampoline = 0;
    if (shCreateDetour(shSharedU64("target"), shSharedU64("nativeCallback"), detour, trampoline) != SH_OK) {
        shSetSharedU64("scriptBad", 4001); return;
    }
    if (shInstallHook(detour) != SH_OK || !shIsValidHook(detour)) {
        shSetSharedU64("scriptBad", 4002); return;
    }
    bool hooked = false;
    uint8 hookType = 0;
    if (shIsHookedStatus(detour, hooked) != SH_OK || !hooked ||
        shHookTypeStatus(detour, hookType) != SH_OK || hookType != SH_HOOK_DETOUR ||
        shTrampolineStatus(detour, trampoline) != SH_OK || trampoline == 0) {
        shSetSharedU64("scriptBad", 4003); return;
    }
    uint8 depth = 0;
    if (shMaxDepthStatus(detour, depth) != SH_OK || shSetMaxDepthStatus(detour, depth) != SH_OK ||
        shSetFollowCallStatus(detour, true) != SH_OK || shSetFollowCallStatus(detour, false) != SH_OK ||
        shSetDebugStatus(detour, true) != SH_OK || shSetDebugStatus(detour, false) != SH_OK) {
        shSetSharedU64("scriptBad", 4004); return;
    }
    uint8 scheme = 0;
    const uint8 schemeStatus = shDetourSchemeStatus(detour, scheme);
    const bool schemeExpected = shBuildMode() == SH_MODE_X64 ? schemeStatus == SH_OK : schemeStatus == SH_ERROR_UNSUPPORTED;
    if (!schemeExpected || (shBuildMode() == SH_MODE_X64 && shSetDetourSchemeStatus(detour, scheme) != SH_OK)) {
        shSetSharedU64("scriptBad", 4005); return;
    }
    if (shRemoveHook(detour) != SH_OK || shIsHookedStatus(detour, hooked) != SH_OK || hooked ||
        shSetHookedStatus(detour, true) != SH_OK || shSetHookedStatus(detour, false) != SH_OK ||
        shRehookStatus(detour) != SH_OK || shDestroyHookStatus(detour) != SH_OK) {
        shSetSharedU64("scriptBad", 4006); return;
    }
}

void testStatusHookKinds() {
    uint64 hook = 0;
    uint64 original = 0;
    if (shCreateBreakpoint(shSharedU64("breakpointTarget"), shSharedU64("breakpointCallback"), hook) != SH_OK ||
        shDestroyHookStatus(hook) != SH_OK) {
        shSetSharedU64("scriptBad", 4010); return;
    }
    if (shCreateHardwareBreakpoint(shSharedU64("hardwareTarget"), shSharedU64("hardwareCallback"),
                                   shSharedU64("hardwareThread"), hook) != SH_OK ||
        shDestroyHookStatus(hook) != SH_OK) {
        shSetSharedU64("scriptBad", 4011); return;
    }
    if (shCreateIat("kernel32.dll", "GetCurrentThreadId", "", shSharedU64("iatCallback"), hook, original) != SH_OK ||
        shDestroyHookStatus(hook) != SH_OK) {
        shSetSharedU64("scriptBad", 4012); return;
    }
    if (shCreateEat("eatTestExport", "", shSharedU64("eatCallback"), hook, original) != SH_OK ||
        shDestroyHookStatus(hook) != SH_OK) {
        shSetSharedU64("scriptBad", 4013); return;
    }
}

void testStatusVirtuals() {
    array<uint16> indices(1);
    indices[0] = 0;
    array<uint64> replacements(1);
    replacements[0] = shSharedU64("vfuncCallback");
    uint64 hook = 0;
    uint64 original = 0;
    if (shCreateVFuncEntries(shSharedU64("vfuncObject"), indices, replacements, hook) != SH_OK ||
        shInstallHook(hook) != SH_OK || shOriginalVFuncStatus(hook, 0, original) != SH_OK || original == 0 ||
        shDestroyHookStatus(hook) != SH_OK) {
        shSetSharedU64("scriptBad", 4020); return;
    }
    if (shCreateVTableEntries(shSharedU64("vtableObject"), indices, replacements, SH_RTTI_DEFAULT, hook) != SH_OK ||
        shInstallHook(hook) != SH_OK || shDestroyHookStatus(hook) != SH_OK) {
        shSetSharedU64("scriptBad", 4021); return;
    }
}

void testStatusJit() {
    uint64 jit = 0;
    uint64 address = 0;
    if (shCreateScriptJit("int", "int", "cdecl", "void onStatusJit()", jit, address) != SH_OK || jit == 0 || address == 0) {
        shSetSharedU64("scriptBad", 4030); return;
    }
    uint64 detour = 0;
    uint64 trampoline = 0;
    uint64 bound = 0;
    if (shCreateDetour(shSharedU64("target"), address, detour, trampoline) != SH_OK ||
        shBindDetourToJit(detour, jit, bound) != SH_OK || shDestroyHookStatus(detour) != SH_OK ||
        shDestroyJit(jit) != SH_OK) {
        shSetSharedU64("scriptBad", 4031); return;
    }
}

void testStatusMemoryAndRuntime() {
    const uint64 dataAddress = shSharedU64("helperValueAddress");
    array<uint8> bytes(4);
    bytes[0] = 0x12; bytes[1] = 0x34; bytes[2] = 0x56; bytes[3] = 0x78;
    uint written = 0;
    if (shWriteBytes(dataAddress, bytes, written) != SH_OK || written != 4) {
        shSetSharedU64("scriptBad", 4040); return;
    }
    array<uint8>@ read = shReadBytes(dataAddress, 4);
    if (read is null || read.length() != 4 || read[0] != 0x12 || read[3] != 0x78) {
        shSetSharedU64("scriptBad", 4041); return;
    }
    uint8 previous = 0;
    if (shMemProtectStatus(dataAddress, 4, SH_PROT_RWX, previous) != SH_OK ||
        shMemProtectStatus(dataAddress, 4, previous, previous) != SH_OK) {
        shSetSharedU64("scriptBad", 4042); return;
    }
    uint64 pattern = 0;
    if (shFindPatternStatus(dataAddress, 4, "12 34", pattern) != SH_OK || pattern != dataAddress) {
        shSetSharedU64("scriptBad", 4043); return;
    }
    uint64 value = 0;
    if (shSetSharedU64Status("statusLoopback", 0x1234) != SH_OK ||
        shSharedU64Status("statusLoopback", value) != SH_OK || value != 0x1234) {
        shSetSharedU64("scriptBad", 4044); return;
    }
    if (shCallEntry("void statusEntry()") != SH_OK || shSharedU64("statusEntry") != 1 ||
        shLoadDirectory("") != SH_ERROR_INVALID_ARGUMENT) {
        shSetSharedU64("scriptBad", 4045); return;
    }
    array<uint64> invalidArguments(1);
    invalidArguments[0] = 1;
    if (shCallUsercall(shSharedU64("usercallTarget"), "unsigned int", "unsigned int",
                       "bad", invalidArguments, value) == SH_OK) {
        shSetSharedU64("scriptBad", 4046); return;
    }
}

void main() {
    shStatusString(SH_OK);
    testStatusDetour();
    if (shSharedU64("scriptBad") != 0) return;
    testStatusHookKinds();
    if (shSharedU64("scriptBad") != 0) return;
    testStatusVirtuals();
    if (shSharedU64("scriptBad") != 0) return;
    testStatusJit();
    if (shSharedU64("scriptBad") != 0) return;
    testStatusMemoryAndRuntime();
}
