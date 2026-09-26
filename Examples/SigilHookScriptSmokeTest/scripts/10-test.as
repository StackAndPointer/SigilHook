// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "SigilHook.ash"
#include "include/Nested.ash"

uint64 g_hook = SH_INVALID_HANDLE;
uint64 g_crossFileShared = 0;

void setCrossFileShared(uint64 value) {
    g_crossFileShared = value;
}

uint64 getCrossFileShared() {
    return g_crossFileShared;
}

uint64 crossFileFunction(uint64 value) {
    return value ^ SIGILHOOK_TEST_NESTED_VALUE;
}
uint64 g_cdeclHook = SH_INVALID_HANDLE;
uint64 g_stdcallHook = SH_INVALID_HANDLE;
uint64 g_fastcallHook = SH_INVALID_HANDLE;
uint64 g_thiscallHook = SH_INVALID_HANDLE;
uint64 g_vectorcallHook = SH_INVALID_HANDLE;
uint64 g_usercallHook = SH_INVALID_HANDLE;
uint64 g_pointerHook = SH_INVALID_HANDLE;
uint64 g_nativeHook = SH_INVALID_HANDLE;
uint64 g_breakpointHook = SH_INVALID_HANDLE;
uint64 g_hardwareHook = SH_INVALID_HANDLE;
uint64 g_iatHook = SH_INVALID_HANDLE;
uint64 g_eatHook = SH_INVALID_HANDLE;
uint64 g_vfuncHook = SH_INVALID_HANDLE;
uint64 g_vtableHook = SH_INVALID_HANDLE;
uint64 g_helperStep = 0;

void failHelperTest() {
    shSetSharedU64("scriptBad", g_helperStep);
}

void verifyHelperApi() {
    g_helperStep = 200;
    shClearLastError();
    shLastError();
    shLog("SigilHook standard helper smoke test");
    shSetSharedU64("helperLoopback", 0x123456789abcdef0);
    if (shSharedU64("helperLoopback") != 0x123456789abcdef0) { failHelperTest(); return; }

    g_helperStep = 201;
    if (shApiVersion() < 0x00020004 ||
        shBuildMode() != uint8(shSharedU64("expectedBuildMode"))) { failHelperTest(); return; }
    if (shApiVersion() < 0x00020006) { failHelperTest(); return; }

    g_helperStep = 202;
    if (shIsValidHook(SH_INVALID_HANDLE) || !shIsValidHook(1)) { failHelperTest(); return; }

    g_helperStep = 203;
    const string disassembly = shDisAsm(shSharedU64("target"), 30);
    uint decodedBytes = 0;
    string statusText = "";
    const uint8 disassemblyStatus = shDisAsmStatus(shSharedU64("target"), 30, statusText, decodedBytes);
    if (disassembly.isEmpty() || disassemblyStatus != SH_OK || decodedBytes == 0 || statusText.isEmpty()) {
        failHelperTest(); return;
    }
    g_helperStep = 204;
    if (shHtoi("0x123AbC") != 0x123abc || shHtoi("xyz") != 0) { failHelperTest(); return; }
    g_helperStep = 205;
    const uint64 cmpFlags = shAsmCmp(1, 2, 4);
    const uint64 equalFlags = shAsmCmp(7, 7, 4);
    const uint64 testFlags = shAsmTest(0xf0, 0x0f, 4);
    if ((cmpFlags & 0x001) == 0 || (cmpFlags & 0x040) != 0 ||
        (equalFlags & 0x040) == 0 || (equalFlags & 0x001) != 0 ||
        (testFlags & 0x040) == 0 || (testFlags & 0x001) != 0 || (testFlags & 0x800) != 0) {
        failHelperTest(); return;
    }
    g_helperStep = 206;
    array<uint8> firstFx(512);
    array<uint8> secondFx(512);
    if (shAsmFxsave(firstFx) != SH_OK || shAsmFxrstor(firstFx) != SH_OK ||
        shAsmFxsave(secondFx) != SH_OK) { failHelperTest(); return; }
    for (uint index = 0; index < firstFx.length(); ++index) {
        if (firstFx[index] != secondFx[index]) { failHelperTest(); return; }
    }
    g_helperStep = 207;
    uint64 returnSnippet = 0;
    uint64 stackSnippet = 0;
    if (shAsmRetStatus(0, returnSnippet) != SH_OK || returnSnippet == 0 ||
        shAsmRetFree(returnSnippet) != SH_OK || shAsmRetFree(returnSnippet) != SH_ERROR_NOT_FOUND ||
        shAsmMovEspAndJmpStatus(0x10000, 0x20000, stackSnippet) != SH_OK || stackSnippet == 0 ||
        shAsmMovEspAndJmpFree(stackSnippet) != SH_OK) { failHelperTest(); return; }

    g_helperStep = 210;
    if (!shIsHooked(g_hook) || shHookType(g_hook) != SH_HOOK_DETOUR ||
        shTrampoline(g_hook) == 0 || shOriginalVFunc(g_hook, 0) != 0) { failHelperTest(); return; }

    g_helperStep = 211;
    if (shHookType(g_nativeHook) != SH_HOOK_DETOUR) { failHelperTest(); return; }
    g_helperStep = 212;
    if (shHookType(g_breakpointHook) != SH_HOOK_SOFTWARE_BREAKPOINT) { failHelperTest(); return; }
    g_helperStep = 213;
    if (shHookType(g_hardwareHook) != SH_HOOK_HARDWARE_BREAKPOINT) { failHelperTest(); return; }
    g_helperStep = 214;
    if (shHookType(g_iatHook) != SH_HOOK_IAT) { failHelperTest(); return; }
    g_helperStep = 215;
    if (shHookType(g_eatHook) != SH_HOOK_EAT) { failHelperTest(); return; }
    g_helperStep = 216;
    if (shHookType(g_vfuncHook) != SH_HOOK_VFUNC_SWAP ||
        shOriginalVFunc(g_vfuncHook, 0) == 0) { failHelperTest(); return; }
    g_helperStep = 217;
    if (shHookType(g_vtableHook) != SH_HOOK_VTABLE_SWAP ||
        shOriginalVFunc(g_vtableHook, 0) == 0) { failHelperTest(); return; }

    g_helperStep = 220;
    shSetDebug(g_hook, true);
    shSetDebug(g_hook, false);
    shSetFollowCall(g_hook, true);
    shSetFollowCall(g_hook, false);
    shSetMaxDepth(g_hook, shMaxDepth(g_hook));
    shSetDetourScheme(g_hook, shDetourScheme(g_hook));

    g_helperStep = 221;
    shRehook(g_hook);
    if (!shIsHooked(g_hook)) { failHelperTest(); return; }
    shUnhook(g_hook);
    if (shIsHooked(g_hook)) { failHelperTest(); return; }
    shEnableHook(g_hook);
    if (!shIsHooked(g_hook)) { failHelperTest(); return; }
    shDisableHook(g_hook);
    if (shIsHooked(g_hook)) { failHelperTest(); return; }
    shEnableHook(g_hook);
    if (!shIsHooked(g_hook)) { failHelperTest(); return; }

    g_helperStep = 230;
    const uint64 dataAddress = shSharedU64("helperValueAddress");
    shWriteU64(dataAddress, 0x1122334455667788);
    if (shReadU64(dataAddress) != 0x1122334455667788 ||
        shFindPattern(dataAddress, 8, "88 77") != dataAddress ||
        shPatternSize("88 ??") != 2) { failHelperTest(); return; }
    if (shReadU8(dataAddress) != 0x88 || shReadU16(dataAddress) != 0x7788 ||
        shReadU32(dataAddress) != 0x55667788) { failHelperTest(); return; }
    shWriteU8(dataAddress, 0xaa);
    if (shReadU64(dataAddress) != 0x11223344556677aa) { failHelperTest(); return; }
    shWriteU16(dataAddress, 0xbbcc);
    if (shReadU64(dataAddress) != 0x112233445566bbcc) { failHelperTest(); return; }
    shWriteU32(dataAddress, 0xddeeff00);
    if (shReadU64(dataAddress) != 0x11223344ddeeff00 ||
        shReadU8(dataAddress) != 0x00 || shReadU16(dataAddress) != 0xff00 ||
        shReadU32(dataAddress) != 0xddeeff00) { failHelperTest(); return; }
    const uint8 previousProtection = shMemProtect(dataAddress, 8, SH_PROT_RWX);
    shMemProtect(dataAddress, 8, previousProtection);
}

void onTarget() {
    g_helperStep = 10;
    if (shArg(0) != 1 || shArg8(0) != 1 || shArg16(0) != 1 ||
        shArg32(0) != 1 || shReturn() != 0) { failHelperTest(); return; }
    shSetArg(0, 41);
    shSetArg8(0, 0x2a);
    if (shArg(0) != 0x2a) { failHelperTest(); return; }
    shSetArg16(0, 0x0123);
    if (shArg(0) != 0x0123) { failHelperTest(); return; }
    shSetArg32(0, 41);
    if (shArg(0) != 41) { failHelperTest(); return; }
    if (shInstructionPointer() != shSharedU64("target") ||
        !shSetInstructionPointer(shTrampoline(g_hook))) { failHelperTest(); return; }
    shSkipOriginal();
}

void onConvention() {
    g_helperStep = 20;
    if (shArg(0) != 7 || shArg(1) != 9) { failHelperTest(); return; }
    shSetArg(0, 4);
    shSetArg(1, 2);
    shSetReturn8(0xa5);
    if (shReturn8() != 0xa5) { failHelperTest(); return; }
    shSetReturn16(0xbeef);
    if (shReturn16() != 0xbeef) { failHelperTest(); return; }
    shSetReturn32(0x12345678);
    if (shReturn32() != 0x12345678) { failHelperTest(); return; }
    shSetReturn(402);
    shSkipOriginal();
}

void onUsercall() {
    g_helperStep = 30;
    if (shArg(0) != 11 || shArg8(1) != 22 || shArg16(1) != 22 ||
        shArg32(2) != 33) { failHelperTest(); return; }
    g_helperStep = 31;
    if (shReg(SH_REG_CX) != 11 || shReg(SH_REG_DX) != 22) { failHelperTest(); return; }
    if (shReg8(SH_REG_CX) != 11 || shReg16(SH_REG_CX) != 11 ||
        shReg32(SH_REG_CX) != 11) { failHelperTest(); return; }
    if (shReg16(SH_REG_CX) != uint16(shReg(SH_REG_CX))) { failHelperTest(); return; }
    g_helperStep = 32;
    if ((shFlags() & 0x40) != 0) { failHelperTest(); return; }

    g_helperStep = 33;
    const uint64 mode = shSharedU64("usercallMode");
    if (mode == 0) {
        shSetArg(0, 55);
        shSetReg(SH_REG_CX, 100);
        shSetReg(SH_REG_DX, 22);
        shSetArg(2, 300);
        shSetFlags((shFlags() & ~uint64(0x40)) | 0x40);
    } else if (mode == 1) {
        shSetReg(SH_REG_AX, 0x12345678);
        const uint64 originalCx = shReg(SH_REG_CX);
        const uint64 seedUpper = shBuildMode() == SH_MODE_X64
            ? 0xA5A5000000000000 : 0x12340000;
        shSetReg(SH_REG_CX, seedUpper | (originalCx & 0xffff));
        if (!shSetReg8(SH_REG_CX, 0x7a) || shReg8(SH_REG_CX) != 0x7a ||
            (shReg(SH_REG_CX) & ~uint64(0xff)) != (seedUpper & ~uint64(0xff))) { failHelperTest(); return; }
        if (!shSetReg16(SH_REG_CX, 0xa5a5) || shReg16(SH_REG_CX) != 0xa5a5 ||
            (shReg(SH_REG_CX) & ~uint64(0xffff)) != (seedUpper & ~uint64(0xffff))) { failHelperTest(); return; }
        if (!shSetReg32(SH_REG_CX, 0x1234cafe) || shReg32(SH_REG_CX) != 0x1234cafe) { failHelperTest(); return; }
        if (shBuildMode() == SH_MODE_X64 &&
            (shReg(SH_REG_CX) & ~uint64(0xffffffff)) != (seedUpper & ~uint64(0xffffffff))) { failHelperTest(); return; }
        shSetReg(SH_REG_CX, (originalCx & ~uint64(0xffff)) | 0x4000);
        if (!shSetReg16(SH_REG_CX, 0xA5A5) ||
            shReg16(SH_REG_CX) != 0xA5A5 ||
            shReg(SH_REG_CX) != ((originalCx & ~uint64(0xffff)) | 0xA5A5)) { failHelperTest(); return; }
        shSetReg(SH_REG_CX, originalCx);
        shSkipOriginal();
    } else {
        shSetReturn(777);
        shKeepOriginal();
    }
}

void onPointerUsercall() {
    if (shArg(0) != shSharedU64("pointerExpected")) { failHelperTest(); return; }
    const uint64 pointerValue = shArg(0);
    shSetArg8(0, uint8(pointerValue));
    shSetArg16(0, uint16(pointerValue));
    shSetArg32(0, uint32(pointerValue));
    if (shArg(0) != pointerValue) { failHelperTest(); return; }
    shSetSharedU64("pointerScriptCallbacks", shSharedU64("pointerScriptCallbacks") + 1);
    shKeepOriginal();
}

void verify() {
    g_helperStep = 100;
    g_hook = shHookScript(shSharedU64("target"), "void onTarget()", "int:int");
    if (!shIsValidHook(g_hook)) { failHelperTest(); return; }

    g_helperStep = 101;
    g_cdeclHook = shHookConvention(shSharedU64("cdeclTarget"),
        "void onConvention()", "int:int,int", "cdecl");
    if (!shIsValidHook(g_cdeclHook)) { failHelperTest(); return; }
    g_helperStep = 102;
    g_stdcallHook = shHookConvention(shSharedU64("stdcallTarget"),
        "void onConvention()", "int:int,int", "stdcall");
    if (!shIsValidHook(g_stdcallHook)) { failHelperTest(); return; }
    g_helperStep = 103;
    g_fastcallHook = shHookConvention(shSharedU64("fastcallTarget"),
        "void onConvention()", "int:int,int", "fastcall");
    if (!shIsValidHook(g_fastcallHook)) { failHelperTest(); return; }
    g_helperStep = 104;
    g_thiscallHook = shHookConvention(shSharedU64("thiscallTarget"),
        "void onConvention()", "int:int,int", "thiscall");
    if (!shIsValidHook(g_thiscallHook)) { failHelperTest(); return; }
    g_helperStep = 105;
    g_vectorcallHook = shHookConvention(shSharedU64("vectorcallTarget"),
        "void onConvention()", "int:int,int", "vectorcall");
    if (!shIsValidHook(g_vectorcallHook)) { failHelperTest(); return; }

    g_helperStep = 106;
    string mapping = shBuildMode() == SH_MODE_X64
        ? "usercall:ret=rax;arg0=rcx;arg1=rdx;arg2=stack+16"
        : "usercall:ret=eax;arg0=ecx;arg1=edx;arg2=stack+8;cleanup=8";

    array<uint64> invokeArguments(3);
    invokeArguments[0] = 11;
    invokeArguments[1] = 22;
    invokeArguments[2] = 33;
    uint64 invokeResult = 0;
    const uint8 invokeStatus = shCallUsercall(shSharedU64("usercallTarget"),
        "unsigned int", "unsigned int,unsigned int,unsigned int",
        mapping, invokeArguments, invokeResult);
    shSetSharedU64("invokeStatus", invokeStatus);
    shSetSharedU64("invokeResult", invokeResult);
    if (invokeStatus != SH_OK) {
        g_helperStep = 1061;
        failHelperTest();
        return;
    }
    if (invokeResult != 66 && invokeResult != 102) {
        g_helperStep = 1062;
        failHelperTest();
        return;
    }
    g_usercallHook = shHookUsercall(shSharedU64("usercallTarget"), "void onUsercall()",
        "unsigned int:unsigned int,unsigned int,unsigned int", mapping);
    if (!shIsValidHook(g_usercallHook)) { failHelperTest(); return; }

    const string pointerMapping = shBuildMode() == SH_MODE_X64
        ? "usercall:ret=rax;arg0=rcx"
        : "usercall:ret=eax;arg0=ecx;cleanup=8";
    const string pointerHookMapping = shBuildMode() == SH_MODE_X64
        ? "usercall:ret=none;arg0=rcx"
        : "usercall:ret=none;arg0=ecx;cleanup=8";
    array<uint64> pointerArguments(1);
    pointerArguments[0] = shSharedU64("pointerExpected");
    uint64 pointerResult = 0;
    const uint8 pointerInvokeStatus = shCallUsercall(
        shSharedU64("pointerTarget"), "void*", "void*", pointerMapping, pointerArguments, pointerResult);
    if (pointerInvokeStatus != SH_OK || pointerResult != pointerArguments[0]) {
        failHelperTest();
        return;
    }
    g_pointerHook = shHookUsercall(
        shSharedU64("pointerTarget"), "void onPointerUsercall()", "void:void*", pointerHookMapping);
    if (!shIsValidHook(g_pointerHook)) { failHelperTest(); return; }

    g_helperStep = 107;
    g_nativeHook = shHookNative(shSharedU64("nativeTarget"), shSharedU64("nativeCallback"));
    if (!shIsValidHook(g_nativeHook)) { failHelperTest(); return; }
    g_helperStep = 108;
    g_breakpointHook = shHookBreakpoint(
        shSharedU64("breakpointTarget"), shSharedU64("breakpointCallback"));
    if (!shIsValidHook(g_breakpointHook)) { failHelperTest(); return; }
    g_helperStep = 109;
    g_hardwareHook = shHookHardwareBreakpoint(
        shSharedU64("hardwareTarget"), shSharedU64("hardwareCallback"),
        shSharedU64("hardwareThread"));
    if (!shIsValidHook(g_hardwareHook)) { failHelperTest(); return; }

    g_helperStep = 110;
    g_iatHook = shHookIat("kernel32.dll", "GetCurrentThreadId", "",
        shSharedU64("iatCallback"));
    if (!shIsValidHook(g_iatHook)) { failHelperTest(); return; }
    g_helperStep = 111;
    g_eatHook = shHookEat("eatTestExport", "", shSharedU64("eatCallback"));
    if (!shIsValidHook(g_eatHook)) { failHelperTest(); return; }

    g_helperStep = 112;
    g_vfuncHook = shHookVFunc(
        shSharedU64("vfuncObject"), 0, shSharedU64("vfuncCallback"));
    if (!shIsValidHook(g_vfuncHook)) { failHelperTest(); return; }
    g_helperStep = 113;
    g_vtableHook = shHookVTable(
        shSharedU64("vtableObject"), 0, shSharedU64("vtableCallback"), SH_RTTI_DEFAULT);
    if (!shIsValidHook(g_vtableHook)) { failHelperTest(); return; }

    verifyHelperApi();
    const bool expectedX86 = shSharedU64("expectedBuildMode") == SH_MODE_X86;
    if (shIsX86() != expectedX86 || shIsX64() == expectedX86 ||
        shPointerSize() != (expectedX86 ? 4 : 8) ||
        !shRegisterAvailable(SH_REG_CX) || !shRegisterWritable(SH_REG_CX) ||
        shRegisterWritable(SH_REG_SP) ||
        shRegisterAvailable(SH_REG_R8) != !expectedX86 ||
        shRegisterWritable(SH_REG_R8) != !expectedX86) { failHelperTest(); return; }
}

void cleanupTestHooks() {
    if (shIsValidHook(g_hook)) { shDestroyHook(g_hook); g_hook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_cdeclHook)) { shDestroyHook(g_cdeclHook); g_cdeclHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_stdcallHook)) { shDestroyHook(g_stdcallHook); g_stdcallHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_fastcallHook)) { shDestroyHook(g_fastcallHook); g_fastcallHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_thiscallHook)) { shDestroyHook(g_thiscallHook); g_thiscallHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_vectorcallHook)) { shDestroyHook(g_vectorcallHook); g_vectorcallHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_usercallHook)) { shDestroyHook(g_usercallHook); g_usercallHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_pointerHook)) { shDestroyHook(g_pointerHook); g_pointerHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_nativeHook)) { shDestroyHook(g_nativeHook); g_nativeHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_breakpointHook)) { shDestroyHook(g_breakpointHook); g_breakpointHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_hardwareHook)) { shDestroyHook(g_hardwareHook); g_hardwareHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_iatHook)) { shDestroyHook(g_iatHook); g_iatHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_eatHook)) { shDestroyHook(g_eatHook); g_eatHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_vfuncHook)) { shDestroyHook(g_vfuncHook); g_vfuncHook = SH_INVALID_HANDLE; }
    if (shIsValidHook(g_vtableHook)) { shDestroyHook(g_vtableHook); g_vtableHook = SH_INVALID_HANDLE; }
}
