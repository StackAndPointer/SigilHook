#include "../SigilHook/SigilHook.ash"

uint64 g_hook = SH_INVALID_HANDLE;
uint64 g_conventionHook = SH_INVALID_HANDLE;
uint64 g_usercallHook = SH_INVALID_HANDLE;
uint64 g_helperStep = 0;

void failHelperTest() {
    shSetSharedU64("scriptBad", g_helperStep);
}

void verifyHelperApi() {
    g_helperStep = 1;
    shClearLastError();
    shLastError();
    shLog("SigilHook standard helper smoke test");

    g_helperStep = 2;
    if (shApiVersion() < 0x00020003 ||
        shBuildMode() != uint8(shSharedU64("expectedBuildMode"))) {
        failHelperTest();
    }
    g_helperStep = 3;
    if (shIsValidHook(SH_INVALID_HANDLE) || !shIsValidHook(1)) {
        failHelperTest();
    }

    g_helperStep = 4;
    if (!shIsHooked(g_hook) || shHookType(g_hook) != SH_HOOK_DETOUR ||
        shTrampoline(g_hook) == 0 || shOriginalVFunc(g_hook, 0) != 0) {
        failHelperTest();
    }

    g_helperStep = 5;
    shSetDebug(g_hook, true);
    shSetDebug(g_hook, false);
    shSetFollowCall(g_hook, true);
    shSetFollowCall(g_hook, false);
    shSetMaxDepth(g_hook, shMaxDepth(g_hook));
    if (shBuildMode() == SH_MODE_X64) {
        shSetDetourScheme(g_hook, shDetourScheme(g_hook));
    }
    shRehook(g_hook);
    if (!shIsHooked(g_hook)) {
        failHelperTest();
    }
    shDisableHook(g_hook);
    if (shIsHooked(g_hook)) {
        failHelperTest();
    }
    shEnableHook(g_hook);
    if (!shIsHooked(g_hook)) {
        failHelperTest();
    }

    g_helperStep = 6;
    const uint64 dataAddress = shSharedU64("helperValueAddress");
    shWriteU64(dataAddress, 0x1122334455667788);
    if (shReadU64(dataAddress) != 0x1122334455667788 ||
        shFindPattern(dataAddress, 8, "88 77") != dataAddress ||
        shPatternSize("88 ??") != 2) {
        failHelperTest();
    }
    const uint8 previousProtection = shMemProtect(dataAddress, 8, SH_PROT_RWX);
    shMemProtect(dataAddress, 8, previousProtection);
}

void onTarget() {
    g_helperStep = 10;
    if (shArg(0) != 1 || shArg8(0) != 1 || shArg16(0) != 1 ||
        shArg32(0) != 1 || shReturn() != 0) {
        failHelperTest();
    }
    shSetArg(0, 41);
    shReturnEarly(77);
}

void onConvention() {
    g_helperStep = 20;
    if (shArg(0) != 7 || shArg(1) != 9) {
        failHelperTest();
    }
    shSetArg(0, 4);
    shSetArg(1, 2);
    shSetReturn(402);
    shSkipOriginal();
}

void onUsercall() {
    g_helperStep = 30;
    if (shArg(0) != 11 || shArg8(1) != 22 || shArg16(1) != 22 ||
        shArg32(2) != 33) {
        failHelperTest();
    }
    g_helperStep = 31;
    if (shReg(SH_REG_CX) != 11 || shReg(SH_REG_DX) != 22) {
        failHelperTest();
    }
    g_helperStep = 32;
    if ((shFlags() & 0x40) != 0) {
        failHelperTest();
    }

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
        shSkipOriginal();
    } else {
        shSetReturn(777);
        shKeepOriginal();
    }
}

void verify() {
    g_helperStep = 40;
    g_hook = shHookScript(shSharedU64("target"), "void onTarget()", "int:int");
    if (!shIsValidHook(g_hook)) {
        failHelperTest();
    }

    g_helperStep = 41;
    g_conventionHook = shHookConvention(
        shSharedU64("conventionTarget"), "void onConvention()", "int:int,int", "cdecl");
    if (!shIsValidHook(g_conventionHook)) {
        failHelperTest();
    }

    g_helperStep = 42;
    string mapping;
    if (shBuildMode() == SH_MODE_X64) {
        mapping = "usercall:ret=rax;arg0=rcx;arg1=rdx;arg2=stack+16";
    } else {
        mapping = "usercall:ret=eax;arg0=ecx;arg1=edx;arg2=stack+8;cleanup=8";
    }
    g_usercallHook = shHookUsercall(
        shSharedU64("usercallTarget"), "void onUsercall()",
        "unsigned int:unsigned int,unsigned int,unsigned int", mapping);
    if (!shIsValidHook(g_usercallHook)) {
        failHelperTest();
    }

    verifyHelperApi();
}

void unload() {
    if (shIsValidHook(g_hook)) {
        shDestroyHook(g_hook);
        g_hook = SH_INVALID_HANDLE;
    }
    if (shIsValidHook(g_conventionHook)) {
        shDestroyHook(g_conventionHook);
        g_conventionHook = SH_INVALID_HANDLE;
    }
    if (shIsValidHook(g_usercallHook)) {
        shDestroyHook(g_usercallHook);
        g_usercallHook = SH_INVALID_HANDLE;
    }
}
