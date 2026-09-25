#include "SigilHook.ash"

uint64 g_hook = SH_INVALID_HANDLE;
uint64 g_usercallHook = SH_INVALID_HANDLE;

void onTarget() {
    shSetArg(0, 41);
    shReturnEarly(77);
}

void onUsercall() {
    if (shArg32(0) != 11 || shArg32(1) != 22 || shArg32(2) != 33) {
        shSetSharedU64("usercallBad", 1);
    }
    if (shReg(SH_REG_CX) != 11 || shReg(SH_REG_DX) != 22) {
        shSetSharedU64("usercallBad", 1);
    }
    if ((shFlags() & 0x40) != 0) {
        shSetSharedU64("usercallBad", 1);
    }

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
    }
}

void verify() {
    g_hook = shHookScript(shSharedU64("target"), "void onTarget()", "int:int");
    if (!shIsValidHook(g_hook)) {
        shSetSharedU64("scriptBad", 1);
    }

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
        shSetSharedU64("scriptBad", 1);
    }
}

void unload() {
    if (shIsValidHook(g_hook)) {
        shDestroyHook(g_hook);
        g_hook = SH_INVALID_HANDLE;
    }
    if (shIsValidHook(g_usercallHook)) {
        shDestroyHook(g_usercallHook);
        g_usercallHook = SH_INVALID_HANDLE;
    }
}
