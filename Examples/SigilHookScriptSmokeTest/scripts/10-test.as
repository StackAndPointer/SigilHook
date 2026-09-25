#include "SigilHook.ash"

uint64 g_hook = SH_INVALID_HANDLE;

void onTarget() {
    shSetArg(0, 41);
    shReturnEarly(77);
}

void verify() {
    g_hook = shHookScript(sharedU64("target"), "void onTarget()", "int:int");
    if (!shIsValidHook(g_hook)) {
        shLog("script detour was not created");
    }
}

void unload() {
    if (shIsValidHook(g_hook)) {
        shDestroyHook(g_hook);
        g_hook = SH_INVALID_HANDLE;
    }
}
