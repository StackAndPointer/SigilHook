// SPDX-License-Identifier: MIT
// SigilHook standard AngelScript helpers.
// Include this file from .as scripts with: #include "SigilHook.ash"

const uint64 SH_INVALID_HANDLE = 0;

enum SHHookType {
    SH_HOOK_UNKNOWN = 0,
    SH_HOOK_DETOUR = 1,
    SH_HOOK_SOFTWARE_BREAKPOINT = 2,
    SH_HOOK_HARDWARE_BREAKPOINT = 3,
    SH_HOOK_IAT = 4,
    SH_HOOK_EAT = 5,
    SH_HOOK_VFUNC_SWAP = 6,
    SH_HOOK_VTABLE_SWAP = 7
};

enum SHProtection {
    SH_PROT_NONE = 0,
    SH_PROT_X = 2,
    SH_PROT_R = 4,
    SH_PROT_W = 8,
    SH_PROT_RWX = 14
};

enum SHBuildMode {
    SH_MODE_X86 = 1,
    SH_MODE_X64 = 2
};

enum SHRegister {
    SH_REG_AX = 0,
    SH_REG_CX = 1,
    SH_REG_DX = 2,
    SH_REG_BX = 3,
    SH_REG_SP = 4,
    SH_REG_BP = 5,
    SH_REG_SI = 6,
    SH_REG_DI = 7,
    SH_REG_R8 = 8,
    SH_REG_R9 = 9,
    SH_REG_R10 = 10,
    SH_REG_R11 = 11,
    SH_REG_R12 = 12,
    SH_REG_R13 = 13,
    SH_REG_R14 = 14,
    SH_REG_R15 = 15
};

enum SHRttiMode {
    SH_RTTI_NONE = 0,
    SH_RTTI_MSVC = 1,
    SH_RTTI_ITANIUM = 2,
    SH_RTTI_DEFAULT = 3
};

bool shIsValidHook(uint64 handle) {
    return handle != SH_INVALID_HANDLE;
}

uint32 shApiVersion() {
    return apiVersion();
}

uint8 shBuildMode() {
    return buildMode();
}

void shClearLastError() {
    clearLastError();
}

string shLastError() {
    return lastError();
}

void shLog(const string &in message) {
    log(message);
}

uint64 shHookScript(uint64 target, const string &in callbackDeclaration, const string &in signature) {
    return hookDetour(target, callbackDeclaration, signature);
}

uint64 shHookConvention(uint64 target, const string &in callbackDeclaration,
                        const string &in signature, const string &in convention) {
    return hookDetourConvention(target, callbackDeclaration, signature, convention);
}

uint64 shHookUsercall(uint64 target, const string &in callbackDeclaration,
                     const string &in signature, const string &in mapping) {
    return hookDetourConvention(target, callbackDeclaration, signature, mapping);
}

uint64 shHookNative(uint64 target, uint64 callback) {
    return hookNative(target, callback);
}

uint64 shHookBreakpoint(uint64 target, uint64 callback) {
    return hookBreakpoint(target, callback);
}

uint64 shHookHardwareBreakpoint(uint64 target, uint64 callback, uint64 thread) {
    return hookHardwareBreakpoint(target, callback, thread);
}

uint64 shHookIat(const string &in importedDll, const string &in importedApi,
                 const string &in moduleName, uint64 callback) {
    return hookIat(importedDll, importedApi, moduleName, callback);
}

uint64 shHookEat(const string &in exportedApi, const string &in moduleName, uint64 callback) {
    return hookEat(exportedApi, moduleName, callback);
}

uint64 shHookVFunc(uint64 object, uint16 index, uint64 replacement) {
    return hookVFunc(object, index, replacement);
}

uint64 shHookVTable(uint64 object, uint16 index, uint64 replacement, uint8 rttiMode) {
    return hookVTable(object, index, replacement, rttiMode);
}

void shEnableHook(uint64 handle) {
    setHooked(handle, true);
}

void shDisableHook(uint64 handle) {
    setHooked(handle, false);
}

void shUnhook(uint64 handle) {
    unhook(handle);
}

void shDestroyHook(uint64 handle) {
    destroyHook(handle);
}

void shRehook(uint64 handle) {
    rehook(handle);
}

bool shIsHooked(uint64 handle) {
    return isHooked(handle);
}

uint8 shHookType(uint64 handle) {
    return hookType(handle);
}

uint64 shTrampoline(uint64 handle) {
    return trampoline(handle);
}

void shSetDebug(uint64 handle, bool enabled) {
    setDebug(handle, enabled);
}

void shSetFollowCall(uint64 handle, bool enabled) {
    setFollowCall(handle, enabled);
}

uint8 shMaxDepth(uint64 handle) {
    return maxDepth(handle);
}

void shSetMaxDepth(uint64 handle, uint8 depth) {
    setMaxDepth(handle, depth);
}

uint8 shDetourScheme(uint64 handle) {
    return detourScheme(handle);
}

void shSetDetourScheme(uint64 handle, uint8 scheme) {
    setDetourScheme(handle, scheme);
}

uint64 shOriginalVFunc(uint64 handle, uint16 index) {
    return originalVFunc(handle, index);
}

uint64 shArg(uint8 index) {
    return arg(index);
}

uint64 shReg(SHRegister reg) {
    return getRegister(uint8(reg));
}

bool shSetReg(SHRegister reg, uint64 value) {
    return setRegister(uint8(reg), value);
}

uint64 shFlags() {
    return getFlags();
}

bool shSetFlags(uint64 flags) {
    return setFlags(flags);
}

uint8 shArg8(uint8 index) {
    return arg8(index);
}

uint16 shArg16(uint8 index) {
    return uint16(arg(index) & 0xffff);
}

uint32 shArg32(uint8 index) {
    return uint32(arg(index) & 0xffffffff);
}

void shSetArg(uint8 index, uint64 value) {
    setArg(index, value);
}

uint64 shReturn() {
    return returnValue();
}

void shSetReturn(uint64 value) {
    setReturnValue(value);
}

void shReturnEarly(uint64 value) {
    setReturnValue(value);
    skipOriginal();
}

void shKeepOriginal() {
    callOriginal();
}

void shSkipOriginal() {
    skipOriginal();
}

uint64 shReadU64(uint64 address) {
    return readU64(address);
}

void shWriteU64(uint64 address, uint64 value) {
    writeU64(address, value);
}

uint8 shMemProtect(uint64 address, uint64 size, uint8 protection) {
    return memProtect(address, size, protection);
}

uint64 shFindPattern(uint64 address, uint64 size, const string &in pattern) {
    return findPattern(address, size, pattern);
}

uint64 shPatternSize(const string &in pattern) {
    return patternSize(pattern);
}

void shSetSharedU64(const string &in name, uint64 value) {
    setSharedU64(name, value);
}

uint64 shSharedU64(const string &in name) {
    return sharedU64(name);
}
