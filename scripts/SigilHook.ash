// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
// SigilHook standard AngelScript helpers.
// This is intentionally one cross-architecture header. Query shBuildMode() at runtime;
// the DLL and target process must both be x86 or both be x64.
// Include this file from .as scripts with: #include "SigilHook.ash"
#pragma once

const uint64 SH_INVALID_HANDLE = 0;

const uint8 SH_OK = 0;
const uint8 SH_ERROR_INVALID_ARGUMENT = 1;
const uint8 SH_ERROR_NOT_FOUND = 2;
const uint8 SH_ERROR_UNSUPPORTED = 3;
const uint8 SH_ERROR_ARCH_MISMATCH = 4;
const uint8 SH_ERROR_HOOK_FAILED = 5;
const uint8 SH_ERROR_MEMORY = 6;
const uint8 SH_ERROR_SCRIPT = 7;
const uint8 SH_ERROR_BUSY = 8;
const uint8 SH_ERROR_EXCEPTION = 9;

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

bool shIsX86() {
    return shBuildMode() == SH_MODE_X86;
}

bool shIsX64() {
    return shBuildMode() == SH_MODE_X64;
}

uint8 shPointerSize() {
    return shIsX64() ? 8 : 4;
}

bool shRegisterAvailable(SHRegister reg) {
    return shIsX64() || uint8(reg) < uint8(SH_REG_R8);
}

bool shRegisterWritable(SHRegister reg) {
    return reg != SH_REG_SP && shRegisterAvailable(reg);
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

uint8 shReg8(SHRegister reg) {
    return uint8(shReg(reg));
}

bool shSetReg(SHRegister reg, uint64 value) {
    return setRegister(uint8(reg), value);
}

bool shSetReg8(SHRegister reg, uint8 value) {
    const uint64 current = shReg(reg);
    return shSetReg(reg, (current & ~uint64(0xff)) | uint64(value));
}

uint16 shReg16(SHRegister reg) {
    return uint16(shReg(reg) & 0xffff);
}

uint32 shReg32(SHRegister reg) {
    return uint32(shReg(reg) & 0xffffffff);
}

bool shSetReg16(SHRegister reg, uint16 value) {
    const uint64 current = shReg(reg);
    return shSetReg(reg, (current & ~uint64(0xffff)) | uint64(value));
}

bool shSetReg32(SHRegister reg, uint32 value) {
    const uint64 current = shReg(reg);
    return shSetReg(reg, (current & ~uint64(0xffffffff)) | uint64(value));
}

uint64 shFlags() {
    return getFlags();
}

bool shSetFlags(uint64 flags) {
    return setFlags(flags);
}

uint64 shInstructionPointer() {
    return getInstructionPointer();
}

bool shSetInstructionPointer(uint64 address) {
    return setInstructionPointer(address);
}

string shDisAsm(uint64 address, uint maxBytes = 30) {
    return disassemble(address, maxBytes);
}

uint8 shDisAsmStatus(uint64 address, uint maxBytes, string &out text, uint &out decodedBytes) {
    return disassembleStatus(address, maxBytes, text, decodedBytes);
}

uint64 shHtoi(const string &in text) {
    return hexToU64(text);
}

uint8 shParseHexStatus(const string &in text, uint64 &out value) {
    return parseHexStatus(text, value);
}

uint64 shAsmCmp(uint64 left, uint64 right, uint8 operandSize = 4) {
    return asmCmp(left, right, operandSize);
}

uint64 shAsmTest(uint64 left, uint64 right, uint8 operandSize = 4) {
    return asmTest(left, right, operandSize);
}

uint8 shAsmFxsave(array<uint8> &inout state) {
    return asmFxsave(state);
}

uint8 shAsmFxrstor(const array<uint8> &in state) {
    return asmFxrstor(state);
}

uint8 shAsmRetStatus(uint stackAdjust, uint64 &out address) {
    return asmRetStatus(stackAdjust, address);
}

uint64 shAsmRet(uint stackAdjust = 0) {
    return asmRet(stackAdjust);
}

uint8 shAsmRetFree(uint64 address) {
    return destroySnippetStatus(address);
}

uint8 shAsmMovEspAndJmpStatus(uint64 stackPointer, uint64 target, uint64 &out address) {
    return asmMovStackJumpStatus(stackPointer, target, address);
}

uint64 shAsmMovEspAndJmp(uint64 stackPointer, uint64 target) {
    return asmMovStackJump(stackPointer, target);
}

uint8 shAsmMovEspAndJmpFree(uint64 address) {
    return destroySnippetStatus(address);
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

void shSetArg8(uint8 index, uint8 value) {
    const uint64 current = arg(index);
    setArg(index, (current & ~uint64(0xff)) | uint64(value));
}

void shSetArg16(uint8 index, uint16 value) {
    const uint64 current = arg(index);
    setArg(index, (current & ~uint64(0xffff)) | uint64(value));
}

void shSetArg32(uint8 index, uint32 value) {
    const uint64 current = arg(index);
    setArg(index, (current & ~uint64(0xffffffff)) | uint64(value));
}

uint64 shReturn() {
    return returnValue();
}

uint8 shReturn8() {
    return uint8(shReturn());
}

uint16 shReturn16() {
    return uint16(shReturn() & 0xffff);
}

uint32 shReturn32() {
    return uint32(shReturn() & 0xffffffff);
}

void shSetReturn(uint64 value) {
    setReturnValue(value);
}

void shSetReturn8(uint8 value) {
    const uint64 current = shReturn();
    setReturnValue((current & ~uint64(0xff)) | uint64(value));
}

void shSetReturn16(uint16 value) {
    const uint64 current = shReturn();
    setReturnValue((current & ~uint64(0xffff)) | uint64(value));
}

void shSetReturn32(uint32 value) {
    const uint64 current = shReturn();
    setReturnValue((current & ~uint64(0xffffffff)) | uint64(value));
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

uint8 shReadU8(uint64 address) {
    array<uint8>@ bytes = shReadBytes(address, 1);
    return bytes is null ? 0 : bytes[0];
}

uint16 shReadU16(uint64 address) {
    array<uint8>@ bytes = shReadBytes(address, 2);
    if (bytes is null || bytes.length() != 2) return 0;
    return uint16(bytes[0]) | (uint16(bytes[1]) << 8);
}

uint32 shReadU32(uint64 address) {
    array<uint8>@ bytes = shReadBytes(address, 4);
    if (bytes is null || bytes.length() != 4) return 0;
    return uint32(bytes[0]) | (uint32(bytes[1]) << 8) |
           (uint32(bytes[2]) << 16) | (uint32(bytes[3]) << 24);
}

void shWriteU8(uint64 address, uint8 value) {
    array<uint8> bytes(1);
    bytes[0] = value;
    uint written = 0;
    shWriteBytes(address, bytes, written);
}

void shWriteU16(uint64 address, uint16 value) {
    array<uint8> bytes(2);
    bytes[0] = uint8(value);
    bytes[1] = uint8(value >> 8);
    uint written = 0;
    shWriteBytes(address, bytes, written);
}

void shWriteU32(uint64 address, uint32 value) {
    array<uint8> bytes(4);
    bytes[0] = uint8(value);
    bytes[1] = uint8(value >> 8);
    bytes[2] = uint8(value >> 16);
    bytes[3] = uint8(value >> 24);
    uint written = 0;
    shWriteBytes(address, bytes, written);
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

// Status-returning low-level API. These preserve the exact result of the
// corresponding sigilhook_* C ABI function for callers that need error handling.
string shStatusString(uint8 status) {
    return statusString(status);
}

uint8 shCreateDetour(uint64 target, uint64 callback,
                     uint64 &out hook, uint64 &out trampoline) {
    return createDetour(target, callback, hook, trampoline);
}

uint8 shInstallHook(uint64 handle) {
    return installHook(handle);
}

uint8 shDestroyHookStatus(uint64 handle) {
    return destroyStatus(handle);
}

uint8 shRemoveHook(uint64 handle) {
    return removeHook(handle);
}

uint8 shRehookStatus(uint64 handle) {
    return rehookStatus(handle);
}

uint8 shSetHookedStatus(uint64 handle, bool hooked) {
    return setHookedStatus(handle, hooked);
}

uint8 shIsHookedStatus(uint64 handle, bool &out hooked) {
    return isHookedStatus(handle, hooked);
}

uint8 shHookTypeStatus(uint64 handle, uint8 &out type) {
    return hookTypeStatus(handle, type);
}

uint8 shSetDebugStatus(uint64 handle, bool enabled) {
    return setDebugStatus(handle, enabled);
}

uint8 shTrampolineStatus(uint64 handle, uint64 &out trampoline) {
    return trampolineStatus(handle, trampoline);
}

uint8 shMaxDepthStatus(uint64 handle, uint8 &out depth) {
    return maxDepthStatus(handle, depth);
}

uint8 shSetMaxDepthStatus(uint64 handle, uint8 depth) {
    return setMaxDepthStatus(handle, depth);
}

uint8 shSetFollowCallStatus(uint64 handle, bool enabled) {
    return setFollowCallStatus(handle, enabled);
}

uint8 shDetourSchemeStatus(uint64 handle, uint8 &out scheme) {
    return detourSchemeStatus(handle, scheme);
}

uint8 shSetDetourSchemeStatus(uint64 handle, uint8 scheme) {
    return setDetourSchemeStatus(handle, scheme);
}

uint8 shCreateBreakpoint(uint64 target, uint64 callback, uint64 &out hook) {
    return createBreakpoint(target, callback, hook);
}

uint8 shCreateHardwareBreakpoint(
    uint64 target, uint64 callback, uint64 thread, uint64 &out hook) {
    return createHardwareBreakpoint(target, callback, thread, hook);
}

uint8 shCreateIat(const string &in importedDll, const string &in importedApi,
                  const string &in moduleName, uint64 callback,
                  uint64 &out hook, uint64 &out original) {
    return createIat(importedDll, importedApi, moduleName, callback, hook, original);
}

uint8 shCreateEat(const string &in exportedApi, const string &in moduleName,
                  uint64 callback, uint64 &out hook, uint64 &out original) {
    return createEat(exportedApi, moduleName, callback, hook, original);
}

uint8 shCreateVFuncEntries(uint64 object, const array<uint16> &in indices,
                           const array<uint64> &in replacements, uint64 &out hook) {
    return createVFuncEntries(object, indices, replacements, hook);
}

uint8 shCreateVTableEntries(uint64 object, const array<uint16> &in indices,
                            const array<uint64> &in replacements, uint8 rttiMode,
                            uint64 &out hook) {
    return createVTableEntries(object, indices, replacements, rttiMode, hook);
}

uint8 shOriginalVFuncStatus(uint64 handle, uint16 index, uint64 &out original) {
    return originalVFuncStatus(handle, index, original);
}

uint8 shCreateScriptJit(const string &in returnType, const string &in parameters,
                        const string &in convention, const string &in callbackDeclaration,
                        uint64 &out jit, uint64 &out address) {
    return createScriptJit(returnType, parameters, convention,
                           callbackDeclaration, jit, address);
}

uint8 shDestroyJit(uint64 jit) {
    return destroyJit(jit);
}

uint8 shBindDetourToJit(uint64 detour, uint64 jit, uint64 &out hook) {
    return bindDetourToJit(detour, jit, hook);
}

array<uint8>@ shReadBytes(uint64 address, uint size) {
    return readBytes(address, size);
}

uint8 shWriteBytes(uint64 address, const array<uint8> &in bytes, uint &out written) {
    return writeBytes(address, bytes, written);
}

uint8 shMemProtectStatus(uint64 address, uint64 size, uint8 protection,
                         uint8 &out previous) {
    return memProtectStatus(address, size, protection, previous);
}

uint8 shFindPatternStatus(uint64 address, uint64 size, const string &in pattern,
                          uint64 &out result) {
    return findPatternStatus(address, size, pattern, result);
}

uint8 shLoadDirectory(const string &in directory) {
    return loadDirectory(directory);
}

uint8 shCallEntry(const string &in declaration) {
    return callEntry(declaration);
}

uint8 shSetSharedU64Status(const string &in name, uint64 value) {
    return setSharedU64Status(name, value);
}

uint8 shSharedU64Status(const string &in name, uint64 &out value) {
    return sharedU64Status(name, value);
}

uint8 shCallUsercall(uint64 target, const string &in returnType,
                     const string &in parameters, const string &in mapping,
                     const array<uint64> &in arguments, uint64 &out result) {
    return invokeUsercall(target, returnType, parameters, mapping, arguments, result);
}
