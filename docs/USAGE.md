# SigilHook Usage Guide

Copyright (c) 2026 StackAndPointer

Chinese version: [中文使用说明](USAGE.zh-CN.md)

This guide describes the script-facing runtime, the standard AngelScript header, and the exported C ABI. It is intended for someone deploying `SigilHook.dll` into a matching x86 or x64 process and writing `.as` code for it.

## 1. Design and architecture

SigilHook builds two DLL variants with the same API:

| Build | Target process | Pointer width | General-purpose registers | x86 usercall cleanup |
| --- | --- | ---: | --- | --- |
| `_build-x86/SigilHook.dll` | 32-bit | 4 bytes | `AX`, `CX`, `DX`, `BX`, `SP`, `BP`, `SI`, `DI` | Allowed |
| `_build-x64/SigilHook.dll` | 64-bit | 8 bytes | `AX` through `R15` aliases | Must be `0` or omitted |

The standard header is intentionally **one file**, [`scripts/SigilHook.ash`](../scripts/SigilHook.ash). It is not split into `x86.ash` and `x64.ash` because the script API is textually identical; only the DLL, target process, pointer width, and available registers differ. A portable script queries the active build at runtime:

```angelscript
#include "SigilHook.ash"

void example() {
    if (shIsX86()) {
        // 32-bit process
    } else if (shIsX64()) {
        // 64-bit process
    }
}
```

`shBuildMode()` returns `SH_MODE_X86` or `SH_MODE_X64`. `shPointerSize()` returns `4` or `8`. Use `shRegisterAvailable()` before touching an extended register and `shRegisterWritable()` to account for the read-only `SP` rule.

An x86 DLL must be injected only into an x86 process, and an x64 DLL only into an x64 process. The DLL does not make an x86 script target valid in an x64 process.

## 2. Build artifacts

From a Visual Studio developer prompt:

```powershell
vcvarsall.bat x64
cmake -S . -B _build-x64 -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-x64 --config Release --target SigilHook SigilHookDll
ctest --test-dir _build-x64 -C Release --output-on-failure
```

For x86, use `vcvarsall.bat x86` and `_build-x86`:

```powershell
vcvarsall.bat x86
cmake -S . -B _build-x86 -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-x86 --config Release --target SigilHook SigilHookDll
ctest --test-dir _build-x86 -C Release --output-on-failure
```

The main outputs are:

```text
_build-x86/SigilHook.dll
_build-x86/SigilHook.lib
_build-x86/SigilHookImport.lib
_build-x64/SigilHook.dll
_build-x64/SigilHook.lib
_build-x64/SigilHookImport.lib
```

`SigilHook.lib` is the static C++ library. `SigilHookImport.lib` is the import library for the exported C ABI. The CMake build copies the standard header into `SigilHook/SigilHook.ash` in the selected build directory.

The repository workflow also builds MSVC and clang-cl with Visual Studio for
both `Win32` and `x64`. The manual workflow accepts an optional `release_tag`.
When supplied, it publishes four Windows packages and two GCC Linux packages:

```text
SigilHook-msvc-x86.zip
SigilHook-msvc-x64.zip
SigilHook-clang-cl-x86.zip
SigilHook-clang-cl-x64.zip
SigilHook-gcc-x86.zip
SigilHook-gcc-x64.zip
```

Each Windows package contains the deployable layout below. The `.ash` file is
shipped beside the DLL so a new deployment has the standard declarations
immediately:

```text
SigilHook.dll
SigilHook/
  SigilHook.ash
```

The GCC x86/x64 jobs are Linux source-build and test checks. They are not
Windows DLL release packages. Their release packages contain the Linux static
library, C header, and standard AngelScript header:

```text
libSigilHook.a
include/
  sigilhook.h
SigilHook/
  SigilHook.ash
```

## 3. Deployment and loading

The default script directory is:

```text
<SigilHook.dll directory>\SigilHook\
```

The runtime creates and writes:

```text
<SigilHook.dll directory>\SigilHook\logs\SigilHook.log
```

The expected application layout is:

```text
<host>\SigilHook.dll
<host>\SigilHookReload.bat
<host>\SigilHook\main.as
<host>\SigilHook\feature.as
<host>\SigilHook\include\*.ash
<host>\SigilHook\SigilHook.ash
<host>\SigilHook\logs\SigilHook.log
```

The injectable DLL starts AngelScript on a worker thread during `DLL_PROCESS_ATTACH`, then loads the directory beside the DLL. Set `SIGILHOOK_DISABLE_AUTOLOAD=1` when the host must manage the runtime explicitly:

```cpp
sigilhook_runtime_start(L"<script directory>");
sigilhook_runtime_load_directory(L"<script directory>");
// ...
sigilhook_runtime_stop();
```

Call `sigilhook_runtime_stop()` before unloading the DLL. Runtime teardown must not run from `DllMain` while the Windows loader lock is active. This is a required protocol: never call `FreeLibrary` while the runtime is started. The default stop timeout is 5000 ms; use `sigilhook_runtime_stop_with_timeout(timeout_ms)` to choose another timeout. Stopping first rejects new script callbacks and the AngelScript line callback asks active scripts to abort on their own script thread. Native code blocked inside a callback cannot be cancelled; if it does not exit before the deadline, the function returns `SIGILHOOK_ERROR_BUSY` and the hooks, module, and engine remain alive. Do not unload the DLL; retry from a native thread or terminate the host process. Calling stop from an active AngelScript context also returns `SIGILHOOK_ERROR_BUSY`. Process termination does not require runtime teardown.

On Windows, the injected DLL also starts a local named pipe for manual script
hot reload. Each host owns its own pipe named `\\.\pipe\SigilHook.<pid>`, so
several injected processes can coexist. Run `SigilHookReload.bat` from the build
output, install directory, or release package:

```bat
SigilHookReload.bat            rem reload every live SigilHook host
SigilHookReload.bat <pid>      rem reload only the host with that process id
```

The script finds the live `SigilHook.<pid>` pipes, connects to each selected
one, and waits for the `OK` request acknowledgement. The pipe worker then
reloads that host's current script directory: it stops the loaded AngelScript
application, reruns `main.as::main()`, and logs the result to
`<SigilHook.dll directory>\SigilHook\logs\SigilHook.log`. The acknowledgement
means only that the reload request was accepted, not that the new script
compiled. A reload fails with `BUSY` while a script callback cannot quiesce; no
scripts or hooks are unloaded in that case. A failed reload still stops the
partially started replacement runtime, so the caller can fix `main.as` and load
the directory again. The pipes are local-only.

The DLL itself is not an injector. The host still needs a process-injection mechanism, and the injected DLL must match the target process architecture.

## 4. Script modules and includes

The loader recursively collects every `.as` file under the script directory in deterministic path order. All collected files are added as sections of one AngelScript module named `SigilHook.Application`.

Consequences:

- Functions declared in one `.as` file are directly callable from another `.as` file.
- Global variables are shared directly.
- No `import` or `export` declaration is needed for application files.
- `.ash` files are headers, not standalone application entry points.
- Only the root `main.as` may define `void main()` and the optional `void unload()`.
- The module is built once; `main()` runs once after the whole module succeeds; `unload()` runs once during shutdown.

A minimal application:

```angelscript
// main.as
#include "SigilHook.ash"

void main() {
    shLog("application started");
}

void unload() {
    shLog("application stopped");
}
```

Headers are resolved relative to the including file first, then relative to the script root:

```angelscript
#include "helpers.ash"
#include <include/shared.ash>
```

The loader removes an optional `#pragma once`. Every normalized header path is expanded once for the application, so repeated includes are safe without protection macros. Include lines are replaced with blank lines, preserving line numbers in errors. Missing files, invalid directives, cycles, and include depth over 16 are reported with the include chain. The loader does not implement `#ifndef`, `#define`, or a complete C preprocessor.

A normal `.as` file should be compiled directly as an application section; include only `.ash` files.

## 5. Standard header API

Copy [`scripts/SigilHook.ash`](../scripts/SigilHook.ash) into the deployed `SigilHook` directory. It defines constants, enums, convenience wrappers, and status-returning wrappers around the registered AngelScript API.

### Runtime and status

```angelscript
uint32 version = shApiVersion();
uint8 mode = shBuildMode();
bool is32 = shIsX86();
bool is64 = shIsX64();
uint8 pointerWidth = shPointerSize();

shClearLastError();
string message = shLastError();
shLog("hello");
string statusText = shStatusString(SH_OK);
```

The current C API version is `0x0002000C`.

`sigilhook_invoke_usercall` caches generated invoker stubs by target and
signature. Runtime shutdown clears that cache. A native host that uses the C
ABI without stopping the runtime should call
`sigilhook_clear_invoker_cache()` when those targets are no longer needed.

Status codes are:

```text
SH_OK
SH_ERROR_INVALID_ARGUMENT
SH_ERROR_NOT_FOUND
SH_ERROR_UNSUPPORTED
SH_ERROR_ARCH_MISMATCH
SH_ERROR_HOOK_FAILED
SH_ERROR_MEMORY
SH_ERROR_SCRIPT
SH_ERROR_BUSY
SH_ERROR_EXCEPTION
```

Convenience functions such as `shHookScript()` and `shDestroyHook()` discard the underlying status where the legacy helper did so. Use `sh...Status` or the explicit status-returning forms when failure handling matters.

### Complete script interface index

The standard header is the public script API. Its functions are grouped below:

| Group | Functions |
| --- | --- |
| Runtime and status | `shIsValidHook`, `shApiVersion`, `shBuildMode`, `shIsX86`, `shIsX64`, `shPointerSize`, `shClearLastError`, `shLastError`, `shLog`, `shStatusString` |
| Hook creation | `shHookScript`, `shHookEntryContinue`, `shHookInstructionStatus`, `shHookMid` (deprecated alias), `shHookConvention`, `shHookUsercall`, `shHookNative`, `shHookBreakpoint`, `shHookHardwareBreakpoint`, `shHookIat`, `shHookEat`, `shHookVFunc`, `shHookVTable` |
| Hook lifecycle | `shEnableHook`, `shDisableHook`, `shUnhook`, `shDestroyHook`, `shRehook`, `shIsHooked`, `shHookType`, `shTrampoline`, `shOriginalVFunc`, `shContinueOriginal`, `shResumeMid` (deprecated alias) |
| Detour configuration | `shSetDebug`, `shSetFollowCall`, `shMaxDepth`, `shSetMaxDepth`, `shDetourScheme`, `shSetDetourScheme` |
| Callback frame | `shArg`, `shArg8`, `shArg16`, `shArg32`, `shSetArg`, `shSetArgStatus`, `shSetArg8`, `shSetArg16`, `shSetArg32`, `shReturn`, `shReturn8`, `shReturn16`, `shReturn32`, `shSetReturn`, `shSetReturnStatus`, `shSetReturn8`, `shSetReturn16`, `shSetReturn32`, `shReturnEarly`, `shKeepOriginal`, `shSkipOriginal` |
| Registers and control flow | `shRegisterAvailable`, `shRegisterWritable`, `shXmmAvailable`, `shReg`, `shReg8`, `shReg16`, `shReg32`, `shSetReg`, `shSetReg8`, `shSetReg16`, `shSetReg32`, `shXmm`, `shSetXmm`, `shXmmFloat`, `shSetXmmFloat`, `shXmmDouble`, `shSetXmmDouble`, `shFloatBits`, `shBitsFloat`, `shDoubleBits`, `shBitsDouble`, `shFlags`, `shSetFlags`, `shInstructionPointer`, `shSetInstructionPointer`, `shInstructionPointerStatus`, `shSetInstructionPointerStatus`, `shContextInstructionPointerStatus`, `shContextSetInstructionPointerStatus` |
| Memory and scanning | `shReadBytes`, `shReadU8`, `shReadU16`, `shReadU32`, `shReadU64`, `shWriteBytes`, `shWriteU8`, `shWriteU16`, `shWriteU32`, `shWriteU64`, `shMemProtect`, `shMemProtectStatus`, `shFindPattern`, `shFindPatternStatus`, `shPatternSize` |
| Assembly and disassembly | `shDisAsm`, `shDisAsmStatus`, `shHtoi`, `shParseHexStatus`, `shAsmCmp`, `shAsmTest`, `shAsmFxsave`, `shAsmFxrstor`, `shAsmRet`, `shAsmRetStatus`, `shAsmRetFree`, `shAsmMovEspAndJmp`, `shAsmMovEspAndJmpStatus`, `shAsmMovEspAndJmpFree` |
| Explicit status APIs | `shCreateDetour`, `shCreateBreakpoint`, `shCreateHardwareBreakpoint`, `shCreateIat`, `shCreateEat`, `shCreateVFuncEntries`, `shCreateVTableEntries`, `shInstallHook`, `shDestroyHookStatus`, `shRemoveHook`, `shRehookStatus`, `shSetHookedStatus`, `shIsHookedStatus`, `shHookTypeStatus`, `shSetDebugStatus`, `shTrampolineStatus`, `shOriginalVFuncStatus`, `shMaxDepthStatus`, `shSetMaxDepthStatus`, `shSetFollowCallStatus`, `shDetourSchemeStatus`, `shSetDetourSchemeStatus` |
| Advanced runtime | `shCreateScriptJit`, `shDestroyJit`, `shBindDetourToJit`, `shLoadDirectory`, `shReloadStatus`, `shReloadWithTimeoutStatus`, `shWaitForTrampolinesStatus`, `shCallEntry`, `shSetSharedU64`, `shSharedU64`, `shSetSharedU64Status`, `shSharedU64Status`, `shCallUsercall`, `shNativeAddress`, `shInvokeNativeBlob`, `shNativeThrow`, `shNativeStringBytes`, `shBufferAddress` |

The exact declarations, parameter widths, return values, and `out` parameters
are defined by [`scripts/SigilHook.ash`](../scripts/SigilHook.ash). Native
integrations use the corresponding C ABI declarations in
[`include/sigilhook.h`](../include/sigilhook.h).

### Hook construction

| Operation | Convenience helper | Status-returning helper |
| --- | --- | --- |
| Detour | `shHookScript`, `shHookConvention`, `shHookUsercall` | `shCreateDetour` + `shInstallHook` |
| Raw callback address | `shHookNative` | `shCreateDetour` + `shInstallHook` |
| Software breakpoint | `shHookBreakpoint` | `shCreateBreakpoint` + `shInstallHook` |
| Hardware breakpoint | `shHookHardwareBreakpoint` | `shCreateHardwareBreakpoint` + `shInstallHook` |
| Import table | `shHookIat` | `shCreateIat` + `shInstallHook` |
| Export table | `shHookEat` | `shCreateEat` + `shInstallHook` |
| Virtual function | `shHookVFunc` | `shCreateVFuncEntries` + `shInstallHook` |
| Virtual table | `shHookVTable` | `shCreateVTableEntries` + `shInstallHook` |

`shHookScript(target, callbackDeclaration, signature)` uses the default convention. Use `shHookConvention()` for `cdecl`, `stdcall`, `fastcall`, `thiscall`, or `vectorcall`, and `shHookUsercall()` for a custom mapping.

A typical installed detour:

```angelscript
uint64 g_hook = SH_INVALID_HANDLE;

void onTarget() {
    shLog("target entered");
    shKeepOriginal();
}

void main() {
    g_hook = shHookScript(0x00415d40, "void onTarget()", "void:void*");
    if (!shIsValidHook(g_hook)) {
        shLog("hook creation failed: " + shLastError());
    }
}

void unload() {
    if (shIsValidHook(g_hook)) {
        shDestroyHook(g_hook);
        g_hook = SH_INVALID_HANDLE;
    }
}
```

The `signature` describes the target function to the JIT callback. It is separate from the AngelScript callback declaration; the callback can use `shArg()` to inspect the target arguments without duplicating them as AngelScript parameters.

### Hook lifecycle and configuration

```angelscript
shDisableHook(g_hook);
shEnableHook(g_hook);
shUnhook(g_hook);
shRehook(g_hook);
bool active = shIsHooked(g_hook);
uint8 type = shHookType(g_hook);
uint64 trampoline = shTrampoline(g_hook);
shSetDebug(g_hook, true);
shSetFollowCall(g_hook, false);
shSetMaxDepth(g_hook, 5);
```

`shSetFollowCall()` controls whether a target function address that is a `CALL` destination is followed while resolving the hook target. `shMaxDepth()` controls detour prologue resolution depth. The x64 detour scheme helpers are available only for x64 detours:

```angelscript
if (shIsX64()) {
    uint8 scheme = shDetourScheme(g_hook);
    shSetDetourScheme(g_hook, scheme);
}
```

`shOriginalVFunc(handle, index)` retrieves a virtual-function entry saved by a VFunc or VTable hook.

## 6. Callback arguments, returns, and original execution

Inside a script callback:

```angelscript
uint64 value = shArg(0);
shSetArg(0, value + 1);

uint64 result = shReturn();
shSetReturn(result + 1);
shKeepOriginal();
```

Available controls:

- `shArg(index)` and `shArg8/16/32(index)` read a logical argument.
- `shSetArg(index, value)` and `shSetArg8/16/32(index, value)` modify it.
- `shSetArgStatus(index, value)` is the status-returning form of `shSetArg`.
- `shReturn()` and `shReturn8/16/32()` read the pending return value.
- `shSetReturn(value)` and `shSetReturn8/16/32(value)` override it.
- `shSetReturnStatus(value)` is the status-returning form of `shSetReturn`.
- `shKeepOriginal()` requests the original/trampoline call.
- `shSkipOriginal()` suppresses the original call.
- `shReturnEarly(value)` sets a return value and suppresses the original call.

Argument indices are logical indices from the declared target signature, not raw stack offsets. An argument mapped to a register is also visible through `shReg()`. If an explicit `shSetArg()` change is made, that argument value wins over a later register-only update; otherwise a mapped register write is applied.

The callback frame is thread-local. Concurrent hook callbacks use separate active frames. Callback state must not be cached across callbacks unless the script explicitly owns the lifetime.

## 7. Calling conventions and usercall

Supported standard conventions are:

```text
cdecl       __cdecl
stdcall     __stdcall
fastcall    __fastcall
thiscall    __thiscall
vectorcall  __vectorcall
```

Custom mappings use:

```text
usercall:ret=<register|none>;argN=<register|stack+offset>;cleanup=<bytes>
```

Rules:

- Every declared parameter needs a unique `argN`.
- Non-void returns require `ret=<register>`; void returns require `ret=none`.
- Register locations cannot be duplicated.
- `SP` cannot be an argument or return location.
- `stack+offset` is a byte offset from target-entry stack pointer, including the return address and ABI-reserved space.
- Stack ranges must be aligned to the pointer size and cannot overlap.
- `cleanup` is accepted only on x86; x64 must omit it or use `cleanup=0`.
- x86 usercall returns wider than 32 bits are not supported.
- x86 cannot use `R8..R15`.
- `xmm0..xmm7` are valid argument locations on both architectures and `xmm8..xmm15` on x64. Use them when a custom convention places a float or double in a specific vector register, for example `usercall:ret=eax;arg0=xmm0;arg1=xmm1`.
- Vector-register returns are not supported for usercall mappings; keep `ret` in a general-purpose register.

Example:

```angelscript
string mapping = shIsX64()
    ? "usercall:ret=rax;arg0=rcx;arg1=rdx;arg2=stack+16"
    : "usercall:ret=eax;arg0=ecx;arg1=edx;arg2=stack+8;cleanup=8";

uint64 hook = shHookUsercall(
    target, "void callback()", "unsigned int:unsigned int,unsigned int,unsigned int", mapping);
```

`shCallUsercall()` invokes an arbitrary target with the same mapping:

```angelscript
array<uint64> args(2);
args[0] = 10;
args[1] = 20;
uint64 result = 0;
uint8 status = shCallUsercall(
    target, "unsigned int", "unsigned int,unsigned int",
    "usercall:ret=rax;arg0=rcx;arg1=rdx", args, result);
```

Pointer types are architecture-sized: `void*`, `T*`, `intptr_t`, and `uintptr_t` are 4 bytes on x86 and 8 bytes on x64.

## 8. Registers, flags, and instruction pointer

`SHRegister` names are logical canonical names. Mapping strings and lower-level APIs accept the usual aliases such as `eax`, `rax`, `r8d`, `r8w`, and `r8b`, case-insensitively.

```angelscript
uint64 cx = shReg(SH_REG_CX);
uint16 low = shReg16(SH_REG_CX);
uint8 byteValue = shReg8(SH_REG_CX);
shSetReg16(SH_REG_CX, low + 1);
```

Semantics:

- `shReg()` reads the full frame value.
- `shReg8()`, `shReg16()`, and `shReg32()` read only the low width.
- Width-specific setters preserve bits above the selected width in the callback frame where the architecture permits it. A 32-bit write in a physical x86 register follows hardware zero-extension, so do not depend on an x86 upper 32-bit value.
- `SP` is readable but read-only.
- `R8..R15` are unavailable on x86.
- XMM0-7 are available on x86 and XMM0-15 on x64. Each XMM value exposes two 64-bit lanes: lane 0 is the low 64 bits and lane 1 is the high 64 bits. `shXmmFloat()` and `shSetXmmFloat()` use lane 0 for `float`; `shXmmDouble()` and `shSetXmmDouble()` use lane 0 for `double`. `shFloatBits()`/`shBitsFloat()` and `shDoubleBits()`/`shBitsDouble()` convert between floating-point values and their integer bit representations. On x64, floating-point arguments are synchronized through XMM registers. On x86, standard floating-point arguments are stack-based, so use `shSetArg()` to change the argument passed to the original function.
- Segment, control, and debug registers are outside the current API.

```angelscript
uint64 flags = shFlags();
shSetFlags((flags & ~uint64(0x40)) | 0x40);
```

Flags are restored before the original call or final return. Do not rely on language-ABI flags surviving across the callback boundary.

```angelscript
uint64 ip = shInstructionPointer();
shSetInstructionPointer(trampoline);
```

`shSetInstructionPointer()` redirects control after mapped arguments and flags are restored. `shInstructionPointerStatus()` and `shSetInstructionPointerStatus()` are the explicit-status forms; `SHCallContext` also exposes `getInstructionPointer[Status]()` and `setInstructionPointer[Status]()`. A callback frame without a redirect destination returns `SH_ERROR_UNSUPPORTED`. The redirect uses one volatile scratch register (`EAX` on x86 or `R10` on x64), so avoid assigning a custom-mapped argument to that register when redirecting.

## 9. Memory, pattern, and assembly helpers

Scalar helpers:

```angelscript
uint8 a = shReadU8(address);
uint16 b = shReadU16(address);
uint32 c = shReadU32(address);
uint64 d = shReadU64(address);

shWriteU8(address, 0x12);
shWriteU16(address, 0x3456);
shWriteU32(address, 0x789abcde);
shWriteU64(address, 0x0123456789abcdef);
```

The scalar helpers are little-endian and convenience forms discard status. For explicit error handling use `shReadBytes()`, `shWriteBytes()`, `shMemProtectStatus()`, and `shFindPatternStatus()`.

Protection flags are `SH_PROT_NONE`, `SH_PROT_X`, `SH_PROT_R`, `SH_PROT_W`, and `SH_PROT_RWX`. Pattern strings use IDA-style bytes and `??` wildcards:

```angelscript
uint64 found = shFindPattern(start, size, "8B ?? ?? 89");
```

Disassembly and parsing:

```angelscript
string text = shDisAsm(address, 32);
uint64 value = shHtoi("0x1234");
uint8 status = shParseHexStatus("1234", value);
```

Executable snippets must be released with their matching free helper:

```angelscript
uint64 retSnippet = 0;
if (shAsmRetStatus(0, retSnippet) == SH_OK) {
    shAsmRetFree(retSnippet);
}

uint64 jumpSnippet = 0;
if (shAsmMovEspAndJmpStatus(stackPointer, destination, jumpSnippet) == SH_OK) {
    shAsmMovEspAndJmpFree(jumpSnippet);
}
```

`shAsmMovEspAndJmp()` moves `ESP` on x86 and `RSP` on x64 before jumping. `shAsmFxsave()` and `shAsmFxrstor()` require a 512-byte `array<uint8>`.

## 10. Shared values and runtime entry calls

The host and scripts can exchange `uint64` values through named shared storage:

```angelscript
shSetSharedU64("seed", 42);
uint64 seed = shSharedU64("seed");
```

Status forms are `shSetSharedU64Status()` and `shSharedU64Status()`. `shCallEntry("void myEntry()")` invokes a function in the loaded application module. `shLoadDirectory()` is available for explicit loading, but the normal deployment path is the DLL autoload described above. `shReloadStatus()` and `shReloadWithTimeoutStatus(timeoutMs)` stop and reload the current application; call them from native-driven tools rather than from a callback that is currently executing in that module. `shWaitForTrampolinesStatus(timeoutMs)` waits for retired detour trampolines that still have target threads executing inside them.

## 11. Error handling and logs

For development, check the log:

```text
<SigilHook.dll directory>\SigilHook\logs\SigilHook.log
```

AngelScript compile errors, missing entry points, callback lookup failures, hook failures, and callback execution failures are written there. Typical checks are:

```angelscript
shClearLastError();
uint64 hook = shHookScript(...);
if (!shIsValidHook(hook)) {
    shLog("failed: " + shLastError());
}
```

When a status-returning API returns non-`SH_OK`, convert it with `shStatusString()` and include it in the log. Treat a failed script load or entry execution as fatal for the current runtime: fix `main.as`, include errors, or duplicate declarations, then restart the runtime before loading again.

## Header conversion and native DLL bindings

`tools/header_to_ash.py` converts supported Windows C ABI `.h`/`.hpp` declarations into deterministic `.ash` wrappers:

```powershell
python tools\header_to_ash.py include\GameApi.h `
  --dll GameApi.dll --output SigilHook\GameApi.ash --arch x86
```

The converter uses only the Python standard library and supports local includes, simple preprocessing macros, typedefs, enums, fixed-layout POD records, pointers, `const char *`, Windows `const wchar_t *`, and `cdecl`, `stdcall`, `fastcall`, `thiscall`, `vectorcall`, or explicit `usercall` annotations. Use `--check` to verify that generated output is current in CI.

Templates, class methods, mangled C++ names, non-POD records, virtual functions, variadic calls, unions, bit-fields, and unknown `#pragma pack` layouts are rejected with file/line/column diagnostics. Generated wrappers cache DLL/export lookup, serialize record fields explicitly, and raise AngelScript exceptions when native invocation fails. `shNativeAddress`, `shInvokeNativeBlob`, `shNativeThrow`, `shNativeStringBytes`, and `shBufferAddress` expose the lower-level runtime operations.

## Entry-continue and instruction hooks

`shHookEntryContinue()` is the clear name for an entry detour that continues through the trampoline; `shHookMid()` and `shResumeMid()` remain as compatibility aliases. `shHookEntryContinue()` runs before the original entry and then continues through the trampoline:

```angelscript
void beforeTarget() {
    // inspect or update state
    shContinueOriginal(g_entryHook);
}
```

`shHookInstructionStatus()` is the real instruction-level hook. It verifies the address is an instruction boundary, relocates the overwritten instructions into a trampoline, and fails with a log message when the overwritten range contains relative control flow or `ret`:

```angelscript
uint64 hook = 0;
uint64 trampoline = 0;
uint64 overwritten = 0;
uint8 status = shHookInstructionStatus(0x415D40, "void onInstruction()", "void");
```

Callbacks may use the `SHCallContext` object instead of the thread-local helper functions:

```angelscript
void onTarget(SHCallContext@ ctx) {
    uint64 value = ctx.getArg(0);
    ctx.setReturn(value + 1);
    ctx.continueOriginal();
}
```

## 12. C ABI and advanced integration

Native hosts use [`include/sigilhook.h`](../include/sigilhook.h). All addresses cross the ABI as `uint64_t`; handles are opaque `sigilhook_handle` values; no C++ exception, STL type, or compiler-specific object layout crosses the boundary.

The C ABI covers:

- detour, breakpoint, IAT, EAT, VFunc, and VTable construction
- hook install, remove, rehook, destroy, query, and configuration
- JIT callbacks with arguments, return values, GPRs, XMM registers, flags, and instruction pointer
- module loading, export resolution, native blob invocation, and architecture validation
- memory read/write/protection, pattern scanning, disassembly, flags, FXSAVE/FXRSTOR, and executable snippets
- script runtime start, load, entry call, shared values, and stop

## Callback failure, unload, and trampoline lifetime

A script callback that raises an exception, aborts, or exceeds the per-callback budget does not cross the JIT boundary as a C++ exception. It is recorded instead: the runtime latches a failure, refuses new callbacks, and reports it through `sigilhook_runtime_last_callback_status()` (or the script helpers `shLastCallbackStatus()` / `shCallbacksHealthy()`). A successful `sigilhook_runtime_reload*()` or `sigilhook_runtime_stop*()` clears it. Callback failures are also written to the runtime log.

`sigilhook_runtime_stop()` / `sigilhook_runtime_stop_with_timeout()` now wait for two things before releasing resources: active script callbacks and any target thread still executing inside a retired trampoline. `sigilhook_wait_for_trampolines(timeout_ms)` exposes the trampoline drain step directly and returns `SIGILHOOK_ERROR_BUSY` if a thread is still inside one. Detour trampolines are retired rather than freed on `unhook`/`destroy`; the registry frees them once the in-flight count reaches zero, so a target thread cannot jump into released memory during hot reload.
Advanced users can create a native JIT callback with `sigilhook_create_jit_callback()`, then bind it to a detour with `sigilhook_bind_detour_to_jit()`. The script helpers implement the same model through `shCreateScriptJit()`, `shBindDetourToJit()`, and `shDestroyJit()`.

## 13. Troubleshooting

- **No log or no hook:** verify that `main.as` exists beside the deployed DLL, that the DLL architecture matches the process, and that autoload was not disabled accidentally.
- **`void main()` missing:** only the root `main.as` may define it.
- **Callback declaration not found:** use the exact declaration, for example `"void onTarget()"`.
- **Wrong arguments or stack corruption:** select the actual calling convention, including `thiscall` or a `usercall` mapping.
- **`R8` failure:** use x64, or switch to `SH_REG_AX..SH_REG_DI`.
- **`SP` write failure:** `SP` is intentionally read-only.
- **x64 cleanup error:** remove `cleanup` or set it to `0`.
- **Injection works but scripts do not:** inspect `logs\SigilHook.log` and check for duplicate/missing sections, include cycles, or an entry point in a non-root file.
- **Unload crash:** call `sigilhook_runtime_stop()` before unloading the DLL; do not perform teardown in `DllMain`.

## 14. License and acknowledgements

SigilHook modifications and original SigilHook integration code are Copyright (c) 2026 StackAndPointer. The project acknowledges PolyHook 2, AngelScript, AsmJit, AsmTK, Zydis, and Zycore; see [`README.md`](../README.md) and [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
