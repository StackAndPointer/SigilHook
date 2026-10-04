# SigilHook

Copyright (c) 2026 StackAndPointer

SigilHook is an x86/x64 hook runtime derived from PolyHook 2 and powered by
AngelScript. It exports a stable C ABI and builds an injectable `SigilHook.dll`
that loads scripts from a directory beside the DLL.

## Extensions over the upstream projects

This section summarizes the deliberate additions on top of the two upstream projects.

### Extensions over PolyHook 2

- PolyHook 2 exposes its core as C++ class interfaces (`Detour`, `BreakPointHook`, `IatHook`, `EatHook`, `VFuncSwapHook`, `VTableSwapHook`, and others). SigilHook adds a stable C ABI on top: every exported function uses `extern "C"` and the `sigilhook_*` prefix, addresses cross the boundary as `uint64_t`, and hooks are passed as opaque handles. C++ class ABIs, STL containers, and exceptions are not exposed to callers.
- SigilHook produces a real injectable deliverable. The build emits `SigilHook.dll` with a minimal `DllMain` and a separate initialization thread, so AngelScript initialization does not run under the Windows loader lock.
- The runtime callback bridge was rewritten around AsmJit. The original `ILCallback` only suited simple callbacks and had callback-memory lifetime, error-handling, and thread-safety gaps that made it unsafe to expose directly to scripts. The replacement JIT callback supports reading and writing arguments, return values, general-purpose registers, and flags.
- A calling-convention layer was added: `cdecl`, `stdcall`, `fastcall`, `thiscall`, `vectorcall`, and custom `usercall` mappings (`argN=<register|stack+offset>`, `ret=<register>`, `x86 cleanup=<bytes>`). These are implemented by AsmJit-generated stubs, with one description grammar shared by x86 and x64.
- Entry-continue and instruction-level hooking were added: `shHookEntryContinue` with `shContinueOriginal` continues through the trampoline, `shHookInstructionStatus` installs a real mid-instruction detour, and `SHCallContext` exposes a per-callback object instead of thread-local helpers. `shHookMid`/`shResumeMid` remain as compatibility aliases.
- Script-level read/write access was added for general-purpose registers, XMM registers, and flags, including partial 8/16/32-bit writes such as `shReg16` and `shSetReg16`. `SP` is read-only so the callback return path stays intact.
- Helper surfaces were added for memory reads and writes, memory protection changes, pattern scanning, Zydis disassembly, CMP/TEST flag computation, FXSAVE/FXRSTOR, executable return snippets, and stack-pointer jump snippets.
- Hot reload was added over a per-process named pipe, `\\.\pipe\SigilHook.<pid>`, together with `SigilHookReload.bat`. Scripts can be reloaded by process or across all live hosts without re-injection.
- Native DLL binding was added: runtime `LoadLibraryW`/`GetProcAddress`, PE bitness validation, export caching, reference counting, reverse-order `FreeLibrary`, and `header_to_ash.py` to generate AngelScript wrappers for supported C ABI headers.

### Extensions over AngelScript

- The whole script directory is compiled into a single `SigilHook.Application` module, with every `.as` file added as a section. Split `.as` files can call each other's global functions and read or write shared globals directly, without `import` or `export`, so the authoring experience stays close to a normal C/C++ project.
- `.ash` header semantics were added: `#include "..."` and `#include <...>` are resolved relative to the including file and then the script root, normalized absolute paths detect cycles, and each header expands once per application without a protection macro. An optional `#pragma once` is recognized and removed. This is not a full C preprocessor; `#ifndef`/`#define` are not implemented.
- A strict single entry point is enforced: only the root `main.as` may provide `void main()` and the optional `void unload()`. A missing `main.as`, a missing `main()`, an entry point in another file, or duplicate entries all return `SIGILHOOK_ERROR_SCRIPT` with a clear log, so test scripts in the same directory cannot be mistaken for entry points.
- A complete AngelScript binding layer was added: core hooks, detours, breakpoints, IAT/EAT, VFunc/VTable, memory, registers, XMM, flags, calling conventions, `usercall`, JIT, script entry invocation, shared values, logging, and error codes are registered as script objects or global functions. `scripts/SigilHook.ash` is the single script-facing surface.
- A bundled `.ash` standard library, `scripts/SigilHook.ash`, was added: constants, enums, convenience wrappers, status-preserving `sh...Status` variants, register/XMM/flag access, memory and scanning, assembly and disassembly, and DLL call wrappers.
- Cross-module support was added: the SigilHook application layer shares globals across one module, while native AngelScript multi-module behavior is still respected in that cross-module calls need `import ... from "Module"` plus `BindAllImportedFunctions()` and raw globals are not shared. Both paths are covered by tests.
- Runtime lifecycle management was added: AngelScript is initialized on a worker thread while `DllMain` does the minimum. Shutdown first rejects new callbacks, asks active scripts to abort through the AngelScript line callback, and supports `sigilhook_runtime_stop_with_timeout()`. If a callback cannot finish in time, the call returns `BUSY` and leaves the engine and hooks alive, avoiding half-initialized state and dangling jumps.
- Script error propagation and status APIs were added: compile errors, hook errors, and run logs go to `<dll-dir>\SigilHook\logs\SigilHook.log`, and callers can query `shLastError`, `shStatusString`, and related helpers.
- AngelScript's own source is not substantially modified. The changes are build integration and surrounding runtime integration; the bindings and runtime code are SigilHook additions.

## Documentation
- [English README](README.md)
- [中文 README](README.zh-CN.md)
- [English usage guide](docs/USAGE.md)
- [中文使用说明](docs/USAGE.zh-CN.md)
- [Usage examples (AngelScript)](Examples/Scripts/UsageExamples/README.md)

## Script layout

The runtime intentionally compiles all application `.as` files into one module. This gives a familiar C/C++-style authoring experience: split source files can call global functions and modify shared globals directly, while `.ash` files provide shared declarations. Native AngelScript modules remain isolated: cross-module calls require `import ... from "Module"` declarations plus `BindAllImportedFunctions()`, and raw global variables are not shared between modules. The smoke test covers this native Provider/Consumer model separately without changing the runtime loader.

Place scripts in:

```text
<SigilHook.dll directory>\SigilHook\*.as
<SigilHook.dll directory>\SigilHook\*.ash
<SigilHook.dll directory>\SigilHook\SigilHook.ash
<SigilHook.dll directory>\SigilHook\logs\SigilHook.log
```

The root script directory must contain `main.as`. Other `.as` files may be organized in subdirectories.

AngelScript source files use `.as`. Script headers use `.ash`; they are not C/C++ headers. Every `.as` file is added as a section of one `SigilHook.Application` module, so global functions and variables can call and modify each other directly without `import` or `export`. The loader recursively collects source files in deterministic path order and requires the root entry file:

```text
<SigilHook.dll directory>\SigilHook\main.as
<SigilHook.dll directory>\SigilHook\include\*.ash
```

Headers are included with `#include "helpers.ash"` or `#include <helpers.ash>`, resolved relative to the including file and then the script root. Each normalized header path is expanded once for the whole application, so repeated includes are safe without a protection macro. `#pragma once` is accepted and removed. Nested includes, missing files, invalid paths, cycles, and depth over 16 are reported with the include chain. This loader does not implement `#ifndef/#define` or a full C preprocessor.

Copy [`scripts/SigilHook.ash`](scripts/SigilHook.ash) into the script directory and include it from any source file to use the standard helper API.

Only root `main.as` may provide the required and optional entry points:

```angelscript
void main() {}
void unload() {}
```

A missing `main.as`, missing `void main()`, duplicate entry, entry in another file, or optional `void unload()` outside `main.as` is a script-load error. The module is built once and `main()` is executed once after the complete application compiles; `unload()` runs once during runtime shutdown. If `main()` fails, the runtime calls the optional `unload()` as a best-effort rollback, destroys script bindings, and discards the module.

Hook callbacks can modify arguments, call `callOriginal()`, skip the original with
`skipOriginal()`, and override the final result with `setReturnValue(value)`. The
standard `shReturnEarly(value)` helper combines a return override with skipping
the original function.

Status-returning writes are also available: `shSetArgStatus(index, value)` and
`shSetReturnStatus(value)`, plus `SHCallContext::setArgStatus` and
`SHCallContext::setReturnStatus`. They return `SH_OK`, `SH_ERROR_BUSY`,
`SH_ERROR_INVALID_ARGUMENT`, or `SH_ERROR_UNSUPPORTED` so scripts can distinguish
"not inside a callback", "argument index out of range", and "this callback has no
writable return value" instead of having `shSetArg` / `shSetReturn` fail silently.
The original no-status functions remain compatible.

The DLL initializes AngelScript on a worker thread. Call `sigilhook_runtime_stop()` before unloading the DLL; teardown is intentionally not performed from `DllMain` under the Windows loader lock. This is a required unload protocol: never call `FreeLibrary` while the runtime is started. The default stop timeout is 5000 ms; `sigilhook_runtime_stop_with_timeout()` can select another timeout. During shutdown, the runtime rejects new callbacks and the AngelScript line callback asks active scripts to abort on their own script thread. Native code blocked inside a callback cannot be cancelled; in that case stopping returns `SIGILHOOK_ERROR_BUSY`, and the hooks and engine remain alive. Do not unload the DLL; retry from a native thread or terminate the host process. Calling stop from an active AngelScript context also returns `SIGILHOOK_ERROR_BUSY`. Process termination does not require runtime teardown.

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

Native callers can also trigger the same path directly with
`sigilhook_runtime_reload()` or `sigilhook_runtime_reload_with_timeout()`. Scripts
can call `shReloadStatus()` and `shReloadWithTimeoutStatus(timeoutMs)`, but
normal hook callbacks should not reload the module that is currently executing.
`shWaitForTrampolinesStatus(timeoutMs)` exposes the retired-trampoline drain step
and returns `SH_ERROR_BUSY` while a target thread is still executing inside one.

## Standard helper API

`scripts/SigilHook.ash` exposes the complete script-facing helper surface. It includes both convenience functions that install immediately
and status-returning functions that preserve the underlying C ABI result:

- detour creation and `cdecl`, `stdcall`, `fastcall`, `thiscall`, `vectorcall`,
  and `usercall` script hooks
- software breakpoint, hardware breakpoint, IAT, EAT, VFunc, and VTable hooks
- install, remove, rehook, destroy, state query, trampoline, debug, follow-call,
  maximum-depth, and x64 detour-scheme controls
- argument, register, XMM, flag, return, original-call, entry-continue,
  instruction-hook, and early-return controls
- 8/16/32/64-bit argument, register, return, and scalar-memory access helpers
- callback instruction-pointer inspection and control-flow redirection
- Zydis disassembly, hexadecimal parsing, CMP/TEST flag helpers, FXSAVE/FXRSTOR,
  return snippets, and stack-pointer jump snippets
- byte-array reads and writes, scalar memory helpers, memory protection, pattern
  scanning, shared values, script-directory loading, and entry invocation
- script JIT creation, detour binding, JIT destruction, status strings, and
  direct `shCallUsercall` invocation

The direct usercall invoker caches generated stubs by target and signature.
`sigilhook_runtime_stop()` clears this cache automatically; native hosts that
keep the C ABI alive without stopping the runtime can call
`sigilhook_clear_invoker_cache()` explicitly.

The convenience wrappers discard status where the legacy API historically did;
use the `sh...Status` or explicit status-returning forms when error handling is
required. `sigilhook_runtime_start` and `sigilhook_runtime_stop` remain C ABI-only
because stopping the runtime from inside one of its own scripts would tear down
the active AngelScript context.

The complete interface is grouped as follows:

| Group | Functions |
| --- | --- |
| Runtime and status | `shIsValidHook`, `shApiVersion`, `shBuildMode`, `shIsX86`, `shIsX64`, `shPointerSize`, `shClearLastError`, `shLastError`, `shLog`, `shStatusString` |
| Hook creation | `shHookScript`, `shHookEntryContinue`, `shHookInstructionStatus`, `shHookMid` (deprecated alias), `shHookConvention`, `shHookUsercall`, `shHookNative`, `shHookBreakpoint`, `shHookHardwareBreakpoint`, `shHookIat`, `shHookEat`, `shHookVFunc`, `shHookVTable` |
| Hook lifecycle | `shEnableHook`, `shDisableHook`, `shUnhook`, `shDestroyHook`, `shRehook`, `shIsHooked`, `shHookType`, `shTrampoline`, `shOriginalVFunc`, `shContinueOriginal`, `shResumeMid` (deprecated alias) |
| Detour configuration | `shSetDebug`, `shSetFollowCall`, `shMaxDepth`, `shSetMaxDepth`, `shDetourScheme`, `shSetDetourScheme` |
| Callback frame | `shArg`, `shArg8`, `shArg16`, `shArg32`, `shSetArg`, `shSetArgStatus`, `shSetArg8`, `shSetArg16`, `shSetArg32`, `shReturn`, `shReturn8`, `shReturn16`, `shReturn32`, `shSetReturn`, `shSetReturnStatus`, `shSetReturn8`, `shSetReturn16`, `shSetReturn32`, `shReturnEarly`, `shKeepOriginal`, `shSkipOriginal`, `currentContext`, `SHCallContext::getArg`, `SHCallContext::setArg`, `SHCallContext::setArgStatus`, `SHCallContext::getReg`, `SHCallContext::setReg`, `SHCallContext::getXmm`, `SHCallContext::setXmm`, `SHCallContext::getReturn`, `SHCallContext::setReturn`, `SHCallContext::setReturnStatus`, `SHCallContext::getFlags`, `SHCallContext::setFlags`, `SHCallContext::continueOriginal`, `SHCallContext::skipOriginal` |
| Registers and control flow | `shRegisterAvailable`, `shRegisterWritable`, `shXmmAvailable`, `shReg`, `shReg8`, `shReg16`, `shReg32`, `shSetReg`, `shSetReg8`, `shSetReg16`, `shSetReg32`, `shXmm`, `shSetXmm`, `shXmmFloat`, `shSetXmmFloat`, `shXmmDouble`, `shSetXmmDouble`, `shFloatBits`, `shBitsFloat`, `shDoubleBits`, `shBitsDouble`, `shFlags`, `shSetFlags`, `shInstructionPointer`, `shSetInstructionPointer`, `shInstructionPointerStatus`, `shSetInstructionPointerStatus`, `shContextInstructionPointerStatus`, `shContextSetInstructionPointerStatus` |
| Memory and scanning | `shReadBytes`, `shReadU8`, `shReadU16`, `shReadU32`, `shReadU64`, `shWriteBytes`, `shWriteU8`, `shWriteU16`, `shWriteU32`, `shWriteU64`, `shMemProtect`, `shMemProtectStatus`, `shFindPattern`, `shFindPatternStatus`, `shPatternSize` |
| Assembly and disassembly | `shDisAsm`, `shDisAsmStatus`, `shHtoi`, `shParseHexStatus`, `shAsmCmp`, `shAsmTest`, `shAsmFxsave`, `shAsmFxrstor`, `shAsmRet`, `shAsmRetStatus`, `shAsmRetFree`, `shAsmMovEspAndJmp`, `shAsmMovEspAndJmpStatus`, `shAsmMovEspAndJmpFree` |
| Explicit status APIs | `shCreateDetour`, `shCreateBreakpoint`, `shCreateHardwareBreakpoint`, `shCreateIat`, `shCreateEat`, `shCreateVFuncEntries`, `shCreateVTableEntries`, `shInstallHook`, `shDestroyHookStatus`, `shRemoveHook`, `shRehookStatus`, `shSetHookedStatus`, `shIsHookedStatus`, `shHookTypeStatus`, `shSetDebugStatus`, `shTrampolineStatus`, `shOriginalVFuncStatus`, `shMaxDepthStatus`, `shSetMaxDepthStatus`, `shSetFollowCallStatus`, `shDetourSchemeStatus`, `shSetDetourSchemeStatus` |
| Advanced runtime | `shCreateScriptJit`, `shDestroyJit`, `shBindDetourToJit`, `shLoadDirectory`, `shReloadStatus`, `shReloadWithTimeoutStatus`, `shWaitForTrampolinesStatus`, `shCallEntry`, `shSetSharedU64`, `shSharedU64`, `shSetSharedU64Status`, `shSharedU64Status`, `shCallUsercall`, `shNativeAddress`, `shInvokeNativeBlob`, `shNativeThrow`, `shNativeStringBytes`, `shBufferAddress` |

Exact argument types and `out` parameters are defined in
[`scripts/SigilHook.ash`](scripts/SigilHook.ash). Native callers should use
the corresponding declarations in [`include/sigilhook.h`](include/sigilhook.h).

## Calling conventions and registers

`shHookScript` keeps the original three-argument behavior. Use
`shHookConvention` for `cdecl`, `stdcall`, `fastcall`, `thiscall`, or `vectorcall`.
AngelScript callbacks can inspect and modify general-purpose registers and flags:

```angelscript
uint64 value = shReg(SH_REG_CX);
shSetReg(SH_REG_CX, value + 1);
shSetFlags(shFlags() | 0x40);
```

Use `shReg16` and `shSetReg16` to read or replace only the low 16 bits while
preserving the upper bits of the register:

```angelscript
uint16 low = shReg16(SH_REG_CX);
shSetReg16(SH_REG_CX, low + 1);
```

Register names are case-insensitive: `AX/CX/DX/BX/SP/BP/SI/DI/R8..R15`, including
the usual `EAX/RAX`, `R8D/R8W/R8B` aliases. x86 frames expose only `AX` through
`DI`. `SP` is read-only. XMM0-7 are available on x86 and XMM0-15 on x64. Lane 0 is the low 64 bits and lane 1 is the high 64 bits; float and double helpers use lane 0. `shFloatBits`/`shBitsFloat` and `shDoubleBits`/`shBitsDouble` convert between floating-point values and their integer bit representations. Segment, control, and debug registers are not included. Flags are restored before an original call or final return, but values
such as direction and trap state should not be relied on across a language ABI.

A mapped argument is available through both `shArg` and its register alias. If
`shSetArg` explicitly changes that argument, the argument value wins over
`shSetReg`; otherwise the mapped register write is applied.

`shInstructionPointer()` reports the hooked target address. Calling
`shSetInstructionPointer(address)` redirects control after the callback has
restored mapped arguments and flags. `shInstructionPointerStatus()` and
`shSetInstructionPointerStatus()` provide the same operations with an explicit
status code; the `SHCallContext` object exposes
`getInstructionPointer[Status]()` and `setInstructionPointer[Status]()` as well.
Redirects are unsupported for callback frames that do not carry a redirect
destination and return `SH_ERROR_UNSUPPORTED`. The redirect uses one volatile
scratch register (`R10` on x64 or `EAX` on x86), so custom mappings should not
assign an argument to that register when redirecting.

## Assembly helpers

- `shDisAsm` and `shDisAsmStatus` decode readable bytes with Zydis
- `shHtoi` and `shParseHexStatus` parse hexadecimal values
- `shAsmCmp` and `shAsmTest` compute x86/x64 arithmetic flag values
- `shAsmFxsave` and `shAsmFxrstor` copy a 512-byte aligned FXSAVE area
- `shAsmRet`, `shAsmRetFree`, `shAsmMovEspAndJmp`, and
  `shAsmMovEspAndJmpFree` create and release executable snippets

The stack-jump helper moves `ESP` on x86 and `RSP` on x64 before jumping to the
target. Snippet addresses must be released with their matching `Free` helper.

AngelScript callbacks can also read and write XMM registers: use `shXmm` and `shSetXmm` for 128-bit values, `shXmmFloat`/`shSetXmmFloat` and `shXmmDouble`/`shSetXmmDouble` for float/double values in lane 0, and `shFloatBits`/`shBitsFloat` plus `shDoubleBits`/`shBitsDouble` to convert between floating-point values and their integer bit representations. x64 floating-point arguments are synchronized through XMM; x86 standard floating-point arguments travel on the stack, so use `shSetArg`.

Reference-project hook entry points map as follows: `HookDisAsm` maps to the
disassembly helpers, `HookBegin`/`HookStop` to `shHookScript`/`shUnhook`,
and `HookFunctionBegin`/`HookFunctionStop` to detour creation plus
`shTrampoline`. The reference `OriginalCodeLocation` choices are represented by
the default original-call ordering, `shSkipOriginal`, `shKeepOriginal`, and
`shSetInstructionPointer`; `jmpBackAddress` is the equivalent IP redirect.
Host-only runtime controls are intentionally not script globals.

## Usercall mappings

Pointer types are sized for the target architecture rather than the host process: `void*`, any `T*` type, `intptr_t`, and `uintptr_t` are 4 bytes in an x86 build and 8 bytes in an x64 build. Pointer parameters and pointer return values are supported by both the C API and AngelScript usercall bindings; scripts may continue to declare `void*` directly.

`shHookUsercall` describes a custom convention with this grammar:

```text
usercall:ret=<register>;argN=<register|stack+offset>;cleanup=<bytes>
```

Every declared parameter must have a unique `argN` mapping. `ret` is required for
non-void returns and must be `ret=none` for `void`. Register locations cannot be
duplicated, and `SP` cannot be an argument or return location. A typical x64
mapping is:

```angelscript
shHookUsercall(target, "void callback()",
    "unsigned int:unsigned int,unsigned int,unsigned int",
    "usercall:ret=rax;arg0=rcx;arg1=rdx;arg2=stack+16");
```

`stack+offset` is a byte offset from the target function-entry stack pointer. It
includes the return address and any ABI-reserved stack space, so it is not
necessarily the first stack argument offset of a compiler-generated caller.
Offsets must be aligned to the pointer size, cannot overlap the return address,
and stack argument ranges cannot overlap.

`cleanup` is the byte count removed by an x86 callee and defaults to zero. It is
accepted only on x86; x64 mappings must omit it or use `cleanup=0`. x86 usercall
returns wider than 32 bits are not supported.

`shCallUsercall` invokes an arbitrary target with the same mapping grammar:

```angelscript
array<uint64> args(2);
args[0] = first;
args[1] = second;
uint64 result = 0;
shCallUsercall(target, "unsigned int", "unsigned int,unsigned int",
    "usercall:ret=rax;arg0=rcx;arg1=rdx", args, result);
```

## Header conversion and native DLL bindings

The repository includes `tools/header_to_ash.py`, a dependency-free Python 3 converter for supported Windows C ABI headers:

```powershell
python tools\header_to_ash.py include\GameApi.h `
  --dll GameApi.dll --output SigilHook\GameApi.ash --arch x86
```

Use `--check` in CI to verify that an existing generated file is current. The converter supports scalar types, pointers, enums, `const char *`, Windows wide strings, fixed-layout POD records, local includes, and `cdecl`, `stdcall`, `fastcall`, `thiscall`, `vectorcall`, or explicit `usercall` annotations. It rejects templates, mangled C++ methods, unions, bit-fields, unknown packing, variadic functions, and other constructs whose ABI cannot be confirmed, with file/line/column diagnostics.

Generated wrappers cache DLL and export lookup, serialize record fields explicitly, and propagate native failures through AngelScript exceptions. At runtime use `shNativeAddress`, `shInvokeNativeBlob`, `shNativeThrow`, `shNativeStringBytes`, and `shBufferAddress` for lower-level integration. The native module manager validates PE architecture, caches exports, reference-counts handles, and unloads modules in reverse order during `sigilhook_modules_shutdown()`.

## Entry-continue, instruction hooks, and floating-point callbacks

`shHookEntryContinue` is the clear name for an entry detour that continues through the trampoline. `shHookMid` and `shResumeMid` remain as compatibility aliases for existing scripts.

Use `shHookEntryContinue` when a hook should run before the original entry and then continue through the trampoline:

```angelscript
void beforeUpdate() {
    // inspect or modify state
    shContinueOriginal(g_entryHook);
}
```

Use `shHookInstructionStatus` for a real instruction-level hook. It verifies an instruction boundary, moves the overwritten instructions into a trampoline, and rejects relative control flow or `ret` in the overwritten range instead of guessing:

```angelscript
uint64 hook = 0;
uint64 trampoline = 0;
uint64 overwritten = 0;
uint8 status = shHookInstructionStatus(0x415D40, "void onInstruction()", "void");
```

Callbacks can use the `SHCallContext` object instead of the thread-local helper functions:

```angelscript
void onTarget(SHCallContext@ ctx) {
    uint64 value = ctx.getArg(0);
    ctx.setReturn(value + 1);
    ctx.continueOriginal();
}
```


## C ABI

The public C interface is `include/sigilhook.h`. It exposes opaque handles and
`sigilhook_*` functions for:

- detours, software breakpoints, and hardware breakpoints
- IAT, EAT, vfunc-swap, and vtable-swap hooks
- hook lifecycle and detour configuration
- JIT callbacks with editable arguments, return values, GPRs, and flags
- memory reads, writes, protection changes, and pattern scanning
- Zydis disassembly, CMP/TEST flags, FXSAVE/FXRSTOR, executable snippets,
  and callback instruction-pointer redirection
- script runtime start, script loading, entry calls, and shutdown

The current API version is `0x0002000C`. All addresses cross the ABI as `uint64_t`.

For `sigilhook_invoke_native_blob()`, `return_blob` must be at least
`return_signature.returnValue.size` bytes. Record returns use a temporary
buffer for the target ABI and are copied back into `return_blob` in full; a
smaller buffer is rejected with `SIGILHOOK_ERROR_INVALID_ARGUMENT`. This is
covered on x86 and x64 for 16-byte records and packed 5-byte records.

## Building

The repository workflow validates GCC x86/x64 on Linux and MSVC plus clang-cl
on Windows for both x86 and x64. Windows builds are the injectable release
artifacts.

Build x64 from a Visual Studio developer prompt:

```powershell
vcvarsall.bat x64
cmake -S . -B _build-x64 -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-x64 --config Release --target SigilHook SigilHookDll
ctest --test-dir _build-x64 -C Release --output-on-failure
```

Set `SIGILHOOK_DISABLE_AUTOLOAD=1` in test or host environments when loading
the DLL explicitly and managing the runtime yourself.

Build x86 with `vcvarsall.bat x86` and `_build-x86`. x86 and x64 DLLs must be
built separately and injected only into matching processes.

Main artifacts:

```text
_build-x64/SigilHook.dll
_build-x64/SigilHookReload.bat
_build-x64/SigilHook.lib
_build-x64/SigilHookImport.lib
_build-x86/SigilHook.dll
_build-x86/SigilHookReload.bat
_build-x86/SigilHook.lib
_build-x86/SigilHookImport.lib
```

`SigilHook.lib` is the static C++ library. `SigilHookImport.lib` is the import
library for the exported C ABI in `SigilHook.dll`.

For clang-cl, use the Visual Studio generator with `-T ClangCL` and use
`-A Win32` for x86:

```powershell
cmake -S . -B _build-clang-cl-x64 -G "Visual Studio 17 2022" -T ClangCL -A x64 `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-clang-cl-x64 --config Release --target SigilHookDll
ctest --test-dir _build-clang-cl-x64 -C Release --output-on-failure
```

Omit `-T ClangCL` to use the regular MSVC toolset with the same generator and
architecture flags.

The manual GitHub Actions workflow accepts an optional `release_tag`. When it
is set, it publishes four Windows packages and two GCC Linux packages:

```text
SigilHook-msvc-x86.zip
SigilHook-msvc-x64.zip
SigilHook-clang-cl-x86.zip
SigilHook-clang-cl-x64.zip
SigilHook-gcc-x86.zip
SigilHook-gcc-x64.zip
```

Each package contains the deployable runtime layout:

```text
SigilHook.dll
SigilHookReload.bat
SigilHook/
  SigilHook.ash
```

The GCC packages provide Linux static-library development artifacts; they do
not contain Windows injectable DLLs:

```text
libSigilHook.a
include/
  sigilhook.h
SigilHook/
  SigilHook.ash
THIRD_PARTY_NOTICES.md
```

## License and acknowledgements

SigilHook modifications and original SigilHook integration code are
Copyright (c) 2026 StackAndPointer.

SigilHook is built from open-source components and thanks their authors:

- [PolyHook 2](https://github.com/stevemk14ebr/PolyHook_2_0), Copyright (c) 2018
  Stephen Eckels, MIT License. See [`LICENSE`](LICENSE).
- [AngelScript](https://www.angelcode.com/angelscript/), Copyright (c) 2003-2025
  Andreas Jonsson, zlib-style permissive license. See
  [`third_party/angelscript/LICENSE.md`](third_party/angelscript/LICENSE.md).
- [AsmJit](https://github.com/asmjit/asmjit), Copyright (c) 2008-2025 The AsmJit
  Authors, zlib-style permissive license.
- [AsmTK](https://github.com/asmjit/asmtk), Copyright (c) 2016 Petr Kobalicek,
  zlib-style permissive license.
- [Zydis](https://github.com/zyantific/zydis) and Zycore, MIT License.

See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and the license files in
each bundled dependency directory. SigilHook contains a modified PolyHook 2
implementation; the original copyright and permission notices remain in
[`LICENSE`](LICENSE).
