# SigilHook

Copyright (c) 2026 StackAndPointer

SigilHook is an x86/x64 hook runtime derived from PolyHook 2 and powered by
AngelScript. It exports a stable C ABI and builds an injectable `SigilHook.dll`
that loads scripts from a directory beside the DLL.

## Script layout

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

A missing `main.as`, missing `void main()`, duplicate entry, entry in another file, or optional `void unload()` outside `main.as` is a script-load error. The module is built once and `main()` is executed once after the complete application compiles; `unload()` runs once during runtime shutdown.

Hook callbacks can modify arguments, call `callOriginal()`, skip the original with
`skipOriginal()`, and override the final result with `setReturnValue(value)`. The
standard `shReturnEarly(value)` helper combines a return override with skipping
the original function.

The DLL initializes AngelScript on a worker thread. Call `sigilhook_runtime_stop` before unloading the DLL; teardown is intentionally not performed from `DllMain` under the Windows loader lock.

## Standard helper API

`scripts/SigilHook.ash` exposes the complete script-facing helper surface with 105
`sh*` functions. It includes both convenience functions that install immediately
and status-returning functions that preserve the underlying C ABI result:

- detour creation and `cdecl`, `stdcall`, `fastcall`, `thiscall`, `vectorcall`,
  and `usercall` script hooks
- software breakpoint, hardware breakpoint, IAT, EAT, VFunc, and VTable hooks
- install, remove, rehook, destroy, state query, trampoline, debug, follow-call,
  maximum-depth, and x64 detour-scheme controls
- argument, register, flag, return, original-call, and early-return controls
- callback instruction-pointer inspection and control-flow redirection
- Zydis disassembly, hexadecimal parsing, CMP/TEST flag helpers, FXSAVE/FXRSTOR,
  return snippets, and stack-pointer jump snippets
- byte-array reads and writes, scalar memory helpers, memory protection, pattern
  scanning, shared values, script-directory loading, and entry invocation
- script JIT creation, detour binding, JIT destruction, status strings, and
  direct `shCallUsercall` invocation

The convenience wrappers discard status where the legacy API historically did;
use the `sh...Status` or explicit status-returning forms when error handling is
required. `sigilhook_runtime_start` and `sigilhook_runtime_stop` remain C ABI-only
because stopping the runtime from inside one of its own scripts would tear down
the active AngelScript context.

## Calling conventions and registers

`shHookScript` keeps the original three-argument behavior. Use
`shHookConvention` for `cdecl`, `stdcall`, `fastcall`, `thiscall`, or `vectorcall`.
AngelScript callbacks can inspect and modify general-purpose registers and flags:

```angelscript
uint64 value = shReg(SH_REG_CX);
shSetReg(SH_REG_CX, value + 1);
shSetFlags(shFlags() | 0x40);
```

Register names are case-insensitive: `AX/CX/DX/BX/SP/BP/SI/DI/R8..R15`, including
the usual `EAX/RAX`, `R8D/R8W/R8B` aliases. x86 frames expose only `AX` through
`DI`. `SP` is read-only. SIMD, segment, control, and debug registers are not
included. Flags are restored before an original call or final return, but values
such as direction and trap state should not be relied on across a language ABI.

A mapped argument is available through both `shArg` and its register alias. If
`shSetArg` explicitly changes that argument, the argument value wins over
`shSetReg`; otherwise the mapped register write is applied.

`shInstructionPointer()` reports the hooked target address. Calling
`shSetInstructionPointer(address)` redirects control after the callback has
restored mapped arguments and flags. The redirect uses one volatile scratch
register (`R10` on x64 or `EAX` on x86), so custom mappings should not assign
an argument to that register when redirecting.

## Assembly helpers

The standard helpers include equivalents for the reference HookAsm API:

- `shDisAsm` and `shDisAsmStatus` decode readable bytes with Zydis
- `shHtoi` and `shParseHexStatus` parse hexadecimal values
- `shAsmCmp` and `shAsmTest` compute x86/x64 arithmetic flag values
- `shAsmFxsave` and `shAsmFxrstor` copy a 512-byte aligned FXSAVE area
- `shAsmRet`, `shAsmRetFree`, `shAsmMovEspAndJmp`, and
  `shAsmMovEspAndJmpFree` create and release executable snippets

The stack-jump helper moves `ESP` on x86 and `RSP` on x64 before jumping to
the target. Snippet addresses must be released with their matching `Free` helper.

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

The current API version is `0x00020005`. All addresses cross the ABI as `uint64_t`.
Hook construction returns status codes instead of throwing C++ exceptions across
the boundary.

## Building

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
_build-x64/SigilHook.lib
_build-x64/SigilHookImport.lib
_build-x86/SigilHook.dll
_build-x86/SigilHook.lib
_build-x86/SigilHookImport.lib
```

`SigilHook.lib` is the static C++ library. `SigilHookImport.lib` is the import
library for the exported C ABI in `SigilHook.dll`.

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
