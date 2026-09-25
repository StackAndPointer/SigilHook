# SigilHook

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

AngelScript source files use `.as`. Script headers use `.ash`; they are not C/C++
headers. The loader supports `#include "helpers.ash"` with relative paths,
recursive include expansion, depth limits, and cycle/error logging.
Copy [`scripts/SigilHook.ash`](scripts/SigilHook.ash) into the script directory and
include it from each script to use the standard helper API.

Each `.as` file is compiled as a separate module. Optional entry points are:

```angelscript
void main() {}
void unload() {}
```

Hook callbacks can modify arguments, call `callOriginal()`, skip the original with
`skipOriginal()`, and override the final result with `setReturnValue(value)`. The
standard `shReturnEarly(value)` helper combines a return override with skipping
the original function.

Scripts are sorted by filename before loading. The DLL initializes AngelScript on
a worker thread. Call `sigilhook_runtime_stop` before unloading the DLL; teardown
is intentionally not performed from `DllMain` under the Windows loader lock.

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

## Usercall mappings

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

## C ABI

The public C interface is `include/sigilhook.h`. It exposes opaque handles and
`sigilhook_*` functions for:

- detours, software breakpoints, and hardware breakpoints
- IAT, EAT, vfunc-swap, and vtable-swap hooks
- hook lifecycle and detour configuration
- JIT callbacks with editable arguments, return values, GPRs, and flags
- memory reads, writes, protection changes, and pattern scanning
- script runtime start, script loading, entry calls, and shutdown

All addresses cross the ABI as `uint64_t`. Hook construction returns status codes
instead of throwing C++ exceptions across the boundary.

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
