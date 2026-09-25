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

## C ABI

The public C interface is `include/sigilhook.h`. It exposes opaque handles and
`sigilhook_*` functions for:

- detours, software breakpoints, and hardware breakpoints
- IAT, EAT, vfunc-swap, and vtable-swap hooks
- hook lifecycle and detour configuration
- JIT callbacks with editable arguments and return values
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
