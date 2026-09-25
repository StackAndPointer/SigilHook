# SigilHook

SigilHook is an x86/x64 hook runtime derived from PolyHook 2 and powered by
AngelScript. It exports a stable C ABI and builds an injectable `SigilHook.dll`
that loads scripts from a directory beside the DLL.

## Script layout

Place scripts in:

```text
<SigilHook.dll directory>\SigilHook\*.as
<SigilHook.dll directory>\SigilHook\*.ash
<SigilHook.dll directory>\SigilHook\logs\SigilHook.log
```

AngelScript source files use `.as`. Script headers use `.ash`; they are not C/C++
headers. The loader supports `#include "helpers.ash"` with relative paths,
recursive include expansion, depth limits, and cycle/error logging.

Each `.as` file is compiled as a separate module. Optional entry points are:

```angelscript
void main() {}
void unload() {}
```

Scripts are sorted by filename before loading. The DLL initializes AngelScript on
a worker thread and reverses hook/script teardown on unload.

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
  -DPOLYHOOK_BUILD_DLL=ON -DPOLYHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-x64 --config Release --target SigilHook SigilHookDll
ctest --test-dir _build-x64 -C Release --output-on-failure
```

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

When using, modifying, or redistributing this project, comply with both licenses
and retain their copyright and permission notices.
