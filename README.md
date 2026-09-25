# SigilHook

SigilHook 是一个基于 PolyHook 2 的 C++20 x86/x64 Hook 库，并集成了 AngelScript 运行时，后续将提供由脚本驱动的 C API。

当前仓库保留 PolyHook 2 的 Hook 能力，并通过 CMake 目标 `angelscript` 提供 AngelScript。`POLYHOOK_FEATURE_ANGELSCRIPT` 控制集成，默认开启；`POLYHOOK_USE_EXTERNAL_ANGELSCRIPT=ON` 时使用外部 AngelScript 包。

## 构建

需要 CMake 3.15+、支持 C++20 的编译器。Windows 上建议使用 Visual Studio 18 的开发者环境：

```powershell
cmd.exe /d /s /c 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" && cmake -S . -B _build-nmake -G "NMake Makefiles" -DPOLYHOOK_BUILD_DLL=ON -DPOLYHOOK_BUILD_ANGELSCRIPT_SMOKE_TEST=ON'
cmd.exe /d /s /c 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" && cmake --build _build-nmake --config Release --target SigilHook AngelScriptSmokeTest'
cmd.exe /d /s /c 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" && ctest --test-dir _build-nmake -C Release --output-on-failure'
```

编译产物通常位于：

- `_build-nmake/SigilHook.lib`：SigilHook 静态库；启用 `POLYHOOK_BUILD_SHARED_LIB=ON` 时会生成 `SigilHook.dll` 和导入库。
- `_build-nmake/AngelScriptSmokeTest.exe`：AngelScript 运行时冒烟测试。
- `_install/lib/`：安装后的库文件。
- `_install/include/`：安装后的 PolyHook、AngelScript 及依赖头文件。

## 许可与致谢

SigilHook 基于以下开源项目构建，感谢原作者和贡献者：

- [PolyHook 2](https://github.com/stevemk14ebr/PolyHook_2_0)，Copyright (c) 2018 Stephen Eckels，MIT License。完整许可文本见 [`LICENSE`](LICENSE)。SigilHook 保留并修改了其中的 Hook、反汇编和测试代码。
- [AngelScript](https://github.com/anjo76/angelscript)，Copyright (c) 2003-2025 Andreas Jönsson，zlib-style permissive license。完整许可文本见 [`third_party/angelscript/LICENSE.md`](third_party/angelscript/LICENSE.md)。AngelScript 作为 vendored runtime 集成，原始许可通知保留在源码目录中。

使用、修改或再分发本项目时，请分别遵守上述许可条款并保留原始版权与许可通知。SigilHook 不代表 PolyHook 2 或 AngelScript 的官方项目，也未获得其背书。
