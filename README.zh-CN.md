# SigilHook

Copyright (c) 2026 StackAndPointer

SigilHook 是一个基于 PolyHook 2、由 AngelScript 驱动的 x86/x64 Hook 运行时。它导出稳定的 C ABI，并生成可注入的 `SigilHook.dll`，从 DLL 同目录下的脚本目录加载 `.as` / `.ash`。

## 对上游项目的拓展

本节汇总 SigilHook 相对两个上游项目所做的有意拓展。

### 在 PolyHook 2 基础上的拓展

- 原始 PolyHook 2 的核心是 C++ 类接口（`Detour`、`BreakPointHook`、`IatHook`、`EatHook`、`VFuncSwapHook`、`VTableSwapHook` 等）。SigilHook 在其上增加了一层稳定的 C ABI：所有导出函数使用 `extern "C"` 和 `sigilhook_*` 前缀，地址统一以 `uint64_t` 跨边界传递，Hook 以 opaque handle 表示，不把 C++ 类 ABI、STL 容器和异常暴露给调用方。
- SigilHook 能产出真正可注入的交付物。构建会生成 `SigilHook.dll`，带最小化的 `DllMain` 和独立初始化线程，AngelScript 初始化不会在 Windows loader lock 中执行。
- 运行时回调桥基于 AsmJit 重写。原来的 `ILCallback` 只适合简单回调，存在回调内存生命周期、错误处理和线程安全缺口，不能直接安全地暴露给脚本。替换后的 JIT 回调支持读写参数、返回值、通用寄存器和 flags。
- 增加了调用约定层：`cdecl`、`stdcall`、`fastcall`、`thiscall`、`vectorcall`，以及自定义 `usercall` 映射（`argN=<register|stack+offset>`、`ret=<register>`、`x86 cleanup=<bytes>`）。这些由 AsmJit 生成的汇编桩实现，x86 和 x64 共用同一套描述语法。
- 增加了 mid-hook 语义：`shHookMid` 配合 `shResumeMid`，把指令指针重定向到 trampoline，让代码在原函数体执行前插入，然后继续进入原函数体。
- 增加了脚本级通用寄存器、XMM 寄存器和 flags 的读写，包括低 8/16/32 位的部分写入，例如 `shReg16`、`shSetReg16`。`SP` 保持只读，避免破坏回调返回路径。
- 增加了内存读写、内存保护修改、特征码扫描、Zydis 反汇编、CMP/TEST 标志计算、FXSAVE/FXRSTOR、可执行返回片段和栈指针跳转片段等辅助接口。
- 增加了热重载：每个进程一个命名管道，`\\.\pipe\SigilHook.<pid>`，配套 `SigilHookReload.bat`。可以按进程或对所有存活宿主触发热重载，不需要重新注入。
- 增加了原生 DLL 动态绑定：运行时 `LoadLibraryW`/`GetProcAddress`、PE 位数校验、导出缓存、引用计数、逆序 `FreeLibrary`，以及 `header_to_ash.py`，用于把受支持的 C ABI 头文件转换为 AngelScript 包装。

### 在 AngelScript 基础上的拓展

- 整个脚本目录被编译成一个 `SigilHook.Application` 模块，每个 `.as` 文件作为该模块的一个 section。拆分的 `.as` 文件之间可以直接互调全局函数、直接读写共享全局变量，不需要 `import` 或 `export`，编写体验接近普通 C/C++ 项目。
- 增加了 `.ash` 头文件语义：`#include "..."` 和 `#include <...>` 会先相对当前文件解析，再相对脚本根目录解析；用规范化绝对路径做循环检测；同一个头文件在一个应用内只展开一次，不要求护宏；可选的 `#pragma once` 会被识别并移除。这不是完整的 C 预处理器，`#ifndef`/`#define` 不支持。
- 强制严格单入口：只允许根目录 `main.as` 提供 `void main()` 和可选的 `void unload()`。缺少 `main.as`、缺少 `main()`、入口写在其他文件、入口重复，都会返回 `SIGILHOOK_ERROR_SCRIPT` 并写入清晰日志，避免同目录下的测试脚本被误认为入口。
- 增加了完整的 AngelScript 绑定层：核心 Hook、Detour、Breakpoint、IAT/EAT、VFunc/VTable、内存、寄存器、XMM、flags、调用约定、`usercall`、JIT、脚本入口调用、共享值、日志和错误码，都注册为脚本对象或全局函数。`scripts/SigilHook.ash` 是唯一的脚本侧接口面。
- 增加了随项目提供的 `.ash` 标准库 `scripts/SigilHook.ash`：常量、枚举、便捷包装、保留状态的 `sh...Status` 版本、寄存器/XMM/flags 访问、内存与扫描、汇编与反汇编，以及 DLL 调用包装。
- 增加了跨模块支持：SigilHook 的应用层在单个模块内共享全局变量；AngelScript 原生多模块行为仍然保留，跨模块调用需要 `import ... from "Module"` 声明加 `BindAllImportedFunctions()`，原始全局变量不在模块间共享。两条路径都有测试覆盖。
- 增加了运行时生命周期管理：AngelScript 在工作线程初始化，`DllMain` 只做最少工作。停止时先拒绝新回调，通过 AngelScript 行回调请求活动脚本中止，并支持 `sigilhook_runtime_stop_with_timeout()`。如果回调无法在期限内结束，调用返回 `BUSY`，engine 和 hooks 保持存活，避免半初始化状态和悬空跳转。
- 增加了脚本异常回传和状态接口：编译错误、Hook 错误和运行日志统一写到 `<dll-dir>\SigilHook\logs\SigilHook.log`，调用方可以查询 `shLastError`、`shStatusString` 等相关接口。
- AngelScript 自身源码没有大幅修改，改动主要是构建集成和外围运行时接入；绑定层和运行时代码属于 SigilHook 新增。

## 文档

- [English README](README.md)
- [English usage guide](docs/USAGE.md)
- [中文使用说明](docs/USAGE.zh-CN.md)

## 脚本布局

运行时有意把所有应用 `.as` 文件编译成一个模块。这带来接近 C/C++ 的编写体验：拆分的源文件可以直接调用全局函数、修改共享全局变量，`.ash` 文件提供共享声明。原生 AngelScript 模块仍然相互隔离：跨模块调用需要 `import ... from "Module"` 声明加 `BindAllImportedFunctions()`，原始全局变量不会在模块间共享。smoke test 另外覆盖了原生 Provider/Consumer 模型，不改变运行时加载器的行为。

脚本放在：

```text
<SigilHook.dll directory>\SigilHook\*.as
<SigilHook.dll directory>\SigilHook\*.ash
<SigilHook.dll directory>\SigilHook\SigilHook.ash
<SigilHook.dll directory>\SigilHook\logs\SigilHook.log
```

根脚本目录必须包含 `main.as`。其他 `.as` 文件可以放在子目录中。

AngelScript 源文件使用 `.as`，脚本头文件使用 `.ash`；`.ash` 不是 C/C++ 头文件。每个 `.as` 文件都会被加入同一个 `SigilHook.Application` 模块，因此全局函数和变量之间可以直接调用、直接修改，不需要 `import` 或 `export`。加载器按确定的路径顺序递归收集源文件，并要求根入口文件：

```text
<SigilHook.dll directory>\SigilHook\main.as
<SigilHook.dll directory>\SigilHook\include\*.ash
```

头文件通过 `#include "helpers.ash"` 或 `#include <helpers.ash>` 引入，先相对当前文件解析，再相对脚本根目录解析。每个规范化后的头文件路径在整个应用中只展开一次，所以重复 include 是安全的，不需要护宏。`#pragma once` 会被接受并移除。嵌套 include、缺失文件、非法路径、循环 include 和超过 16 层的深度都会连同 include 链一起报错。加载器不实现 `#ifndef/#define` 或完整的 C 预处理器。

把 [`scripts/SigilHook.ash`](scripts/SigilHook.ash) 复制到脚本目录，并在任意源文件中 include，即可使用标准辅助 API。

只有根目录 `main.as` 可以提供必需的入口和可选入口：

```angelscript
void main() {}
void unload() {}
```

缺少 `main.as`、缺少 `void main()`、入口重复、入口写在其他文件，或可选的 `void unload()` 不在 `main.as` 中，都会被视为脚本加载错误。模块整体编译成功后才执行一次 `main()`；`unload()` 在运行时装停时执行一次。如果 `main()` 失败，运行时会尽力调用可选的 `unload()` 回滚，销毁脚本绑定并丢弃模块。

Hook 回调可以修改参数、调用 `callOriginal()`、用 `skipOriginal()` 跳过原函数，并用 `setReturnValue(value)` 覆盖最终返回值。标准辅助函数 `shReturnEarly(value)` 把返回值覆盖和跳过原函数合在一起。

DLL 会在工作线程中初始化 AngelScript。卸载 DLL 前必须调用 `sigilhook_runtime_stop()`；运行时有意不在 Windows loader lock 下的 `DllMain` 中执行清理解构。这是必须遵守的卸载协议：运行时已启动时绝不要调用 `FreeLibrary`。默认停止超时是 5000 ms，`sigilhook_runtime_stop_with_timeout()` 可以选择其他超时。停止期间，运行时拒绝新回调，AngelScript 行回调会请求活动脚本在自己的脚本线程上中止。阻塞在回调里的原生代码无法被取消；这种情况下停止返回 `SIGILHOOK_ERROR_BUSY`，hooks 和 engine 保持存活。不要卸载 DLL，改用原生线程重试，或终止宿主进程。在活动 AngelScript 上下文中调用 stop 也会返回 `SIGILHOOK_ERROR_BUSY`。进程终止不需要运行时装停。

在 Windows 上，被注入的 DLL 还会启动一个本地命名管道，用于手动脚本热重载。每个宿主拥有自己的管道名 `\\.\pipe\SigilHook.<pid>`，因此多个被注入进程可以共存。从构建输出、安装目录或发布包运行 `SigilHookReload.bat`：

```bat
SigilHookReload.bat            rem 重载所有存活的 SigilHook 宿主
SigilHookReload.bat <pid>      rem 只重载指定进程 id 的宿主
```

脚本会找到存活的 `SigilHook.<pid>` 管道，连接每个选中的管道，并等待 `OK` 请求确认。管道工作线程随后重载该宿主当前的脚本目录：停止已加载的 AngelScript 应用，重新执行 `main.as::main()`，并把结果写入 `<SigilHook.dll directory>\SigilHook\logs\SigilHook.log`。确认只表示重载请求已接受，不表示新脚本已编译成功。脚本回调无法静默退出时，重载会以 `BUSY` 失败；这种情况下不会卸载任何脚本或 Hook。失败的重载仍会停止部分启动的替换运行时，所以调用方可以修好 `main.as` 后重新加载该目录。管道仅限本地。

原生调用方也可以直接用 `sigilhook_runtime_reload()` 或 `sigilhook_runtime_reload_with_timeout()` 触发同一路径。脚本可以调用 `shReloadStatus()` 和 `shReloadWithTimeoutStatus(timeoutMs)`，但普通 Hook 回调不应重载当前正在执行的模块。

## 标准辅助 API

`scripts/SigilHook.ash` 暴露完整的脚本侧辅助接口。它同时包含立即安装的便捷函数，和保留底层 C ABI 返回状态的状态返回函数：

- detour 创建，以及 `cdecl`、`stdcall`、`fastcall`、`thiscall`、`vectorcall` 和 `usercall` 脚本 Hook
- 软件断点、硬件断点、IAT、EAT、VFunc、VTable Hook
- 安装、移除、rehook、销毁、状态查询、trampoline、debug、follow-call、最大深度和 x64 detour scheme 控制
- 参数、寄存器、XMM、flag、返回值、原函数调用、mid-hook 和提前返回控制
- 8/16/32/64 位参数、寄存器、返回值和标量内存访问辅助函数
- 回调指令指针检查和控流重定向
- Zydis 反汇编、十六进制解析、CMP/TEST 标志辅助、FXSAVE/FXRSTOR、返回片段和栈指针跳转片段
- 字节数组读写、标量内存辅助、内存保护、特征码扫描、共享值、脚本目录加载和入口调用
- 脚本 JIT 创建、detour 绑定、JIT 销毁、状态字符串，以及直接调用 `shCallUsercall`

直接 usercall 调用器会按 target 和签名缓存生成的桩。`sigilhook_runtime_stop()` 会自动清空该缓存；维持 C ABI 存活但不停止运行时的原生宿主可以显式调用 `sigilhook_clear_invoker_cache()`。

便捷包装会像旧 API 一样丢弃状态；需要错误处理时请使用 `sh...Status` 或显式状态返回形式。`sigilhook_runtime_start` 和 `sigilhook_runtime_stop` 只保留在 C ABI 中，因为在自己的脚本内部停止运行时会销毁正在执行的 AngelScript 上下文。

完整接口按以下分组：

| 分组 | 函数 |
| --- | --- |
| 运行时和状态 | `shIsValidHook`、`shApiVersion`、`shBuildMode`、`shIsX86`、`shIsX64`、`shPointerSize`、`shClearLastError`、`shLastError`、`shLog`、`shStatusString` |
| Hook 创建 | `shHookScript`、`shHookMid`、`shHookConvention`、`shHookUsercall`、`shHookNative`、`shHookBreakpoint`、`shHookHardwareBreakpoint`、`shHookIat`、`shHookEat`、`shHookVFunc`、`shHookVTable` |
| Hook 生命周期 | `shEnableHook`、`shDisableHook`、`shUnhook`、`shDestroyHook`、`shRehook`、`shIsHooked`、`shHookType`、`shTrampoline`、`shOriginalVFunc`、`shResumeMid` |
| Detour 配置 | `shSetDebug`、`shSetFollowCall`、`shMaxDepth`、`shSetMaxDepth`、`shDetourScheme`、`shSetDetourScheme` |
| 回调帧 | `shArg`、`shArg8`、`shArg16`、`shArg32`、`shSetArg`、`shSetArg8`、`shSetArg16`、`shSetArg32`、`shReturn`、`shReturn8`、`shReturn16`、`shReturn32`、`shSetReturn`、`shSetReturn8`、`shSetReturn16`、`shSetReturn32`、`shReturnEarly`、`shKeepOriginal`、`shSkipOriginal` |
| 寄存器和控流 | `shRegisterAvailable`、`shRegisterWritable`、`shXmmAvailable`、`shReg`、`shReg8`、`shReg16`、`shReg32`、`shSetReg`、`shSetReg8`、`shSetReg16`、`shSetReg32`、`shXmm`、`shSetXmm`、`shXmmFloat`、`shSetXmmFloat`、`shXmmDouble`、`shSetXmmDouble`、`shFloatBits`、`shBitsFloat`、`shDoubleBits`、`shBitsDouble`、`shFlags`、`shSetFlags`、`shInstructionPointer`、`shSetInstructionPointer` |
| 内存和扫描 | `shReadBytes`、`shReadU8`、`shReadU16`、`shReadU32`、`shReadU64`、`shWriteBytes`、`shWriteU8`、`shWriteU16`、`shWriteU32`、`shWriteU64`、`shMemProtect`、`shMemProtectStatus`、`shFindPattern`、`shFindPatternStatus`、`shPatternSize` |
| 汇编和反汇编 | `shDisAsm`、`shDisAsmStatus`、`shHtoi`、`shParseHexStatus`、`shAsmCmp`、`shAsmTest`、`shAsmFxsave`、`shAsmFxrstor`、`shAsmRet`、`shAsmRetStatus`、`shAsmRetFree`、`shAsmMovEspAndJmp`、`shAsmMovEspAndJmpStatus`、`shAsmMovEspAndJmpFree` |
| 显式状态 API | `shCreateDetour`、`shCreateBreakpoint`、`shCreateHardwareBreakpoint`、`shCreateIat`、`shCreateEat`、`shCreateVFuncEntries`、`shCreateVTableEntries`、`shInstallHook`、`shDestroyHookStatus`、`shRemoveHook`、`shRehookStatus`、`shSetHookedStatus`、`shIsHookedStatus`、`shHookTypeStatus`、`shSetDebugStatus`、`shTrampolineStatus`、`shOriginalVFuncStatus`、`shMaxDepthStatus`、`shSetMaxDepthStatus`、`shSetFollowCallStatus`、`shDetourSchemeStatus`、`shSetDetourSchemeStatus` |
| 高级运行时 | `shCreateScriptJit`、`shDestroyJit`、`shBindDetourToJit`、`shLoadDirectory`、`shReloadStatus`、`shReloadWithTimeoutStatus`、`shCallEntry`、`shSetSharedU64`、`shSharedU64`、`shSetSharedU64Status`、`shSharedU64Status`、`shCallUsercall`、`shNativeAddress`、`shInvokeNativeBlob`、`shNativeThrow`、`shNativeStringBytes`、`shBufferAddress` |

确切的参数类型和 `out` 参数定义见 [`scripts/SigilHook.ash`](scripts/SigilHook.ash)。原生调用方应使用 [`include/sigilhook.h`](include/sigilhook.h) 中对应的声明。

## 调用约定和寄存器

`shHookScript` 保持原来的三参数行为。使用 `shHookConvention` 选择 `cdecl`、`stdcall`、`fastcall`、`thiscall` 或 `vectorcall`。AngelScript 回调可以检查和修改通用寄存器与 flags：

```angelscript
uint64 value = shReg(SH_REG_CX);
shSetReg(SH_REG_CX, value + 1);
shSetFlags(shFlags() | 0x40);
```

使用 `shReg16` 和 `shSetReg16` 只读取或替换低 16 位，同时保留寄存器高位：

```angelscript
uint16 low = shReg16(SH_REG_CX);
shSetReg16(SH_REG_CX, low + 1);
```

寄存器名不区分大小写：`AX/CX/DX/BX/SP/BP/SI/DI/R8..R15`，也包括常用的 `EAX/RAX`、`R8D/R8W/R8B` 别名。x86 帧只暴露 `AX` 到 `DI`。`SP` 只读。x86 上可用 XMM0-7，x64 上可用 XMM0-15。lane 0 是低 64 位，lane 1 是高 64 位；float 和 double 辅助函数使用 lane 0。`shFloatBits`/`shBitsFloat` 和 `shDoubleBits`/`shBitsDouble` 在浮点值和整数位表示之间转换。不包括段寄存器、控制寄存器和调试寄存器。flags 会在调用原函数或最终返回前恢复，但方向标志和陷阱状态这类值不应跨语言 ABI 依赖。

被映射的参数可以同时通过 `shArg` 和它的寄存器别名访问。如果 `shSetArg` 显式修改了该参数，参数值会优先于 `shSetReg`；否则会应用映射寄存器的写入。

`shInstructionPointer()` 报告被 Hook 的目标地址。调用 `shSetInstructionPointer(address)` 会在回调恢复映射参数和 flags 之后重定向控制流。重定向会使用一个 volatile scratch 寄存器（x64 是 `R10`，x86 是 `EAX`），因此自定义映射在需要重定向时不应把参数分配给该寄存器。

## 汇编辅助

- `shDisAsm` 和 `shDisAsmStatus` 使用 Zydis 解码可读字节
- `shHtoi` 和 `shParseHexStatus` 解析十六进制值
- `shAsmCmp` 和 `shAsmTest` 计算 x86/x64 算术 flags
- `shAsmFxsave` 和 `shAsmFxrstor` 复制 512 字节对齐的 FXSAVE 区域
- `shAsmRet`、`shAsmRetFree`、`shAsmMovEspAndJmp` 和 `shAsmMovEspAndJmpFree` 创建和释放可执行片段

栈跳转辅助函数在 x86 上移动 `ESP`，在 x64 上移动 `RSP`，然后跳到目标。片段地址必须用对应的 `Free` 辅助函数释放。

参考项目的 Hook 入口映射如下：`HookDisAsm` 映射到反汇编辅助，`HookBegin`/`HookStop` 映射到 `shHookScript`/`shUnhook`，`HookFunctionBegin`/`HookFunctionStop` 映射到 detour 创建加 `shTrampoline`。参考项目的 `OriginalCodeLocation` 选择由默认的原函数调用顺序、`shSkipOriginal`、`shKeepOriginal` 和 `shSetInstructionPointer` 表示；`jmpBackAddress` 等价于 IP 重定向。仅宿主可用的运行时控制有意不注册为脚本全局。

## Usercall 映射

指针类型按目标架构而不是宿主进程确定大小：`void*`、任意 `T*` 类型、`intptr_t` 和 `uintptr_t` 在 x86 构建中是 4 字节，在 x64 构建中是 8 字节。C API 和 AngelScript usercall 绑定都支持指针参数与指针返回值；脚本可以继续直接声明 `void*`。

`shHookUsercall` 用以下语法描述自定义调用约定：

```text
usercall:ret=<register>;argN=<register|stack+offset>;cleanup=<bytes>
```

每个声明的参数都必须有唯一的 `argN` 映射。非 void 返回值必须有 `ret`，void 返回值必须使用 `ret=none`。寄存器位置不能重复，`SP` 不能作为参数或返回值位置。典型的 x64 映射如下：

```angelscript
shHookUsercall(target, "void callback()",
    "unsigned int:unsigned int,unsigned int,unsigned int",
    "usercall:ret=rax;arg0=rcx;arg1=rdx;arg2=stack+16");
```

`stack+offset` 是从目标函数入口栈指针开始的字节偏移。它包含返回地址以及 ABI 保留的栈空间，所以不一定是编译器生成调用方的第一个栈参数偏移。偏移必须按指针大小对齐，不能与返回地址重叠，栈参数范围之间也不能重叠。

`cleanup` 是 x86 被调用方移除的字节数，默认值为 0。只在 x86 上接受；x64 映射必须省略它或使用 `cleanup=0`。x86 usercall 不支持宽于 32 位的返回值。

`shCallUsercall` 用相同的映射语法调用任意目标：

```angelscript
array<uint64> args(2);
args[0] = first;
args[1] = second;
uint64 result = 0;
shCallUsercall(target, "unsigned int", "unsigned int,unsigned int",
    "usercall:ret=rax;arg0=rcx;arg1=rdx", args, result);
```

## 头文件转换和原生 DLL 绑定

仓库包含 `tools/header_to_ash.py`，这是一个零依赖的 Python 3 转换器，用于把受支持的 Windows C ABI 头文件转换为 AngelScript：

```powershell
python tools\header_to_ash.py include\GameApi.h `
  --dll GameApi.dll --output SigilHook\GameApi.ash --arch x86
```

在 CI 中使用 `--check` 可以验证已有生成文件是否最新。转换器支持标量类型、指针、枚举、`const char *`、Windows 宽字符串、固定布局 POD 记录、本地 include，以及 `cdecl`、`stdcall`、`fastcall`、`thiscall`、`vectorcall` 或显式 `usercall` 标注。它会带文件名/行号/列号诊断拒绝模板、mangled C++ 方法、union、位域、未知 packing、可变参数，以及其他无法确认 ABI 的构造。

生成的包装会缓存 DLL 和导出查找，显式序列化记录字段，并通过 AngelScript 异常传递原生失败。运行时可以使用 `shNativeAddress`、`shInvokeNativeBlob`、`shNativeThrow`、`shNativeStringBytes` 和 `shBufferAddress` 做更低层集成。原生模块管理器会校验 PE 架构、缓存导出、对句柄引用计数，并在 `sigilhook_modules_shutdown()` 中按逆序卸载模块。

## Mid-hook 和浮点回调

`shHookMid` 创建普通 detour；在它的回调里，`shResumeMid(handle)` 会把指令指针重定向到 trampoline，跳过原函数入口。这适合在原函数体执行前插入代码：

```angelscript
void beforeUpdate() {
    // 检查或修改状态
    shResumeMid(g_midHook);
}
```

AngelScript 回调可以用 `shXmm`、`shSetXmm`、`shXmmFloat`、`shSetXmmFloat`、`shXmmDouble` 和 `shSetXmmDouble` 读写 XMM 寄存器；用 `shFloatBits`/`shBitsFloat` 和 `shDoubleBits`/`shBitsDouble` 在浮点值和整数表示之间转换。x86 上可用 XMM0-7，x64 上可用 XMM0-15；lane 0 是低 64 位，lane 1 是高 64 位。float 和 double 辅助函数使用 lane 0。x64 浮点参数通过 XMM 同步；x86 标准浮点参数因为走栈传递，所以使用 `shSetArg`。

## C ABI

公开 C 接口位于 `include/sigilhook.h`。它暴露 opaque handle 和 `sigilhook_*` 函数，覆盖：

- detour、软件断点和硬件断点
- IAT、EAT、vfunc-swap 和 vtable-swap Hook
- Hook 生命周期和 detour 配置
- 可编辑参数、返回值、GPR 和 flags 的 JIT 回调
- 内存读写、内存保护修改和特征码扫描
- Zydis 反汇编、CMP/TEST flags、FXSAVE/FXRSTOR、可执行片段，以及回调指令指针重定向
- 脚本运行时启动、脚本加载、入口调用和停止

当前 API 版本是 `0x00020009`。所有地址都以 `uint64_t` 跨 ABI 传递。Hook 构造返回状态码，不把 C++ 异常抛出边界。

## 构建

仓库工作流会验证 Linux 上的 GCC x86/x64，以及 Windows 上的 MSVC 和 clang-cl x86/x64。Windows 构建会产出可注入发布包。

在 Visual Studio 开发者命令行中构建 x64：

```powershell
vcvarsall.bat x64
cmake -S . -B _build-x64 -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-x64 --config Release --target SigilHook SigilHookDll
ctest --test-dir _build-x64 -C Release --output-on-failure
```

在测试或宿主环境中显式加载 DLL 并自行管理运行时时，设置 `SIGILHOOK_DISABLE_AUTOLOAD=1`。

构建 x86 时使用 `vcvarsall.bat x86` 和 `_build-x86`。x86 和 x64 DLL 必须分别构建，并且只能注入匹配位数的进程。

主要产物：

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

`SigilHook.lib` 是静态 C++ 库。`SigilHookImport.lib` 是 `SigilHook.dll` 导出 C ABI 的导入库。

clang-cl 使用 Visual Studio generator 加 `-T ClangCL`，x86 加 `-A Win32`：

```powershell
cmake -S . -B _build-clang-cl-x64 -G "Visual Studio 17 2022" -T ClangCL -A x64 `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-clang-cl-x64 --config Release --target SigilHookDll
ctest --test-dir _build-clang-cl-x64 -C Release --output-on-failure
```

去掉 `-T ClangCL` 即可用相同 generator 和架构参数使用常规 MSVC 工具集。

手动 GitHub Actions 工作流接受可选的 `release_tag`。设置后会发布四个 Windows 包和两个 GCC Linux 包：

```text
SigilHook-msvc-x86.zip
SigilHook-msvc-x64.zip
SigilHook-clang-cl-x86.zip
SigilHook-clang-cl-x64.zip
SigilHook-gcc-x86.zip
SigilHook-gcc-x64.zip
```

每个包都包含可部署的运行时布局：

```text
SigilHook.dll
SigilHookReload.bat
SigilHook/
  SigilHook.ash
```

GCC 包提供 Linux 静态库开发产物，不包含 Windows 可注入 DLL：

```text
libSigilHook.a
include/
  sigilhook.h
SigilHook/
  SigilHook.ash
THIRD_PARTY_NOTICES.md
```

## 许可证和致谢

SigilHook 的修改和原创集成代码版权归
Copyright (c) 2026 StackAndPointer。

SigilHook 基于以下开源组件构建，并感谢其作者：

- [PolyHook 2](https://github.com/stevemk14ebr/PolyHook_2_0)，Copyright (c) 2018
  Stephen Eckels，MIT License。见 [`LICENSE`](LICENSE)。
- [AngelScript](https://www.angelcode.com/angelscript/)，Copyright (c) 2003-2025
  Andreas Jonsson，zlib-style permissive license。见
  [`third_party/angelscript/LICENSE.md`](third_party/angelscript/LICENSE.md)。
- [AsmJit](https://github.com/asmjit/asmjit)，Copyright (c) 2008-2025 The AsmJit
  Authors，zlib-style permissive license。
- [AsmTK](https://github.com/asmjit/asmtk)，Copyright (c) 2016 Petr Kobalicek，
  zlib-style permissive license。
- [Zydis](https://github.com/zyantific/zydis) 和 Zycore，MIT License。

见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 以及各自依赖目录中的许可证文件。SigilHook 包含修改过的 PolyHook 2 实现；原始版权和许可声明保留在 [`LICENSE`](LICENSE) 中。