# SigilHook 使用说明

Copyright (c) 2026 StackAndPointer

English version: [Usage Guide](USAGE.md)

本文说明脚本运行时、标准 AngelScript 头文件和导出的 C ABI，面向需要把 `SigilHook.dll` 注入到匹配位数进程并编写 `.as` 代码的使用者。

## 1. 设计与架构

SigilHook 提供两套 API 完全一致的构建：

| 构建 | 目标进程 | 指针宽度 | 通用寄存器 | x86 usercall 栈清理 |
| --- | --- | ---: | --- | --- |
| `_build-x86/SigilHook.dll` | 32 位 | 4 字节 | `AX`、`CX`、`DX`、`BX`、`SP`、`BP`、`SI`、`DI` | 允许 |
| `_build-x64/SigilHook.dll` | 64 位 | 8 字节 | `AX` 到 `R15` 别名 | 必须省略或为 `0` |

标准头文件刻意只有一份：[`scripts/SigilHook.ash`](../scripts/SigilHook.ash)。不需要拆成 `x86.ash` 和 `x64.ash`，因为脚本 API 文本相同，真正不同的是 DLL、目标进程、指针宽度和可用寄存器。可移植脚本通过运行时查询选择分支：

```angelscript
#include "SigilHook.ash"

void example() {
    if (shIsX86()) {
        // 32 位进程
    } else if (shIsX64()) {
        // 64 位进程
    }
}
```

`shBuildMode()` 返回 `SH_MODE_X86` 或 `SH_MODE_X64`，`shPointerSize()` 返回 `4` 或 `8`。访问扩展寄存器前先使用 `shRegisterAvailable()`；判断是否允许写入时使用 `shRegisterWritable()`，它会考虑只读的 `SP`。

x86 DLL 只能注入 x86 进程，x64 DLL 只能注入 x64 进程。注入 DLL 不会把一个 32 位脚本目标变成有效的 64 位目标。

## 2. 构建产物

在 Visual Studio 开发者命令行中构建 x64：

```powershell
vcvarsall.bat x64
cmake -S . -B _build-x64 -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-x64 --config Release --target SigilHook SigilHookDll
ctest --test-dir _build-x64 -C Release --output-on-failure
```

x86 使用 `vcvarsall.bat x86` 和 `_build-x86`：

```powershell
vcvarsall.bat x86
cmake -S . -B _build-x86 -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release `
  -DSIGILHOOK_BUILD_DLL=ON -DSIGILHOOK_BUILD_INJECTOR_DLL=ON
cmake --build _build-x86 --config Release --target SigilHook SigilHookDll
ctest --test-dir _build-x86 -C Release --output-on-failure
```

主要产物：

```text
_build-x86/SigilHook.dll
_build-x86/SigilHook.lib
_build-x86/SigilHookImport.lib
_build-x64/SigilHook.dll
_build-x64/SigilHook.lib
_build-x64/SigilHookImport.lib
```

`SigilHook.lib` 是静态 C++ 库，`SigilHookImport.lib` 是导出 C ABI 的导入库。CMake 会把标准头复制到所选构建目录的 `SigilHook/SigilHook.ash`。

仓库工作流还会使用 Visual Studio 分别构建 MSVC 和 clang-cl 的
`Win32`、`x64` 版本。手动工作流接受可选的 `release_tag`；提供该参数时会发布以下
四个 Windows 压缩包和两个 GCC Linux 压缩包：

```text
SigilHook-msvc-x86.zip
SigilHook-msvc-x64.zip
SigilHook-clang-cl-x86.zip
SigilHook-clang-cl-x64.zip
SigilHook-gcc-x86.zip
SigilHook-gcc-x64.zip
```

Windows 压缩包包含可直接部署的目录结构，DLL 旁边同时提供标准 `.ash` 头文件：

```text
SigilHook.dll
SigilHook/
  SigilHook.ash
```

GCC x86/x64 Job 使用 Linux 构建和测试。它们不是 Windows DLL 发布包；
对应的 GCC 发布包包含 Linux 静态库、C 头文件和标准 AngelScript 头文件：

```text
libSigilHook.a
include/
  sigilhook.h
SigilHook/
  SigilHook.ash
```

## 3. 部署与加载

默认脚本目录：

```text
<SigilHook.dll 所在目录>\SigilHook\
```

运行时会创建并写入：

```text
<SigilHook.dll 所在目录>\SigilHook\logs\SigilHook.log
```

推荐部署结构：

```text
<host>\SigilHook.dll
<host>\SigilHookReload.bat
<host>\SigilHook\main.as
<host>\SigilHook\feature.as
<host>\SigilHook\include\*.ash
<host>\SigilHook\SigilHook.ash
<host>\SigilHook\logs\SigilHook.log
```

可注入 DLL 在 `DLL_PROCESS_ATTACH` 中启动一个工作线程，随后加载 DLL 同目录下的 `SigilHook`。如果宿主要自己管理运行时，设置 `SIGILHOOK_DISABLE_AUTOLOAD=1`：

```cpp
sigilhook_runtime_start(L"<script directory>");
sigilhook_runtime_load_directory(L"<script directory>");
// ...
sigilhook_runtime_stop();
```

卸载 DLL 前必须调用 `sigilhook_runtime_stop()`。这是强制协议：运行时启动期间绝不能直接调用 `FreeLibrary`。运行时清理不能在 Windows loader lock 下的 `DllMain` 中执行。默认停止超时为 5000 毫秒，也可以使用 `sigilhook_runtime_stop_with_timeout(timeout_ms)` 指定超时。停止时会先拒绝新的脚本回调，并由 AngelScript 的 line callback 在脚本自身线程中请求活动脚本中止。若原生代码阻塞在回调中，运行时无法强制取消；到达截止时间后会返回 `SIGILHOOK_ERROR_BUSY`，此时 Hook、模块和引擎仍然有效，不要卸载 DLL，应从原生线程重试停止或终止宿主进程。从活动 AngelScript context 内调用 stop 同样会返回 `SIGILHOOK_ERROR_BUSY`。进程终止不需要运行时清理。

在 Windows 上，注入 DLL 还会启动一个仅限本机的命名管道，用于手动热重载脚本。每个宿主进程拥有自己的管道 `\\.\pipe\SigilHook.<pid>`，因此多个被注入进程可以同时存在。运行构建输出目录、安装目录或发布包中的 `SigilHookReload.bat`：

```bat
SigilHookReload.bat            重载所有在线的 SigilHook 宿主
SigilHookReload.bat <pid>      只重载指定进程号的宿主
```

脚本会枚举在线的 `SigilHook.<pid>` 管道，连接被选中的每一个并等待 `OK` 请求确认。随后对应宿主的管道工作线程会重载它自己的脚本目录：停止已加载的 AngelScript 应用，重新执行 `main.as::main()`，并把结果写入 `<SigilHook.dll 所在目录>\SigilHook\logs\SigilHook.log`。`OK` 只表示请求已被接受，不表示新脚本编译成功。当脚本回调无法在超时内静默下来时，重载失败并返回 `BUSY`，此时不会卸载任何脚本或 Hook。重载失败时，部分启动的新运行时会再次停止，因此可以直接修复 `main.as` 后重新加载目录。该管道只接受本机连接。

原生宿主也可以直接调用 `sigilhook_runtime_reload()` 或 `sigilhook_runtime_reload_with_timeout()` 触发同一路径。脚本可以调用 `shReloadStatus()` 和 `shReloadWithTimeoutStatus(timeoutMs)`，但普通 Hook 回调不应重载正在执行的模块。

DLL 本身不是注入器；仍需要宿主自己的注入机制，并且 DLL 必须与目标进程位数一致。

## 4. 脚本模块与头文件

加载器会递归收集脚本目录下的所有 `.as` 文件，并按确定的路径顺序加入同一个 AngelScript 模块 `SigilHook.Application`。

因此：

- 一个 `.as` 文件中的全局函数可以直接被另一个 `.as` 文件调用。
- 全局变量可以直接共享。
- 应用文件之间不需要 `import` 或 `export`。
- `.ash` 是头文件，不是独立入口。
- 只有根目录的 `main.as` 可以定义 `void main()` 和可选的 `void unload()`。
- 整个模块构建成功后只执行一次 `main()`；运行时关闭时只执行一次 `unload()`。

最小应用：

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

头文件查找顺序是先相对于当前文件，再相对于脚本根目录：

```angelscript
#include "helpers.ash"
#include <include/shared.ash>
```

加载器会移除可选的 `#pragma once`。每个规范化后的头文件路径在应用内只展开一次，因此重复包含不需要保护宏。包含行会替换成空行，保留原 `.as` 文件行号。缺失文件、非法指令、循环包含和超过 16 层的包含深度都会带包含链报告。加载器不实现 `#ifndef`、`#define` 或完整 C 预处理器。

普通 `.as` 文件应作为应用 section 直接编译，只包含 `.ash` 文件。

## 5. 标准头 API

把 [`scripts/SigilHook.ash`](../scripts/SigilHook.ash) 复制到部署的 `SigilHook` 目录。它提供常量、枚举、便利封装，以及对应 C ABI 的状态返回封装。

### 运行时与状态

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

当前 C API 版本是 `0x0002000C`。

`sigilhook_invoke_usercall` 会按目标地址和签名缓存生成的调用桩。运行时停止时会自动清理该缓存；如果原生宿主持续使用 C ABI 而不停止运行时，应在这些目标不再使用时显式调用
`sigilhook_clear_invoker_cache()`。

状态码：

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

`shHookScript()`、`shDestroyHook()` 等便利函数会像旧接口一样丢弃底层状态。需要可靠错误处理时，使用 `sh...Status` 或显式状态返回函数。

### 完整脚本接口索引

标准头是脚本层的公开 API，函数按用途分组如下：

| 分组 | 函数 |
| --- | --- |
| 运行时与状态 | `shIsValidHook`、`shApiVersion`、`shBuildMode`、`shIsX86`、`shIsX64`、`shPointerSize`、`shRegisterAvailable`、`shRegisterWritable`、`shClearLastError`、`shLastError`、`shLog`、`shStatusString` |
| Hook 创建 | `shHookScript`、`shHookEntryContinue`、`shHookInstructionStatus`、`shHookMid`（兼容别名）、`shHookConvention`、`shHookUsercall`、`shHookNative`、`shHookBreakpoint`、`shHookHardwareBreakpoint`、`shHookIat`、`shHookEat`、`shHookVFunc`、`shHookVTable` |
| Hook 生命周期 | `shEnableHook`、`shDisableHook`、`shUnhook`、`shDestroyHook`、`shRehook`、`shIsHooked`、`shHookType`、`shTrampoline`、`shOriginalVFunc`、`shContinueOriginal`、`shResumeMid`（兼容别名） |
| Detour 配置 | `shSetDebug`、`shSetFollowCall`、`shMaxDepth`、`shSetMaxDepth`、`shDetourScheme`、`shSetDetourScheme` |
| 回调帧 | `shArg`、`shArg8`、`shArg16`、`shArg32`、`shSetArg`、`shSetArgStatus`、`shSetArg8`、`shSetArg16`、`shSetArg32`、`shReturn`、`shReturn8`、`shReturn16`、`shReturn32`、`shSetReturn`、`shSetReturnStatus`、`shSetReturn8`、`shSetReturn16`、`shSetReturn32`、`shReturnEarly`、`shKeepOriginal`、`shSkipOriginal` |
| 寄存器与控制流 | `shRegisterAvailable`、`shRegisterWritable`、`shXmmAvailable`、`shReg`、`shReg8`、`shReg16`、`shReg32`、`shSetReg`、`shSetReg8`、`shSetReg16`、`shSetReg32`、`shXmm`、`shSetXmm`、`shXmmFloat`、`shSetXmmFloat`、`shXmmDouble`、`shSetXmmDouble`、`shFloatBits`、`shBitsFloat`、`shDoubleBits`、`shBitsDouble`、`shFlags`、`shSetFlags`、`shInstructionPointer`、`shSetInstructionPointer`、`shInstructionPointerStatus`、`shSetInstructionPointerStatus`、`shContextInstructionPointerStatus`、`shContextSetInstructionPointerStatus` |
| 内存与特征码 | `shReadBytes`、`shReadU8`、`shReadU16`、`shReadU32`、`shReadU64`、`shWriteBytes`、`shWriteU8`、`shWriteU16`、`shWriteU32`、`shWriteU64`、`shMemProtect`、`shMemProtectStatus`、`shFindPattern`、`shFindPatternStatus`、`shPatternSize` |
| 汇编与反汇编 | `shDisAsm`、`shDisAsmStatus`、`shHtoi`、`shParseHexStatus`、`shAsmCmp`、`shAsmTest`、`shAsmFxsave`、`shAsmFxrstor`、`shAsmRet`、`shAsmRetStatus`、`shAsmRetFree`、`shAsmMovEspAndJmp`、`shAsmMovEspAndJmpStatus`、`shAsmMovEspAndJmpFree` |
| 显式状态 API | `shCreateDetour`、`shCreateBreakpoint`、`shCreateHardwareBreakpoint`、`shCreateIat`、`shCreateEat`、`shCreateVFuncEntries`、`shCreateVTableEntries`、`shInstallHook`、`shDestroyHookStatus`、`shRemoveHook`、`shRehookStatus`、`shSetHookedStatus`、`shIsHookedStatus`、`shHookTypeStatus`、`shSetDebugStatus`、`shTrampolineStatus`、`shOriginalVFuncStatus`、`shMaxDepthStatus`、`shSetMaxDepthStatus`、`shSetFollowCallStatus`、`shDetourSchemeStatus`、`shSetDetourSchemeStatus` |
| 高级运行时 | `shCreateScriptJit`、`shDestroyJit`、`shBindDetourToJit`、`shLoadDirectory`、`shReloadStatus`、`shReloadWithTimeoutStatus`、`shWaitForTrampolinesStatus`、`shCallEntry`、`shSetSharedU64`、`shSharedU64`、`shSetSharedU64Status`、`shSharedU64Status`、`shCallUsercall`、`shNativeAddress`、`shInvokeNativeBlob`、`shNativeThrow`、`shNativeStringBytes`、`shBufferAddress` |

具体声明、参数宽度、返回值和 `out` 参数以
[`scripts/SigilHook.ash`](../scripts/SigilHook.ash) 为准。原生集成应使用对应的
[`include/sigilhook.h`](../include/sigilhook.h) C ABI 声明。

### Hook 构造

| 操作 | 便利封装 | 状态返回封装 |
| --- | --- | --- |
| Detour | `shHookScript`、`shHookConvention`、`shHookUsercall` | `shCreateDetour` + `shInstallHook` |
| 原生回调地址 | `shHookNative` | `shCreateDetour` + `shInstallHook` |
| 软件断点 | `shHookBreakpoint` | `shCreateBreakpoint` + `shInstallHook` |
| 硬件断点 | `shHookHardwareBreakpoint` | `shCreateHardwareBreakpoint` + `shInstallHook` |
| 导入表 | `shHookIat` | `shCreateIat` + `shInstallHook` |
| 导出表 | `shHookEat` | `shCreateEat` + `shInstallHook` |
| 虚函数表项 | `shHookVFunc` | `shCreateVFuncEntries` + `shInstallHook` |
| VTable | `shHookVTable` | `shCreateVTableEntries` + `shInstallHook` |

`shHookScript(target, callbackDeclaration, signature)` 使用默认约定。`cdecl`、`stdcall`、`fastcall`、`thiscall`、`vectorcall` 使用 `shHookConvention()`，自定义映射使用 `shHookUsercall()`。

已安装的典型 Detour：

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

`signature` 描述目标函数给 JIT 回调使用，和 AngelScript 回调声明是两回事。回调通常使用 `shArg()` 读取目标参数，不需要把所有参数重复声明成 AngelScript 参数。

### Hook 生命周期与配置

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

`shSetFollowCall()` 控制目标函数地址本身是 `CALL` 目标时是否继续解析调用目标；`shMaxDepth()` 控制 Detour 序言解析深度。x64 Detour 方案只在 x64 有效：

```angelscript
if (shIsX64()) {
    uint8 scheme = shDetourScheme(g_hook);
    shSetDetourScheme(g_hook, scheme);
}
```

`shOriginalVFunc(handle, index)` 读取 VFunc 或 VTable Hook 保存的原始虚函数地址。

## 6. 回调参数、返回值与原函数调用

脚本回调内部：

```angelscript
uint64 value = shArg(0);
shSetArg(0, value + 1);

uint64 result = shReturn();
shSetReturn(result + 1);
shKeepOriginal();
```

可用控制：

- `shArg(index)`、`shArg8/16/32(index)` 读取逻辑参数。
- `shSetArg(index, value)`、`shSetArg8/16/32(index, value)` 修改参数；`shSetArgStatus(index, value)` 是其状态返回版本。
- `shReturn()`、`shReturn8/16/32()` 读取待返回值。
- `shSetReturn(value)`、`shSetReturn8/16/32(value)` 覆盖返回值；`shSetReturnStatus(value)` 是其状态返回版本。
- `shKeepOriginal()` 请求执行原函数/trampoline。
- `shSkipOriginal()` 跳过原函数。
- `shReturnEarly(value)` 设置返回值并跳过原函数。

参数下标是目标签名中的逻辑下标，不是原始栈偏移。映射到寄存器的参数也能通过 `shReg()` 读取。如果显式调用了 `shSetArg()`，该参数值优先于后续的纯寄存器修改；否则应用映射寄存器的写入。

回调 frame 是线程局部的，多个线程的活动回调不会互相覆盖。除非脚本自己管理生命周期，否则不要跨回调保存 frame 指针。

## 7. 调用约定与 usercall

支持的标准约定：

```text
cdecl       __cdecl
stdcall     __stdcall
fastcall    __fastcall
thiscall    __thiscall
vectorcall  __vectorcall
```

自定义映射格式：

```text
usercall:ret=<register|none>;argN=<register|stack+offset>;cleanup=<bytes>
```

规则：

- 每个声明参数必须有唯一的 `argN`。
- 非 `void` 返回必须写 `ret=<register>`，`void` 返回必须写 `ret=none`。
- 寄存器位置不能重复。
- `SP` 不能作为参数或返回位置。
- `stack+offset` 是目标函数入口栈指针的字节偏移，包含返回地址和 ABI 预留空间。
- 栈区间必须按指针宽度对齐且不能重叠。
- `cleanup` 只在 x86 接受；x64 必须省略或写 `0`。
- x86 的 usercall 返回值不能超过 32 位。
- x86 不能使用 `R8..R15`。
- `xmm0..xmm7` 在两种架构上都是合法的参数位置，x64 另外支持 `xmm8..xmm15`。自定义约定把 float/double 放在特定向量寄存器时使用它们，例如 `usercall:ret=eax;arg0=xmm0;arg1=xmm1`。
- usercall 映射不支持向量寄存器返回值；请把 `ret` 保留为通用寄存器。

示例：

```angelscript
string mapping = shIsX64()
    ? "usercall:ret=rax;arg0=rcx;arg1=rdx;arg2=stack+16"
    : "usercall:ret=eax;arg0=ecx;arg1=edx;arg2=stack+8;cleanup=8";

uint64 hook = shHookUsercall(
    target, "void callback()", "unsigned int:unsigned int,unsigned int,unsigned int", mapping);
```

`shCallUsercall()` 使用同样的映射直接调用任意目标：

```angelscript
array<uint64> args(2);
args[0] = 10;
args[1] = 20;
uint64 result = 0;
uint8 status = shCallUsercall(
    target, "unsigned int", "unsigned int,unsigned int",
    "usercall:ret=rax;arg0=rcx;arg1=rdx", args, result);
```

指针类型按目标架构计算宽度：`void*`、`T*`、`intptr_t`、`uintptr_t` 在 x86 是 4 字节，在 x64 是 8 字节。

## 8. 寄存器、标志与指令指针

`SHRegister` 是规范名称。映射字符串和底层 API 还接受大小写不敏感的常见别名，例如 `eax`、`rax`、`r8d`、`r8w`、`r8b`。

```angelscript
uint64 cx = shReg(SH_REG_CX);
uint16 low = shReg16(SH_REG_CX);
uint8 byteValue = shReg8(SH_REG_CX);
shSetReg16(SH_REG_CX, low + 1);
```

语义：

- `shReg()` 读取完整 frame 值。
- `shReg8()`、`shReg16()`、`shReg32()` 只读取低位。
- 宽度写入在架构允许时保留 frame 中高于该宽度的位。x86 物理 32 位寄存器写入会遵循硬件零扩展，因此不要依赖 x86 的高 32 位值。
- `SP` 可读但不可写。
- x86 不提供 `R8..R15`。
- XMM0-7 在 x86 可用，XMM0-15 在 x64 可用。每个 XMM 值暴露两个 64 位 lane：lane 0 是低 64 位，lane 1 是高 64 位；`shXmmFloat()` 和 `shSetXmmFloat()` 使用 lane 0 操作 `float`，`shXmmDouble()` 和 `shSetXmmDouble()` 使用 lane 0 操作 `double`；`shFloatBits()`/`shBitsFloat()` 与 `shDoubleBits()`/`shBitsDouble()` 可在浮点值和整数位表示之间转换。x64 浮点参数会通过 XMM 同步；x86 标准浮点参数位于栈上，修改传给原函数的浮点参数使用 `shSetArg()`。
- 段、控制和调试寄存器暂不包含在当前 API 中。

```angelscript
uint64 flags = shFlags();
shSetFlags((flags & ~uint64(0x40)) | 0x40);
```

调用原函数或最终返回前会恢复标志。不要假设语言 ABI 会把标志值跨回调保留。

```angelscript
uint64 ip = shInstructionPointer();
shSetInstructionPointer(trampoline);
```

`shSetInstructionPointer()` 会在恢复映射参数和标志后重定向控制流。`shInstructionPointerStatus()` 和 `shSetInstructionPointerStatus()` 是显式状态版本；`SHCallContext` 也提供 `getInstructionPointer[Status]()` 和 `setInstructionPointer[Status]()`。没有重定向目的地的回调帧会返回 `SH_ERROR_UNSUPPORTED`。重定向使用一个易失寄存器（x86 为 `EAX`，x64 为 `R10`），需要重定向时不要把自定义参数映射到该寄存器。

## 9. 内存、特征码与汇编辅助

标量辅助：

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

标量读写是小端格式，便利封装会丢弃状态。需要错误处理时使用 `shReadBytes()`、`shWriteBytes()`、`shMemProtectStatus()` 和 `shFindPatternStatus()`。

保护标志为 `SH_PROT_NONE`、`SH_PROT_X`、`SH_PROT_R`、`SH_PROT_W`、`SH_PROT_RWX`。特征码使用 IDA 风格字节和 `??` 通配符：

```angelscript
uint64 found = shFindPattern(start, size, "8B ?? ?? 89");
```

反汇编和解析：

```angelscript
string text = shDisAsm(address, 32);
uint64 value = shHtoi("0x1234");
uint8 status = shParseHexStatus("1234", value);
```

可执行代码片段必须用对应的释放函数清理：

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

`shAsmMovEspAndJmp()` 在 x86 移动 `ESP`，在 x64 移动 `RSP` 后跳转。`shAsmFxsave()` 和 `shAsmFxrstor()` 需要 512 字节的 `array<uint8>`。

## 10. 共享值与运行时入口

宿主和脚本可以通过命名共享存储交换 `uint64`：

```angelscript
shSetSharedU64("seed", 42);
uint64 seed = shSharedU64("seed");
```

状态版本是 `shSetSharedU64Status()` 和 `shSharedU64Status()`。`shCallEntry("void myEntry()")` 调用已加载应用模块中的函数。`shLoadDirectory()` 可用于显式加载，但正常部署路径是上一节的 DLL 自动加载。`shReloadStatus()` 和 `shReloadWithTimeoutStatus(timeoutMs)` 会停止并重载当前应用；应从原生工具或其他驱动入口调用，不要在正在该模块中执行的回调里重载自身。`shWaitForTrampolinesStatus(timeoutMs)` 会等待仍在已退役 detour trampoline 中执行的目标线程退出。

## 11. 错误处理与日志

开发时先查看日志：

```text
<SigilHook.dll 所在目录>\SigilHook\logs\SigilHook.log
```

AngelScript 编译错误、入口缺失、回调查找失败、Hook 失败和回调执行失败都会写入这里。常用检查：

```angelscript
shClearLastError();
uint64 hook = shHookScript(...);
if (!shIsValidHook(hook)) {
    shLog("failed: " + shLastError());
}
```

状态返回 API 返回非 `SH_OK` 时，用 `shStatusString()` 转换并记录。脚本加载或入口执行失败时，当前运行时必须视为失败：修复 `main.as`、包含错误或重复声明，然后重启运行时再加载。

## 头文件转换与原生 DLL 绑定

`tools/header_to_ash.py` 可以把受支持的 Windows C ABI `.h`/`.hpp` 声明转换为确定性的 `.ash` 包装函数：

```powershell
python tools\header_to_ash.py include\GameApi.h `
  --dll GameApi.dll --output SigilHook\GameApi.ash --arch x86
```

转换器只依赖 Python 标准库，支持本地 include、简单预处理宏、typedef、enum、固定布局 POD 结构体、指针、`const char *`、Windows 宽字符串，以及 `cdecl`、`stdcall`、`fastcall`、`thiscall`、`vectorcall` 或显式 `usercall` 标注。使用 `--check` 可在 CI 中验证生成文件是否过期。

模板、类方法、mangled C++ 名称、非 POD 记录、虚函数、可变参数、union、位域和未知 `#pragma pack` 布局会以文件/行/列诊断拒绝。生成的包装函数缓存 DLL 和导出查找、显式序列化结构体字段，并通过 AngelScript 异常传播原生调用失败。底层运行时接口包括 `shNativeAddress`、`shInvokeNativeBlob`、`shNativeThrow`、`shNativeStringBytes` 和 `shBufferAddress`。

## 入口继续和指令级 Hook

`shHookEntryContinue()` 是入口 detour 的明确命名；`shHookMid()` 和 `shResumeMid()` 保留为兼容别名。`shHookEntryContinue()` 在原函数入口前执行，然后通过 trampoline 继续原函数体：

```angelscript
void beforeTarget() {
    // 检查或修改状态
    shContinueOriginal(g_entryHook);
}
```

`shHookInstructionStatus()` 是真正的指令级 Hook。它先校验目标地址落在指令边界，再把被覆盖指令搬进 trampoline；覆盖范围内出现相对控制流或 `ret` 时直接失败并写日志，不做猜测：

```angelscript
uint64 hook = 0;
uint64 trampoline = 0;
uint64 overwritten = 0;
uint8 status = shHookInstructionStatus(0x415D40, "void onInstruction()", "void");
```

回调可以用 `SHCallContext` 对象替代线程局部的全局辅助函数：

```angelscript
void onTarget(SHCallContext@ ctx) {
    uint64 value = ctx.getArg(0);
    ctx.setReturn(value + 1);
    ctx.continueOriginal();
}
```

## 12. C ABI 与高级集成

原生宿主使用 [`include/sigilhook.h`](../include/sigilhook.h)。所有地址都以 `uint64_t` 传递，句柄是不透明的 `sigilhook_handle`，边界上不暴露 C++ 异常、STL 类型或编译器对象布局。

C ABI 覆盖：

- Detour、断点、IAT、EAT、VFunc 和 VTable 构造
- 安装、移除、重装、销毁、查询和配置
- 带参数、返回值、通用寄存器、XMM 寄存器、标志和指令指针的 JIT 回调
- DLL 模块加载、导出解析、原生 blob 调用和位数校验
- 内存读写/保护、特征码、反汇编、标志、FXSAVE/FXRSTOR 和可执行片段
- 脚本运行时启动、加载、入口调用、共享值和停止

## 回调失败、卸载与 trampoline 生命周期

脚本回调抛异常、被中止或超过单次回调预算时，不会以 C++ 异常穿过 JIT 边界。运行时会记录并锁存该失败，停止分发新的回调，并通过 `sigilhook_runtime_last_callback_status()`（脚本层为 `shLastCallbackStatus()` / `shCallbacksHealthy()`）报告。成功执行 `sigilhook_runtime_reload*()` 或 `sigilhook_runtime_stop*()` 会清除该状态。失败原因同时写入运行时日志。

`sigilhook_runtime_stop()` / `sigilhook_runtime_stop_with_timeout()` 释放资源前会等待两件事：仍在执行的脚本回调，以及仍停留在已退役 trampoline 中的目标线程。`sigilhook_wait_for_trampolines(timeout_ms)` 直接暴露 trampoline 回收步骤，若有线程仍在其中会返回 `SIGILHOOK_ERROR_BUSY`。Detour 的 trampoline 在 `unhook` / `destroy` 时只是标记退役，不再立即释放；注册表会在在途计数归零后回收，因此热重载期间目标线程不会跳入已释放内存。
高级用户可以用 `sigilhook_create_jit_callback()` 创建原生 JIT 回调，再用 `sigilhook_bind_detour_to_jit()` 绑定到 Detour。脚本层的 `shCreateScriptJit()`、`shBindDetourToJit()`、`shDestroyJit()` 实现同一模型。

## 13. 排错

- **没有日志或没有 Hook：**确认 `main.as` 位于 DLL 旁的 `SigilHook` 目录，DLL 与进程位数一致，且没有意外设置 `SIGILHOOK_DISABLE_AUTOLOAD`。
- **缺少 `void main()`：**只有根目录 `main.as` 可以定义它。
- **找不到回调声明：**使用完整声明，例如 `"void onTarget()"`。
- **参数错误或栈损坏：**选择真实调用约定，包括 `thiscall` 或 `usercall` 映射。
- **`R8` 失败：**改用 x64，或改用 `SH_REG_AX..SH_REG_DI`。
- **`SP` 写入失败：**`SP` 是故意只读的。
- **x64 cleanup 错误：**删除 `cleanup` 或设置为 `0`。
- **注入成功但脚本没有执行：**查看 `logs\SigilHook.log`，检查 section、包含循环和非根入口。
- **卸载崩溃：**卸载 DLL 前调用 `sigilhook_runtime_stop()`，不要在 `DllMain` 中清理运行时。

## 14. 许可与致谢

SigilHook 修改和原始 SigilHook 集成代码 Copyright (c) 2026 StackAndPointer。项目感谢 PolyHook 2、AngelScript、AsmJit、AsmTK、Zydis 和 Zycore，详见 [`README.md`](../README.md) 与 [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)。
