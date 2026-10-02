<!--
Copyright (c) 2026 StackAndPointer
SPDX-License-Identifier: MIT
-->

# AngelScript 使用示例

这个目录是一个小型、中立的示例应用，不是游戏脚本，也不包含特定游戏内容。
它展示真实部署时应采用的编写模型：

```text
main.as
  01-entry-detour.as
  02-call-another-function.as
  03-thiscall-ecx-usercall.as
  04-skip-original-and-return.as
  05-mid-hook.as
  06-registers-xmm-flags.as
  07-native-binding.as
  08-multi-file.as
  include/
    Shared.ash
    SharedConstants.ash
```

只有 `main.as` 定义 `main()` 和 `unload()`。其他 `.as` 文件都是同一个
`SigilHook.Application` 模块的普通 section，因此可以直接互调全局函数、
直接读写共享全局变量。

## 三种常见 Hook 形态

### 执行脚本代码后继续原函数

[01-entry-detour.as](01-entry-detour.as) 是最基础的形态：

```angelscript
void onEntry() {
    shSetArg(0, shArg(0) + 100);
    shKeepOriginal();
}
```

被替换的函数入口会跳到生成的代码，随后脚本回调执行，再由 trampoline 继续
原函数体。回调可以检查或替换参数、读写寄存器和 XMM、设置 flags，或者调用
`shSkipOriginal()` 跳过原函数。

### Hook A，并调用 B

[02-call-another-function.as](02-call-another-function.as) 展示游戏 Hook
常见的部署模式：进入函数 A 时修改或检查调用上下文，然后调用另一个原生函数 B。
示例使用 `shCallUsercall()`，因为 B 使用自定义寄存器映射。

普通导出函数应使用 `tools/header_to_ash.py` 生成的包装；裸地址则使用
`shCallUsercall()` 或 `shInvokeNativeBlob()`。

### 跳过 A，直接返回脚本值

[04-skip-original-and-return.as](04-skip-original-and-return.as) 调用
`shSkipOriginal()` 和 `shSetReturn()`。这是“替换函数”而不是“包裹函数”时应采用的形态。

## 地址和签名

`0x00401000` 之类的占位地址对真实进程无效。部署时需要把地址、签名和映射一起
替换成目标版本对应的值。签名格式是 `returnType:parameterType,...`；参数值
用 `shArg(index)` 读取，用 `shSetArg(index, value)` 写入。

运行时不从类型声明猜测调用约定。请通过 `shHookConvention()` 或
`shHookUsercall()` 显式选择：

```angelscript
// x86 thiscall：this 位于 ecx
shHookUsercall(0x00415D40, "void onUpdate()", "void:void*",
    "usercall:ret=none;arg0=ecx");
```

只有目标函数确实从栈读取参数时才使用 `stack+offset`。偏移从函数入口的栈指针
开始计算，并包含返回地址；具体语义见标准头文件。

## 运行示例

编译检查会在构建期间验证示例。要执行真实目标，请复制这个目录，替换占位地址，
然后把结果作为运行时脚本目录加载：

```text
<SigilHook.dll 所在目录>\SigilHook\main.as
<SigilHook.dll 所在目录>\SigilHook\01-entry-detour.as
<SigilHook.dll 所在目录>\SigilHook\include\Shared.ash
```

如果要采用类似 C++ 的多文件布局，请保持同样的目录结构，并在需要 API 的每个
源文件或头文件中 include `SigilHook.ash`。完整接口见
[`docs/USAGE.zh-CN.md`](../../../docs/USAGE.zh-CN.md)。
