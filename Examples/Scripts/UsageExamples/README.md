<!--
Copyright (c) 2026 StackAndPointer
SPDX-License-Identifier: MIT
-->

# AngelScript usage examples

This directory is a small, neutral example application. It is not a game or
test fixture, and it does not contain game-specific scripts. The files show
the intended authoring model for a real deployment:

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

Only `main.as` defines `main()` and `unload()`. All other `.as` files are
ordinary sections of the same `SigilHook.Application` module, so they can call
each other's global functions and update shared globals directly.

## The three common hook shapes

### Run script code and continue the original

[01-entry-detour.as](01-entry-detour.as) is the basic shape:

```angelscript
void onEntry() {
    shSetArg(0, shArg(0) + 100);
    shKeepOriginal();
}
```

The replaced prologue jumps to generated code, the callback runs, and the
trampoline continues the original function body. The callback can inspect or
replace arguments, read registers and XMM values, set flags, or call
`shSkipOriginal()` instead.

### Hook A, call B

[02-call-another-function.as](02-call-another-function.as) demonstrates the
deployment pattern often needed by a game hook: when function A is entered,
patch or inspect the call context, then call a different native function B.
The example uses `shCallUsercall()` because B has a custom register mapping.

For ordinary exported functions, use a generated wrapper from
`tools/header_to_ash.py`; for a raw address, use `shCallUsercall()` or
`shInvokeNativeBlob()`.

### Skip A and return a script value

[04-skip-original-and-return.as](04-skip-original-and-return.as) calls
`shSkipOriginal()` and `shSetReturn()`. This is the correct shape for replacing
a function rather than wrapping it.

## Addresses and signatures

The placeholder addresses such as `0x00401000` are intentionally invalid for a
real process. Replace them together with the signature and mapping for the
target build. The signature is `returnType:parameterType,...`; argument values
are then read with `shArg(index)` and written with `shSetArg(index, value)`.

The runtime does not guess a calling convention from a type declaration.
Choose one explicitly with `shHookConvention()` or `shHookUsercall()`:

```angelscript
// x86 thiscall: this in ecx
shHookUsercall(0x00415D40, "void onUpdate()", "void:void*",
    "usercall:ret=none;arg0=ecx");
```

Use `stack+offset` only when the target really reads an argument from the
stack. The offset is measured from the function-entry stack pointer and
includes the return address, as documented in the standard library header.

## Multi-file headers

The runtime expands each `.ash` path once automatically, even when multiple `.as` sections include it. Use `#pragma once` for editor/tool compatibility, not as a required guard. Namespace public APIs and keep implementation helpers in a per-header private namespace:

```angelscript
#pragma sigilhook namespace Game::Player
export int health(uint64 entity);
#pragma sigilhook endnamespace

#pragma sigilhook private
int decodeFlags(uint64 flags) { return int(flags & 7); }
#pragma sigilhook endprivate
```

`export` is a documentation marker, not access control. See the full usage guide for directive constraints.

## Engineering deployment checklist

Before loading these scripts into a production process:

1. Identify each target address from the exact binary build and verify its calling convention.
2. Replace every placeholder address and update the signature and register/stack mapping together.
3. Prefer generated bindings for exported APIs; use `shNativeAddress()` plus `shInvokeNativeBlob()` only when a typed wrapper cannot express the ABI.
4. Keep hook handles in one owner, remove them in `unload()`, and treat `SH_ERROR_BUSY` as a retry condition during stop or reload.
5. Use `shSetArgStatus()`, `shSetReturnStatus()`, and the `SHCallContext` status APIs when a callback must distinguish an invalid frame from a valid zero value.
6. Gate x64-only registers, XMM registers, and pointer-width signatures with `shIsX64()`/`shPointerSize()`.
7. Test the script against the target process with logging enabled before enabling hot reload.

The compile check validates the examples during a build, but it intentionally does not execute placeholder hooks. To execute a real target, copy this directory, replace the placeholder addresses, and load the result as the runtime script directory:

```text
<SigilHook.dll directory>\SigilHook\main.as
<SigilHook.dll directory>\SigilHook\01-entry-detour.as
<SigilHook.dll directory>\SigilHook\include\Shared.ash
```

For a C++-style multi-file layout, keep the same directory shape and include
`SigilHook.ash` from each source/header that needs the API. See
[`docs/USAGE.md`](../../../docs/USAGE.md) and
[`docs/USAGE.zh-CN.md`](../../../docs/USAGE.zh-CN.md) for the complete API.
