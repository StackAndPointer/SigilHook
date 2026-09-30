# Third-Party Notices

SigilHook modifications and original SigilHook integration code are
Copyright (c) 2026 StackAndPointer.

SigilHook includes or derives from the following open-source components.

## PolyHook 2

- Project: https://github.com/stevemk14ebr/PolyHook_2_0
- Copyright: Copyright (c) 2018 Stephen Eckels
- License: MIT License
- License file: [`LICENSE`](LICENSE)

The hook core under `sigilhook/` and related implementation files is a modified
and renamed PolyHook 2 implementation. SigilHook changes are not represented as
the original PolyHook 2 software. The original MIT copyright and permission
notice is retained in `LICENSE`.

## AngelScript

- Project: https://www.angelcode.com/angelscript/
- Copyright: Copyright (c) 2003-2025 Andreas Jonsson
- License: zlib-style permissive license
- License file: [`third_party/angelscript/LICENSE.md`](third_party/angelscript/LICENSE.md)

The bundled AngelScript SDK is used under its original zlib-style license.
SigilHook carries build-integration changes around the bundled AngelScript
project, including its CMake project files, and adds surrounding runtime
integration code. Those SigilHook-specific changes are Copyright (c) 2026
StackAndPointer and are not part of official AngelScript.

The original AngelScript source notices and license text are retained, and the
AngelScript core is not represented as a SigilHook-owned implementation.

## AsmJit

- Project: https://github.com/asmjit/asmjit
- Copyright: Copyright (c) 2008-2025 The AsmJit Authors
- License: zlib-style permissive license
- License file: [`asmjit/LICENSE.md`](asmjit/LICENSE.md)

## AsmTK

- Project: https://github.com/asmjit/asmtk
- Copyright: Copyright (c) 2016 Petr Kobalicek
- License: zlib-style permissive license
- License file: [`asmtk/LICENSE.md`](asmtk/LICENSE.md)

## Zydis and Zycore

- Project: https://github.com/zyantific/zydis
- Copyright: Copyright (c) 2014-2024 Florian Bernd and Joel Hoener
- License: MIT License
- License files: [`zydis/LICENSE`](zydis/LICENSE),
  [`zydis/dependencies/zycore/LICENSE`](zydis/dependencies/zycore/LICENSE)

When redistributing SigilHook or substantial portions of these components, retain
the applicable copyright notices and license texts. Modified source versions
must be identified as modified and must not be presented as the upstream
originals.
