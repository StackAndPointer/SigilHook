// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#if defined(_WIN32)
#include <Windows.h>
#include <filesystem>
#endif

#if defined(SIGILHOOK_NATIVE_BINDING_TEST)
#include "NativeBindingTest.h"
#endif

#include <asmjit/core.h>
#include <asmjit/x86.h>

#include <cstdint>
#include <cstring>
#include <array>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression << " at line " << __LINE__ << '\n'; char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); std::cerr << error << '\n'; return __LINE__; } } while (false)

namespace {
void printLog(sigilhook_log_level level, const char* message, void*) {
    std::cerr << (level == SIGILHOOK_LOG_ERROR ? "error: " : level == SIGILHOOK_LOG_WARNING ? "warning: " : "info: ")
              << (message == nullptr ? "" : message) << '\n';
}


int g_testMode = 0;
volatile int g_targetCalls = 0;
volatile int g_badArgumentValues = 0;
int g_usercallMode = 0;
volatile int g_usercallTargetCalls = 0;
volatile int g_pointerTargetCalls = 0;
volatile int g_pointerCallbackCalls = 0;
volatile int g_badPointerFrame = 0;
void* g_expectedPointer = nullptr;
int g_badUsercallFrame = 0;
uint64_t g_redirectAddress = 0;
uint64_t g_expectedInstructionPointer = 0;
int g_badInstructionPointer = 0;
volatile int g_redirectTargetCalls = 0;
volatile int g_stackTargetCalls = 0;
volatile int g_stackRedirectCalls = 0;
int g_badStackFrame = 0;
int g_badXmmFrame = 0;
uint64_t g_stackExpectedInstructionPointer = 0;
uint64_t g_stackRedirectAddress = 0;

#if defined(_MSC_VER)
__declspec(noinline)
#endif
int SIGILHOOK_CALL target(int value) {
    volatile int result = value;
    for (int index = 0; index < 8; ++index) {
        result = result + (index - index);
    }
    ++g_targetCalls;
    return result + 1;
}

__declspec(noinline) int SIGILHOOK_CALL stackTarget(int a, int b, int c, int d, int e) {
    ++g_stackTargetCalls;
    return a + b + c + d + e;
}

__declspec(noinline) int SIGILHOOK_CALL stackRedirectTarget(int a, int b, int c, int d, int e) {
    ++g_stackRedirectCalls;
    return e + 100;
}

void SIGILHOOK_CALL stackRedirectCallback(sigilhook_call_frame* frame, void*) {
    if (frame->argument_count != 5 || frame->arguments[4] != 5) ++g_badStackFrame;
    uint64_t instructionPointer = 0;
    if (sigilhook_call_frame_get_instruction_pointer(frame, &instructionPointer) != SIGILHOOK_OK ||
        instructionPointer != g_stackExpectedInstructionPointer ||
        sigilhook_call_frame_set_instruction_pointer(frame, g_stackRedirectAddress) != SIGILHOOK_OK) {
        ++g_badStackFrame;
    }
    *frame->call_original = 0;
}

__declspec(noinline) int SIGILHOOK_CALL redirectTarget(int value) {
    ++g_redirectTargetCalls;
    return value + 5;
}

void SIGILHOOK_CALL callback(sigilhook_call_frame* frame, void*) {
    if (frame->argument_count != 1 || frame->arguments[0] != 1) {
        ++g_badArgumentValues;
    }
    frame->arguments[0] = 41;
    switch (g_testMode) {
    case 0:
        *frame->return_value = 42;
        *frame->return_value_overridden = 1;
        break;
    case 1:
        *frame->return_value = 99;
        *frame->return_value_overridden = 1;
        *frame->call_original = 0;
        break;
    case 2:
        *frame->call_original = 1;
        break;
    case 3: {
        uint64_t instructionPointer = 0;
        if (sigilhook_call_frame_get_instruction_pointer(frame, &instructionPointer) != SIGILHOOK_OK ||
            instructionPointer != g_expectedInstructionPointer ||
            sigilhook_call_frame_set_instruction_pointer(frame, g_redirectAddress) != SIGILHOOK_OK) {
            ++g_badInstructionPointer;
        }
        *frame->call_original = 0;
        break;
    }
    default:
        break;
    }
}

void SIGILHOOK_CALL conventionCallback(sigilhook_call_frame* frame, void*) {
    if (frame->argument_count != 2 || frame->arguments[0] != 7 || frame->arguments[1] != 9) {
        ++g_badArgumentValues;
    }
    uint64_t flags = 0;
    if (sigilhook_call_frame_get_flags(frame, &flags) != SIGILHOOK_OK) ++g_badArgumentValues;
    if (sigilhook_call_frame_set_flags(frame, flags ^ 0x20) != SIGILHOOK_OK) ++g_badArgumentValues;
    frame->arguments[0] = 30;
    frame->arguments[1] = 4;
    if (sigilhook_call_frame_set_register(frame, SIGILHOOK_REGISTER_CX, 30) != SIGILHOOK_OK) {
        ++g_badArgumentValues;
    }
    *frame->return_value = 304;
    *frame->return_value_overridden = 1;
    *frame->call_original = 0;
}

void SIGILHOOK_CALL usercallCallback(sigilhook_call_frame* frame, void*) {
    if (frame->argument_count != 3 ||
        frame->arguments[0] != 11 || frame->arguments[1] != 22 || frame->arguments[2] != 33) {
        ++g_badUsercallFrame;
    }
    uint64_t value = 0;
    if (sigilhook_call_frame_get_register(frame, SIGILHOOK_REGISTER_SP, &value) != SIGILHOOK_OK) {
        ++g_badUsercallFrame;
    }
    if (sigilhook_call_frame_set_register(frame, SIGILHOOK_REGISTER_SP, value) != SIGILHOOK_ERROR_UNSUPPORTED) {
        ++g_badUsercallFrame;
    }
    uint64_t flags = 0;
    if (sigilhook_call_frame_get_flags(frame, &flags) != SIGILHOOK_OK) ++g_badUsercallFrame;
    if (sigilhook_call_frame_set_flags(frame, (flags & ~uint64_t{0x40}) | 0x40) != SIGILHOOK_OK) {
        ++g_badUsercallFrame;
    }

    switch (g_usercallMode) {
    case 0:
        if (sigilhook_call_frame_set_register(frame, SIGILHOOK_REGISTER_CX, 100) != SIGILHOOK_OK ||
            sigilhook_call_frame_set_register(frame, SIGILHOOK_REGISTER_DX, 22) != SIGILHOOK_OK) {
            ++g_badUsercallFrame;
        }
        frame->arguments[2] = 300;
        break;
    case 1:
        if (sigilhook_call_frame_set_register(frame, SIGILHOOK_REGISTER_AX, 0x12345678) != SIGILHOOK_OK) {
            ++g_badUsercallFrame;
        }
        *frame->call_original = 0;
        break;
    case 2:
        *frame->return_value = 777;
        *frame->return_value_overridden = 1;
        break;
    default:
        break;
    }
}

void SIGILHOOK_CALL invalidMappingCallback(sigilhook_call_frame*, void*) {}
void SIGILHOOK_CALL xmmCallback(sigilhook_call_frame* frame, void*) {
    uint64_t low = 0;
    uint64_t high = 0;
    if (sigilhook_call_frame_get_xmm(frame, SIGILHOOK_XMM_0, 0, &low) != SIGILHOOK_OK || low != UINT64_C(0x40200000)) ++g_badXmmFrame;
    if (sigilhook_call_frame_set_xmm(frame, SIGILHOOK_XMM_0, 0, UINT64_C(0x3f800000)) != SIGILHOOK_OK) ++g_badXmmFrame;
    if (sigilhook_call_frame_set_xmm(frame, SIGILHOOK_XMM_0, 1, UINT64_C(0x1122334455667788)) != SIGILHOOK_OK) ++g_badXmmFrame;
    if (sigilhook_call_frame_get_xmm(frame, SIGILHOOK_XMM_0, 0, &low) != SIGILHOOK_OK || low != UINT64_C(0x3f800000)) ++g_badXmmFrame;
    if (sigilhook_call_frame_get_xmm(frame, SIGILHOOK_XMM_0, 1, &high) != SIGILHOOK_OK || high != UINT64_C(0x1122334455667788)) ++g_badXmmFrame;
    if (sigilhook_call_frame_get_xmm(frame, SIGILHOOK_XMM_0, 2, &low) != SIGILHOOK_ERROR_INVALID_ARGUMENT) ++g_badXmmFrame;
    if (sigilhook_build_mode() == SIGILHOOK_MODE_X86 &&
        sigilhook_call_frame_get_xmm(frame, SIGILHOOK_XMM_8, 0, &low) != SIGILHOOK_ERROR_ARCH_MISMATCH) ++g_badXmmFrame;
    *frame->call_original = 0;
}

void SIGILHOOK_CALL pointerCallback(sigilhook_call_frame* frame, void*) {
    if (frame->argument_count != 1 || frame->arguments[0] != reinterpret_cast<uint64_t>(g_expectedPointer)) {
        ++g_badPointerFrame;
    }
    ++g_pointerCallbackCalls;
}

using UsercallCaller = unsigned int (SIGILHOOK_CALL *)(uintptr_t, unsigned int, unsigned int, unsigned int);
using PointerUsercallCaller = void* (SIGILHOOK_CALL *)(uintptr_t, void*, unsigned int, unsigned int);
#if defined(_MSC_VER) && defined(_M_IX86)
using StdCallFn = int (__stdcall *)(int, int);
using FastCallFn = int (__fastcall *)(int, int);
using ThisCallFn = int (__thiscall *)(int, int);
using VectorCallFn = int (__vectorcall *)(int, int);
#else
using StdCallFn = int (*)(int, int);
using FastCallFn = int (*)(int, int);
using ThisCallFn = int (*)(int, int);
using VectorCallFn = int (*)(int, int);
#endif

struct Stub {
    uint64_t address = 0;
};

Stub makeStub(asmjit::JitRuntime& runtime, const std::function<void(asmjit::x86::Assembler&)>& emit) {
    Stub result;
    asmjit::CodeHolder code;
    code.init(runtime.environment());
    asmjit::x86::Assembler assembler(&code);
    emit(assembler);
    void* address = nullptr;
    if (runtime.add(&address, &code) != asmjit::kErrorOk) return result;
    result.address = reinterpret_cast<uint64_t>(address);
    return result;
}

uint64_t makeXmmProbe(asmjit::JitRuntime& runtime, uint64_t callback) {
    return makeStub(runtime, [callback](asmjit::x86::Assembler& a) {
        const bool is64 = asmjit::Environment::host().arch() == asmjit::Arch::kX64;
        a.mov(asmjit::x86::eax, UINT32_C(0x40200000));
        a.movd(asmjit::x86::xmm0, asmjit::x86::eax);
        if (is64) {
            a.sub(asmjit::x86::rsp, 40);
            a.mov(asmjit::x86::r10, callback);
            a.call(asmjit::x86::r10);
            a.add(asmjit::x86::rsp, 40);
        } else {
            a.push(0);
            a.mov(asmjit::x86::eax, static_cast<uint32_t>(callback));
            a.call(asmjit::x86::eax);
            a.add(asmjit::x86::esp, 4);
        }
        if (is64) {
            a.movd(asmjit::x86::eax, asmjit::x86::xmm0);
        } else {
            a.sub(asmjit::x86::esp, 4);
            a.fstp(asmjit::x86::dword_ptr(asmjit::x86::esp));
            a.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(asmjit::x86::esp));
            a.add(asmjit::x86::esp, 4);
        }
        a.ret();
    }).address;
}
uint64_t makeUsercallTarget(asmjit::JitRuntime& runtime) {
    return makeStub(runtime, [](asmjit::x86::Assembler& a) {
        const bool is64 = asmjit::Environment::host().arch() == asmjit::Arch::kX64;
        if (is64) {
            a.pushfq();
            a.pop(asmjit::x86::rax);
            a.and_(asmjit::x86::rax, 0x40);
            a.add(asmjit::x86::rax, asmjit::x86::rcx);
            a.add(asmjit::x86::rax, asmjit::x86::rdx);
            a.add(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rsp, 16));
            a.mov(asmjit::x86::r10, reinterpret_cast<uint64_t>(&g_usercallTargetCalls));
            a.add(asmjit::x86::byte_ptr(asmjit::x86::r10), 1);
            a.ret();
        } else {
            a.pushfd();
            a.pop(asmjit::x86::eax);
            a.and_(asmjit::x86::eax, 0x40);
            a.add(asmjit::x86::eax, asmjit::x86::ecx);
            a.add(asmjit::x86::eax, asmjit::x86::edx);
            a.add(asmjit::x86::eax, asmjit::x86::ptr(asmjit::x86::esp, 8));
            a.mov(asmjit::x86::edx, reinterpret_cast<uint64_t>(&g_usercallTargetCalls));
            a.add(asmjit::x86::byte_ptr(asmjit::x86::edx), 1);
            a.ret(8);
        }
    }).address;
}

uint64_t makePointerTarget(asmjit::JitRuntime& runtime) {
    return makeStub(runtime, [](asmjit::x86::Assembler& a) {
        const bool is64 = asmjit::Environment::host().arch() == asmjit::Arch::kX64;
        if (is64) {
            a.mov(asmjit::x86::r10, reinterpret_cast<uint64_t>(&g_pointerTargetCalls));
            a.add(asmjit::x86::byte_ptr(asmjit::x86::r10), 1);
            a.mov(asmjit::x86::rax, asmjit::x86::rcx);
        } else {
            a.mov(asmjit::x86::edx, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_pointerTargetCalls)));
            a.add(asmjit::x86::byte_ptr(asmjit::x86::edx), 1);
            a.mov(asmjit::x86::eax, asmjit::x86::ecx);
        }
        if (is64) a.ret(); else a.ret(8);
    }).address;
}

// Adds two floats using the mapped argument registers and returns the sum in
// the configured XMM return register.
uint64_t makeXmmUsercallTarget(asmjit::JitRuntime& runtime) {
    return makeStub(runtime, [](asmjit::x86::Assembler& a) {
        a.movaps(asmjit::x86::xmm3, asmjit::x86::xmm1);
        a.addss(asmjit::x86::xmm3, asmjit::x86::xmm2);
        a.movd(asmjit::x86::eax, asmjit::x86::xmm3);
        a.ret();
    }).address;
}
uint64_t makeUsercallCaller(asmjit::JitRuntime& runtime) {
    return makeStub(runtime, [](asmjit::x86::Assembler& a) {
        const bool is64 = asmjit::Environment::host().arch() == asmjit::Arch::kX64;
        if (is64) {
            a.mov(asmjit::x86::r11, asmjit::x86::rcx);
            a.mov(asmjit::x86::r10, asmjit::x86::r9);
            a.mov(asmjit::x86::rcx, asmjit::x86::rdx);
            a.mov(asmjit::x86::rdx, asmjit::x86::r8);
            a.sub(asmjit::x86::rsp, 40);
            a.mov(asmjit::x86::ptr(asmjit::x86::rsp, 8), asmjit::x86::r10);
            a.call(asmjit::x86::r11);
            a.add(asmjit::x86::rsp, 40);
            a.ret();
        } else {
            a.push(asmjit::x86::esi);
            a.mov(asmjit::x86::ecx, asmjit::x86::ptr(asmjit::x86::esp, 12));
            a.mov(asmjit::x86::edx, asmjit::x86::ptr(asmjit::x86::esp, 16));
            a.mov(asmjit::x86::eax, asmjit::x86::ptr(asmjit::x86::esp, 8));
            a.mov(asmjit::x86::esi, asmjit::x86::ptr(asmjit::x86::esp, 20));
            a.push(asmjit::x86::esi);
            a.push(0);
            a.call(asmjit::x86::eax);
            a.pop(asmjit::x86::esi);
            a.ret();
        }
    }).address;
}

int testXmmRegisters() {
    asmjit::JitRuntime runtime;
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    const char* xmmArgumentType = sigilhook_build_mode() == SIGILHOOK_MODE_X64 ? "float" : "int";
    CHECK(sigilhook_create_jit_callback(
        "float", xmmArgumentType, "cdecl", xmmCallback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);
    const uint64_t probe = makeXmmProbe(runtime, callbackAddress);
    CHECK(probe != 0);
    const auto probeFunction = reinterpret_cast<uint32_t (*)()>(probe);
    (void)probeFunction();
    CHECK(g_badXmmFrame == 0);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    return 0;
}
int testBasicJitDetour() {
    CHECK(sigilhook_api_version() >= 0x00020006);
    CHECK(sigilhook_api_version() >= 0x00020009);
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    CHECK(sigilhook_create_jit_callback(
        "int", "int", "cdecl", callback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);
    sigilhook_handle hook{};
    uint64_t trampoline = 0;
    CHECK(sigilhook_create_detour(
        reinterpret_cast<uint64_t>(&target), callbackAddress, &hook, &trampoline) == SIGILHOOK_OK);
    CHECK(sigilhook_bind_detour_to_jit(hook, jit, nullptr) == SIGILHOOK_OK);
    sigilhook_handle secondHook{};
    CHECK(sigilhook_create_detour(
        reinterpret_cast<uint64_t>(&target), callbackAddress, &secondHook, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_bind_detour_to_jit(secondHook, jit, nullptr) == SIGILHOOK_ERROR_BUSY);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_ERROR_BUSY);
    CHECK(sigilhook_destroy(secondHook) == SIGILHOOK_OK);
    CHECK(sigilhook_hook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_get_trampoline(hook, &trampoline) == SIGILHOOK_OK);
    CHECK(trampoline != 0);

    g_testMode = 0;
    CHECK(target(1) == 42);
    CHECK(g_targetCalls == 1);

    g_testMode = 1;
    CHECK(target(1) == 99);
    CHECK(g_targetCalls == 1);

    g_testMode = 2;
    CHECK(target(1) == 42);
    CHECK(g_targetCalls == 2);
    CHECK(g_badArgumentValues == 0);

    g_expectedInstructionPointer = reinterpret_cast<uint64_t>(&target);
    g_redirectAddress = reinterpret_cast<uint64_t>(&redirectTarget);
    g_testMode = 3;
    const int redirectResult = target(1);
    CHECK(redirectResult == 46);
    CHECK(g_targetCalls == 2);
    CHECK(g_redirectTargetCalls == 1);
    CHECK(g_badInstructionPointer == 0);

    CHECK(sigilhook_unhook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    return 0;
}

int testAssemblyHelpers() {
    const std::vector<uint8_t> code(5, 0x90);
    char disassembly[4096]{};
    size_t decoded = 0;
    CHECK(sigilhook_disassemble(reinterpret_cast<uint64_t>(code.data()), 5,
        disassembly, sizeof(disassembly), &decoded) == SIGILHOOK_OK);
    CHECK(decoded == code.size());
    CHECK(std::string(disassembly).find("nop") != std::string::npos);
    CHECK(sigilhook_disassemble(reinterpret_cast<uint64_t>(code.data()), 0,
        disassembly, sizeof(disassembly), &decoded) == SIGILHOOK_ERROR_INVALID_ARGUMENT);

    uint64_t parsed = 0;
    CHECK(sigilhook_parse_hex("0x123AbC", &parsed) == SIGILHOOK_OK);
    CHECK(parsed == 0x123abc);
    CHECK(sigilhook_parse_hex("xyz", &parsed) == SIGILHOOK_ERROR_INVALID_ARGUMENT);

    uint64_t flags = 0;
    CHECK(sigilhook_compute_cmp_flags(1, 2, 4, &flags) == SIGILHOOK_OK);
    CHECK((flags & 0x001) != 0 && (flags & 0x040) == 0);
    CHECK(sigilhook_compute_cmp_flags(7, 7, 4, &flags) == SIGILHOOK_OK);
    CHECK((flags & 0x040) != 0 && (flags & 0x001) == 0);
    CHECK(sigilhook_compute_test_flags(0xf0, 0x0f, 4, &flags) == SIGILHOOK_OK);
    CHECK((flags & 0x040) != 0 && (flags & 0x001) == 0 && (flags & 0x800) == 0);
    CHECK(sigilhook_compute_cmp_flags(1, 2, 3, &flags) == SIGILHOOK_ERROR_INVALID_ARGUMENT);

    alignas(16) std::array<uint8_t, 512> firstState{};
    alignas(16) std::array<uint8_t, 512> secondState{};
    CHECK(sigilhook_fxsave(firstState.data(), firstState.size()) == SIGILHOOK_OK);
    CHECK(sigilhook_fxrstor(firstState.data(), firstState.size()) == SIGILHOOK_OK);
    CHECK(sigilhook_fxsave(secondState.data(), secondState.size()) == SIGILHOOK_OK);
    CHECK(firstState == secondState);
    CHECK(sigilhook_fxsave(firstState.data(), 16) == SIGILHOOK_ERROR_INVALID_ARGUMENT);

    uint64_t returnSnippet = 0;
    uint64_t stackSnippet = 0;
    CHECK(sigilhook_create_return_snippet(4, &returnSnippet) == SIGILHOOK_OK);
    CHECK(returnSnippet != 0);
    CHECK(sigilhook_destroy_snippet(returnSnippet) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy_snippet(returnSnippet) == SIGILHOOK_ERROR_NOT_FOUND);
    const uint64_t pointer = sigilhook_build_mode() == SIGILHOOK_MODE_X64 ? 0x10000 : 0x10000;
    CHECK(sigilhook_create_stack_jump_snippet(pointer, 0x20000, &stackSnippet) == SIGILHOOK_OK);
    CHECK(stackSnippet != 0);
    CHECK(sigilhook_destroy_snippet(stackSnippet) == SIGILHOOK_OK);
    CHECK(sigilhook_create_stack_jump_snippet(0, 0x20000, &stackSnippet) == SIGILHOOK_ERROR_INVALID_ARGUMENT);
    return 0;
}

int testStandardConventions() {
    struct ConventionCase {
        const char* name;
        bool thiscall;
        bool vectorcall;
        bool fastcall;
        bool stdcall;
    } cases[] = {
        {"cdecl", false, false, false, false},
        {"stdcall", false, false, false, true},
        {"fastcall", false, false, true, false},
        {"thiscall", true, false, false, false},
        {"vectorcall", false, true, false, false},
    };

    for (const auto& item : cases) {
        sigilhook_jit_handle jit{};
        uint64_t callbackAddress = 0;
        CHECK(sigilhook_create_jit_callback(
            "int", "int,int", item.name, conventionCallback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);
        int result = 0;
        if (item.thiscall) {
            result = reinterpret_cast<ThisCallFn>(callbackAddress)(7, 9);
        } else if (item.vectorcall) {
            result = reinterpret_cast<VectorCallFn>(callbackAddress)(7, 9);
        } else if (item.fastcall) {
            result = reinterpret_cast<FastCallFn>(callbackAddress)(7, 9);
        } else if (item.stdcall) {
            result = reinterpret_cast<StdCallFn>(callbackAddress)(7, 9);
        } else {
            result = reinterpret_cast<int (SIGILHOOK_CALL *)(int, int)>(callbackAddress)(7, 9);
        }
        CHECK(result == 304);
        CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    }
    CHECK(g_badArgumentValues == 0);
    return 0;
}

int expectJitFailure(const char* convention, sigilhook_status expected) {
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    const sigilhook_status status = sigilhook_create_jit_callback(
        "int", "int,int", convention, invalidMappingCallback, nullptr, &jit, &callbackAddress);
    CHECK(status == expected);
    CHECK(callbackAddress == 0);
    return 0;
}

int testInvalidMappings() {
    CHECK(expectJitFailure("unknown", SIGILHOOK_ERROR_UNSUPPORTED) == 0);
    CHECK(expectJitFailure("usercall:arg0=cx", SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
    CHECK(expectJitFailure("usercall:ret=ax;arg0=cx;arg1=cx", SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
    CHECK(expectJitFailure("usercall:ret=ax;ret=bx;arg0=cx;arg1=dx", SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
    CHECK(expectJitFailure("usercall:arg0=cx;arg1=dx", SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
    CHECK(expectJitFailure("usercall:ret=cx;arg0=cx;arg1=dx", SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
    CHECK(expectJitFailure("usercall:ret=ax;arg0=stack+2", SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
    const char* stackMapping = sigilhook_build_mode() == SIGILHOOK_MODE_X64
        ? "usercall:ret=ax;arg0=stack+16;arg1=stack+16"
        : "usercall:ret=ax;arg0=stack+8;arg1=stack+8";
    CHECK(expectJitFailure(stackMapping, SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
    if (sigilhook_build_mode() == SIGILHOOK_MODE_X64) {
        CHECK(expectJitFailure("usercall:ret=ax;arg0=stack+4;arg1=dx", SIGILHOOK_ERROR_INVALID_ARGUMENT) == 0);
        CHECK(expectJitFailure("usercall:ret=ax;arg0=cx;arg1=dx;cleanup=8", SIGILHOOK_ERROR_ARCH_MISMATCH) == 0);
    } else {
        CHECK(expectJitFailure("usercall:ret=ax;arg0=r8", SIGILHOOK_ERROR_ARCH_MISMATCH) == 0);
        CHECK(expectJitFailure("usercall:ret=ax;arg0=xmm8", SIGILHOOK_ERROR_ARCH_MISMATCH) == 0);
    }
    CHECK(expectJitFailure("usercall:ret=xmm0;arg0=xmm0;arg1=dx", SIGILHOOK_ERROR_UNSUPPORTED) == 0);
    return 0;
}

int testUsercall() {
    asmjit::JitRuntime runtime;
    const uint64_t targetAddress = makeUsercallTarget(runtime);
    const uint64_t callerAddress = makeUsercallCaller(runtime);
    CHECK(targetAddress != 0);
    CHECK(callerAddress != 0);

    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    const char* mapping = sigilhook_build_mode() == SIGILHOOK_MODE_X64
        ? "usercall:ret=rax;arg0=rcx;arg1=rdx;arg2=stack+16"
        : "usercall:ret=eax;arg0=ecx;arg1=edx;arg2=stack+8;cleanup=8";
    CHECK(sigilhook_create_jit_callback(
        "unsigned int", "unsigned int,unsigned int,unsigned int", mapping,
        usercallCallback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);

    const auto directCaller = reinterpret_cast<UsercallCaller>(callerAddress);
    g_usercallMode = 1;
    const unsigned int directResult = directCaller(callbackAddress, 11, 22, 33);
    CHECK(directResult == 0x12345678);
    CHECK(g_usercallTargetCalls == 0);

    sigilhook_handle hook{};
    CHECK(sigilhook_create_detour(targetAddress, callbackAddress, &hook, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_bind_detour_to_jit(hook, jit, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_hook(hook) == SIGILHOOK_OK);

    const auto caller = reinterpret_cast<UsercallCaller>(callerAddress);
    g_usercallTargetCalls = 0;
    g_usercallMode = 1;
    CHECK(caller(targetAddress, 11, 22, 33) == 0x12345678);
    CHECK(g_usercallTargetCalls == 0);

    g_usercallMode = 0;
    CHECK(caller(targetAddress, 11, 22, 33) == 486);
    CHECK(g_usercallTargetCalls == 1);

    g_usercallMode = 2;
    CHECK(caller(targetAddress, 11, 22, 33) == 777);
    CHECK(g_usercallTargetCalls == 2);
    CHECK(g_badUsercallFrame == 0);

    CHECK(sigilhook_unhook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    CHECK(sigilhook_clear_invoker_cache() == SIGILHOOK_OK);
    return 0;
}

int testPointerUsercall() {
    asmjit::JitRuntime runtime;
    const uint64_t targetAddress = makePointerTarget(runtime);
    const uint64_t callerAddress = makeUsercallCaller(runtime);
    CHECK(targetAddress != 0);
    CHECK(callerAddress != 0);
    const char* mapping = sigilhook_build_mode() == SIGILHOOK_MODE_X64
        ? "usercall:ret=rax;arg0=rcx"
        : "usercall:ret=eax;arg0=ecx;cleanup=8";
    const char* pointerTypes[] = {"void*", "Board*", "intptr_t", "uintptr_t"};
    const void* pointerValue = reinterpret_cast<const void*>(static_cast<uintptr_t>(
        sigilhook_build_mode() == SIGILHOOK_MODE_X64 ? 0x123456789abcdu : 0x12345678u));
    for (const char* pointerType : pointerTypes) {
        const uint64_t arguments[] = {reinterpret_cast<uint64_t>(pointerValue)};
        uint64_t result = 0;
        CHECK(sigilhook_invoke_usercall(
            targetAddress, pointerType, pointerType, mapping, arguments, 1, &result) == SIGILHOOK_OK);
        CHECK(result == arguments[0]);
    }

    g_expectedPointer = const_cast<void*>(pointerValue);
    g_pointerTargetCalls = 0;
    g_pointerCallbackCalls = 0;
    g_badPointerFrame = 0;
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    CHECK(sigilhook_create_jit_callback(
        "void*", "void*", mapping, pointerCallback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);
    sigilhook_handle hook{};
    CHECK(sigilhook_create_detour(targetAddress, callbackAddress, &hook, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_bind_detour_to_jit(hook, jit, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_hook(hook) == SIGILHOOK_OK);
    const auto pointerFunction = reinterpret_cast<PointerUsercallCaller>(callerAddress);
    CHECK(pointerFunction(targetAddress, const_cast<void*>(pointerValue), 0, 0) == pointerValue);
    CHECK(g_pointerTargetCalls == 1);
    CHECK(g_pointerCallbackCalls == 1);
    CHECK(g_badPointerFrame == 0);

    CHECK(sigilhook_unhook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    return 0;
}

int testXmmUsercall() {
    asmjit::JitRuntime runtime;
    const uint64_t targetAddress = makeXmmUsercallTarget(runtime);
    CHECK(targetAddress != 0);
    const float argumentValues[] = {1.5f, 2.5f};
    uint64_t arguments[2] = {};
    std::memcpy(&arguments[0], &argumentValues[0], sizeof(float));
    std::memcpy(&arguments[1], &argumentValues[1], sizeof(float));

    // The invoke stub must load XMM arguments for the generated call.
    uint64_t sumBits = 0;
    CHECK(sigilhook_invoke_usercall(
        targetAddress, "unsigned int", "float,float",
        "usercall:ret=eax;arg0=xmm1;arg1=xmm2", arguments, 2, &sumBits) == SIGILHOOK_OK);
    CHECK(static_cast<uint32_t>(sumBits) == 0x40800000); // 4.0f
    return 0;
}
int testStackArgumentRedirect() {
    g_stackTargetCalls = 0;
    g_stackRedirectCalls = 0;
    g_badStackFrame = 0;
    g_stackExpectedInstructionPointer = reinterpret_cast<uint64_t>(&stackTarget);
    g_stackRedirectAddress = reinterpret_cast<uint64_t>(&stackRedirectTarget);
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    CHECK(sigilhook_create_jit_callback(
        "int", "int,int,int,int,int", "cdecl", stackRedirectCallback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);
    sigilhook_handle hook{};
    CHECK(sigilhook_create_detour(
        reinterpret_cast<uint64_t>(&stackTarget), callbackAddress, &hook, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_bind_detour_to_jit(hook, jit, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_hook(hook) == SIGILHOOK_OK);
    CHECK(stackTarget(1, 2, 3, 4, 5) == 105);
    CHECK(g_stackTargetCalls == 0);
    CHECK(g_stackRedirectCalls == 1);
    CHECK(g_badStackFrame == 0);
    CHECK(sigilhook_unhook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    return 0;
}

#if defined(SIGILHOOK_NATIVE_BINDING_TEST)
int testNativeBindingBlob() {
    uint64_t module = 0;
    CHECK(sigilhook_module_load("NativeBindingTestDll.dll", &module) == SIGILHOOK_OK);
    CHECK(module != 0);
    CHECK(sigilhook_module_export(module, "MissingNativeExport", nullptr) == SIGILHOOK_ERROR_INVALID_ARGUMENT);
    uint64_t missing = 0;
    CHECK(sigilhook_module_export(module, "MissingNativeExport", &missing) == SIGILHOOK_ERROR_NOT_FOUND);

    uint64_t addAddress = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeAdd", "cdecl", &addAddress) == SIGILHOOK_OK);
    const char* addSignature = "ret=i,4,4,0,4;args=i,4,4,0,4|i,4,4,4,4";
    int32_t addArguments[2] = {6, 7};
    int32_t addResult = 0;
    CHECK(sigilhook_invoke_native_blob(addAddress, addSignature, addSignature, "cdecl",
        addArguments, sizeof(addArguments), &addResult, sizeof(addResult)) == SIGILHOOK_OK);
    if (addResult != SHNativeAdd(6, 7)) {
        CHECK(false);
    }

    uint64_t scaleAddress = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeScale", "cdecl", &scaleAddress) == SIGILHOOK_OK);
    const char* scaleSignature = "ret=d,8,8,0,8;args=f,4,4,0,4";
    float scaleArgument = 1.5f;
    double scaleResult = 0.0;
    CHECK(sigilhook_invoke_native_blob(scaleAddress, scaleSignature, scaleSignature, "cdecl",
        &scaleArgument, sizeof(scaleArgument), &scaleResult, sizeof(scaleResult)) == SIGILHOOK_OK);
    CHECK(scaleResult == SHNativeScale(scaleArgument));
    const std::string pointerWidth = std::to_string(sizeof(void*));
    const std::string pointerSignature = "ret=p," + pointerWidth + "," + pointerWidth + ",0," + pointerWidth + ";args=p," + pointerWidth + "," + pointerWidth + ",0," + pointerWidth;
    uint64_t pointerAddress = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeEchoPointer", "cdecl", &pointerAddress) == SIGILHOOK_OK);
    const uintptr_t pointerValue = sizeof(void*) == 8 ? UINT64_C(0x123456789abc) : UINT32_C(0x12345678);
    uintptr_t pointerResult = 0;
    CHECK(sigilhook_invoke_native_blob(pointerAddress, pointerSignature.c_str(), pointerSignature.c_str(), "cdecl", &pointerValue, sizeof(pointerValue), &pointerResult, sizeof(pointerResult)) == SIGILHOOK_OK);
    CHECK(pointerResult == pointerValue);

    uint64_t textLengthAddress = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeTextLength", "cdecl", &textLengthAddress) == SIGILHOOK_OK);
    const char* narrowText = "SigilHook";
    const uintptr_t narrowTextPointer = reinterpret_cast<uintptr_t>(narrowText);
    const std::string textSignature = "ret=i,4,4,0,4;args=s," + pointerWidth + "," + pointerWidth + ",0," + pointerWidth;
    int32_t narrowLength = 0;
    CHECK(sigilhook_invoke_native_blob(textLengthAddress, textSignature.c_str(), textSignature.c_str(), "cdecl", &narrowTextPointer, sizeof(narrowTextPointer), &narrowLength, sizeof(narrowLength)) == SIGILHOOK_OK);
    CHECK(narrowLength == 9);

    uint64_t wideLengthAddress = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeWideLength", "cdecl", &wideLengthAddress) == SIGILHOOK_OK);
    const wchar_t* wideText = L"SigilHook";
    const uintptr_t wideTextPointer = reinterpret_cast<uintptr_t>(wideText);
    const std::string wideSignature = "ret=i,4,4,0,4;args=w," + pointerWidth + "," + pointerWidth + ",0," + pointerWidth;
    int32_t wideLength = 0;
    CHECK(sigilhook_invoke_native_blob(wideLengthAddress, wideSignature.c_str(), wideSignature.c_str(), "cdecl", &wideTextPointer, sizeof(wideTextPointer), &wideLength, sizeof(wideLength)) == SIGILHOOK_OK);
    CHECK(wideLength == 9);
    struct ProbeS1 { uint8_t value; } probe1{10}, probe1Result{};
    const char* record1Signature = "ret=r,1,1,0,1;args=r,1,1,0,1";
    uint64_t echo1Address = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeEcho1", "cdecl", &echo1Address) == SIGILHOOK_OK);
    CHECK(sigilhook_invoke_native_blob(echo1Address, record1Signature, record1Signature, "cdecl", &probe1, sizeof(probe1), &probe1Result, sizeof(probe1Result)) == SIGILHOOK_OK);
    CHECK(probe1Result.value == 11);

    struct ProbeS4 { uint32_t value; } probe4{20}, probe4Result{};
    const char* record4Signature = "ret=r,4,4,0,4;args=r,4,4,0,4";
    uint64_t echo4Address = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeEcho4", "cdecl", &echo4Address) == SIGILHOOK_OK);
    CHECK(sigilhook_invoke_native_blob(echo4Address, record4Signature, record4Signature, "cdecl", &probe4, sizeof(probe4), &probe4Result, sizeof(probe4Result)) == SIGILHOOK_OK);
    CHECK(probe4Result.value == 24);

    struct ProbeS8 { uint64_t value; } probe8{30}, probe8Result{};
    const char* record8Signature = "ret=r,8,8,0,8;args=r,8,8,0,8";
    uint64_t echo8Address = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeEcho8", "cdecl", &echo8Address) == SIGILHOOK_OK);
    CHECK(sigilhook_invoke_native_blob(echo8Address, record8Signature, record8Signature, "cdecl", &probe8, sizeof(probe8), &probe8Result, sizeof(probe8Result)) == SIGILHOOK_OK);
    CHECK(probe8Result.value == 38);
    struct ProbeS32 { uint64_t a, b, c, d; } probe32{60, 70, 80, 90}, probe32Result{};
    const char* record32Signature = "ret=r,32,8,0,32;args=r,32,8,0,32";
    uint64_t echo32Address = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeEcho32", "cdecl", &echo32Address) == SIGILHOOK_OK);
    CHECK(sigilhook_invoke_native_blob(echo32Address, record32Signature, record32Signature, "cdecl", &probe32, sizeof(probe32), &probe32Result, sizeof(probe32Result)) == SIGILHOOK_OK);
    CHECK(probe32Result.a == 61 && probe32Result.b == 72 && probe32Result.c == 83 && probe32Result.d == 94);
    uint64_t echo16Address = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeEcho16", "cdecl", &echo16Address) == SIGILHOOK_OK);
    struct ProbeS16 { uint64_t low; uint64_t high; } probe16{40, 50}, probe16Result{};
    const char* record16Signature = "ret=r,16,8,0,16;args=r,16,8,0,16";
    CHECK(sigilhook_invoke_native_blob(echo16Address, record16Signature, record16Signature, "cdecl", &probe16, sizeof(probe16), &probe16Result, sizeof(probe16Result)) == SIGILHOOK_OK);
    CHECK(probe16Result.low == 56 && probe16Result.high == 82);
    SHNativePacked5 probePacked{2, 100}, probePackedResult{};
    uint64_t packedAddress = 0;
    CHECK(sigilhook_native_address("NativeBindingTestDll.dll", "SHNativeEchoPacked", "cdecl", &packedAddress) == SIGILHOOK_OK);
    const char* packedSignature = "ret=r,5,1,0,5;args=r,5,1,0,5";
    CHECK(sigilhook_invoke_native_blob(packedAddress, packedSignature, packedSignature, "cdecl", &probePacked, sizeof(probePacked), &probePackedResult, sizeof(probePackedResult)) == SIGILHOOK_OK);
    CHECK(probePackedResult.tag == 3 && probePackedResult.value == 105);
    const char* conventionNames[] = {"cdecl", "stdcall", "fastcall", "thiscall", "vectorcall"};
    const char* conventionExports[] = {"SHNativeCdeclSum", "SHNativeStdcallSum", "SHNativeFastcallSum", "SHNativeThiscallSum", "SHNativeVectorcallSum"};
    for (size_t conventionIndex = 0; conventionIndex < std::size(conventionNames); ++conventionIndex) {
        uint64_t conventionAddress = 0;
        CHECK(sigilhook_native_address("NativeBindingTestDll.dll", conventionExports[conventionIndex], conventionNames[conventionIndex], &conventionAddress) == SIGILHOOK_OK);
        int32_t conventionArguments[2] = {7, 9};
        int32_t conventionResult = 0;
        const sigilhook_status conventionStatus = sigilhook_invoke_native_blob(conventionAddress, addSignature, addSignature, conventionNames[conventionIndex], conventionArguments, sizeof(conventionArguments), &conventionResult, sizeof(conventionResult));
        if (conventionStatus != SIGILHOOK_OK || conventionResult != 402) {
            CHECK(false);
        }
    }
    CHECK(sigilhook_invoke_native_blob(scaleAddress, scaleSignature, "ret=d,8,8,0,8;args=f,4,4,0,5", "cdecl",
        &scaleArgument, sizeof(scaleArgument), &scaleResult, sizeof(scaleResult)) == SIGILHOOK_ERROR_INVALID_ARGUMENT);
    asmjit::JitRuntime usercallRuntime;
    const uint64_t usercallTarget = makePointerTarget(usercallRuntime);
    CHECK(usercallTarget != 0);
    const char* usercallConvention = sigilhook_build_mode() == SIGILHOOK_MODE_X64
        ? "usercall:ret=rax;arg0=rcx"
        : "usercall:ret=eax;arg0=ecx;cleanup=8";
    const std::string usercallSignature = "ret=p," + pointerWidth + "," + pointerWidth + ",0," + pointerWidth + ";args=p," + pointerWidth + "," + pointerWidth + ",0," + pointerWidth;
    const uintptr_t usercallArgument = pointerValue;
    uintptr_t usercallResult = 0;
    g_pointerTargetCalls = 0;
    CHECK(sigilhook_invoke_native_blob(usercallTarget, usercallSignature.c_str(), usercallSignature.c_str(), usercallConvention, &usercallArgument, sizeof(usercallArgument), &usercallResult, sizeof(usercallResult)) == SIGILHOOK_OK);
    CHECK(usercallResult == usercallArgument);
    CHECK(g_pointerTargetCalls == 1);

#if defined(_WIN32)
    std::filesystem::path oppositePath = std::filesystem::current_path().parent_path();
#if defined(_WIN64)
    oppositePath /= "_build-x86/NativeBindingTestDll.dll";
#else
    oppositePath /= "_build-x64/NativeBindingTestDll.dll";
#endif
    const std::string oppositeNarrow = oppositePath.string();
    uint64_t mismatchedModule = 0;
    const sigilhook_status mismatchStatus = sigilhook_module_load(oppositeNarrow.c_str(), &mismatchedModule);
    CHECK(mismatchStatus == SIGILHOOK_ERROR_ARCH_MISMATCH || mismatchStatus == SIGILHOOK_ERROR_NOT_FOUND);
#endif

    CHECK(sigilhook_module_free(module) == SIGILHOOK_OK);
    uint64_t missingModule = 0;
    CHECK(sigilhook_module_load("DefinitelyMissingSigilHookTest.dll", &missingModule) == SIGILHOOK_ERROR_NOT_FOUND);
    return 0;
}
#endif

} // namespace

int testRuntimeReloadContract() {
    CHECK(sigilhook_runtime_reload() == SIGILHOOK_ERROR_NOT_FOUND);
    CHECK(sigilhook_runtime_reload_with_timeout(100) == SIGILHOOK_ERROR_NOT_FOUND);
    return 0;
}

int main() {
    sigilhook_set_log_callback(printLog, nullptr);
    CHECK(testBasicJitDetour() == 0);
    CHECK(testXmmRegisters() == 0);
    CHECK(testStackArgumentRedirect() == 0);
    CHECK(testAssemblyHelpers() == 0);
    CHECK(testStandardConventions() == 0);
    CHECK(testInvalidMappings() == 0);
    CHECK(testUsercall() == 0);
    CHECK(testXmmUsercall() == 0);
    CHECK(testPointerUsercall() == 0);
    CHECK(testRuntimeReloadContract() == 0);
#if defined(SIGILHOOK_NATIVE_BINDING_TEST)
    CHECK(testNativeBindingBlob() == 0);
#endif
    return 0;
}
