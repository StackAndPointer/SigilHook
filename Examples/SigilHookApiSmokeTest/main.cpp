// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#include <asmjit/core.h>
#include <asmjit/x86.h>

#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression << " at line " << __LINE__ << '\n'; char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); std::cerr << error << '\n'; return __LINE__; } } while (false)

namespace {

int g_testMode = 0;
volatile int g_targetCalls = 0;
volatile int g_badArgumentValues = 0;
int g_usercallMode = 0;
volatile int g_usercallTargetCalls = 0;
int g_badUsercallFrame = 0;

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

using UsercallCaller = unsigned int (SIGILHOOK_CALL *)(uintptr_t, unsigned int, unsigned int, unsigned int);
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

int testBasicJitDetour() {
    CHECK(sigilhook_api_version() >= 0x00020004);
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

    CHECK(sigilhook_unhook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
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
    }
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
    return 0;
}

} // namespace

int main() {
    CHECK(testBasicJitDetour() == 0);
    CHECK(testStandardConventions() == 0);
    CHECK(testInvalidMappings() == 0);
    CHECK(testUsercall() == 0);
    return 0;
}
