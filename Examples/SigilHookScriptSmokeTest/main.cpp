// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#include <Windows.h>
#include <asmjit/core.h>
#include <asmjit/x86.h>

#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression " at line " << __LINE__ << '\n'; char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); std::cerr << error << '\n'; sigilhook_runtime_stop(); return __LINE__; } } while (false)

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif

#if defined(_MSC_VER) && defined(_M_IX86)
#define TEST_THISCALL __thiscall
using StdCallFn = int (__stdcall *)(int, int);
using FastCallFn = int (__fastcall *)(int, int);
using ThisCallFn = int (__thiscall *)(int, int);
using VectorCallFn = int (__vectorcall *)(int, int);
#else
#define TEST_THISCALL
using StdCallFn = int (*)(int, int);
using FastCallFn = int (*)(int, int);
using ThisCallFn = int (*)(int, int);
using VectorCallFn = int (*)(int, int);
#endif

namespace {

volatile LONG g_targetCalls = 0;
volatile LONG g_conventionTargetCalls = 0;
volatile LONG g_usercallTargetCalls = 0;
volatile LONG g_pointerTargetCalls = 0;
volatile LONG g_nativeTargetCalls = 0;
volatile LONG g_breakpointTargetCalls = 0;
volatile LONG g_breakpointCallbackCalls = 0;
volatile LONG g_hardwareTargetCalls = 0;
volatile LONG g_hardwareCallbackCalls = 0;
volatile LONG g_iatCallbackCalls = 0;
volatile LONG g_eatTargetCalls = 0;
volatile LONG g_eatCallbackCalls = 0;
volatile LONG g_virtualTargetCalls = 0;
volatile LONG g_vfuncCallbackCalls = 0;
volatile LONG g_vtableCallbackCalls = 0;
volatile LONG g_hardwareResult = 0;

struct ThisCallTarget {
    NOINLINE int TEST_THISCALL target(int) {
        ++g_conventionTargetCalls;
        return 402;
    }
};

struct VirtualObject {
    NOINLINE virtual int SIGILHOOK_CALL value() {
        ++g_virtualTargetCalls;
        return 12;
    }
};

VirtualObject g_vfuncObject;
VirtualObject g_vtableObject;

NOINLINE int SIGILHOOK_CALL target(int value) {
    volatile int result = value;
    for (int index = 0; index < 8; ++index) result += index - index;
    ++g_targetCalls;
    return result + 1;
}

NOINLINE int SIGILHOOK_CALL cdeclTarget(int left, int right) {
    ++g_conventionTargetCalls;
    return left * 100 + right;
}

NOINLINE int __stdcall stdcallTarget(int left, int right) {
    ++g_conventionTargetCalls;
    return left * 100 + right;
}

NOINLINE int __fastcall fastcallTarget(int left, int right) {
    ++g_conventionTargetCalls;
    return left * 100 + right;
}

NOINLINE int __vectorcall vectorcallTarget(int left, int right) {
    ++g_conventionTargetCalls;
    return left * 100 + right;
}

NOINLINE int SIGILHOOK_CALL nativeTarget(int value) {
    ++g_nativeTargetCalls;
    return value + 100;
}

NOINLINE int SIGILHOOK_CALL nativeCallback(int) { return 456; }

NOINLINE int SIGILHOOK_CALL breakpointTarget(int value) {
    ++g_breakpointTargetCalls;
    return value + 100;
}

NOINLINE int SIGILHOOK_CALL breakpointCallback(int) {
    ++g_breakpointCallbackCalls;
    return 654;
}

NOINLINE int SIGILHOOK_CALL hardwareTarget(int value) {
    ++g_hardwareTargetCalls;
    return value + 100;
}

NOINLINE int SIGILHOOK_CALL hardwareCallback(int) {
    ++g_hardwareCallbackCalls;
    return 888;
}

NOINLINE DWORD WINAPI iatCallback() {
    ++g_iatCallbackCalls;
    return 0x12345678;
}

extern "C" __declspec(dllexport) NOINLINE int SIGILHOOK_CALL eatTestExport() {
    ++g_eatTargetCalls;
    return 11;
}

NOINLINE int SIGILHOOK_CALL eatCallback() {
    ++g_eatCallbackCalls;
    return 909;
}

NOINLINE int SIGILHOOK_CALL vfuncCallback() {
    ++g_vfuncCallbackCalls;
    return 202;
}

NOINLINE int SIGILHOOK_CALL vtableCallback() {
    ++g_vtableCallbackCalls;
    return 303;
}

DWORD WINAPI hardwareWorker(LPVOID) {
    g_hardwareResult = hardwareTarget(3);
    return 0;
}

template <typename T>
uint64_t memberFunctionAddress(T member) {
    uint64_t address = 0;
    std::memcpy(&address, &member, sizeof(member));
    return address;
}

using UsercallCaller = unsigned int (SIGILHOOK_CALL *)(uintptr_t, unsigned int, unsigned int, unsigned int);
using PointerUsercallCaller = void* (SIGILHOOK_CALL *)(uintptr_t, void*, unsigned int, unsigned int);

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
    if (runtime.add(&address, &code) == asmjit::kErrorOk) {
        result.address = reinterpret_cast<uint64_t>(address);
    }
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

} // namespace

int main() {
    asmjit::JitRuntime runtime;
    const uint64_t usercallTarget = makeUsercallTarget(runtime);
    const uint64_t pointerTarget = makePointerTarget(runtime);
    const uint64_t pointerCaller = makeUsercallCaller(runtime);
    const uint64_t usercallCaller = makeUsercallCaller(runtime);
    const Stub memoryStub = makeStub(runtime, [](asmjit::x86::Assembler& a) { a.ret(); });
    CHECK(usercallTarget != 0);
    CHECK(pointerTarget != 0);
    CHECK(pointerCaller != 0);
    CHECK(usercallCaller != 0);
    CHECK(memoryStub.address != 0);

    DWORD hardwareThreadId = 0;
    HANDLE hardwareThread = CreateThread(nullptr, 0, hardwareWorker, nullptr, CREATE_SUSPENDED, &hardwareThreadId);
    CHECK(hardwareThread != nullptr);

    CHECK(sigilhook_runtime_start(nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("target", reinterpret_cast<uint64_t>(&target)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("cdeclTarget", reinterpret_cast<uint64_t>(&cdeclTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("stdcallTarget", reinterpret_cast<uint64_t>(&stdcallTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("fastcallTarget", reinterpret_cast<uint64_t>(&fastcallTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("thiscallTarget", memberFunctionAddress(&ThisCallTarget::target)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("vectorcallTarget", reinterpret_cast<uint64_t>(&vectorcallTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("usercallTarget", usercallTarget) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("pointerTarget", pointerTarget) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("pointerScriptCallbacks", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("pointerExpected", static_cast<uintptr_t>(
        sizeof(void*) == 8 ? 0x123456789abcdu : 0x12345678u)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("scriptBad", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("nativeTarget", reinterpret_cast<uint64_t>(&nativeTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("nativeCallback", reinterpret_cast<uint64_t>(&nativeCallback)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("breakpointTarget", reinterpret_cast<uint64_t>(&breakpointTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("breakpointCallback", reinterpret_cast<uint64_t>(&breakpointCallback)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("hardwareTarget", reinterpret_cast<uint64_t>(&hardwareTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("hardwareCallback", reinterpret_cast<uint64_t>(&hardwareCallback)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("hardwareThread", reinterpret_cast<uint64_t>(hardwareThread)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("iatCallback", reinterpret_cast<uint64_t>(&iatCallback)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("eatCallback", reinterpret_cast<uint64_t>(&eatCallback)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("vfuncObject", reinterpret_cast<uint64_t>(&g_vfuncObject)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("vtableObject", reinterpret_cast<uint64_t>(&g_vtableObject)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("vfuncCallback", reinterpret_cast<uint64_t>(&vfuncCallback)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("vtableCallback", reinterpret_cast<uint64_t>(&vtableCallback)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("helperValueAddress", memoryStub.address + 8) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("expectedBuildMode", sizeof(void*) == 8 ? 2 : 1) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_load_directory(SIGILHOOK_TEST_SCRIPT_DIRECTORY) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_call_entry("void verify()") == SIGILHOOK_OK);

    uint64_t scriptBad = 0;
    CHECK(sigilhook_runtime_get_shared_u64("scriptBad", &scriptBad) == SIGILHOOK_OK);
    if (scriptBad != 0) {
        std::cerr << "helper failure step: " << scriptBad << std::endl;
        uint64_t invokeStatus = 0;
        uint64_t invokeResult = 0;
        sigilhook_runtime_get_shared_u64("invokeStatus", &invokeStatus);
        sigilhook_runtime_get_shared_u64("invokeResult", &invokeResult);
        std::cerr << "invoke status: " << invokeStatus << ", result: " << invokeResult << std::endl;
    }
    CHECK(scriptBad == 0);
    CHECK(g_usercallTargetCalls == 1);
    g_usercallTargetCalls = 0;
    CHECK(g_pointerTargetCalls == 1);
    g_pointerTargetCalls = 0;
    const auto pointerFunction = reinterpret_cast<PointerUsercallCaller>(pointerCaller);
    void* pointerValue = reinterpret_cast<void*>(static_cast<uintptr_t>(
        sizeof(void*) == 8 ? 0x123456789abcdu : 0x12345678u));
    CHECK(pointerFunction(pointerTarget, pointerValue, 0, 0) == pointerValue);
    CHECK(g_pointerTargetCalls == 1);
    uint64_t pointerScriptCallbacks = 0;
    CHECK(sigilhook_runtime_get_shared_u64("pointerScriptCallbacks", &pointerScriptCallbacks) == SIGILHOOK_OK);
    CHECK(pointerScriptCallbacks == 1);

    CHECK(target(1) == 42);
    CHECK(g_targetCalls == 1);
    CHECK(reinterpret_cast<StdCallFn>(&stdcallTarget)(7, 9) == 402);
    CHECK(reinterpret_cast<FastCallFn>(&fastcallTarget)(7, 9) == 402);
    CHECK(reinterpret_cast<ThisCallFn>(memberFunctionAddress(&ThisCallTarget::target))(7, 9) == 402);
    CHECK(reinterpret_cast<VectorCallFn>(&vectorcallTarget)(7, 9) == 402);
    CHECK(reinterpret_cast<int (SIGILHOOK_CALL *)(int, int)>(reinterpret_cast<uint64_t>(&cdeclTarget))(7, 9) == 402);
    CHECK(g_conventionTargetCalls == 0);

    const auto invoke = reinterpret_cast<UsercallCaller>(usercallCaller);
    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 0) == SIGILHOOK_OK);
    CHECK(invoke(static_cast<uintptr_t>(usercallTarget), 11, 22, 33) == 441);
    CHECK(g_usercallTargetCalls == 1);
    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 1) == SIGILHOOK_OK);
    CHECK(invoke(static_cast<uintptr_t>(usercallTarget), 11, 22, 33) == 0x12345678);
    CHECK(g_usercallTargetCalls == 1);
    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 2) == SIGILHOOK_OK);
    CHECK(invoke(static_cast<uintptr_t>(usercallTarget), 11, 22, 33) == 777);
    CHECK(g_usercallTargetCalls == 2);

    CHECK(nativeTarget(5) == 456);
    CHECK(g_nativeTargetCalls == 0);
    CHECK(breakpointTarget(2) == 654);
    CHECK(g_breakpointTargetCalls == 0);
    CHECK(g_breakpointCallbackCalls == 1);

    using GetCurrentThreadIdFn = DWORD (WINAPI *)();
    CHECK(reinterpret_cast<GetCurrentThreadIdFn>(&GetCurrentThreadId)() == 0x12345678);
    CHECK(g_iatCallbackCalls == 1);

    using EatExportFn = int (SIGILHOOK_CALL *)();
    const auto eatExport = reinterpret_cast<EatExportFn>(GetProcAddress(GetModuleHandle(nullptr), "eatTestExport"));
    CHECK(eatExport != nullptr);
    CHECK(eatExport() == 909);
    CHECK(g_eatTargetCalls == 0);
    CHECK(g_eatCallbackCalls == 1);

    VirtualObject* volatile vfuncObject = &g_vfuncObject;
    VirtualObject* volatile vtableObject = &g_vtableObject;
    CHECK(vfuncObject->value() == 202);
    CHECK(vtableObject->value() == 303);
    CHECK(g_virtualTargetCalls == 0);
    CHECK(g_vfuncCallbackCalls == 1);
    CHECK(g_vtableCallbackCalls == 1);

    CHECK(ResumeThread(hardwareThread) != static_cast<DWORD>(-1));
    CHECK(WaitForSingleObject(hardwareThread, 5000) == WAIT_OBJECT_0);
    CHECK(g_hardwareResult == 888);
    CHECK(g_hardwareTargetCalls == 0);
    CHECK(g_hardwareCallbackCalls == 1);

    CHECK(sigilhook_runtime_get_shared_u64("scriptBad", &scriptBad) == SIGILHOOK_OK);
    CHECK(scriptBad == 0);
    CHECK(sigilhook_runtime_stop() == SIGILHOOK_OK);
    CloseHandle(hardwareThread);
    return 0;
}
