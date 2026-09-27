// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#if defined(SIGILHOOK_NATIVE_BINDING_TEST)
#include "NativeBindingTest.h"
#endif

#include <Windows.h>
#include <asmjit/core.h>
#include <asmjit/x86.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
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
#elif defined(_MSC_VER)
#define TEST_THISCALL
using StdCallFn = int (*)(int, int);
using FastCallFn = int (*)(int, int);
using ThisCallFn = int (*)(int, int);
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
volatile LONG g_midTargetCalls = 0;
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
volatile LONG g_slowResult = 0;

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

NOINLINE float floatTarget(float value) {
    return value + 1.0f;
}

NOINLINE int SIGILHOOK_CALL midTarget(int value) {
    ++g_midTargetCalls;
    return value + 7;
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

DWORD WINAPI slowWorker(LPVOID) {
    g_slowResult = target(1);
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

bool writeScriptFile(const std::filesystem::path& path, const std::string& source) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output) return false;
    output << source;
    return output.good();
}

bool copyStandardHeader(const std::filesystem::path& directory) {
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error) return false;
    std::filesystem::copy_file(
        std::filesystem::path(SIGILHOOK_TEST_SCRIPT_DIRECTORY) / "SigilHook.ash",
        directory / "SigilHook.ash",
        std::filesystem::copy_options::overwrite_existing,
        error);
    return !error;
}

bool expectScriptLoadFailure(const std::filesystem::path& directory, const char* label) {
    const sigilhook_status status = sigilhook_runtime_load_directory(directory.c_str());
    if (status == SIGILHOOK_ERROR_SCRIPT) return true;
    std::cerr << label << " returned status " << static_cast<int>(status) << '\n';
    return false;
}

} // namespace

int main() {
    const std::filesystem::path configuredScriptDirectory = SIGILHOOK_TEST_SCRIPT_DIRECTORY;
    const std::filesystem::path scriptDirectory = std::filesystem::temp_directory_path() /
        ("SigilHookScriptSmokeTestScripts-" + std::to_string(GetCurrentProcessId()));
    std::error_code scriptCopyError;
    std::filesystem::remove_all(scriptDirectory, scriptCopyError);
    scriptCopyError.clear();
    std::filesystem::copy(configuredScriptDirectory, scriptDirectory,
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
        scriptCopyError);
    CHECK(!scriptCopyError);
    std::filesystem::remove_all(scriptDirectory / "logs", scriptCopyError);
    CHECK(!scriptCopyError);
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

#if defined(SIGILHOOK_NATIVE_BINDING_TEST)
    CHECK(SHNativeAdd(6, 7) == 13);
    CHECK(SHNativeScale(1.5f) == 4.5);
    CHECK(SHNativeTextLength("SigilHook") == 9);
    CHECK(SHNativeWideLength(L"SigilHook") == 9);
    CHECK(SHNativeEchoPointer(reinterpret_cast<void*>(static_cast<uintptr_t>(0x1234))) ==
        reinterpret_cast<void*>(static_cast<uintptr_t>(0x1234)));
    CHECK(SHNativeCdeclSum(7, 9) == 402);
    CHECK(reinterpret_cast<StdCallFn>(&SHNativeStdcallSum)(7, 9) == 402);
    CHECK(reinterpret_cast<FastCallFn>(&SHNativeFastcallSum)(7, 9) == 402);
    CHECK(reinterpret_cast<ThisCallFn>(&SHNativeThiscallSum)(7, 9) == 402);
    CHECK(SHNativeVectorcallSum(7, 9) == 402);
    SHNativeS1 s1{10};
    SHNativeS4 s4{20};
    SHNativeS8 s8{30};
    SHNativeS16 s16{40, 50};
    SHNativeS32 s32{60, 70, 80, 90};
    SHNativePacked5 packed{2, 100};
    CHECK(SHNativeEcho1(s1).value == 11);
    CHECK(SHNativeEcho4(s4).value == 24);
    CHECK(SHNativeEcho8(s8).value == 38);
    const SHNativeS16 s16Result = SHNativeEcho16(s16);
    CHECK(s16Result.low == 56 && s16Result.high == 82);
    const SHNativeS32 s32Result = SHNativeEcho32(s32);
    CHECK(s32Result.a == 61 && s32Result.b == 72 && s32Result.c == 83 && s32Result.d == 94);
    const SHNativePacked5 packedResult = SHNativeEchoPacked(packed);
    CHECK(packedResult.tag == 3 && packedResult.value == 105);
#endif

    DWORD hardwareThreadId = 0;
    HANDLE hardwareThread = CreateThread(nullptr, 0, hardwareWorker, nullptr, CREATE_SUSPENDED, &hardwareThreadId);
    CHECK(hardwareThread != nullptr);

    CHECK(sigilhook_runtime_start(nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("target", reinterpret_cast<uint64_t>(&target)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("floatTarget", reinterpret_cast<uint64_t>(&floatTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("midTarget", reinterpret_cast<uint64_t>(&midTarget)) == SIGILHOOK_OK);
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
    CHECK(sigilhook_runtime_set_shared_u64("nativeBindingPointer", 0x1234) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("nativeBindingBad", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("conventionCallbackCalls", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_load_directory(scriptDirectory.c_str()) == SIGILHOOK_OK);
    uint64_t mainEntryCount = 0;
    CHECK(sigilhook_runtime_get_shared_u64("mainEntryCount", &mainEntryCount) == SIGILHOOK_OK);
    CHECK(mainEntryCount == 1);
    CHECK(sigilhook_runtime_call_entry("void verify()") == SIGILHOOK_OK);

    uint64_t scriptBad = 0;
    CHECK(sigilhook_runtime_get_shared_u64("scriptBad", &scriptBad) == SIGILHOOK_OK);
    if (scriptBad != 0) {
        std::cerr << "helper failure step: " << scriptBad << std::endl;
        std::ifstream runtimeLog(scriptDirectory / "logs" / "SigilHook.log");
        if (runtimeLog) std::cerr << runtimeLog.rdbuf() << std::endl;
        uint64_t invokeStatus = 0;
        uint64_t invokeResult = 0;
        sigilhook_runtime_get_shared_u64("invokeStatus", &invokeStatus);
        sigilhook_runtime_get_shared_u64("invokeResult", &invokeResult);
        std::cerr << "invoke status: " << invokeStatus << ", result: " << invokeResult << std::endl;
    }
    CHECK(scriptBad == 0);
    uint64_t nativeBindingBad = 0;
    CHECK(sigilhook_runtime_get_shared_u64("nativeBindingBad", &nativeBindingBad) == SIGILHOOK_OK);
    CHECK(nativeBindingBad == 0);
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
    const float floatResult = floatTarget(1.5f);
    CHECK(floatResult == 4.5f);
    CHECK(midTarget(35) == 42);
    CHECK(g_midTargetCalls == 1);
    g_conventionTargetCalls = 0;
    std::cerr << "calling stdcall" << std::endl;
    CHECK(reinterpret_cast<StdCallFn>(&stdcallTarget)(7, 9) == 402);
    if (g_conventionTargetCalls != 0) std::cerr << "after stdcall: " << g_conventionTargetCalls << '\n';
    std::cerr << "after stdcall value: " << g_conventionTargetCalls << std::endl;
    uint64_t conventionCallbackCalls = 0;
    std::cerr << "calling fastcall" << std::endl;
    CHECK(reinterpret_cast<FastCallFn>(&fastcallTarget)(7, 9) == 402);
    if (g_conventionTargetCalls != 0) std::cerr << "after fastcall: " << g_conventionTargetCalls << '\n';
    std::cerr << "after fastcall value: " << g_conventionTargetCalls << std::endl;
    sigilhook_runtime_get_shared_u64("conventionCallbackCalls", &conventionCallbackCalls);
    std::cerr << "callbacks after fastcall: " << conventionCallbackCalls << std::endl;
    std::cerr << "calling thiscall" << std::endl;
    const auto thiscallAddress = memberFunctionAddress(&ThisCallTarget::target);
    std::cerr << "thiscall address=0x" << std::hex << thiscallAddress << " byte=" << static_cast<unsigned>(*reinterpret_cast<const unsigned char*>(thiscallAddress)) << std::dec << std::endl;
    CHECK(reinterpret_cast<ThisCallFn>(memberFunctionAddress(&ThisCallTarget::target))(7, 9) == 402);
    if (g_conventionTargetCalls != 0) std::cerr << "after thiscall: " << g_conventionTargetCalls << '\n';
    std::cerr << "after thiscall value: " << g_conventionTargetCalls << std::endl;
    sigilhook_runtime_get_shared_u64("conventionCallbackCalls", &conventionCallbackCalls);
    std::cerr << "callbacks after thiscall: " << conventionCallbackCalls << std::endl;
    std::cerr << "calling vectorcall" << std::endl;
    const auto vectorcallAddress = reinterpret_cast<uint64_t>(&vectorcallTarget);
    std::cerr << "vectorcall address=0x" << std::hex << vectorcallAddress << " byte=" << static_cast<unsigned>(*reinterpret_cast<const unsigned char*>(vectorcallAddress)) << std::dec << std::endl;
    CHECK(reinterpret_cast<VectorCallFn>(&vectorcallTarget)(7, 9) == 402);
    if (g_conventionTargetCalls != 0) std::cerr << "after vectorcall: " << g_conventionTargetCalls << '\n';
    std::cerr << "after vectorcall value: " << g_conventionTargetCalls << std::endl;
    sigilhook_runtime_get_shared_u64("conventionCallbackCalls", &conventionCallbackCalls);
    std::cerr << "callbacks after vectorcall: " << conventionCallbackCalls << std::endl;
    std::cerr << "calling cdecl" << std::endl;
    CHECK(reinterpret_cast<int (SIGILHOOK_CALL *)(int, int)>(reinterpret_cast<uint64_t>(&cdeclTarget))(7, 9) == 402);
    if (g_conventionTargetCalls != 0) std::cerr << "after cdecl: " << g_conventionTargetCalls << '\n';
    std::cerr << "after cdecl value: " << g_conventionTargetCalls << std::endl;
    std::cerr << "convention target calls final: " << g_conventionTargetCalls << std::endl;
    if (g_conventionTargetCalls != 0) {
        std::ifstream runtimeLog(scriptDirectory / "logs" / "SigilHook.log");
        if (runtimeLog) std::cerr << runtimeLog.rdbuf() << std::endl;
    }
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
    uint64_t unloadCount = 0;
    CHECK(sigilhook_runtime_get_shared_u64("unloadCount", &unloadCount) == SIGILHOOK_OK);
    CHECK(unloadCount == 1);

    const std::filesystem::path negativeRoot = std::filesystem::temp_directory_path() /
        ("SigilHookScriptSmoke-" + std::to_string(GetCurrentProcessId()));
    std::error_code cleanupError;
    std::filesystem::remove_all(negativeRoot, cleanupError);
    cleanupError.clear();
    CHECK(std::filesystem::create_directories(negativeRoot, cleanupError) && !cleanupError);

    const auto rollbackRoot = negativeRoot / "rollback";
    CHECK(copyStandardHeader(rollbackRoot));
    CHECK(sigilhook_runtime_set_shared_u64("rollbackZero", 0) == SIGILHOOK_OK);
    CHECK(writeScriptFile(rollbackRoot / "main.as", R"SIGIL(
#include "SigilHook.ash"

void rollbackCallback() {
    shSetReturn(999);
    shSkipOriginal();
}

void main() {
    if (!shIsValidHook(shHookScript(shSharedU64("target"), "void rollbackCallback()", "int:int"))) {
        shSetSharedU64("rollbackHookFailed", 1);
        return;
    }
    const uint64 zero = shSharedU64("rollbackZero");
    const uint64 failure = 1 / zero;
}

void unload() {
    shSetSharedU64("rollbackUnloadCount", shSharedU64("rollbackUnloadCount") + 1);
}
)SIGIL" ));
    CHECK(expectScriptLoadFailure(rollbackRoot, "main rollback"));
    uint64_t rollbackUnloadCount = 0;
    CHECK(sigilhook_runtime_get_shared_u64("rollbackUnloadCount", &rollbackUnloadCount) == SIGILHOOK_OK);
    CHECK(rollbackUnloadCount == 1);
    uint64_t rollbackHookFailed = 0;
    CHECK(sigilhook_runtime_get_shared_u64("rollbackHookFailed", &rollbackHookFailed) == SIGILHOOK_ERROR_NOT_FOUND);
    CHECK(target(7) == 8);

    const auto timeoutRoot = negativeRoot / "callback-timeout";
    CHECK(copyStandardHeader(timeoutRoot));
    CHECK(sigilhook_runtime_set_shared_u64("slowEntered", 0) == SIGILHOOK_OK);
    CHECK(writeScriptFile(timeoutRoot / "main.as", R"SIGIL(
#include "SigilHook.ash"

void slowCallback() {
    shSetSharedU64("slowEntered", 1);
    while (true) {}
}

void main() {
    if (!shIsValidHook(shHookScript(shSharedU64("target"), "void slowCallback()", "int:int"))) {
        shSetSharedU64("slowHookFailed", 1);
    }
}

void unload() {
    shSetSharedU64("slowUnloaded", 1);
}
)SIGIL" ));
    CHECK(sigilhook_runtime_load_directory(timeoutRoot.c_str()) == SIGILHOOK_OK);
    HANDLE slowThread = CreateThread(nullptr, 0, slowWorker, nullptr, 0, nullptr);
    CHECK(slowThread != nullptr);
    bool slowEntered = false;
    for (int attempt = 0; attempt < 100 && !slowEntered; ++attempt) {
        uint64_t entered = 0;
        CHECK(sigilhook_runtime_get_shared_u64("slowEntered", &entered) == SIGILHOOK_OK);
        slowEntered = entered != 0;
        if (!slowEntered) Sleep(10);
    }
    CHECK(slowEntered);
    CHECK(sigilhook_runtime_stop_with_timeout(100) == SIGILHOOK_OK);
    CHECK(WaitForSingleObject(slowThread, 5000) == WAIT_OBJECT_0);
    CHECK(g_slowResult == 2);
    uint64_t slowUnloaded = 0;
    CHECK(sigilhook_runtime_get_shared_u64("slowUnloaded", &slowUnloaded) == SIGILHOOK_OK);
    CHECK(slowUnloaded == 1);
    CloseHandle(slowThread);

    const auto missingMain = negativeRoot / "missing-main";
    CHECK(writeScriptFile(missingMain / "legacy.as", "void legacy() {}\n"));
    CHECK(expectScriptLoadFailure(missingMain, "missing main.as"));

    const auto missingEntry = negativeRoot / "missing-entry";
    CHECK(writeScriptFile(missingEntry / "main.as", "void helper() {}\n"));
    CHECK(expectScriptLoadFailure(missingEntry, "missing void main()"));

    const auto foreignEntry = negativeRoot / "foreign-entry";
    CHECK(writeScriptFile(foreignEntry / "main.as", "void helper() {}\n"));
    CHECK(writeScriptFile(foreignEntry / "other.as", "void main() {}\n"));
    CHECK(expectScriptLoadFailure(foreignEntry, "main outside main.as"));

    const auto duplicateEntry = negativeRoot / "duplicate-entry";
    CHECK(writeScriptFile(duplicateEntry / "main.as", "void main() {}\n"));
    CHECK(writeScriptFile(duplicateEntry / "duplicate.as", "void main() {}\n"));
    CHECK(expectScriptLoadFailure(duplicateEntry, "duplicate main"));

    const auto cyclicInclude = negativeRoot / "cyclic-include";
    CHECK(writeScriptFile(cyclicInclude / "main.as", "#include \"a.ash\"\nvoid main() {}\n"));
    CHECK(writeScriptFile(cyclicInclude / "a.ash", "#include \"b.ash\"\n"));
    CHECK(writeScriptFile(cyclicInclude / "b.ash", "#include \"a.ash\"\n"));
    CHECK(expectScriptLoadFailure(cyclicInclude, "cyclic include"));

    const auto missingInclude = negativeRoot / "missing-include";
    CHECK(writeScriptFile(missingInclude / "main.as", "#include \"not-found.ash\"\nvoid main() {}\n"));
    CHECK(expectScriptLoadFailure(missingInclude, "missing include"));

    CHECK(sigilhook_runtime_stop() == SIGILHOOK_OK);
    std::filesystem::remove_all(negativeRoot, cleanupError);
    CHECK(!cleanupError);
    CloseHandle(hardwareThread);
    return 0;
}
