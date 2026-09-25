// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#include <asmjit/core.h>
#include <asmjit/x86.h>

#include <cstdint>
#include <functional>
#include <iostream>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression << " at line " << __LINE__ << '\n'; char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); std::cerr << error << '\n'; return __LINE__; } } while (false)

namespace {

volatile int g_targetCalls = 0;
volatile int g_usercallTargetCalls = 0;

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

using UsercallCaller = unsigned int (SIGILHOOK_CALL *)(uintptr_t, unsigned int, unsigned int, unsigned int);

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

} // namespace

int main() {
    asmjit::JitRuntime runtime;
    const uint64_t usercallTarget = makeUsercallTarget(runtime);
    const uint64_t usercallCaller = makeUsercallCaller(runtime);
    CHECK(usercallTarget != 0);
    CHECK(usercallCaller != 0);

    CHECK(sigilhook_runtime_start(nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64(
        "target", reinterpret_cast<uint64_t>(&target)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("usercallTarget", usercallTarget) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("usercallBad", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("scriptBad", 0) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_load_directory(SIGILHOOK_TEST_SCRIPT_DIRECTORY) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_call_entry("void verify()") == SIGILHOOK_OK);

    CHECK(target(1) == 77);
    CHECK(g_targetCalls == 0);

    const auto invoke = reinterpret_cast<UsercallCaller>(usercallCaller);
    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 0) == SIGILHOOK_OK);
    const unsigned int forwardResult = invoke(static_cast<uintptr_t>(usercallTarget), 11, 22, 33);
    CHECK(forwardResult == 441);
    CHECK(g_usercallTargetCalls == 1);

    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 1) == SIGILHOOK_OK);
    CHECK(invoke(static_cast<uintptr_t>(usercallTarget), 11, 22, 33) == 0x12345678);
    CHECK(g_usercallTargetCalls == 1);

    CHECK(sigilhook_runtime_set_shared_u64("usercallMode", 2) == SIGILHOOK_OK);
    CHECK(invoke(static_cast<uintptr_t>(usercallTarget), 11, 22, 33) == 777);
    CHECK(g_usercallTargetCalls == 2);

    uint64_t value = 1;
    CHECK(sigilhook_runtime_get_shared_u64("usercallBad", &value) == SIGILHOOK_OK);
    CHECK(value == 0);
    CHECK(sigilhook_runtime_get_shared_u64("scriptBad", &value) == SIGILHOOK_OK);
    CHECK(value == 0);
    CHECK(sigilhook_runtime_stop() == SIGILHOOK_OK);
    return 0;
}
