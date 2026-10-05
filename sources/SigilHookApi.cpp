// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include <filesystem>
#include "include/sigilhook.h"

#include "sigilhook/ErrorLog.hpp"
#include "sigilhook/Detour/ILCallback.hpp"
#include "sigilhook/Detour/CodeDetour.hpp"
#include "sigilhook/ZydisDisassembler.hpp"
#include "sigilhook/Detour/x64Detour.hpp"
#include "sigilhook/Detour/x86Detour.hpp"
#include "sigilhook/Exceptions/BreakPointHook.hpp"
#include "sigilhook/Exceptions/HWBreakPointHook.hpp"
#include "sigilhook/MemAccessor.hpp"
#include "sigilhook/Misc.hpp"
#include "sigilhook/PE/EatHook.hpp"
#include "sigilhook/PE/IatHook.hpp"
#include "sigilhook/Virtuals/VFuncSwapHook.hpp"
#include "sigilhook/Virtuals/VTableSwapHook.hpp"

#pragma warning(push, 0)
#include <asmjit/x86.h>
#pragma warning(pop)

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <cstring>
#include <cwctype>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#  include <intrin.h>
#endif

namespace {

thread_local std::string g_lastError;

std::mutex g_logMutex;
sigilhook_log_callback g_logCallback = nullptr;
void* g_logUserData = nullptr;

class CallbackLogger final : public SIGILHOOK::Logger {
public:
    void log(const std::string& message, SIGILHOOK::ErrorLevel level) override {
        std::lock_guard lock(g_logMutex);
        if (g_logCallback == nullptr) return;
        const sigilhook_log_level translated =
            level == SIGILHOOK::ErrorLevel::SEV ? SIGILHOOK_LOG_ERROR :
            level == SIGILHOOK::ErrorLevel::WARN ? SIGILHOOK_LOG_WARNING : SIGILHOOK_LOG_INFO;
        g_logCallback(translated, message.c_str(), g_logUserData);
    }
};

std::shared_ptr<CallbackLogger> g_logger = std::make_shared<CallbackLogger>();

void setError(std::string message) {
    g_lastError = std::move(message);
}

sigilhook_status fail(sigilhook_status status, std::string message) {
    setError(std::move(message));
    return status;
}

template<typename T>
T* pointerFrom(sigilhook_handle handle) {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(handle.value));
}

sigilhook_handle handleFrom(void* pointer) {
    sigilhook_handle result{};
    result.value = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pointer));
    return result;
}

SIGILHOOK::Mode currentMode() {
#if defined(SIGILHOOK_ARCH_X64)
    return SIGILHOOK::Mode::x64;
#else
    return SIGILHOOK::Mode::x86;
#endif
}

std::wstring utf8ToWide(const char* text) {
    if (text == nullptr || *text == '\0') {
        return {};
    }
#if defined(_WIN32)
    const int size = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
    if (size <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, text, -1, result.data(), size) != size) {
        return {};
    }
    result.pop_back();
    return result;
#else
    std::wstring result;
    while (*text != '\0') {
        result.push_back(static_cast<unsigned char>(*text++));
    }
    return result;
#endif
}
std::vector<std::string> splitParameters(const std::string& input) {
    std::vector<std::string> result;
    std::stringstream stream(input);
    std::string item;
    while (std::getline(stream, item, ',')) {
        const auto begin = item.find_first_not_of(" \t\r\n");
        const auto end = item.find_last_not_of(" \t\r\n");
        if (begin == std::string::npos) {
            continue;
        }
        result.push_back(item.substr(begin, end - begin + 1));
    }
    return result;
}

struct JitRecord {
    std::unique_ptr<SIGILHOOK::ILCallback> callback;
    sigilhook_jit_callback userCallback = nullptr;
    size_t slot = 32;
    void* userData = nullptr;
    uint64_t codeAddress = 0;
    uint64_t target = 0;
    std::vector<uint8_t> argumentWidths;
    std::atomic<uint64_t> boundHook{0};
    std::mutex callbackMutex;
    std::condition_variable callbackCondition;
    uint32_t activeCallbacks = 0;
    bool acceptingCallbacks = true;
};

// A trampoline is freed only when no thread can still be executing inside it.
// The detour writes its address into the record; the generated JIT stub calls
// the enter/exit callbacks around the original-function invocation.
struct TrampolineAllocation {
    uint64_t address = 0;
    uint64_t size = 0;
    bool heapAllocated = false;
    std::atomic<bool> retiring{false};
    std::atomic<uint32_t> inFlight{0};
    std::mutex mutex;
    std::condition_variable drained;
};

void freeTrampolineIfRetired(const std::shared_ptr<TrampolineAllocation>& allocation) {
    if (allocation == nullptr || !allocation->retiring.load(std::memory_order_acquire)) return;
    if (allocation->inFlight.load(std::memory_order_acquire) != 0) return;
    std::lock_guard lock(allocation->mutex);
    if (!allocation->retiring.load(std::memory_order_relaxed) ||
        allocation->inFlight.load(std::memory_order_relaxed) != 0 || allocation->address == 0) {
        return;
    }
    if (allocation->heapAllocated) {
        delete[] reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(allocation->address));
    }
    allocation->address = 0;
    allocation->size = 0;
}

struct HookRecord {
    std::unique_ptr<SIGILHOOK::IHook> hook;
    std::shared_ptr<JitRecord> jit;
    std::shared_ptr<TrampolineAllocation> trampolineAllocation;
    uint64_t trampoline = 0;
    uint64_t target = 0;
    SIGILHOOK::VFuncMap originalVFuncs;
    sigilhook_hook_type type = SIGILHOOK_HOOK_UNKNOWN;
};

std::mutex g_trampolineMutex;
std::vector<std::shared_ptr<TrampolineAllocation>> g_trampolines;

std::shared_ptr<TrampolineAllocation> registerTrampoline(
    uint64_t address, uint64_t size, bool heapAllocated) {
    if (address == 0) return nullptr;
    auto allocation = std::make_shared<TrampolineAllocation>();
    allocation->address = address;
    allocation->size = size;
    allocation->heapAllocated = heapAllocated;
    std::lock_guard lock(g_trampolineMutex);
    g_trampolines.push_back(allocation);
    return allocation;
}

void unregisterTrampoline(const std::shared_ptr<TrampolineAllocation>& allocation) {
    if (allocation == nullptr) return;
    std::lock_guard lock(g_trampolineMutex);
    g_trampolines.erase(
        std::remove(g_trampolines.begin(), g_trampolines.end(), allocation),
        g_trampolines.end());
}

void trampolineEnterCallback(void* userData) {
    auto* allocation = static_cast<TrampolineAllocation*>(userData);
    if (allocation != nullptr) allocation->inFlight.fetch_add(1, std::memory_order_acq_rel);
}

void trampolineExitCallback(void* userData) {
    auto* allocation = static_cast<TrampolineAllocation*>(userData);
    if (allocation == nullptr) return;
    if (allocation->inFlight.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        allocation->drained.notify_all();
    }
}

std::mutex g_registryMutex;
std::unordered_map<uint64_t, std::shared_ptr<HookRecord>> g_hooks;
std::unordered_map<uint64_t, std::shared_ptr<JitRecord>> g_jits;
std::atomic<uint64_t> g_nextKey{1};

constexpr size_t kJitSlotCount = 32;
std::array<std::atomic<std::shared_ptr<JitRecord>>, kJitSlotCount> g_jitSlots{};

std::mutex g_invokerMutex;
struct InvokerRecord {
    std::shared_ptr<SIGILHOOK::ILCallback> callback;
    uint64_t address = 0;
};
std::unordered_map<std::string, InvokerRecord> g_invokers;

uint64_t readArgument(
    const SIGILHOOK::ILCallback::Parameters* parameters, uint8_t index, uint8_t width) {
    switch (width) {
    case 1: return parameters->getArg<uint8_t>(index);
    case 2: return parameters->getArg<uint16_t>(index);
    case 4: return parameters->getArg<uint32_t>(index);
    case 8: return parameters->getArg<uint64_t>(index);
    default: return 0;
    }
}

void writeArgument(
    const SIGILHOOK::ILCallback::Parameters* parameters, uint8_t index, uint8_t width, uint64_t value) {
    switch (width) {
    case 1: parameters->setArg(index, static_cast<uint8_t>(value)); break;
    case 2: parameters->setArg(index, static_cast<uint16_t>(value)); break;
    case 4: parameters->setArg(index, static_cast<uint32_t>(value)); break;
    case 8: parameters->setArg(index, value); break;
    default: break;
    }
}

void writeStackArgument(
    const SIGILHOOK::ILCallback::Parameters* parameters, int32_t stackOffset, uint8_t width, uint64_t value) {
    const uintptr_t entryStack = static_cast<uintptr_t>(parameters->m_entryStack);
    if (entryStack == 0 || width == 0 || width > sizeof(value)) return;
    auto* destination = reinterpret_cast<uint8_t*>(entryStack) + stackOffset;
    std::memcpy(destination, &value, width);
}

void writeXmmArgument(
    const SIGILHOOK::ILCallback::Parameters* parameters, uint8_t reg, uint8_t width, uint64_t value) {
    if (reg >= SIGILHOOK_XMM_COUNT || width == 0 || width > sizeof(value)) return;
    auto* destination = reinterpret_cast<uint8_t*>(
        const_cast<uint64_t*>(&parameters->m_xmm[reg][0]));
    std::memcpy(destination, &value, width);
}

bool beginJitCallback(const std::shared_ptr<JitRecord>& record) {
    std::lock_guard lock(record->callbackMutex);
    if (!record->acceptingCallbacks) return false;
    ++record->activeCallbacks;
    return true;
}

void finishJitCallback(const std::shared_ptr<JitRecord>& record) {
    {
        std::lock_guard lock(record->callbackMutex);
        if (record->activeCallbacks != 0) --record->activeCallbacks;
    }
    record->callbackCondition.notify_all();
}

void dispatchJitSlot(size_t slot, const SIGILHOOK::ILCallback::Parameters* parameters, uint8_t count, const SIGILHOOK::ILCallback::ReturnValue* returnValue) {
    if (returnValue == nullptr) return;
    auto* result = const_cast<SIGILHOOK::ILCallback::ReturnValue*>(returnValue);
    result->m_retVal = 0;
    result->m_callOriginal = 1;
    result->m_overrideReturn = 0;
    std::shared_ptr<JitRecord> record = slot < kJitSlotCount ? g_jitSlots[slot].load(std::memory_order_acquire) : nullptr;
    if (record == nullptr || !record->userCallback || parameters == nullptr ||
        !beginJitCallback(record)) return;

    struct CallbackGuard {
        std::shared_ptr<JitRecord> record;
        ~CallbackGuard() { finishJitCallback(record); }
    } callbackGuard{record};

    auto* registers = reinterpret_cast<sigilhook_register_context*>(const_cast<uint64_t*>(parameters->m_registers));
    const size_t availableRegisters = currentMode() == SIGILHOOK::Mode::x64 ? SIGILHOOK_REGISTER_COUNT : SIGILHOOK_REGISTER_R8;
    for (size_t index = availableRegisters; index < SIGILHOOK_REGISTER_COUNT; ++index) {
        registers->registers[index] = 0;
    }
    registers->write_mask = 0;
    auto* xmm = reinterpret_cast<sigilhook_xmm_context*>(
        const_cast<uint64_t*>(&parameters->m_xmm[0][0]));
    if (currentMode() != SIGILHOOK::Mode::x64) {
        for (size_t index = 8; index < SIGILHOOK_XMM_COUNT; ++index) {
            xmm->values[index][0] = 0;
            xmm->values[index][1] = 0;
        }
    }
    xmm->write_mask = 0;

    std::vector<uint64_t> arguments(count);
    std::vector<uint64_t> originalArguments(count);
    const auto& layout = record->callback->callLayout();
    for (uint8_t index = 0; index < count; ++index) {
        const uint8_t width = index < record->argumentWidths.size() ? record->argumentWidths[index] : sizeof(uint64_t);
        arguments[index] = readArgument(parameters, index, width);
        originalArguments[index] = arguments[index];
        if (index < layout.arguments.size() && layout.arguments[index].kind == SIGILHOOK::ILCallback::ArgumentLocation::Kind::Register) {
            const uint8_t reg = layout.arguments[index].reg;
            const uint64_t mask = width == sizeof(uint64_t) ? ~uint64_t{0} : (uint64_t{1} << (width * 8)) - 1;
            registers->registers[reg] = arguments[index] & mask;
        } else if (index < layout.arguments.size() && layout.arguments[index].kind == SIGILHOOK::ILCallback::ArgumentLocation::Kind::XmmRegister) {
            const uint8_t reg = layout.arguments[index].reg;
            const uint64_t mask = width == sizeof(uint64_t) ? ~uint64_t{0} : (uint64_t{1} << (width * 8)) - 1;
            arguments[index] = xmm->values[reg][0] & mask;
            originalArguments[index] = arguments[index];
        }
    }

    sigilhook_call_frame frame{
        arguments.data(), count, &result->m_retVal, &result->m_callOriginal, &result->m_overrideReturn, registers,
        record->target, &result->m_redirectAddress, &result->m_redirect, xmm
    };
    record->userCallback(&frame, record->userData);
    if (result->m_redirect != 0 && result->m_redirectAddress == 0) {
        result->m_redirect = 0;
    }
    if (result->m_redirect != 0) result->m_callOriginal = 0;
    bool argumentsChanged = false;

    for (uint8_t index = 0; index < count; ++index) {
        const uint8_t width = index < record->argumentWidths.size() ? record->argumentWidths[index] : sizeof(uint64_t);
        if (arguments[index] != originalArguments[index]) argumentsChanged = true;
        if (index < layout.arguments.size() && layout.arguments[index].kind == SIGILHOOK::ILCallback::ArgumentLocation::Kind::Register) {
            const uint8_t reg = layout.arguments[index].reg;
            const uint64_t bit = uint64_t{1} << reg;
            // Explicit argument edits win over the mapped register alias.
            const uint64_t mask = width == sizeof(uint64_t) ? ~uint64_t{0} : (uint64_t{1} << (width * 8)) - 1;
            if ((registers->write_mask & bit) != 0 && arguments[index] == originalArguments[index]) {
                arguments[index] = registers->registers[reg] & mask;
                argumentsChanged = true;
            } else {
                registers->registers[reg] = arguments[index] & mask;
            }
        } else if (index < layout.arguments.size() && layout.arguments[index].kind == SIGILHOOK::ILCallback::ArgumentLocation::Kind::XmmRegister) {
            const uint8_t reg = layout.arguments[index].reg;
            const uint64_t bit = uint64_t{1} << reg;
            const uint64_t mask = width == sizeof(uint64_t) ? ~uint64_t{0} : (uint64_t{1} << (width * 8)) - 1;
            if ((xmm->write_mask & bit) != 0 && arguments[index] == originalArguments[index]) {
                arguments[index] = xmm->values[reg][0] & mask;
                argumentsChanged = true;
            } else {
                const uint64_t lane = xmm->values[reg][0];
                xmm->values[reg][0] = width == sizeof(uint64_t)
                    ? arguments[index]
                    : (lane & ~mask) | (arguments[index] & mask);
                xmm->write_mask |= bit;
            }
            writeXmmArgument(parameters, reg, width, arguments[index]);
        } else if (index < layout.arguments.size() && layout.arguments[index].kind == SIGILHOOK::ILCallback::ArgumentLocation::Kind::Stack) {
            writeStackArgument(parameters, layout.arguments[index].stackOffset, width, arguments[index]);
            if (arguments[index] != originalArguments[index]) argumentsChanged = true;
        }
        writeArgument(parameters, index, width, arguments[index]);
        if (arguments[index] != originalArguments[index]) argumentsChanged = true;
    }

    if (layout.returnRegister >= 0) {
        const uint8_t reg = static_cast<uint8_t>(layout.returnRegister);
        if ((registers->write_mask & (uint64_t{1} << reg)) != 0) {
            result->m_retVal = registers->registers[reg];
            result->m_overrideReturn = 1;
        }
    }
}
template<size_t Slot>
void dispatchJitTemplate(const SIGILHOOK::ILCallback::Parameters* parameters, uint8_t count, const SIGILHOOK::ILCallback::ReturnValue* returnValue) {
    dispatchJitSlot(Slot, parameters, count, returnValue);
}

template<size_t... Slots>
std::array<SIGILHOOK::ILCallback::tUserCallback, sizeof...(Slots)> makeJitDispatchers(std::index_sequence<Slots...>) {
    return {&dispatchJitTemplate<Slots>...};
}

const auto g_jitDispatchers = makeJitDispatchers(std::make_index_sequence<kJitSlotCount>{});

SIGILHOOK::VFuncMap makeVFuncMap(const sigilhook_vfunc_entry* entries, size_t count) {
    SIGILHOOK::VFuncMap result;
    for (size_t index = 0; index < count; ++index) {
        result.emplace(entries[index].index, entries[index].replacement);
    }
    return result;
}


std::shared_ptr<HookRecord> findHook(sigilhook_handle handle) {
    std::lock_guard lock(g_registryMutex);
    const auto iterator = g_hooks.find(handle.value);
    return iterator == g_hooks.end() ? nullptr : iterator->second;
}

std::shared_ptr<JitRecord> findJit(sigilhook_jit_handle handle) {
    std::lock_guard lock(g_registryMutex);
    const auto iterator = g_jits.find(handle.value);
    return iterator == g_jits.end() ? nullptr : iterator->second;
}

sigilhook_status validateHook(sigilhook_handle handle, std::shared_ptr<HookRecord>* outRecord) {
    std::shared_ptr<HookRecord> record = findHook(handle);
    if (record == nullptr || record->hook == nullptr) {
        return fail(SIGILHOOK_ERROR_NOT_FOUND, "The hook handle does not exist");
    }
    *outRecord = record;
    return SIGILHOOK_OK;
}

asmjit::JitRuntime g_snippetRuntime;
std::mutex g_snippetMutex;
std::unordered_set<uint64_t> g_snippetAddresses;

sigilhook_status makeSnippet(
    const std::function<void(asmjit::x86::Assembler&)>& emit, uint64_t* outAddress) {
    if (outAddress == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Snippet output address is required");
    *outAddress = 0;
    asmjit::CodeHolder code;
    if (code.init(g_snippetRuntime.environment()) != asmjit::kErrorOk) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "Failed to initialize snippet code");
    }
    asmjit::x86::Assembler assembler(&code);
    emit(assembler);
    void* address = nullptr;
    std::lock_guard lock(g_snippetMutex);
    if (g_snippetRuntime.add(&address, &code) != asmjit::kErrorOk || address == nullptr) {
        return fail(SIGILHOOK_ERROR_MEMORY, "Failed to allocate executable snippet memory");
    }
    g_snippetAddresses.insert(reinterpret_cast<uint64_t>(address));
    *outAddress = reinterpret_cast<uint64_t>(address);
    return SIGILHOOK_OK;
}
sigilhook_status validateDetour(sigilhook_handle handle, std::shared_ptr<HookRecord>* outRecord) {
    const sigilhook_status status = validateHook(handle, outRecord);
    if (status != SIGILHOOK_OK) {
        return status;
    }
    if ((*outRecord)->type != SIGILHOOK_HOOK_DETOUR) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "The operation requires a detour handle");
    }
    return SIGILHOOK_OK;
}

SIGILHOOK::HookType translateType(sigilhook_hook_type type) {
    switch (type) {
    case SIGILHOOK_HOOK_DETOUR: return SIGILHOOK::HookType::Detour;
    case SIGILHOOK_HOOK_IAT: return SIGILHOOK::HookType::IAT;
    case SIGILHOOK_HOOK_EAT: return SIGILHOOK::HookType::EAT;
    case SIGILHOOK_HOOK_VFUNC_SWAP:
    case SIGILHOOK_HOOK_VTABLE_SWAP: return SIGILHOOK::HookType::VTableSwap;
    case SIGILHOOK_HOOK_SOFTWARE_BREAKPOINT:
    case SIGILHOOK_HOOK_HARDWARE_BREAKPOINT: return SIGILHOOK::HookType::VEHHOOK;
    default: return SIGILHOOK::HookType::UNKNOWN;
    }
}

sigilhook_hook_type translateType(SIGILHOOK::HookType type) {
    switch (type) {
    case SIGILHOOK::HookType::Detour: return SIGILHOOK_HOOK_DETOUR;
    case SIGILHOOK::HookType::VEHHOOK: return SIGILHOOK_HOOK_SOFTWARE_BREAKPOINT;
    case SIGILHOOK::HookType::VTableSwap: return SIGILHOOK_HOOK_VTABLE_SWAP;
    case SIGILHOOK::HookType::IAT: return SIGILHOOK_HOOK_IAT;
    case SIGILHOOK::HookType::EAT: return SIGILHOOK_HOOK_EAT;
    default: return SIGILHOOK_HOOK_UNKNOWN;
    }
}

template<typename Factory>
sigilhook_status createHook(Factory&& factory, sigilhook_hook_type type, sigilhook_handle* outHandle) {
    if (outHandle == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "The output hook handle is null");
    }
    *outHandle = {};
    try {
        auto record = std::make_shared<HookRecord>();
        record->type = type;
        if (!factory(*record)) {
            return fail(SIGILHOOK_ERROR_HOOK_FAILED, "Failed to construct the hook");
        }
        const uint64_t key = g_nextKey++;
        *outHandle = handleFrom(reinterpret_cast<void*>(static_cast<uintptr_t>(key)));
        std::lock_guard lock(g_registryMutex);
        g_hooks.emplace(key, std::move(record));
        return SIGILHOOK_OK;
    } catch (const std::exception& exception) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, exception.what());
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "Unknown C++ exception while constructing the hook");
    }
}

} // namespace

extern "C" {

uint32_t SIGILHOOK_CALL sigilhook_api_version(void) {
    return 0x0002000C;
}

sigilhook_status SIGILHOOK_CALL sigilhook_wait_for_trampolines(uint32_t timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    std::unique_lock lock(g_trampolineMutex);
    for (;;) {
        for (auto& allocation : g_trampolines) {
            freeTrampolineIfRetired(allocation);
        }
        g_trampolines.erase(
            std::remove_if(g_trampolines.begin(), g_trampolines.end(),
                [](const std::shared_ptr<TrampolineAllocation>& allocation) {
                    return allocation == nullptr || allocation->address == 0;
                }),
            g_trampolines.end());
        bool pending = false;
        for (auto& allocation : g_trampolines) {
            if (allocation != nullptr && allocation->retiring.load(std::memory_order_acquire) &&
                allocation->inFlight.load(std::memory_order_acquire) != 0) {
                pending = true;
                break;
            }
        }
        if (!pending) return SIGILHOOK_OK;
        bool waited = false;
        for (auto& allocation : g_trampolines) {
            if (allocation == nullptr ||
                !allocation->retiring.load(std::memory_order_acquire) ||
                allocation->inFlight.load(std::memory_order_acquire) == 0) {
                continue;
            }
            waited = true;
            if (allocation->drained.wait_until(lock, deadline) == std::cv_status::timeout) {
                return SIGILHOOK_ERROR_BUSY;
            }
            break;
        }
        if (!waited) return SIGILHOOK_OK;
    }
}

sigilhook_mode SIGILHOOK_CALL sigilhook_build_mode(void) {
    return currentMode() == SIGILHOOK::Mode::x64 ? SIGILHOOK_MODE_X64 : SIGILHOOK_MODE_X86;
}

sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_get_register(
    const sigilhook_call_frame* frame, sigilhook_register reg, uint64_t* outValue) {
    if (frame == nullptr || frame->registers == nullptr || outValue == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame, register context, and output are required");
    }
    if (reg < 0 || reg >= SIGILHOOK_REGISTER_COUNT) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Register index is out of range");
    }
    if (currentMode() != SIGILHOOK::Mode::x64 && reg >= SIGILHOOK_REGISTER_R8) {
        return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "R8-R15 are unavailable in x86 callback frames");
    }
    *outValue = frame->registers->registers[reg];
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_set_register(
    sigilhook_call_frame* frame, sigilhook_register reg, uint64_t value) {
    if (frame == nullptr || frame->registers == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame and register context are required");
    }
    if (reg < 0 || reg >= SIGILHOOK_REGISTER_COUNT) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Register index is out of range");
    }
    if (currentMode() != SIGILHOOK::Mode::x64 && reg >= SIGILHOOK_REGISTER_R8) {
        return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "R8-R15 are unavailable in x86 callback frames");
    }
    if (reg == SIGILHOOK_REGISTER_SP) {
        return fail(SIGILHOOK_ERROR_UNSUPPORTED, "SP is read-only in callback frames");
    }
    frame->registers->registers[reg] = value;
    frame->registers->write_mask |= uint64_t{1} << reg;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_get_flags(
    const sigilhook_call_frame* frame, uint64_t* outFlags) {
    if (frame == nullptr || frame->registers == nullptr || outFlags == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame, register context, and output are required");
    }
    *outFlags = frame->registers->flags;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_set_flags(
    sigilhook_call_frame* frame, uint64_t flags) {
    if (frame == nullptr || frame->registers == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame and register context are required");
    }
    frame->registers->flags = flags;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_get_instruction_pointer(
    const sigilhook_call_frame* frame, uint64_t* outAddress) {
    if (frame == nullptr || outAddress == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame and output address are required");
    }
    *outAddress = frame->instruction_pointer;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_set_instruction_pointer(
    sigilhook_call_frame* frame, uint64_t address) {
    if (frame == nullptr || frame->instruction_pointer_overridden == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame and redirect output are required");
    }
    if (address == 0) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Redirect address cannot be zero");
    if (currentMode() != SIGILHOOK::Mode::x64 && address > UINT32_MAX) {
        return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "Redirect address does not fit in x86");
    }
    if (frame->instruction_pointer_destination == nullptr) {
        return fail(SIGILHOOK_ERROR_UNSUPPORTED, "This callback frame cannot redirect instruction pointer");
    }
    frame->instruction_pointer = address;
    *frame->instruction_pointer_destination = address;
    *frame->instruction_pointer_overridden = 1;
    return SIGILHOOK_OK;
}

const char* SIGILHOOK_CALL sigilhook_status_string(sigilhook_status status) {
    switch (status) {
    case SIGILHOOK_OK: return "ok";
    case SIGILHOOK_ERROR_INVALID_ARGUMENT: return "invalid argument";
    case SIGILHOOK_ERROR_NOT_FOUND: return "not found";
    case SIGILHOOK_ERROR_UNSUPPORTED: return "unsupported";
    case SIGILHOOK_ERROR_ARCH_MISMATCH: return "architecture mismatch";
    case SIGILHOOK_ERROR_HOOK_FAILED: return "hook failed";
    case SIGILHOOK_ERROR_MEMORY: return "memory operation failed";
    case SIGILHOOK_ERROR_SCRIPT: return "script error";
    case SIGILHOOK_ERROR_BUSY: return "busy";
    case SIGILHOOK_ERROR_EXCEPTION: return "exception";
    default: return "unknown";
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_last_error(char* buffer, size_t capacity) {
    if (buffer == nullptr || capacity == 0) {
        return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    }
    const size_t count = (std::min)(capacity - 1, g_lastError.size());
    std::memcpy(buffer, g_lastError.data(), count);
    buffer[count] = '\0';
    return SIGILHOOK_OK;
}

void SIGILHOOK_CALL sigilhook_clear_last_error(void) {
    g_lastError.clear();
}

void SIGILHOOK_CALL sigilhook_set_log_callback(
    sigilhook_log_callback callback, void* userData) {
    std::lock_guard lock(g_logMutex);
    g_logCallback = callback;
    g_logUserData = userData;
    SIGILHOOK::Log::registerLogger(callback == nullptr ? nullptr : g_logger);
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_detour(
    uint64_t target, uint64_t callback, sigilhook_handle* outHook, uint64_t* outTrampoline) {
    if (target == 0 || callback == 0 || outHook == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Target, callback, and output handle are required");
    }
    if (outTrampoline != nullptr) *outTrampoline = 0;
    const sigilhook_status status = createHook([&](HookRecord& record) {
        record.trampoline = 0;
        record.target = target;
#if defined(SIGILHOOK_ARCH_X64)
        record.hook = std::make_unique<SIGILHOOK::x64Detour>(target, callback, &record.trampoline);
#else
        record.hook = std::make_unique<SIGILHOOK::x86Detour>(target, callback, &record.trampoline);
#endif
        return true;
    }, SIGILHOOK_HOOK_DETOUR, outHook);
    if (status == SIGILHOOK_OK) {
        const auto record = findHook(*outHook);
        if (record != nullptr && record->trampoline != 0) {
            record->trampolineAllocation = registerTrampoline(record->trampoline, 0, true);
        }
    }
    if (status == SIGILHOOK_OK && outTrampoline != nullptr) {
        const auto record = findHook(*outHook);
        if (record != nullptr) *outTrampoline = record->trampoline;
    }
    return status;
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_code_detour(
    uint64_t address, uint64_t callback, sigilhook_handle* outHook,
    uint64_t* outTrampoline, uint32_t* outOverwrittenBytes) {
    if (address == 0 || callback == 0 || outHook == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Address, callback, and output handle are required");
    }
    if (outTrampoline != nullptr) *outTrampoline = 0;
    if (outOverwrittenBytes != nullptr) *outOverwrittenBytes = 0;

    sigilhook_status status = SIGILHOOK_ERROR_HOOK_FAILED;
    {
        auto record = std::make_shared<HookRecord>();
        record->type = SIGILHOOK_HOOK_DETOUR;
        record->target = address;
#if defined(SIGILHOOK_ARCH_X64)
        auto hook = std::make_unique<SIGILHOOK::CodeDetour>(
            address, callback, &record->trampoline, SIGILHOOK::Mode::x64);
#else
        auto hook = std::make_unique<SIGILHOOK::CodeDetour>(
            address, callback, &record->trampoline, SIGILHOOK::Mode::x86);
#endif
        if (!hook->hook()) {
            return fail(SIGILHOOK_ERROR_HOOK_FAILED, "Failed to install the instruction-level detour");
        }
        const uint32_t overwritten = hook->getOverwrittenBytes();
        record->hook = std::move(hook);
        const uint64_t key = g_nextKey++;
        *outHook = handleFrom(reinterpret_cast<void*>(static_cast<uintptr_t>(key)));
        if (outTrampoline != nullptr) *outTrampoline = record->trampoline;
        if (outOverwrittenBytes != nullptr) *outOverwrittenBytes = overwritten;
        std::lock_guard lock(g_registryMutex);
        g_hooks.emplace(key, std::move(record));
        status = SIGILHOOK_OK;
    }
    return status;
}

sigilhook_status SIGILHOOK_CALL sigilhook_destroy(sigilhook_handle handle) {
    std::shared_ptr<HookRecord> record;
    {
        std::lock_guard lock(g_registryMutex);
        const auto iterator = g_hooks.find(handle.value);
        if (iterator == g_hooks.end()) {
            return fail(SIGILHOOK_ERROR_NOT_FOUND, "The hook handle does not exist");
        }
        record = iterator->second;
    }
    if (record && record->hook) {
        try {
            if (record->hook->isHooked() && !record->hook->unHook()) {
                return fail(SIGILHOOK_ERROR_HOOK_FAILED, "Hook removal failed during destruction");
            }
        } catch (const std::exception& exception) {
            return fail(SIGILHOOK_ERROR_EXCEPTION, std::string("Hook destruction raised an exception: ") + exception.what());
        } catch (...) {
            return fail(SIGILHOOK_ERROR_EXCEPTION, "Hook destruction raised an unknown exception");
        }
    }
    if (record && record->jit && record->jit->callback) {
        *record->jit->callback->getTrampolineHolder() = 0;
        record->jit->boundHook.store(0, std::memory_order_release);
    }
    if (record && record->trampolineAllocation) {
        record->trampolineAllocation->retiring.store(true, std::memory_order_release);
        // Keep the registry's shared ownership until wait_for_trampolines
        // observes that all generated stubs have exited. The callback stores
        // only a raw user-data pointer.
        freeTrampolineIfRetired(record->trampolineAllocation);
    }
    {
        std::lock_guard lock(g_registryMutex);
        const auto iterator = g_hooks.find(handle.value);
        if (iterator != g_hooks.end() && iterator->second == record) {
            g_hooks.erase(iterator);
        }
    }
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_hook(sigilhook_handle handle) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        if (!record->hook->hook()) return fail(SIGILHOOK_ERROR_HOOK_FAILED, "Hook installation failed");
        if (record->jit && record->jit->callback) {
            *record->jit->callback->getTrampolineHolder() = record->trampoline;
        }
        return SIGILHOOK_OK;
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "hook() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_unhook(sigilhook_handle handle) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        return record->hook->unHook() ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_HOOK_FAILED, "Hook removal failed");
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "unhook() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_rehook(sigilhook_handle handle) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        const bool installed = record->hook->isHooked();
        const bool result = installed ? record->hook->reHook() : record->hook->hook();
        return result ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_HOOK_FAILED, "Hook reinstallation failed");
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "rehook() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_hooked(sigilhook_handle handle, int hooked) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        return record->hook->setHooked(hooked != 0) ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_HOOK_FAILED, "Changing hook state failed");
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "setHooked() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_is_hooked(sigilhook_handle handle, int* outHooked) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outHooked == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output state is null");
    *outHooked = record->hook->isHooked() ? 1 : 0;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_type(sigilhook_handle handle, sigilhook_hook_type* outType) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outType == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output type is null");
    *outType = record->type;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_debug(sigilhook_handle handle, int enabled) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    record->hook->setDebug(enabled != 0);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_trampoline(sigilhook_handle handle, uint64_t* outTrampoline) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outTrampoline == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output trampoline is null");
    *outTrampoline = record->trampoline;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_max_depth(sigilhook_handle handle, uint8_t* outDepth) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outDepth == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output depth is null");
    *outDepth = static_cast<SIGILHOOK::Detour*>(record->hook.get())->getMaxDepth();
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_max_depth(sigilhook_handle handle, uint8_t depth) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    static_cast<SIGILHOOK::Detour*>(record->hook.get())->setMaxDepth(depth);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_follow_call_on_target(sigilhook_handle handle, int enabled) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    static_cast<SIGILHOOK::Detour*>(record->hook.get())->setIsFollowCallOnFnAddress(enabled != 0);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_detour_scheme(sigilhook_handle handle, uint8_t* outScheme) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
#if defined(SIGILHOOK_ARCH_X64)
    if (outScheme == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output scheme is null");
    *outScheme = static_cast<uint8_t>(static_cast<SIGILHOOK::x64Detour*>(record->hook.get())->getDetourScheme());
    return SIGILHOOK_OK;
#else
    (void)outScheme;
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Detour schemes are x64-only");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_detour_scheme(sigilhook_handle handle, uint8_t scheme) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
#if defined(SIGILHOOK_ARCH_X64)
    static_cast<SIGILHOOK::x64Detour*>(record->hook.get())->setDetourScheme(
        static_cast<SIGILHOOK::x64Detour::detour_scheme_t>(scheme));
    return SIGILHOOK_OK;
#else
    (void)scheme;
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Detour schemes are x64-only");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_breakpoint(
    uint64_t target, uint64_t callback, sigilhook_handle* outHook) {
#if defined(SIGILHOOK_OS_WINDOWS)
    if (target == 0 || callback == 0) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Target and callback are required");
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<SIGILHOOK::BreakPointHook>(target, callback);
        return true;
    }, SIGILHOOK_HOOK_SOFTWARE_BREAKPOINT, outHook);
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Breakpoint hooks require Windows");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_hardware_breakpoint(
    uint64_t target, uint64_t callback, uintptr_t thread, sigilhook_handle* outHook) {
#if defined(SIGILHOOK_OS_WINDOWS)
    if (target == 0 || callback == 0 || thread == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Target, callback, and thread are required");
    }
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<SIGILHOOK::HWBreakPointHook>(target, callback, reinterpret_cast<HANDLE>(thread));
        return true;
    }, SIGILHOOK_HOOK_HARDWARE_BREAKPOINT, outHook);
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Hardware breakpoint hooks require Windows");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_iat_hook(
    const char* importedDll, const char* importedApi, const char* moduleName,
    uint64_t callback, sigilhook_handle* outHook, uint64_t* outOriginal) {
#if defined(SIGILHOOK_OS_WINDOWS)
    if (importedDll == nullptr || importedApi == nullptr || callback == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Imported DLL, API, and callback are required");
    }
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<SIGILHOOK::IatHook>(
            importedDll, importedApi, callback, &record.trampoline, utf8ToWide(moduleName));
        if (outOriginal != nullptr) *outOriginal = record.trampoline;
        return true;
    }, SIGILHOOK_HOOK_IAT, outHook);
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "IAT hooks require Windows");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_eat_hook(
    const char* exportedApi, const char* moduleName,
    uint64_t callback, sigilhook_handle* outHook, uint64_t* outOriginal) {
#if defined(SIGILHOOK_OS_WINDOWS)
    if (exportedApi == nullptr || callback == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Exported API and callback are required");
    }
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<SIGILHOOK::EatHook>(
            exportedApi, utf8ToWide(moduleName), callback, &record.trampoline);
        if (outOriginal != nullptr) *outOriginal = record.trampoline;
        return true;
    }, SIGILHOOK_HOOK_EAT, outHook);
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "EAT hooks require Windows");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_vfunc_swap(
    uint64_t object, const sigilhook_vfunc_entry* entries, size_t entryCount, sigilhook_handle* outHook) {
    if (object == 0 || entries == nullptr || entryCount == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Object and non-empty entry array are required");
    }
    return createHook([&](HookRecord& record) {
        record.originalVFuncs.clear();
        record.hook = std::make_unique<SIGILHOOK::VFuncSwapHook>(
            object, makeVFuncMap(entries, entryCount), &record.originalVFuncs);
        return true;
    }, SIGILHOOK_HOOK_VFUNC_SWAP, outHook);
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_vtable_swap(
    uint64_t object, const sigilhook_vfunc_entry* entries, size_t entryCount,
    sigilhook_rtti_mode rttiMode, sigilhook_handle* outHook) {
    if (object == 0 || entries == nullptr || entryCount == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Object and non-empty entry array are required");
    }
    SIGILHOOK::VTableRTTIMode mode = SIGILHOOK::VTableRTTIMode::Default;
    if (rttiMode == SIGILHOOK_RTTI_NONE) mode = SIGILHOOK::VTableRTTIMode::None;
    else if (rttiMode == SIGILHOOK_RTTI_MSVC) mode = SIGILHOOK::VTableRTTIMode::MSVC;
    else if (rttiMode == SIGILHOOK_RTTI_ITANIUM) mode = SIGILHOOK::VTableRTTIMode::Itanium;
    return createHook([&](HookRecord& record) {
        record.originalVFuncs.clear();
        record.hook = std::make_unique<SIGILHOOK::VTableSwapHook>(
            object, makeVFuncMap(entries, entryCount), &record.originalVFuncs, mode);
        return true;
    }, SIGILHOOK_HOOK_VTABLE_SWAP, outHook);
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_original_vfunc(
    sigilhook_handle handle, uint16_t index, uint64_t* outOriginal) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outOriginal == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output original is null");
    const auto iterator = record->originalVFuncs.find(index);
    if (iterator == record->originalVFuncs.end()) return fail(SIGILHOOK_ERROR_NOT_FOUND, "Original vfunc not found");
    *outOriginal = iterator->second;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_jit_callback(
    const char* returnType, const char* commaSeparatedParameters, const char* callConvention,
    sigilhook_jit_callback callback, void* userData, sigilhook_jit_handle* outJit, uint64_t* outAddress) {
    if (returnType == nullptr || callback == nullptr || outJit == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Return type, callback, and output handle are required");
    }
    size_t slot = kJitSlotCount;
    try {
        auto owner = std::make_shared<JitRecord>();
        owner->callback = std::make_unique<SIGILHOOK::ILCallback>();
        owner->userCallback = callback;
        owner->userData = userData;
        const std::vector<std::string> parameterTypes =
            splitParameters(commaSeparatedParameters == nullptr ? "" : commaSeparatedParameters);
        for (const std::string& parameterType : parameterTypes) {
            owner->argumentWidths.push_back(owner->callback->getTypeWidth(parameterType, asmjit::Arch::kHost));
        }
        for (size_t index = 0; index < kJitSlotCount; ++index) {
            std::shared_ptr<JitRecord> expected;
            if (g_jitSlots[index].compare_exchange_strong(expected, owner, std::memory_order_acq_rel)) {
                slot = index;
                break;
            }
        }
        if (slot == kJitSlotCount) return fail(SIGILHOOK_ERROR_BUSY, "All JIT callback slots are in use");
        owner->slot = slot;
        owner->codeAddress = owner->callback->getJitFunc(
            returnType,
            parameterTypes,
            asmjit::Arch::kHost,
            g_jitDispatchers[slot],
            callConvention == nullptr ? std::string() : std::string(callConvention));
        if (owner->codeAddress == 0) {
            g_jitSlots[slot].store({}, std::memory_order_release);
            const sigilhook_status status = owner->callback->lastErrorStatus();
            const std::string message = owner->callback->lastError();
            return fail(status, message.empty() ? "Failed to generate the JIT callback" : message);
        }
        const uint64_t key = g_nextKey++;
        {
            std::lock_guard lock(g_registryMutex);
            g_jits.emplace(key, owner);
        }
        *outJit = {};
        outJit->value = key;
        if (outAddress != nullptr) *outAddress = owner->codeAddress;
        return SIGILHOOK_OK;    } catch (const std::exception& exception) {
        if (slot < kJitSlotCount) g_jitSlots[slot].store({}, std::memory_order_release);
        return fail(SIGILHOOK_ERROR_EXCEPTION, exception.what());
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_destroy_jit_callback(sigilhook_jit_handle jit) {
    std::shared_ptr<JitRecord> owner;
    {
        std::lock_guard lock(g_registryMutex);
        const auto iterator = g_jits.find(jit.value);
        if (iterator == g_jits.end()) return fail(SIGILHOOK_ERROR_NOT_FOUND, "The JIT handle does not exist");
        if (iterator->second->boundHook.load(std::memory_order_acquire) != 0) {
            return fail(SIGILHOOK_ERROR_BUSY, "The JIT callback is still bound to a hook");
        }
        owner = iterator->second;
        g_jits.erase(iterator);
    }
    if (owner->slot < kJitSlotCount) {
        g_jitSlots[owner->slot].store({}, std::memory_order_release);
    }
    {
        std::unique_lock lock(owner->callbackMutex);
        owner->acceptingCallbacks = false;
        owner->callbackCondition.wait(lock, [&owner] {
            return owner->activeCallbacks == 0;
        });
    }
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_bind_detour_to_jit(
    sigilhook_handle detour, sigilhook_jit_handle jit, sigilhook_handle* outHook) {
    std::shared_ptr<HookRecord> record;
    sigilhook_status status = validateDetour(detour, &record);
    if (status != SIGILHOOK_OK) return status;
    auto owner = findJit(jit);
    if (!owner) return fail(SIGILHOOK_ERROR_NOT_FOUND, "The JIT handle does not exist");
    if (record->jit != nullptr && record->jit != owner) {
        return fail(SIGILHOOK_ERROR_BUSY, "The detour is already bound to another JIT callback");
    }
    uint64_t expected = 0;
    if (!owner->boundHook.compare_exchange_strong(expected, detour.value, std::memory_order_acq_rel) &&
        expected != detour.value) {
        return fail(SIGILHOOK_ERROR_BUSY, "The JIT callback is already bound to another hook");
    }
    record->jit = std::move(owner);
    record->jit->target = record->target;
    if (record->jit->callback != nullptr) {
        *record->jit->callback->getTrampolineHolder() = record->trampoline;
        if (record->trampolineAllocation != nullptr) {
            record->jit->callback->setTrampolineRefCallbacks(
                trampolineEnterCallback, trampolineExitCallback,
                record->trampolineAllocation.get());
        }
    }
    if (outHook != nullptr) *outHook = detour;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_mem_read(
    uint64_t address, void* destination, size_t size, size_t* outRead) {
    if (address == 0 || destination == nullptr || size == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Address, destination, and non-zero size are required");
    }
    size_t read = 0;
    SIGILHOOK::MemAccessor accessor;
    const bool result = accessor.safe_mem_read(address, reinterpret_cast<uint64_t>(destination), size, read);
    if (outRead != nullptr) *outRead = read;
    return result ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_MEMORY, "Memory read failed");
}

sigilhook_status SIGILHOOK_CALL sigilhook_mem_write(
    uint64_t address, const void* source, size_t size, size_t* outWritten) {
    if (address == 0 || source == nullptr || size == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Address, source, and non-zero size are required");
    }
    size_t written = 0;
    SIGILHOOK::MemAccessor accessor;
    const bool result = accessor.safe_mem_write(
        address, reinterpret_cast<uint64_t>(const_cast<void*>(source)), size, written);
    if (outWritten != nullptr) *outWritten = written;
    return result ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_MEMORY, "Memory write failed");
}

sigilhook_status SIGILHOOK_CALL sigilhook_mem_protect(
    uint64_t address, size_t size, sigilhook_protect protection, sigilhook_protect* outPrevious) {
    if (address == 0 || size == 0) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Address and size are required");
    bool status = false;
    SIGILHOOK::MemAccessor accessor;
    const SIGILHOOK::ProtFlag previous = accessor.mem_protect(
        address, size, static_cast<SIGILHOOK::ProtFlag>(protection), status);
    if (outPrevious != nullptr) *outPrevious = static_cast<sigilhook_protect>(previous);
    return status ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_MEMORY, "VirtualProtect/mprotect failed");
}

sigilhook_status SIGILHOOK_CALL sigilhook_find_pattern(
    uint64_t address, size_t size, const char* idaPattern, uint64_t* outAddress) {
    if (address == 0 || size == 0 || idaPattern == nullptr || outAddress == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Range, pattern, and output address are required");
    }
    *outAddress = SIGILHOOK::findPattern(address, size, idaPattern);
    return *outAddress == 0 ? fail(SIGILHOOK_ERROR_NOT_FOUND, "Pattern was not found") : SIGILHOOK_OK;
}

uint64_t SIGILHOOK_CALL sigilhook_pattern_size(const char* idaPattern) {
    return idaPattern == nullptr ? 0 : SIGILHOOK::getPatternSize(idaPattern);
}

sigilhook_status SIGILHOOK_CALL sigilhook_disassemble(
    uint64_t address, uint32_t maxBytes, char* output, size_t outputCapacity,
    size_t* outDecodedBytes) {
    if (address == 0 || output == nullptr || outputCapacity == 0 || maxBytes == 0 || maxBytes > 4096) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Address, output, and 1-4096 max bytes are required");
    }
    output[0] = '\0';
    if (outDecodedBytes != nullptr) *outDecodedBytes = 0;
    std::vector<uint8_t> bytes(maxBytes);
    size_t read = 0;
    SIGILHOOK::MemAccessor accessor;
    if (!accessor.safe_mem_read(address, reinterpret_cast<uint64_t>(bytes.data()), bytes.size(), read) || read == 0) {
        return fail(SIGILHOOK_ERROR_MEMORY, "Could not read bytes for disassembly");
    }

    ZydisDecoder decoder;
    ZydisFormatter formatter;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder,
            currentMode() == SIGILHOOK::Mode::x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
            currentMode() == SIGILHOOK::Mode::x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32)) ||
        ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "Failed to initialize the Zydis disassembler");
    }

    std::ostringstream text;
    size_t offset = 0;
    while (offset < read && offset < maxBytes) {
        ZydisDecodedInstruction instruction;
        if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, bytes.data() + offset, read - offset, &instruction, operands))) break;
        if (offset + instruction.length > maxBytes || offset + instruction.length > read) break;
        char formatted[512]{};
        if (ZYAN_FAILED(ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count,
                formatted, sizeof(formatted), address + offset, ZYAN_NULL))) break;
        text << std::hex << std::setfill('0') << std::setw(16) << (address + offset) << "  ";
        for (size_t index = 0; index < instruction.length; ++index) {
            text << std::setw(2) << static_cast<unsigned>(bytes[offset + index]) << ' ';
        }
        text << std::dec << std::setfill(' ') << " " << formatted << '\n';
        offset += instruction.length;
    }
    if (offset == 0) return fail(SIGILHOOK_ERROR_NOT_FOUND, "No instruction could be decoded at the requested address");
    const std::string result = text.str();
    if (result.size() + 1 > outputCapacity) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Disassembly output buffer is too small");
    }
    std::memcpy(output, result.c_str(), result.size() + 1);
    if (outDecodedBytes != nullptr) *outDecodedBytes = offset;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_parse_hex(const char* text, uint64_t* outValue) {
    if (text == nullptr || outValue == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Hex text and output value are required");
    }
    while (*text == ' ' || *text == '\t') ++text;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    if (*text == '\0') return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Hex text is empty");
    const auto result = std::from_chars(text, text + std::strlen(text), *outValue, 16);
    if (result.ec != std::errc() || result.ptr != text + std::strlen(text)) {
        *outValue = 0;
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Hex text is invalid");
    }
    return SIGILHOOK_OK;
}

} // extern "C"

namespace {
uint64_t currentEflags() {
#if defined(_MSC_VER)
    return static_cast<uint64_t>(__readeflags());
#elif defined(__GNUC__) && defined(__x86_64__)
    return __builtin_ia32_readeflags_u64();
#elif defined(__GNUC__)
    return __builtin_ia32_readeflags_u32();
#else
    return 0;
#endif
}

sigilhook_status computeFlags(
    uint64_t left, uint64_t right, uint8_t operandSize, bool test, uint64_t* outFlags) {
    if (outFlags == nullptr || (operandSize != 1 && operandSize != 2 && operandSize != 4 && operandSize != 8)) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Flags output and operand size 1, 2, 4, or 8 are required");
    }
    const uint32_t bits = operandSize * 8;
    const uint64_t mask = bits == 64 ? ~uint64_t{0} : (uint64_t{1} << bits) - 1;
    left &= mask;
    right &= mask;
    const uint64_t result = test ? (left & right) : ((left - right) & mask);
    const uint64_t sign = uint64_t{1} << (bits - 1);
    uint64_t computed = 0;
    if ((result & 0xff) == 0) computed |= 0x40;
    if ((result & sign) != 0) computed |= 0x80;
    uint8_t parityByte = static_cast<uint8_t>(result & 0xff);
    parityByte ^= static_cast<uint8_t>(parityByte >> 4);
    parityByte ^= static_cast<uint8_t>(parityByte >> 2);
    parityByte ^= static_cast<uint8_t>(parityByte >> 1);
    if ((parityByte & 1) == 0) computed |= 0x04;
    if (test) {
        constexpr uint64_t modifiedMask = 0x8c5; // CF, PF, ZF, SF, OF
        *outFlags = (currentEflags() & ~modifiedMask) | (computed & modifiedMask);
    } else {
        if (left < right) computed |= 0x01;
        if (((~(left ^ right) & (left ^ result)) & sign) != 0) computed |= 0x800;
        if (((left ^ right ^ result) & 0x10) != 0) computed |= 0x10;
        constexpr uint64_t modifiedMask = 0x8d5; // CF, PF, AF, ZF, SF, OF
        *outFlags = (currentEflags() & ~modifiedMask) | (computed & modifiedMask);
    }
    return SIGILHOOK_OK;
}
} // namespace

namespace {
struct NativeValueDesc {
    char kind = 'v';
    uint8_t width = 0;
    uint8_t alignment = 1;
    uint32_t offset = 0;
    uint32_t size = 0;
};

struct NativeSignature {
    NativeValueDesc returnValue{};
    std::vector<NativeValueDesc> arguments;
};

std::string trimNative(const std::string& value) {
    const size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseNativeUnsigned(const std::string& value, uint32_t* out) {
    if (value.empty() || out == nullptr) return false;
    uint32_t result = 0;
    for (char ch : value) {
        if (ch < '0' || ch > '9' || result > (UINT32_MAX - static_cast<uint32_t>(ch - '0')) / 10) return false;
        result = result * 10 + static_cast<uint32_t>(ch - '0');
    }
    *out = result;
    return true;
}

bool parseNativeValue(const std::string& text, NativeValueDesc* out) {
    if (out == nullptr) return false;
    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t end = text.find(',', start);
        fields.push_back(trimNative(text.substr(start, end == std::string::npos ? std::string::npos : end - start)));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (fields.size() != 5 || fields[0].size() != 1) return false;
    const char kind = fields[0][0];
    if (!strchr("vidupr", kind) && kind != 'f' && kind != 'd' && kind != 'w' && kind != 's') return false;
    uint32_t width = 0, alignment = 0, offset = 0, size = 0;
    if (!parseNativeUnsigned(fields[1], &width) || !parseNativeUnsigned(fields[2], &alignment) ||
        !parseNativeUnsigned(fields[3], &offset) || !parseNativeUnsigned(fields[4], &size)) return false;
    if (alignment == 0 || alignment > 64 || width > 64 || size > (1u << 20) || offset > (1u << 20)) return false;
    out->kind = kind;
    out->width = static_cast<uint8_t>(width);
    out->alignment = static_cast<uint8_t>(alignment);
    out->offset = offset;
    out->size = size;
    return true;
}

bool parseNativeSignature(const std::string& text, NativeSignature* out) {
    if (out == nullptr) return false;
    const size_t argsMarker = text.find(";args=");
    if (argsMarker == std::string::npos || text.compare(0, 4, "ret=") != 0) return false;
    if (!parseNativeValue(text.substr(4, argsMarker - 4), &out->returnValue)) return false;
    out->arguments.clear();
    const std::string args = text.substr(argsMarker + 6);
    if (args.empty()) return true;
    size_t start = 0;
    while (start <= args.size()) {
        const size_t end = args.find('|', start);
        NativeValueDesc value{};
        if (!parseNativeValue(args.substr(start, end == std::string::npos ? std::string::npos : end - start), &value)) return false;
        out->arguments.push_back(value);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return true;
}

bool sameNativeValue(const NativeValueDesc& left, const NativeValueDesc& right) {
    return left.kind == right.kind && left.width == right.width &&
        left.alignment == right.alignment && left.offset == right.offset && left.size == right.size;
}

bool sameNativeSignature(const NativeSignature& left, const NativeSignature& right) {
    if (!sameNativeValue(left.returnValue, right.returnValue) || left.arguments.size() != right.arguments.size()) return false;
    for (size_t index = 0; index < left.arguments.size(); ++index) {
        if (!sameNativeValue(left.arguments[index], right.arguments[index])) return false;
    }
    return true;
}

asmjit::TypeId nativeTypeId(const NativeValueDesc& value) {
    switch (value.kind) {
    case 'f': return value.width == 8 ? asmjit::TypeId::kFloat64 : asmjit::TypeId::kFloat32;
    case 'd': return asmjit::TypeId::kFloat64;
    case 'p': case 's': case 'w': return asmjit::TypeId::kUIntPtr;
    case 'u':
        if (value.width == 1) return asmjit::TypeId::kUInt8;
        if (value.width == 2) return asmjit::TypeId::kUInt16;
        if (value.width == 4) return asmjit::TypeId::kUInt32;
        return asmjit::TypeId::kUInt64;
    case 'i':
        if (value.width == 1) return asmjit::TypeId::kInt8;
        if (value.width == 2) return asmjit::TypeId::kInt16;
        if (value.width == 4) return asmjit::TypeId::kInt32;
        return asmjit::TypeId::kInt64;
    default:
        if (value.width == 1) return asmjit::TypeId::kUInt8;
        if (value.width == 2) return asmjit::TypeId::kUInt16;
        if (value.width == 4) return asmjit::TypeId::kUInt32;
        return asmjit::TypeId::kUInt64;
    }
}

bool nativeRecordRegisterSize(uint32_t width) {
    return width == 1 || width == 2 || width == 4 || width == 8;
}

bool nativeIsVector(const NativeValueDesc& value) {
    return value.kind == 'f' || value.kind == 'd';
}

uint64_t readNativeBlobValue(const void* blob, size_t blobSize, const NativeValueDesc& value) {
    if (blob == nullptr || value.offset > blobSize || value.size > blobSize - value.offset || value.size == 0) return 0;
    uint64_t result = 0;
    std::memcpy(&result, static_cast<const uint8_t*>(blob) + value.offset, std::min<size_t>(value.size, sizeof(result)));
    return result;
}

void writeNativeBlobValue(void* blob, size_t blobSize, const NativeValueDesc& value, uint64_t data) {
    if (blob == nullptr || value.offset > blobSize || value.size > blobSize - value.offset || value.size == 0) return;
    std::memcpy(static_cast<uint8_t*>(blob) + value.offset, &data, std::min<size_t>(value.size, sizeof(data)));
}

struct NativeInvokerRecord {
    void* allocation = nullptr;
    size_t size = 0;
};
std::mutex g_nativeInvokerMutex;
std::unordered_map<std::string, NativeInvokerRecord> g_nativeInvokers;

void freeNativeInvoker(NativeInvokerRecord& record) {
#if defined(_WIN32)
    if (record.allocation != nullptr) VirtualFree(record.allocation, 0, MEM_RELEASE);
#endif
    record = {};
}

uint64_t allocateNativeCode(asmjit::CodeHolder& code) {
    if (code.flatten() != asmjit::kErrorOk || code.resolveCrossSectionFixups() != asmjit::kErrorOk) return 0;
    const size_t size = code.codeSize();
    if (size == 0) return 0;
#if defined(_WIN32)
    void* memory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (memory == nullptr) return 0;
    if (code.relocateToBase(reinterpret_cast<uint64_t>(memory)) != asmjit::kErrorOk) {
        VirtualFree(memory, 0, MEM_RELEASE);
        return 0;
    }
    code.copyFlattenedData(static_cast<uint8_t*>(memory), size);
    return reinterpret_cast<uint64_t>(memory);
#else
    return 0;
#endif
}

struct NativeTargetArg {
    NativeValueDesc source{};
    asmjit::TypeId type = asmjit::TypeId::kVoid;
    uint32_t sourceOffset = 0;
    bool pointerToSource = false;
    bool hiddenReturn = false;
};

bool buildNativeInvoker(const NativeSignature& signature, const std::string& convention, uint64_t target, uint64_t* outAddress) {
    if (outAddress == nullptr || target == 0) return false;
    if (convention.rfind("usercall", 0) == 0) return false;
    asmjit::CallConvId callConv = asmjit::CallConvId::kCDecl;
    const std::string normalized = trimNative(convention);
    if (normalized == "stdcall" || normalized == "__stdcall") callConv = asmjit::CallConvId::kStdCall;
    else if (normalized == "fastcall" || normalized == "__fastcall") callConv = asmjit::CallConvId::kFastCall;
    else if (normalized == "thiscall" || normalized == "__thiscall") callConv = asmjit::CallConvId::kThisCall;
    else if (normalized == "vectorcall" || normalized == "__vectorcall") callConv = asmjit::CallConvId::kVectorCall;
    else if (!normalized.empty() && normalized != "cdecl" && normalized != "__cdecl") return false;

    const bool recordByReference = currentMode() == SIGILHOOK::Mode::x64 &&
        !nativeRecordRegisterSize(signature.returnValue.width);
    const bool hiddenReturn = signature.returnValue.kind == 'r' &&
        (currentMode() == SIGILHOOK::Mode::x64
            ? recordByReference
            : signature.returnValue.width > 4 && signature.returnValue.width != 8);
    const asmjit::TypeId returnTypeId = hiddenReturn || signature.returnValue.kind == 'v'
        ? asmjit::TypeId::kVoid : nativeTypeId(signature.returnValue);
    asmjit::FuncSignature targetSignature(callConv, asmjit::FuncSignature::kNoVarArgs, returnTypeId);
    std::vector<NativeTargetArg> plans;
    if (hiddenReturn) {
        targetSignature.addArg(asmjit::TypeId::kUIntPtr);
        NativeTargetArg hidden{};
        hidden.hiddenReturn = true;
        plans.push_back(hidden);
    }
    for (const NativeValueDesc& argument : signature.arguments) {
        if (argument.kind == 'r') {
            const bool passedByReference = currentMode() == SIGILHOOK::Mode::x64 &&
                !nativeRecordRegisterSize(argument.width);
            if (passedByReference) {
                targetSignature.addArg(asmjit::TypeId::kUIntPtr);
                NativeTargetArg plan{argument, asmjit::TypeId::kUIntPtr, argument.offset, true, false};
                plans.push_back(plan);
                continue;
            }
            uint32_t consumed = 0;
            while (consumed < argument.width) {
                const uint32_t chunk = std::min<uint32_t>(currentMode() == SIGILHOOK::Mode::x86 ? 4 : 8, argument.width - consumed);
                NativeValueDesc chunkDesc = argument;
                chunkDesc.kind = 'u';
                chunkDesc.width = static_cast<uint8_t>(chunk);
                chunkDesc.size = chunk;
                const asmjit::TypeId type = nativeTypeId(chunkDesc);
                targetSignature.addArg(type);
                plans.push_back({chunkDesc, type, argument.offset + consumed, false, false});
                consumed += chunk;
            }
            continue;
        }
        const asmjit::TypeId type = nativeTypeId(argument);
        targetSignature.addArg(type);
        plans.push_back({argument, type, argument.offset, false, false});
    }

    asmjit::Environment environment = asmjit::Environment::host();
    environment.setArch(asmjit::Arch::kHost);
    asmjit::CodeHolder code;
    if (code.init(environment) != asmjit::kErrorOk) return false;
    asmjit::StringLogger logger;
    code.setLogger(&logger);
    asmjit::x86::Compiler compiler(&code);
    asmjit::x86::Gp argumentBase = compiler.newUIntPtr("argumentBase");
    asmjit::x86::Gp returnBase = compiler.newUIntPtr("returnBase");
    asmjit::x86::Mem hiddenReturnBuffer;
    if (hiddenReturn) {
        hiddenReturnBuffer = compiler.newStack(signature.returnValue.width, 8);
    }
    asmjit::FuncNode* function = compiler.addFunc(asmjit::FuncSignature::build<void, const void*, void*>());
    function->setArg(0, argumentBase);
    function->setArg(1, returnBase);

    std::vector<asmjit::Reg> preparedArgs;
    preparedArgs.reserve(plans.size());
    for (const NativeTargetArg& plan : plans) {
        if (plan.hiddenReturn) {
            asmjit::x86::Gp pointer = compiler.newUIntPtr();
            compiler.lea(pointer, hiddenReturnBuffer);
            preparedArgs.push_back(pointer);
            continue;
        }
        asmjit::x86::Mem source = asmjit::x86::ptr(argumentBase, static_cast<int32_t>(plan.sourceOffset));
        source.setSize(plan.source.size == 0 ? plan.source.width : plan.source.size);
        if (plan.pointerToSource) {
            asmjit::x86::Gp pointer = compiler.newUIntPtr();
            compiler.lea(pointer, asmjit::x86::ptr(argumentBase, static_cast<int32_t>(plan.sourceOffset)));
            preparedArgs.push_back(pointer);
        } else if (nativeIsVector(plan.source)) {
            asmjit::x86::Vec value = compiler.newXmm();
            if (plan.source.width == 8) compiler.movq(value, source); else compiler.movd(value, source);
            preparedArgs.push_back(value);
        } else {
            asmjit::x86::Gp value = compiler.newGp(plan.type);
            compiler.mov(value, source);
            preparedArgs.push_back(value);
        }
    }
    asmjit::InvokeNode* invocation = nullptr;
    if (compiler.invoke(&invocation, asmjit::Imm(static_cast<int64_t>(target)), targetSignature) != asmjit::kErrorOk) return false;
    for (size_t index = 0; index < preparedArgs.size(); ++index) invocation->setArg(index, preparedArgs[index]);

    if (hiddenReturn) {
        for (uint32_t offset = 0; offset < signature.returnValue.width; ++offset) {
            asmjit::x86::Gp value = compiler.newGp(asmjit::TypeId::kUInt8);
            compiler.movzx(value, hiddenReturnBuffer.cloneAdjusted(offset).cloneResized(1));
            compiler.mov(asmjit::x86::ptr(returnBase, static_cast<int32_t>(offset)).cloneResized(1), value);
        }
    }

    if (!hiddenReturn && signature.returnValue.kind != 'v' && signature.returnValue.width != 0 && invocation->hasRet()) {
        const size_t count = invocation->detail().retPack().count();
        for (size_t index = 0; index < count; ++index) {
            const asmjit::TypeId resultType = count == 1
                ? nativeTypeId(signature.returnValue)
                : asmjit::TypeId::kUInt32;
            asmjit::x86::Gp returnedGp = compiler.newGp(resultType);
            invocation->setRet(index, returnedGp);
            asmjit::Operand value = returnedGp;
            if (!value.isReg()) continue;
            uint32_t storeOffset = 0;
            uint32_t storeWidth = signature.returnValue.width;
            if (count > 1) {
                storeOffset = static_cast<uint32_t>(index * 4);
                storeWidth = std::min<uint32_t>(4, signature.returnValue.width - storeOffset);
            }
            if (storeWidth == 0 || storeOffset >= signature.returnValue.width) continue;
            asmjit::x86::Mem destination = asmjit::x86::ptr(returnBase, static_cast<int32_t>(storeOffset));
            destination.setSize(storeWidth);
            const asmjit::Reg returnedRegister = value.as<asmjit::Reg>();
            if (returnedRegister.isGp()) {
                compiler.mov(destination, value.as<asmjit::x86::Gp>());
            } else if (returnedRegister.isVec() && nativeIsVector(signature.returnValue)) {
                if (storeWidth == 8) compiler.movq(destination, value.as<asmjit::x86::Vec>());
                else compiler.movd(destination, value.as<asmjit::x86::Vec>());
            }
        }
    }
    compiler.ret();
    if (compiler.endFunc() != asmjit::kErrorOk || compiler.finalize() != asmjit::kErrorOk) return false;
    const uint64_t address = allocateNativeCode(code);
    if (address == 0) return false;
    NativeInvokerRecord record{reinterpret_cast<void*>(static_cast<uintptr_t>(address)), code.codeSize()};
    *outAddress = address;
    return true;
}

} // namespace

extern "C" {
sigilhook_status SIGILHOOK_CALL sigilhook_compute_cmp_flags(
    uint64_t left, uint64_t right, uint8_t operandSize, uint64_t* outFlags) {
    return computeFlags(left, right, operandSize, false, outFlags);
}

sigilhook_status SIGILHOOK_CALL sigilhook_compute_test_flags(
    uint64_t left, uint64_t right, uint8_t operandSize, uint64_t* outFlags) {
    return computeFlags(left, right, operandSize, true, outFlags);
}

sigilhook_status SIGILHOOK_CALL sigilhook_fxsave(void* buffer, size_t size) {
    if (buffer == nullptr || size != 512) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "FXSAVE requires a 512-byte buffer");
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    alignas(16) uint8_t state[512]{};
    _fxsave(state);
    std::memcpy(buffer, state, sizeof(state));
    return SIGILHOOK_OK;
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "FXSAVE is only implemented for MSVC x86/x64 builds");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_fxrstor(const void* buffer, size_t size) {
    if (buffer == nullptr || size != 512) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "FXRSTOR requires a 512-byte buffer");
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    alignas(16) uint8_t state[512]{};
    std::memcpy(state, buffer, sizeof(state));
    _fxrstor(state);
    return SIGILHOOK_OK;
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "FXRSTOR is only implemented for MSVC x86/x64 builds");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_return_snippet(
    uint64_t stackAdjust, uint64_t* outAddress) {
    if (stackAdjust > UINT16_MAX) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Return stack adjustment exceeds 65535 bytes");
    return makeSnippet([stackAdjust](asmjit::x86::Assembler& assembler) {
        if (stackAdjust == 0) assembler.ret();
        else assembler.ret(static_cast<uint16_t>(stackAdjust));
    }, outAddress);
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_stack_jump_snippet(
    uint64_t stackPointer, uint64_t target, uint64_t* outAddress) {
    if (stackPointer == 0 || target == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Stack pointer and jump target are required");
    }
    if (currentMode() != SIGILHOOK::Mode::x64 && (stackPointer > UINT32_MAX || target > UINT32_MAX)) {
        return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "Stack jump values do not fit in x86");
    }
    return makeSnippet([stackPointer, target](asmjit::x86::Assembler& assembler) {
        if (currentMode() == SIGILHOOK::Mode::x64) {
            assembler.mov(asmjit::x86::rsp, stackPointer);
            assembler.jmp(asmjit::Imm(target));
        } else {
            assembler.mov(asmjit::x86::esp, static_cast<uint32_t>(stackPointer));
            assembler.jmp(asmjit::Imm(static_cast<uint32_t>(target)));
        }
    }, outAddress);
}

sigilhook_status SIGILHOOK_CALL sigilhook_destroy_snippet(uint64_t address) {
    if (address == 0 || address > UINTPTR_MAX) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Snippet address is invalid");
    }
    std::lock_guard lock(g_snippetMutex);
    if (g_snippetAddresses.erase(address) == 0) {
        return fail(SIGILHOOK_ERROR_NOT_FOUND, "Snippet address was not allocated by SigilHook");
    }
    if (g_snippetRuntime.release(reinterpret_cast<void*>(static_cast<uintptr_t>(address))) != asmjit::kErrorOk) {
        return fail(SIGILHOOK_ERROR_NOT_FOUND, "Snippet address was not allocated by SigilHook");
    }
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_invoke_usercall(
    uint64_t target, const char* returnType, const char* commaSeparatedParameters,
    const char* callConvention, const uint64_t* arguments, size_t argumentCount,
    uint64_t* outReturnValue) {
    if (target == 0 || returnType == nullptr || callConvention == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Target, return type, and usercall mapping are required");
    }
    const std::vector<std::string> parameterTypes =
        splitParameters(commaSeparatedParameters == nullptr ? "" : commaSeparatedParameters);
    if (parameterTypes.size() != argumentCount || (argumentCount != 0 && arguments == nullptr)) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Usercall argument count does not match the parameter signature");
    }
    const std::string key =
        std::to_string(target) + "|" + returnType + "|" +
        (commaSeparatedParameters == nullptr ? "" : commaSeparatedParameters) + "|" + callConvention;
    InvokerRecord invoker;
    {
        std::lock_guard lock(g_invokerMutex);
        const auto iterator = g_invokers.find(key);
        if (iterator != g_invokers.end()) {
            invoker = iterator->second;
        } else {
            invoker.callback = std::make_shared<SIGILHOOK::ILCallback>();
            invoker.address = invoker.callback->getInvokeJitFunc(
                returnType, parameterTypes, target, callConvention);
            if (invoker.address == 0) {
                return fail(invoker.callback->lastErrorStatus(), invoker.callback->lastError());
            }
            g_invokers.emplace(key, invoker);
        }
    }
    uint64_t dummyArgument = 0;
    const uint64_t* actualArguments = arguments == nullptr ? &dummyArgument : arguments;
    const auto invoke = reinterpret_cast<SIGILHOOK::ILCallback::tInvokeCallback>(invoker.address);
    const uint64_t result = invoke(actualArguments);
    if (outReturnValue != nullptr) *outReturnValue = result;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_clear_invoker_cache(void) {
    std::unordered_map<std::string, InvokerRecord> discardedUsercall;
    {
        std::lock_guard lock(g_invokerMutex);
        discardedUsercall.swap(g_invokers);
    }
    std::unordered_map<std::string, NativeInvokerRecord> discardedNative;
    {
        std::lock_guard lock(g_nativeInvokerMutex);
        discardedNative.swap(g_nativeInvokers);
    }
    for (auto& entry : discardedNative) freeNativeInvoker(entry.second);
    return SIGILHOOK_OK;
}
} // extern "C"
#if defined(_WIN32)
struct NativeModuleRecord { HMODULE handle = nullptr; uint32_t references = 0; };
std::mutex g_nativeModuleMutex;
std::unordered_map<std::wstring, NativeModuleRecord> g_nativeModules;
std::unordered_map<std::string, uint64_t> g_nativeAddressCache;
std::mutex g_nativeAddressMutex;
uint64_t lookupNativeAddress(const std::string& key) {
    std::lock_guard lock(g_nativeAddressMutex);
    const auto iterator = g_nativeAddressCache.find(key);
    return iterator == g_nativeAddressCache.end() ? 0 : iterator->second;
}
std::wstring nativeLower(std::wstring value) { std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); }); return value; }
std::filesystem::path nativeSelfDirectory() { HMODULE self = nullptr; if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCWSTR>(&sigilhook_api_version), &self) || self == nullptr) return {}; wchar_t buffer[32768]{}; const DWORD length = GetModuleFileNameW(self, buffer, static_cast<DWORD>(std::size(buffer))); if (length == 0 || length >= std::size(buffer)) return {}; return std::filesystem::path(buffer).parent_path(); }
std::filesystem::path resolveNativeModulePath(const char* dllName) {
    std::filesystem::path path;
    if (dllName != nullptr && *dllName != '\0') {
        path = std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(dllName)));
    }
    if (path.is_relative()) path = nativeSelfDirectory() / path;
    std::error_code error;
    const auto canonical = std::filesystem::weakly_canonical(path, error);
    return error ? path.lexically_normal() : canonical;
}
bool nativePeCompatible(HMODULE handle) {
    if (handle == nullptr) return false;
    const auto* base = reinterpret_cast<const uint8_t*>(handle);
    const uint16_t dosSignature = *reinterpret_cast<const uint16_t*>(base);
    if (dosSignature != IMAGE_DOS_SIGNATURE) return false;
    const uint32_t ntOffset = *reinterpret_cast<const uint32_t*>(base + 0x3c);
    if (ntOffset > 0x10000000u || ntOffset + 6 > 0x10000000u) return false;
    const auto* nt = base + ntOffset;
    if (*reinterpret_cast<const uint32_t*>(nt) != IMAGE_NT_SIGNATURE) return false;
    const uint16_t machine = *reinterpret_cast<const uint16_t*>(nt + 4);
#if defined(_WIN64)
    return machine == IMAGE_FILE_MACHINE_AMD64;
#else
    return machine == IMAGE_FILE_MACHINE_I386;
#endif
}
#endif
std::string nativeTypeName(const NativeValueDesc& value) { if (value.kind == 'v') return "void"; if (value.kind == 'p' || value.kind == 's' || value.kind == 'w') return "void*"; if (value.kind == 'f') return value.width == 8 ? "double" : "float"; if (value.kind == 'd') return "double"; if (value.kind == 'r') return value.width <= 4 ? "uint32" : "uint64"; const char* prefix = value.kind == 'i' ? "int" : "uint"; return std::string(prefix) + std::to_string(value.width * 8); }
#include <filesystem>
#include <cstdlib>
#include <cstdio>
extern "C" {
#if defined(_WIN32)
sigilhook_status SIGILHOOK_CALL sigilhook_module_load(const char* dll_name, uint64_t* out_module) {
    if (dll_name == nullptr || *dll_name == '\0' || out_module == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "DLL name and module output are required");
    const std::filesystem::path path = resolveNativeModulePath(dll_name);
    if (path.empty()) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Cannot resolve DLL path");
#if defined(_WIN32)
    DWORD binaryType = 0;
    if (GetBinaryTypeW(path.c_str(), &binaryType)) {
#if defined(_WIN64)
        const DWORD expectedType = 6; // SCS_64BIT_BINARY
#else
        const DWORD expectedType = 0; // SCS_32BIT_BINARY
#endif
        if (binaryType != expectedType) return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "DLL architecture does not match SigilHook: " + path.string());
    }
#endif
    const std::wstring key = nativeLower(path.wstring());
    {
        std::lock_guard lock(g_nativeModuleMutex);
        const auto existing = g_nativeModules.find(key);
        if (existing != g_nativeModules.end()) {
            if (existing->second.references == UINT32_MAX) return fail(SIGILHOOK_ERROR_BUSY, "DLL reference count overflow");
            ++existing->second.references;
            *out_module = reinterpret_cast<uint64_t>(existing->second.handle);
            return SIGILHOOK_OK;
        }
    }
    HMODULE handle = LoadLibraryW(path.c_str());
    if (handle == nullptr) return fail(SIGILHOOK_ERROR_NOT_FOUND, "LoadLibraryW failed for " + path.string());
    if (!nativePeCompatible(handle)) {
        FreeLibrary(handle);
        return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "DLL architecture does not match SigilHook");
    }
    {
        std::lock_guard lock(g_nativeModuleMutex);
        const auto inserted = g_nativeModules.emplace(key, NativeModuleRecord{handle, 1});
        if (!inserted.second) {
            FreeLibrary(handle);
            ++inserted.first->second.references;
            handle = inserted.first->second.handle;
        }
    }
    *out_module = reinterpret_cast<uint64_t>(handle);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_module_export(uint64_t module, const char* export_name, uint64_t* out_address) {
    if (module == 0 || export_name == nullptr || *export_name == '\0' || out_address == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Module, export name, and output are required");
    HMODULE handle = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(module));
    FARPROC address = GetProcAddress(handle, export_name);
        if (address == nullptr) {
            for (uint32_t bytes = 0; bytes <= 128 && address == nullptr; ++bytes) {
                const std::string decorated = "_" + std::string(export_name) + "@" + std::to_string(bytes);
                address = GetProcAddress(handle, decorated.c_str());
            }
        }
        if (address == nullptr) address = GetProcAddress(handle, ("_" + std::string(export_name)).c_str());
        if (address == nullptr) {
            for (uint32_t bytes = 0; bytes <= 256 && address == nullptr; ++bytes) {
                const std::string decorated = std::string(export_name) + "@@" + std::to_string(bytes);
                address = GetProcAddress(handle, decorated.c_str());
            }
        }
        if (address == nullptr) {
            for (uint32_t bytes = 0; bytes <= 128 && address == nullptr; ++bytes) {
                const std::string decorated = "@" + std::string(export_name) + "@" + std::to_string(bytes);
                address = GetProcAddress(handle, decorated.c_str());
            }
        }
    if (address == nullptr) return fail(SIGILHOOK_ERROR_NOT_FOUND, "DLL export not found: " + std::string(export_name));
    *out_address = reinterpret_cast<uint64_t>(address);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_module_free(uint64_t module) {
    if (module == 0) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Module handle is required");
    std::lock_guard lock(g_nativeModuleMutex);
    for (auto iterator = g_nativeModules.begin(); iterator != g_nativeModules.end(); ++iterator) {
        if (reinterpret_cast<uint64_t>(iterator->second.handle) != module) continue;
        if (iterator->second.references > 1) {
            --iterator->second.references;
            return SIGILHOOK_OK;
        }
        FreeLibrary(iterator->second.handle);
        g_nativeModules.erase(iterator);
        std::unordered_map<std::string, uint64_t> discardedAddresses;
        {
            std::lock_guard addressLock(g_nativeAddressMutex);
            discardedAddresses.swap(g_nativeAddressCache);
        }
        return SIGILHOOK_OK;
    }
    return fail(SIGILHOOK_ERROR_NOT_FOUND, "Module was not loaded by SigilHook");
}

sigilhook_status SIGILHOOK_CALL sigilhook_modules_shutdown(void) {
    std::unordered_map<std::string, uint64_t> addresses;
    {
        std::lock_guard lock(g_nativeAddressMutex);
        addresses.swap(g_nativeAddressCache);
    }
    std::unordered_map<std::wstring, NativeModuleRecord> modules;
    {
        std::lock_guard lock(g_nativeModuleMutex);
        modules.swap(g_nativeModules);
    }
    for (auto& entry : modules) FreeLibrary(entry.second.handle);
    return SIGILHOOK_OK;
}
}

extern "C" {
sigilhook_status SIGILHOOK_CALL sigilhook_native_address(const char* dll_name, const char* export_name, const char* call_convention, uint64_t* out_address) {
    if (dll_name == nullptr || export_name == nullptr || call_convention == nullptr || out_address == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "DLL, export, convention, and address output are required");
    const std::string key = std::string(dll_name) + "|" + export_name + "|" + call_convention;
    if (const uint64_t cached = lookupNativeAddress(key); cached != 0) {
        *out_address = cached;
        return SIGILHOOK_OK;
    }
    uint64_t module = 0;
    sigilhook_status status = sigilhook_module_load(dll_name, &module);
    if (status != SIGILHOOK_OK) return status;
    status = sigilhook_module_export(module, export_name, out_address);
    if (status != SIGILHOOK_OK) {
        sigilhook_module_free(module);
        return status;
    }
    {
        std::lock_guard lock(g_nativeAddressMutex);
        const auto inserted = g_nativeAddressCache.emplace(key, *out_address);
        if (!inserted.second) *out_address = inserted.first->second;
    }
    return SIGILHOOK_OK;
}
}
#else
sigilhook_status SIGILHOOK_CALL sigilhook_module_load(const char*, uint64_t*) { return fail(SIGILHOOK_ERROR_UNSUPPORTED, "DLL loading is Windows-only"); }
sigilhook_status SIGILHOOK_CALL sigilhook_module_export(uint64_t, const char*, uint64_t*) { return fail(SIGILHOOK_ERROR_UNSUPPORTED, "DLL loading is Windows-only"); }
sigilhook_status SIGILHOOK_CALL sigilhook_module_free(uint64_t) { return fail(SIGILHOOK_ERROR_UNSUPPORTED, "DLL loading is Windows-only"); }
sigilhook_status SIGILHOOK_CALL sigilhook_modules_shutdown(void) { return SIGILHOOK_OK; }
sigilhook_status SIGILHOOK_CALL sigilhook_native_address(const char*, const char*, const char*, uint64_t*) { return fail(SIGILHOOK_ERROR_UNSUPPORTED, "DLL loading is Windows-only"); }
#endif

extern "C" {
sigilhook_status SIGILHOOK_CALL sigilhook_invoke_native_blob(
    uint64_t target, const char* return_signature, const char* argument_signature,
    const char* call_convention, const void* argument_blob, size_t argument_size,
    void* return_blob, size_t return_size) {
    if (target == 0 || return_signature == nullptr || call_convention == nullptr ||
        (argument_size != 0 && argument_blob == nullptr) || (return_size != 0 && return_blob == nullptr)) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Native target, signatures, and blobs are required");
    }
    NativeSignature signature{};
    if (!parseNativeSignature(return_signature, &signature)) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Malformed native signature");
    NativeSignature argumentSignature{};
    if (argument_signature == nullptr || !parseNativeSignature(argument_signature, &argumentSignature) ||
        !sameNativeSignature(signature, argumentSignature)) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Return and argument signatures do not match");
    }
    if (signature.returnValue.size != 0 && (return_blob == nullptr || return_size < signature.returnValue.size)) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Return blob is too small");
    for (const NativeValueDesc& argument : signature.arguments) {
        if (argument.offset > argument_size || argument.size > argument_size - argument.offset) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Argument blob is too small");
    }
    const std::string convention = trimNative(call_convention);
    if (convention.rfind("usercall", 0) == 0) {
        if (signature.returnValue.kind == 'f' || signature.returnValue.kind == 'd') return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Floating-point usercall returns are not supported");
        std::vector<uint64_t> values;
        std::vector<std::string> types;
        for (const NativeValueDesc& argument : signature.arguments) {
            if (argument.kind == 'f' || argument.kind == 'd') return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Floating-point usercall arguments are not supported");
            if (argument.kind == 'r' && argument.width > 8) return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Wide record usercall arguments are not supported");
            values.push_back(readNativeBlobValue(argument_blob, argument_size, argument));
            types.push_back(nativeTypeName(argument));
        }
        std::string parameterText;
        for (size_t index = 0; index < types.size(); ++index) {
            if (index != 0) parameterText += ',';
            parameterText += types[index];
        }
        uint64_t result = 0;
        const sigilhook_status status = sigilhook_invoke_usercall(target, nativeTypeName(signature.returnValue).c_str(), parameterText.c_str(), convention.c_str(), values.data(), values.size(), &result);
        if (status == SIGILHOOK_OK) writeNativeBlobValue(return_blob, return_size, signature.returnValue, result);
        return status;
    }

    const std::string key = std::to_string(target) + "|" + return_signature + "|" + convention;
    uint64_t invoker = 0;
    NativeInvokerRecord record{};
    {
        std::lock_guard lock(g_nativeInvokerMutex);
        const auto existing = g_nativeInvokers.find(key);
        if (existing != g_nativeInvokers.end()) invoker = reinterpret_cast<uint64_t>(existing->second.allocation);
    }
    if (invoker == 0) {
        if (!buildNativeInvoker(signature, convention, target, &invoker)) {
            return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Native signature cannot be generated for this ABI");
        }
        record.allocation = reinterpret_cast<void*>(static_cast<uintptr_t>(invoker));
        record.size = 0;
        std::lock_guard lock(g_nativeInvokerMutex);
        g_nativeInvokers.emplace(key, record);
    }
    const auto invoke = reinterpret_cast<void(*)(const void*, void*)>(static_cast<uintptr_t>(invoker));
    invoke(argument_blob, return_blob);
    return SIGILHOOK_OK;
}
} // extern "C"
extern "C" {
sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_get_xmm(
    const sigilhook_call_frame* frame, uint8_t reg, uint8_t lane, uint64_t* outValue) {
    if (frame == nullptr || frame->xmm == nullptr || outValue == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame, XMM context, and output are required");
    }
    if (reg >= SIGILHOOK_XMM_COUNT || lane >= 2) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "XMM register or lane is out of range");
    }
    if (currentMode() != SIGILHOOK::Mode::x64 && reg >= 8) {
        return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "XMM8-XMM15 are unavailable in x86 callback frames");
    }
    *outValue = frame->xmm->values[reg][lane];
    return SIGILHOOK_OK;
}
sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_set_xmm(
    sigilhook_call_frame* frame, uint8_t reg, uint8_t lane, uint64_t value) {
    if (frame == nullptr || frame->xmm == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Frame and XMM context are required");
    }
    if (reg >= SIGILHOOK_XMM_COUNT || lane >= 2) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "XMM register or lane is out of range");
    }
    if (currentMode() != SIGILHOOK::Mode::x64 && reg >= 8) {
        return fail(SIGILHOOK_ERROR_ARCH_MISMATCH, "XMM8-XMM15 are unavailable in x86 callback frames");
    }
    frame->xmm->values[reg][lane] = value;
    frame->xmm->write_mask |= uint64_t{1} << reg;
    return SIGILHOOK_OK;
}
}
