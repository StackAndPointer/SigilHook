#include "include/sigilhook.h"

#include "polyhook2/Detour/ILCallback.hpp"
#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/Detour/x86Detour.hpp"
#include "polyhook2/Exceptions/BreakPointHook.hpp"
#include "polyhook2/Exceptions/HWBreakPointHook.hpp"
#include "polyhook2/MemAccessor.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/PE/EatHook.hpp"
#include "polyhook2/PE/IatHook.hpp"
#include "polyhook2/Virtuals/VFuncSwapHook.hpp"
#include "polyhook2/Virtuals/VTableSwapHook.hpp"

#include <array>
#include <cstring>
#include <mutex>
#include <new>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace {

thread_local std::string g_lastError;

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

PLH::Mode currentMode() {
#if defined(POLYHOOK2_ARCH_X64)
    return PLH::Mode::x64;
#else
    return PLH::Mode::x86;
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
    std::wstring result(static_cast<size_t>(size - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text, -1, result.data(), size);
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
    std::unique_ptr<PLH::ILCallback> callback;
    sigilhook_jit_callback userCallback = nullptr;
    size_t slot = 32;
    void* userData = nullptr;
    uint64_t codeAddress = 0;
};

struct HookRecord {
    std::unique_ptr<PLH::IHook> hook;
    std::shared_ptr<JitRecord> jit;
    uint64_t trampoline = 0;
    PLH::VFuncMap originalVFuncs;
    sigilhook_hook_type type = SIGILHOOK_HOOK_UNKNOWN;
};

std::mutex g_registryMutex;
std::unordered_map<uint64_t, std::unique_ptr<HookRecord>> g_hooks;
std::unordered_map<uint64_t, std::shared_ptr<JitRecord>> g_jits;
std::atomic<uint64_t> g_nextKey{1};

constexpr size_t kJitSlotCount = 32;
std::array<std::atomic<JitRecord*>, kJitSlotCount> g_jitSlots{};

void dispatchJitSlot(size_t slot, const PLH::ILCallback::Parameters* parameters, uint8_t count, const PLH::ILCallback::ReturnValue* returnValue) {
    JitRecord* record = slot < kJitSlotCount ? g_jitSlots[slot].load(std::memory_order_acquire) : nullptr;
    if (record == nullptr || !record->userCallback) return;
    std::vector<uint64_t> arguments(count);
    for (uint8_t index = 0; index < count; ++index) arguments[index] = parameters->getArg<uint64_t>(index);
    uint64_t result = returnValue->m_retVal;
    uint8_t callOriginal = 1;
    sigilhook_call_frame frame{arguments.data(), count, &result, &callOriginal};
    record->userCallback(&frame, record->userData);
    std::memcpy(returnValue->getRetPtr(), &result, sizeof(result));
}

template<size_t Slot>
void dispatchJitTemplate(const PLH::ILCallback::Parameters* parameters, uint8_t count, const PLH::ILCallback::ReturnValue* returnValue) {
    dispatchJitSlot(Slot, parameters, count, returnValue);
}

template<size_t... Slots>
std::array<PLH::ILCallback::tUserCallback, sizeof...(Slots)> makeJitDispatchers(std::index_sequence<Slots...>) {
    return {&dispatchJitTemplate<Slots>...};
}

const auto g_jitDispatchers = makeJitDispatchers(std::make_index_sequence<kJitSlotCount>{});

PLH::VFuncMap makeVFuncMap(const sigilhook_vfunc_entry* entries, size_t count) {
    PLH::VFuncMap result;
    for (size_t index = 0; index < count; ++index) {
        result.emplace(entries[index].index, entries[index].replacement);
    }
    return result;
}

void jitDispatch(
    const PLH::ILCallback::Parameters* parameters,
    const uint8_t count,
    const PLH::ILCallback::ReturnValue* returnValue) {
#if defined(_WIN32)
    const uint64_t returnAddress = reinterpret_cast<uint64_t>(_ReturnAddress());
    std::shared_ptr<JitRecord> record;
    {
        std::lock_guard lock(g_registryMutex);
        uint64_t bestDistance = UINT64_MAX;
        for (const auto& [base, candidate] : g_jits) {
            if (returnAddress >= base && returnAddress - base < 64 * 1024 &&
                returnAddress - base < bestDistance) {
                bestDistance = returnAddress - base;
                record = candidate;
            }
        }
    }
#else
    std::shared_ptr<JitRecord> record;
#endif
    if (!record || !record->userCallback) {
        return;
    }

    std::vector<uint64_t> arguments(count);
    for (uint8_t index = 0; index < count; ++index) {
        arguments[index] = parameters->getArg<uint64_t>(index);
    }
    uint64_t result = returnValue->m_retVal;
    uint8_t callOriginal = 1;
    sigilhook_call_frame frame{
        arguments.data(), count, &result, &callOriginal
    };
    record->userCallback(&frame, record->userData);
    std::memcpy(returnValue->getRetPtr(), &result, sizeof(result));
}

HookRecord* findHook(sigilhook_handle handle) {
    std::lock_guard lock(g_registryMutex);
    const auto iterator = g_hooks.find(handle.value);
    return iterator == g_hooks.end() ? nullptr : iterator->second.get();
}

std::shared_ptr<JitRecord> findJit(sigilhook_jit_handle handle) {
    std::lock_guard lock(g_registryMutex);
    const auto iterator = g_jits.find(handle.value);
    return iterator == g_jits.end() ? nullptr : iterator->second;
}

sigilhook_status validateHook(sigilhook_handle handle, HookRecord** outRecord) {
    HookRecord* record = findHook(handle);
    if (record == nullptr || record->hook == nullptr) {
        return fail(SIGILHOOK_ERROR_NOT_FOUND, "The hook handle does not exist");
    }
    *outRecord = record;
    return SIGILHOOK_OK;
}

sigilhook_status validateDetour(sigilhook_handle handle, HookRecord** outRecord) {
    const sigilhook_status status = validateHook(handle, outRecord);
    if (status != SIGILHOOK_OK) {
        return status;
    }
    if ((*outRecord)->type != SIGILHOOK_HOOK_DETOUR) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "The operation requires a detour handle");
    }
    return SIGILHOOK_OK;
}

PLH::HookType translateType(sigilhook_hook_type type) {
    switch (type) {
    case SIGILHOOK_HOOK_DETOUR: return PLH::HookType::Detour;
    case SIGILHOOK_HOOK_IAT: return PLH::HookType::IAT;
    case SIGILHOOK_HOOK_EAT: return PLH::HookType::EAT;
    case SIGILHOOK_HOOK_VFUNC_SWAP:
    case SIGILHOOK_HOOK_VTABLE_SWAP: return PLH::HookType::VTableSwap;
    case SIGILHOOK_HOOK_SOFTWARE_BREAKPOINT:
    case SIGILHOOK_HOOK_HARDWARE_BREAKPOINT: return PLH::HookType::VEHHOOK;
    default: return PLH::HookType::UNKNOWN;
    }
}

sigilhook_hook_type translateType(PLH::HookType type) {
    switch (type) {
    case PLH::HookType::Detour: return SIGILHOOK_HOOK_DETOUR;
    case PLH::HookType::VEHHOOK: return SIGILHOOK_HOOK_SOFTWARE_BREAKPOINT;
    case PLH::HookType::VTableSwap: return SIGILHOOK_HOOK_VTABLE_SWAP;
    case PLH::HookType::IAT: return SIGILHOOK_HOOK_IAT;
    case PLH::HookType::EAT: return SIGILHOOK_HOOK_EAT;
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
        auto record = std::make_unique<HookRecord>();
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
    return 0x00020000;
}

sigilhook_mode SIGILHOOK_CALL sigilhook_build_mode(void) {
    return currentMode() == PLH::Mode::x64 ? SIGILHOOK_MODE_X64 : SIGILHOOK_MODE_X86;
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

sigilhook_status SIGILHOOK_CALL sigilhook_create_detour(
    uint64_t target, uint64_t callback, sigilhook_handle* outHook, uint64_t* outTrampoline) {
    if (target == 0 || callback == 0 || outHook == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Target, callback, and output handle are required");
    }
    if (outTrampoline != nullptr) *outTrampoline = 0;
    return createHook([&](HookRecord& record) {
        record.trampoline = 0;
#if defined(POLYHOOK2_ARCH_X64)
        record.hook = std::make_unique<PLH::x64Detour>(target, callback, &record.trampoline);
#else
        record.hook = std::make_unique<PLH::x86Detour>(target, callback, &record.trampoline);
#endif
        return true;
    }, SIGILHOOK_HOOK_DETOUR, outHook);
}

sigilhook_status SIGILHOOK_CALL sigilhook_destroy(sigilhook_handle handle) {
    std::unique_ptr<HookRecord> record;
    {
        std::lock_guard lock(g_registryMutex);
        const auto iterator = g_hooks.find(handle.value);
        if (iterator == g_hooks.end()) {
            return fail(SIGILHOOK_ERROR_NOT_FOUND, "The hook handle does not exist");
        }
        record = std::move(iterator->second);
        g_hooks.erase(iterator);
    }
    if (record && record->hook) {
        try {
            record->hook->unHook();
        } catch (...) {
        }
    }
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_hook(sigilhook_handle handle) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        return record->hook->hook() ? SIGILHOOK_OK : SIGILHOOK_ERROR_HOOK_FAILED;
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "hook() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_unhook(sigilhook_handle handle) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        return record->hook->unHook() ? SIGILHOOK_OK : SIGILHOOK_ERROR_HOOK_FAILED;
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "unhook() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_rehook(sigilhook_handle handle) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        return record->hook->reHook() ? SIGILHOOK_OK : SIGILHOOK_ERROR_HOOK_FAILED;
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "rehook() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_hooked(sigilhook_handle handle, int hooked) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    try {
        return record->hook->setHooked(hooked != 0) ? SIGILHOOK_OK : SIGILHOOK_ERROR_HOOK_FAILED;
    } catch (...) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, "setHooked() raised an exception");
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_is_hooked(sigilhook_handle handle, int* outHooked) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outHooked == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output state is null");
    *outHooked = record->hook->isHooked() ? 1 : 0;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_type(sigilhook_handle handle, sigilhook_hook_type* outType) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outType == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output type is null");
    *outType = translateType(record->hook->getType());
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_debug(sigilhook_handle handle, int enabled) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    record->hook->setDebug(enabled != 0);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_trampoline(sigilhook_handle handle, uint64_t* outTrampoline) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateHook(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outTrampoline == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output trampoline is null");
    *outTrampoline = record->trampoline;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_max_depth(sigilhook_handle handle, uint8_t* outDepth) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    if (outDepth == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output depth is null");
    *outDepth = static_cast<PLH::Detour*>(record->hook.get())->getMaxDepth();
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_max_depth(sigilhook_handle handle, uint8_t depth) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    static_cast<PLH::Detour*>(record->hook.get())->setMaxDepth(depth);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_follow_call_on_target(sigilhook_handle handle, int enabled) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
    static_cast<PLH::Detour*>(record->hook.get())->setIsFollowCallOnFnAddress(enabled != 0);
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_detour_scheme(sigilhook_handle handle, uint8_t* outScheme) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
#if defined(POLYHOOK2_ARCH_X64)
    if (outScheme == nullptr) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Output scheme is null");
    *outScheme = static_cast<uint8_t>(static_cast<PLH::x64Detour*>(record->hook.get())->getDetourScheme());
    return SIGILHOOK_OK;
#else
    (void)outScheme;
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Detour schemes are x64-only");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_set_detour_scheme(sigilhook_handle handle, uint8_t scheme) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateDetour(handle, &record);
    if (status != SIGILHOOK_OK) return status;
#if defined(POLYHOOK2_ARCH_X64)
    static_cast<PLH::x64Detour*>(record->hook.get())->setDetourScheme(
        static_cast<PLH::x64Detour::detour_scheme_t>(scheme));
    return SIGILHOOK_OK;
#else
    (void)scheme;
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Detour schemes are x64-only");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_breakpoint(
    uint64_t target, uint64_t callback, sigilhook_handle* outHook) {
#if defined(POLYHOOK2_OS_WINDOWS)
    if (target == 0 || callback == 0) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Target and callback are required");
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<PLH::BreakPointHook>(target, callback);
        return true;
    }, SIGILHOOK_HOOK_SOFTWARE_BREAKPOINT, outHook);
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Breakpoint hooks require Windows");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_hardware_breakpoint(
    uint64_t target, uint64_t callback, uintptr_t thread, sigilhook_handle* outHook) {
#if defined(POLYHOOK2_OS_WINDOWS)
    if (target == 0 || callback == 0 || thread == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Target, callback, and thread are required");
    }
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<PLH::HWBreakPointHook>(target, callback, reinterpret_cast<HANDLE>(thread));
        return true;
    }, SIGILHOOK_HOOK_HARDWARE_BREAKPOINT, outHook);
#else
    return fail(SIGILHOOK_ERROR_UNSUPPORTED, "Hardware breakpoint hooks require Windows");
#endif
}

sigilhook_status SIGILHOOK_CALL sigilhook_create_iat_hook(
    const char* importedDll, const char* importedApi, const char* moduleName,
    uint64_t callback, sigilhook_handle* outHook, uint64_t* outOriginal) {
#if defined(POLYHOOK2_OS_WINDOWS)
    if (importedDll == nullptr || importedApi == nullptr || callback == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Imported DLL, API, and callback are required");
    }
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<PLH::IatHook>(
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
#if defined(POLYHOOK2_OS_WINDOWS)
    if (exportedApi == nullptr || callback == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Exported API and callback are required");
    }
    return createHook([&](HookRecord& record) {
        record.hook = std::make_unique<PLH::EatHook>(
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
        record.hook = std::make_unique<PLH::VFuncSwapHook>(
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
    PLH::VTableRTTIMode mode = PLH::VTableRTTIMode::Default;
    if (rttiMode == SIGILHOOK_RTTI_NONE) mode = PLH::VTableRTTIMode::None;
    else if (rttiMode == SIGILHOOK_RTTI_MSVC) mode = PLH::VTableRTTIMode::MSVC;
    else if (rttiMode == SIGILHOOK_RTTI_ITANIUM) mode = PLH::VTableRTTIMode::Itanium;
    return createHook([&](HookRecord& record) {
        record.originalVFuncs.clear();
        record.hook = std::make_unique<PLH::VTableSwapHook>(
            object, makeVFuncMap(entries, entryCount), &record.originalVFuncs, mode);
        return true;
    }, SIGILHOOK_HOOK_VTABLE_SWAP, outHook);
}

sigilhook_status SIGILHOOK_CALL sigilhook_get_original_vfunc(
    sigilhook_handle handle, uint16_t index, uint64_t* outOriginal) {
    HookRecord* record = nullptr;
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
    try {
        auto owner = std::make_shared<JitRecord>();
        owner->callback = std::make_unique<PLH::ILCallback>();
        owner->userCallback = callback;
        owner->userData = userData;
        size_t slot = kJitSlotCount;
        for (size_t index = 0; index < kJitSlotCount; ++index) {
            if (g_jitSlots[index].load(std::memory_order_relaxed) == nullptr) {
                slot = index;
                break;
            }
        }
        if (slot == kJitSlotCount) return fail(SIGILHOOK_ERROR_BUSY, "All JIT callback slots are in use");
        owner->slot = slot;
        owner->codeAddress = owner->callback->getJitFunc(
            returnType,
            splitParameters(commaSeparatedParameters == nullptr ? "" : commaSeparatedParameters),
            asmjit::Arch::kHost,
            g_jitDispatchers[slot],
            callConvention == nullptr ? std::string() : std::string(callConvention));
        g_jitSlots[slot].store(owner.get(), std::memory_order_release);
        if (owner->codeAddress == 0) {
            g_jitSlots[slot].store(nullptr, std::memory_order_release);
            return fail(SIGILHOOK_ERROR_SCRIPT, "Failed to generate the JIT callback");
        }
        const uint64_t key = g_nextKey++;
        *outJit = {};
        outJit->value = key;
        if (outAddress != nullptr) *outAddress = owner->codeAddress;
        std::lock_guard lock(g_registryMutex);
        g_jits.emplace(key, std::move(owner));
        return SIGILHOOK_OK;
    } catch (const std::exception& exception) {
        return fail(SIGILHOOK_ERROR_EXCEPTION, exception.what());
    }
}

sigilhook_status SIGILHOOK_CALL sigilhook_destroy_jit_callback(sigilhook_jit_handle jit) {
    std::shared_ptr<JitRecord> owner;
    {
        std::lock_guard lock(g_registryMutex);
        const auto iterator = g_jits.find(jit.value);
        if (iterator == g_jits.end()) return fail(SIGILHOOK_ERROR_NOT_FOUND, "The JIT handle does not exist");
        if (iterator->second->slot < kJitSlotCount) {
            g_jitSlots[iterator->second->slot].store(nullptr, std::memory_order_release);
        }
        owner = iterator->second;
        g_jits.erase(iterator);
    }
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_bind_detour_to_jit(
    sigilhook_handle detour, sigilhook_jit_handle jit, sigilhook_handle* outHook) {
    HookRecord* record = nullptr;
    sigilhook_status status = validateDetour(detour, &record);
    if (status != SIGILHOOK_OK) return status;
    auto owner = findJit(jit);
    if (!owner) return fail(SIGILHOOK_ERROR_NOT_FOUND, "The JIT handle does not exist");
    record->jit = std::move(owner);
    if (outHook != nullptr) *outHook = detour;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_mem_read(
    uint64_t address, void* destination, size_t size, size_t* outRead) {
    if (address == 0 || destination == nullptr || size == 0) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Address, destination, and non-zero size are required");
    }
    size_t read = 0;
    PLH::MemAccessor accessor;
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
    PLH::MemAccessor accessor;
    const bool result = accessor.safe_mem_write(
        address, reinterpret_cast<uint64_t>(const_cast<void*>(source)), size, written);
    if (outWritten != nullptr) *outWritten = written;
    return result ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_MEMORY, "Memory write failed");
}

sigilhook_status SIGILHOOK_CALL sigilhook_mem_protect(
    uint64_t address, size_t size, sigilhook_protect protection, sigilhook_protect* outPrevious) {
    if (address == 0 || size == 0) return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Address and size are required");
    bool status = false;
    PLH::MemAccessor accessor;
    const PLH::ProtFlag previous = accessor.mem_protect(
        address, size, static_cast<PLH::ProtFlag>(protection), status);
    if (outPrevious != nullptr) *outPrevious = static_cast<sigilhook_protect>(previous);
    return status ? SIGILHOOK_OK : fail(SIGILHOOK_ERROR_MEMORY, "VirtualProtect/mprotect failed");
}

sigilhook_status SIGILHOOK_CALL sigilhook_find_pattern(
    uint64_t address, size_t size, const char* idaPattern, uint64_t* outAddress) {
    if (address == 0 || size == 0 || idaPattern == nullptr || outAddress == nullptr) {
        return fail(SIGILHOOK_ERROR_INVALID_ARGUMENT, "Range, pattern, and output address are required");
    }
    *outAddress = PLH::findPattern(address, size, idaPattern);
    return *outAddress == 0 ? SIGILHOOK_ERROR_NOT_FOUND : SIGILHOOK_OK;
}

uint64_t SIGILHOOK_CALL sigilhook_pattern_size(const char* idaPattern) {
    return idaPattern == nullptr ? 0 : PLH::getPatternSize(idaPattern);
}

} // extern "C"

