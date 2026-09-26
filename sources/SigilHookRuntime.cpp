// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "include/sigilhook.h"

#include <angelscript.h>
#include <scriptarray.h>
#include <scriptstdstring.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace {

namespace fs = std::filesystem;

struct ScriptBinding {
    std::string declaration;
    asIScriptFunction* callback = nullptr;
    sigilhook_handle hook{};
    sigilhook_jit_handle jit{};
};

struct RuntimeState {
    asIScriptEngine* engine = nullptr;
    std::vector<std::unique_ptr<ScriptBinding>> bindings;
    std::mutex bindingsMutex;
    std::vector<asIScriptModule*> modules;
    std::unordered_map<std::string, uint64_t> sharedValues;
    fs::path scriptDirectory;
    fs::path logPath;
    std::mutex mutex;
    std::recursive_mutex entryMutex;
    std::mutex sharedMutex;
    std::atomic<bool> started{false};
    std::atomic<bool> stopping{false};
    std::atomic<uint32_t> activeCallbacks{0};
};

RuntimeState g_runtime;
thread_local sigilhook_call_frame* g_currentFrame = nullptr;

asIScriptFunction* findScriptFunction(const std::string& declaration);

std::mutex g_logMutex;

void writeLog(const std::string& message) {
    std::lock_guard lock(g_logMutex);
    std::ofstream log(g_runtime.logPath, std::ios::app);
    if (log) {
        log << message << '\n';
    }
}

void SIGILHOOK_CALL runtimeLogCallback(
    sigilhook_log_level level, const char* message, void*) {
    const char* prefix =
        level == SIGILHOOK_LOG_ERROR ? "error " :
        level == SIGILHOOK_LOG_WARNING ? "warning " : "info ";
    writeLog(std::string(prefix) + (message == nullptr ? "" : message));
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string loadScriptSource(const fs::path& path, int depth, std::string& error) {
    if (depth > 16) {
        error = "include depth exceeds 16";
        return {};
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot open " + path.string();
        return {};
    }
    std::stringstream buffer;
    buffer << input.rdbuf();
    std::string source = buffer.str();
    std::stringstream output;
    std::istringstream lines(source);
    std::string line;
    while (std::getline(lines, line)) {
        const std::string stripped = trim(line);
        if (stripped.rfind("#include", 0) == 0) {
            const auto quote = stripped.find('"');
            const auto endQuote = stripped.find('"', quote == std::string::npos ? 0 : quote + 1);
            if (quote == std::string::npos || endQuote == std::string::npos) {
                error = "invalid include in " + path.string();
                return {};
            }
            const fs::path includePath = path.parent_path() / stripped.substr(quote + 1, endQuote - quote - 1);
            std::string included = loadScriptSource(includePath, depth + 1, error);
            if (!error.empty()) return {};
            output << included << '\n';
        } else {
            output << line << '\n';
        }
    }
    return output.str();
}

void messageCallback(const asSMessageInfo* message, void*) {
    if (message == nullptr) return;
    std::ostringstream line;
    line << (message->type == asMSGTYPE_ERROR ? "error" : message->type == asMSGTYPE_WARNING ? "warning" : "info")
         << " " << message->section << ":" << message->row << ":" << message->col << ": " << message->message;
    writeLog(line.str());
}

asQWORD scriptReadU64(asQWORD address) {
    uint64_t value = 0;
    sigilhook_mem_read(static_cast<uint64_t>(address), &value, sizeof(value), nullptr);
    return value;
}

void scriptWriteU64(asQWORD address, asQWORD value) {
    sigilhook_mem_write(static_cast<uint64_t>(address), &value, sizeof(value), nullptr);
}

asQWORD scriptFindPattern(asQWORD address, asQWORD size, const std::string& pattern) {
    uint64_t result = 0;
    sigilhook_find_pattern(static_cast<uint64_t>(address), static_cast<size_t>(size), pattern.c_str(), &result);
    return result;
}

void scriptLog(const std::string& message) {
    writeLog(message);
}

void scriptHook(asQWORD handle, int enable) {
    sigilhook_set_hooked(sigilhook_handle{static_cast<uint64_t>(handle)}, enable);
}

int scriptIsHooked(asQWORD handle) {
    int result = 0;
    sigilhook_is_hooked(sigilhook_handle{static_cast<uint64_t>(handle)}, &result);
    return result;
}

void scriptUnhook(asQWORD handle) {
    sigilhook_unhook(sigilhook_handle{static_cast<uint64_t>(handle)});
}

void scriptDestroy(asQWORD handle) {
    sigilhook_destroy(sigilhook_handle{static_cast<uint64_t>(handle)});
}

void scriptSetMaxDepth(asQWORD handle, asBYTE depth) {
    sigilhook_set_max_depth(sigilhook_handle{static_cast<uint64_t>(handle)}, depth);
}

asBYTE scriptGetArg(asBYTE index) {
    if (g_currentFrame == nullptr || index >= g_currentFrame->argument_count) return 0;
    return static_cast<asBYTE>(g_currentFrame->arguments[index] & 0xff);
}

asQWORD scriptGetArgU64(asBYTE index) {
    if (g_currentFrame == nullptr || index >= g_currentFrame->argument_count) return 0;
    return g_currentFrame->arguments[index];
}

void scriptSetArgU64(asBYTE index, asQWORD value) {
    if (g_currentFrame != nullptr && index < g_currentFrame->argument_count) {
        g_currentFrame->arguments[index] = static_cast<uint64_t>(value);
    }
}

asQWORD scriptGetReturnU64() {
    return g_currentFrame == nullptr || g_currentFrame->return_value == nullptr ? 0 : *g_currentFrame->return_value;
}

void scriptSetReturnU64(asQWORD value) {
    if (g_currentFrame != nullptr && g_currentFrame->return_value != nullptr) {
        *g_currentFrame->return_value = static_cast<uint64_t>(value);
        if (g_currentFrame->return_value_overridden != nullptr) {
            *g_currentFrame->return_value_overridden = 1;
        }
    }
}

asQWORD scriptGetRegister(asBYTE reg) {
    uint64_t value = 0;
    sigilhook_call_frame_get_register(
        g_currentFrame, static_cast<sigilhook_register>(reg), &value);
    return value;
}

bool scriptSetRegister(asBYTE reg, asQWORD value) {
    return sigilhook_call_frame_set_register(
               g_currentFrame, static_cast<sigilhook_register>(reg), static_cast<uint64_t>(value)) == SIGILHOOK_OK;
}

asQWORD scriptGetFlags() {
    uint64_t flags = 0;
    sigilhook_call_frame_get_flags(g_currentFrame, &flags);
    return flags;
}

bool scriptSetFlags(asQWORD flags) {
    return sigilhook_call_frame_set_flags(g_currentFrame, static_cast<uint64_t>(flags)) == SIGILHOOK_OK;
}

asQWORD scriptGetInstructionPointer() {
    uint64_t address = 0;
    sigilhook_call_frame_get_instruction_pointer(g_currentFrame, &address);
    return address;
}

bool scriptSetInstructionPointer(asQWORD address) {
    return sigilhook_call_frame_set_instruction_pointer(
               g_currentFrame, static_cast<uint64_t>(address)) == SIGILHOOK_OK;
}

std::string scriptDisassemble(asQWORD address, asUINT maxBytes) {
    char buffer[8192]{};
    size_t decoded = 0;
    if (sigilhook_disassemble(static_cast<uint64_t>(address), maxBytes, buffer, sizeof(buffer), &decoded) != SIGILHOOK_OK) {
        return {};
    }
    return buffer;
}

asBYTE scriptDisassembleStatus(asQWORD address, asUINT maxBytes, std::string& output, asUINT& decoded) {
    char buffer[8192]{};
    size_t count = 0;
    const sigilhook_status status = sigilhook_disassemble(
        static_cast<uint64_t>(address), maxBytes, buffer, sizeof(buffer), &count);
    output = status == SIGILHOOK_OK ? buffer : std::string();
    decoded = static_cast<asUINT>(count);
    return static_cast<asBYTE>(status);
}

asQWORD scriptHexToU64(const std::string& text) {
    uint64_t value = 0;
    return sigilhook_parse_hex(text.c_str(), &value) == SIGILHOOK_OK ? value : 0;
}

asBYTE scriptParseHexStatus(const std::string& text, asQWORD& value) {
    uint64_t parsed = 0;
    const sigilhook_status status = sigilhook_parse_hex(text.c_str(), &parsed);
    value = parsed;
    return static_cast<asBYTE>(status);
}

asQWORD scriptAsmCmp(asQWORD left, asQWORD right, asBYTE operandSize) {
    uint64_t flags = 0;
    sigilhook_compute_cmp_flags(left, right, static_cast<uint8_t>(operandSize), &flags);
    return flags;
}

asQWORD scriptAsmTest(asQWORD left, asQWORD right, asBYTE operandSize) {
    uint64_t flags = 0;
    sigilhook_compute_test_flags(left, right, static_cast<uint8_t>(operandSize), &flags);
    return flags;
}

asBYTE scriptAsmFxsave(CScriptArray& state) {
    if (state.GetSize() != 512) return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    return static_cast<asBYTE>(sigilhook_fxsave(state.GetBuffer(), state.GetSize()));
}

asBYTE scriptAsmFxrstor(const CScriptArray& state) {
    if (state.GetSize() != 512) return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    return static_cast<asBYTE>(sigilhook_fxrstor(
        const_cast<CScriptArray&>(state).GetBuffer(), state.GetSize()));
}

asBYTE scriptAsmRetStatus(asUINT stackAdjust, asQWORD& address) {
    uint64_t result = 0;
    const sigilhook_status status = sigilhook_create_return_snippet(stackAdjust, &result);
    address = result;
    return static_cast<asBYTE>(status);
}

asQWORD scriptAsmRet(asUINT stackAdjust) {
    asQWORD address = 0;
    scriptAsmRetStatus(stackAdjust, address);
    return address;
}

asBYTE scriptAsmMovStackJumpStatus(asQWORD stackPointer, asQWORD target, asQWORD& address) {
    uint64_t result = 0;
    const sigilhook_status status = sigilhook_create_stack_jump_snippet(stackPointer, target, &result);
    address = result;
    return static_cast<asBYTE>(status);
}

asQWORD scriptAsmMovStackJump(asQWORD stackPointer, asQWORD target) {
    asQWORD address = 0;
    scriptAsmMovStackJumpStatus(stackPointer, target, address);
    return address;
}

asBYTE scriptDestroySnippetStatus(asQWORD address) {
    return static_cast<asBYTE>(sigilhook_destroy_snippet(static_cast<uint64_t>(address)));
}

void scriptCallOriginal() {
    if (g_currentFrame != nullptr && g_currentFrame->call_original != nullptr) {
        *g_currentFrame->call_original = 1;
    }
}

void scriptSkipOriginal() {
    if (g_currentFrame != nullptr && g_currentFrame->call_original != nullptr) {
        *g_currentFrame->call_original = 0;
    }
}

void scriptJitCallback(sigilhook_call_frame* frame, void* userData) {
    auto* binding = static_cast<ScriptBinding*>(userData);
    if (binding == nullptr || binding->callback == nullptr || g_runtime.stopping.load(std::memory_order_acquire)) return;
    g_runtime.activeCallbacks.fetch_add(1, std::memory_order_acq_rel);
    if (g_runtime.stopping.load(std::memory_order_acquire)) {
        g_runtime.activeCallbacks.fetch_sub(1, std::memory_order_acq_rel);
        return;
    }

    sigilhook_call_frame* previous = g_currentFrame;
    g_currentFrame = frame;
    asIScriptContext* context = g_runtime.engine != nullptr ? g_runtime.engine->RequestContext() : nullptr;
    if (context != nullptr) {
        if (context->Prepare(binding->callback) >= 0) {
            const int result = context->Execute();
            if (result != asEXECUTION_FINISHED) {
                writeLog("script callback did not finish normally: " + binding->declaration);
            }
        }
        g_runtime.engine->ReturnContext(context);
    }
    g_currentFrame = previous;
    g_runtime.activeCallbacks.fetch_sub(1, std::memory_order_acq_rel);
}

void scriptSetFollowCall(asQWORD handle, int enabled) {
    sigilhook_set_follow_call_on_target(sigilhook_handle{static_cast<uint64_t>(handle)}, enabled);
}
asQWORD activateHook(sigilhook_handle hook) {
    if (sigilhook_hook(hook) != SIGILHOOK_OK) {
        sigilhook_destroy(hook);
        return 0;
    }
    return hook.value;
}

asQWORD scriptHookBreakpoint(asQWORD target, asQWORD callback) {
    sigilhook_handle hook{};
    return sigilhook_create_breakpoint(target, callback, &hook) == SIGILHOOK_OK ? activateHook(hook) : 0;
}

asQWORD scriptHookHardwareBreakpoint(asQWORD target, asQWORD callback, asQWORD thread) {
    sigilhook_handle hook{};
    return sigilhook_create_hardware_breakpoint(target, callback, static_cast<uintptr_t>(thread), &hook) == SIGILHOOK_OK ? activateHook(hook) : 0;
}

asQWORD scriptHookIat(const std::string& dll, const std::string& api, const std::string& module, asQWORD callback) {
    sigilhook_handle hook{};
    return sigilhook_create_iat_hook(dll.c_str(), api.c_str(), module.c_str(), callback, &hook, nullptr) == SIGILHOOK_OK ? activateHook(hook) : 0;
}

asQWORD scriptHookEat(const std::string& api, const std::string& module, asQWORD callback) {
    sigilhook_handle hook{};
    return sigilhook_create_eat_hook(api.c_str(), module.c_str(), callback, &hook, nullptr) == SIGILHOOK_OK ? activateHook(hook) : 0;
}

asQWORD scriptHookVFunc(asQWORD object, asWORD index, asQWORD replacement) {
    sigilhook_vfunc_entry entry{index, replacement};
    sigilhook_handle hook{};
    return sigilhook_create_vfunc_swap(object, &entry, 1, &hook) == SIGILHOOK_OK ? activateHook(hook) : 0;
}

asQWORD scriptHookVTable(asQWORD object, asWORD index, asQWORD replacement, asBYTE rttiMode) {
    sigilhook_vfunc_entry entry{index, replacement};
    sigilhook_handle hook{};
    return sigilhook_create_vtable_swap(object, &entry, 1, static_cast<sigilhook_rtti_mode>(rttiMode), &hook) == SIGILHOOK_OK ? activateHook(hook) : 0;
}

void scriptRehook(asQWORD handle) { sigilhook_rehook(sigilhook_handle{static_cast<uint64_t>(handle)}); }
asBYTE scriptHookType(asQWORD handle) { sigilhook_hook_type type = SIGILHOOK_HOOK_UNKNOWN; sigilhook_get_type(sigilhook_handle{static_cast<uint64_t>(handle)}, &type); return static_cast<asBYTE>(type); }
void scriptSetDebug(asQWORD handle, int enabled) { sigilhook_set_debug(sigilhook_handle{static_cast<uint64_t>(handle)}, enabled); }
asQWORD scriptGetTrampoline(asQWORD handle) { uint64_t trampoline = 0; sigilhook_get_trampoline(sigilhook_handle{static_cast<uint64_t>(handle)}, &trampoline); return trampoline; }
asBYTE scriptGetMaxDepth(asQWORD handle) { uint8_t depth = 0; sigilhook_get_max_depth(sigilhook_handle{static_cast<uint64_t>(handle)}, &depth); return depth; }
asBYTE scriptGetDetourScheme(asQWORD handle) { uint8_t scheme = 0; sigilhook_get_detour_scheme(sigilhook_handle{static_cast<uint64_t>(handle)}, &scheme); return scheme; }
void scriptSetDetourScheme(asQWORD handle, asBYTE scheme) { sigilhook_set_detour_scheme(sigilhook_handle{static_cast<uint64_t>(handle)}, scheme); }
asQWORD scriptGetOriginalVFunc(asQWORD handle, asWORD index) { uint64_t original = 0; sigilhook_get_original_vfunc(sigilhook_handle{static_cast<uint64_t>(handle)}, index, &original); return original; }
asBYTE scriptMemProtect(asQWORD address, asQWORD size, asBYTE protection) { sigilhook_protect previous = SIGILHOOK_PROT_NONE; sigilhook_mem_protect(static_cast<uint64_t>(address), static_cast<size_t>(size), static_cast<sigilhook_protect>(protection), &previous); return static_cast<asBYTE>(previous); }
asQWORD scriptPatternSize(const std::string& pattern) { return sigilhook_pattern_size(pattern.c_str()); }
void scriptSetSharedU64(const std::string& name, asQWORD value) {
    std::lock_guard lock(g_runtime.sharedMutex);
    g_runtime.sharedValues[name] = static_cast<uint64_t>(value);
}

asQWORD scriptSharedU64(const std::string& name) {
    std::lock_guard lock(g_runtime.sharedMutex);
    const auto iterator = g_runtime.sharedValues.find(name);
    return iterator == g_runtime.sharedValues.end() ? 0 : iterator->second;
}

asDWORD scriptApiVersion() { return sigilhook_api_version(); }
asBYTE scriptBuildMode() { return static_cast<asBYTE>(sigilhook_build_mode()); }
void scriptClearLastError() { sigilhook_clear_last_error(); }
std::string scriptLastError() { char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); return error; }
std::string scriptStatusString(asBYTE status) {
    return sigilhook_status_string(static_cast<sigilhook_status>(status));
}

asBYTE scriptCreateDetour(
    asQWORD target, asQWORD callback, asQWORD& outHook, asQWORD& outTrampoline) {
    sigilhook_handle hook{};
    uint64_t trampoline = 0;
    const sigilhook_status status = sigilhook_create_detour(
        static_cast<uint64_t>(target), static_cast<uint64_t>(callback), &hook, &trampoline);
    outHook = hook.value;
    outTrampoline = trampoline;
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusDestroy(asQWORD handle) {
    return static_cast<asBYTE>(sigilhook_destroy(sigilhook_handle{static_cast<uint64_t>(handle)}));
}

asBYTE scriptStatusHook(asQWORD handle) {
    return static_cast<asBYTE>(sigilhook_hook(sigilhook_handle{static_cast<uint64_t>(handle)}));
}

asBYTE scriptStatusUnhook(asQWORD handle) {
    return static_cast<asBYTE>(sigilhook_unhook(sigilhook_handle{static_cast<uint64_t>(handle)}));
}

asBYTE scriptStatusRehook(asQWORD handle) {
    return static_cast<asBYTE>(sigilhook_rehook(sigilhook_handle{static_cast<uint64_t>(handle)}));
}

asBYTE scriptStatusSetHooked(asQWORD handle, int hooked) {
    return static_cast<asBYTE>(sigilhook_set_hooked(
        sigilhook_handle{static_cast<uint64_t>(handle)}, hooked));
}

asBYTE scriptStatusIsHooked(asQWORD handle, bool& outHooked) {
    int hooked = 0;
    const sigilhook_status status = sigilhook_is_hooked(
        sigilhook_handle{static_cast<uint64_t>(handle)}, &hooked);
    outHooked = hooked != 0;
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusHookType(asQWORD handle, asBYTE& outType) {
    sigilhook_hook_type type = SIGILHOOK_HOOK_UNKNOWN;
    const sigilhook_status status = sigilhook_get_type(
        sigilhook_handle{static_cast<uint64_t>(handle)}, &type);
    outType = static_cast<asBYTE>(type);
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusSetDebug(asQWORD handle, int enabled) {
    return static_cast<asBYTE>(sigilhook_set_debug(
        sigilhook_handle{static_cast<uint64_t>(handle)}, enabled));
}

asBYTE scriptStatusTrampoline(asQWORD handle, asQWORD& outTrampoline) {
    uint64_t trampoline = 0;
    const sigilhook_status status = sigilhook_get_trampoline(
        sigilhook_handle{static_cast<uint64_t>(handle)}, &trampoline);
    outTrampoline = trampoline;
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusMaxDepth(asQWORD handle, asBYTE& outDepth) {
    uint8_t depth = 0;
    const sigilhook_status status = sigilhook_get_max_depth(
        sigilhook_handle{static_cast<uint64_t>(handle)}, &depth);
    outDepth = depth;
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusSetMaxDepth(asQWORD handle, asBYTE depth) {
    return static_cast<asBYTE>(sigilhook_set_max_depth(
        sigilhook_handle{static_cast<uint64_t>(handle)}, depth));
}

asBYTE scriptStatusSetFollowCall(asQWORD handle, int enabled) {
    return static_cast<asBYTE>(sigilhook_set_follow_call_on_target(
        sigilhook_handle{static_cast<uint64_t>(handle)}, enabled));
}

asBYTE scriptStatusDetourScheme(asQWORD handle, asBYTE& outScheme) {
    uint8_t scheme = 0;
    const sigilhook_status status = sigilhook_get_detour_scheme(
        sigilhook_handle{static_cast<uint64_t>(handle)}, &scheme);
    outScheme = scheme;
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusSetDetourScheme(asQWORD handle, asBYTE scheme) {
    return static_cast<asBYTE>(sigilhook_set_detour_scheme(
        sigilhook_handle{static_cast<uint64_t>(handle)}, scheme));
}

asBYTE scriptCreateBreakpoint(asQWORD target, asQWORD callback, asQWORD& outHook) {
    sigilhook_handle hook{};
    const sigilhook_status status = sigilhook_create_breakpoint(
        static_cast<uint64_t>(target), static_cast<uint64_t>(callback), &hook);
    outHook = hook.value;
    return static_cast<asBYTE>(status);
}

asBYTE scriptCreateHardwareBreakpoint(
    asQWORD target, asQWORD callback, asQWORD thread, asQWORD& outHook) {
    sigilhook_handle hook{};
    const sigilhook_status status = sigilhook_create_hardware_breakpoint(
        static_cast<uint64_t>(target), static_cast<uint64_t>(callback),
        static_cast<uintptr_t>(thread), &hook);
    outHook = hook.value;
    return static_cast<asBYTE>(status);
}

asBYTE scriptCreateIat(
    const std::string& importedDll, const std::string& importedApi,
    const std::string& moduleName, asQWORD callback,
    asQWORD& outHook, asQWORD& outOriginal) {
    sigilhook_handle hook{};
    uint64_t original = 0;
    const sigilhook_status status = sigilhook_create_iat_hook(
        importedDll.c_str(), importedApi.c_str(), moduleName.c_str(),
        static_cast<uint64_t>(callback), &hook, &original);
    outHook = hook.value;
    outOriginal = original;
    return static_cast<asBYTE>(status);
}

asBYTE scriptCreateEat(
    const std::string& exportedApi, const std::string& moduleName,
    asQWORD callback, asQWORD& outHook, asQWORD& outOriginal) {
    sigilhook_handle hook{};
    uint64_t original = 0;
    const sigilhook_status status = sigilhook_create_eat_hook(
        exportedApi.c_str(), moduleName.c_str(),
        static_cast<uint64_t>(callback), &hook, &original);
    outHook = hook.value;
    outOriginal = original;
    return static_cast<asBYTE>(status);
}

asBYTE createVFuncEntries(
    bool vtable, asQWORD object, const CScriptArray& indices,
    const CScriptArray& replacements, asBYTE rttiMode, asQWORD& outHook) {
    outHook = 0;
    if (indices.GetSize() != replacements.GetSize() || indices.IsEmpty()) {
        return static_cast<asBYTE>(SIGILHOOK_ERROR_INVALID_ARGUMENT);
    }
    std::vector<sigilhook_vfunc_entry> entries;
    entries.reserve(indices.GetSize());
    for (asUINT index = 0; index < indices.GetSize(); ++index) {
        entries.push_back({
            *static_cast<const asWORD*>(indices.At(index)),
            *static_cast<const asQWORD*>(replacements.At(index))
        });
    }
    sigilhook_handle hook{};
    const sigilhook_status status = vtable
        ? sigilhook_create_vtable_swap(
            static_cast<uint64_t>(object), entries.data(), entries.size(),
            static_cast<sigilhook_rtti_mode>(rttiMode), &hook)
        : sigilhook_create_vfunc_swap(
            static_cast<uint64_t>(object), entries.data(), entries.size(), &hook);
    outHook = hook.value;
    return static_cast<asBYTE>(status);
}

asBYTE scriptCreateVFuncEntries(
    asQWORD object, const CScriptArray& indices,
    const CScriptArray& replacements, asQWORD& outHook) {
    return createVFuncEntries(false, object, indices, replacements, 0, outHook);
}

asBYTE scriptCreateVTableEntries(
    asQWORD object, const CScriptArray& indices,
    const CScriptArray& replacements, asBYTE rttiMode, asQWORD& outHook) {
    return createVFuncEntries(true, object, indices, replacements, rttiMode, outHook);
}

asBYTE scriptStatusOriginalVFunc(
    asQWORD handle, asWORD index, asQWORD& outOriginal) {
    uint64_t original = 0;
    const sigilhook_status status = sigilhook_get_original_vfunc(
        sigilhook_handle{static_cast<uint64_t>(handle)}, index, &original);
    outOriginal = original;
    return static_cast<asBYTE>(status);
}

asBYTE scriptCreateScriptJit(
    const std::string& returnType, const std::string& parameters,
    const std::string& convention, const std::string& callbackDeclaration,
    asQWORD& outJit, asQWORD& outAddress) {
    outJit = 0;
    outAddress = 0;
    asIScriptFunction* callback = findScriptFunction(callbackDeclaration);
    if (callback == nullptr) {
        writeLog("callback declaration not found: " + callbackDeclaration);
        return static_cast<asBYTE>(SIGILHOOK_ERROR_NOT_FOUND);
    }
    auto binding = std::make_unique<ScriptBinding>();
    binding->declaration = callbackDeclaration;
    binding->callback = callback;
    sigilhook_jit_handle jit{};
    uint64_t address = 0;
    const sigilhook_status status = sigilhook_create_jit_callback(
        returnType.c_str(), parameters.c_str(), convention.c_str(),
        scriptJitCallback, binding.get(), &jit, &address);
    if (status != SIGILHOOK_OK) return static_cast<asBYTE>(status);
    binding->jit = jit;
    outJit = jit.value;
    outAddress = address;
    std::lock_guard bindingLock(g_runtime.bindingsMutex);
    g_runtime.bindings.push_back(std::move(binding));
    return static_cast<asBYTE>(SIGILHOOK_OK);
}

asBYTE scriptStatusDestroyJit(asQWORD jitHandle) {
    const sigilhook_jit_handle jit{static_cast<uint64_t>(jitHandle)};
    const sigilhook_status status = sigilhook_destroy_jit_callback(jit);
    if (status == SIGILHOOK_OK) {
        std::lock_guard lock(g_runtime.bindingsMutex);
        std::erase_if(g_runtime.bindings, [jit](const std::unique_ptr<ScriptBinding>& binding) {
            return binding != nullptr && binding->jit.value == jit.value;
        });
    }
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusBindDetourToJit(
    asQWORD detour, asQWORD jitHandle, asQWORD& outHook) {
    const sigilhook_jit_handle jit{static_cast<uint64_t>(jitHandle)};
    sigilhook_handle hook{};
    const sigilhook_status status = sigilhook_bind_detour_to_jit(
        sigilhook_handle{static_cast<uint64_t>(detour)}, jit, &hook);
    outHook = hook.value;
    if (status == SIGILHOOK_OK) {
        std::lock_guard lock(g_runtime.bindingsMutex);
        for (const auto& binding : g_runtime.bindings) {
            if (binding != nullptr && binding->jit.value == jit.value) {
                binding->hook = hook;
                break;
            }
        }
    }
    return static_cast<asBYTE>(status);
}

CScriptArray* scriptReadBytes(asQWORD address, asUINT size) {
    if (size == 0) return nullptr;
    asIScriptContext* context = asGetActiveContext();
    asITypeInfo* arrayType = context == nullptr || context->GetEngine() == nullptr
        ? nullptr
        : context->GetEngine()->GetTypeInfoByDecl("array<uint8>");
    if (arrayType == nullptr) return nullptr;
    CScriptArray* result = CScriptArray::Create(arrayType, size);
    if (result == nullptr) return nullptr;
    size_t read = 0;
    const sigilhook_status status = sigilhook_mem_read(
        static_cast<uint64_t>(address), result->GetBuffer(), size, &read);
    if (status != SIGILHOOK_OK || read != size) {
        result->Release();
        return nullptr;
    }
    return result;
}

asBYTE scriptWriteBytes(
    asQWORD address, const CScriptArray& bytes, asUINT& outWritten) {
    size_t written = 0;
    const sigilhook_status status = sigilhook_mem_write(
        static_cast<uint64_t>(address), const_cast<CScriptArray&>(bytes).GetBuffer(), bytes.GetSize(), &written);
    outWritten = static_cast<asUINT>(written);
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusMemProtect(
    asQWORD address, asQWORD size, asBYTE protection, asBYTE& outPrevious) {
    sigilhook_protect previous = SIGILHOOK_PROT_NONE;
    const sigilhook_status status = sigilhook_mem_protect(
        static_cast<uint64_t>(address), static_cast<size_t>(size),
        static_cast<sigilhook_protect>(protection), &previous);
    outPrevious = static_cast<asBYTE>(previous);
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusFindPattern(
    asQWORD address, asQWORD size, const std::string& pattern, asQWORD& outAddress) {
    uint64_t result = 0;
    const sigilhook_status status = sigilhook_find_pattern(
        static_cast<uint64_t>(address), static_cast<size_t>(size),
        pattern.c_str(), &result);
    outAddress = result;
    return static_cast<asBYTE>(status);
}

asBYTE scriptLoadDirectory(const std::string& directory) {
    return static_cast<asBYTE>(sigilhook_runtime_load_directory(
        fs::path(std::u8string(directory.begin(), directory.end())).c_str()));
}

asBYTE scriptCallEntry(const std::string& declaration) {
    return static_cast<asBYTE>(sigilhook_runtime_call_entry(declaration.c_str()));
}

asBYTE scriptStatusSetSharedU64(const std::string& name, asQWORD value) {
    return static_cast<asBYTE>(sigilhook_runtime_set_shared_u64(
        name.c_str(), static_cast<uint64_t>(value)));
}

asBYTE scriptStatusSharedU64(const std::string& name, asQWORD& outValue) {
    uint64_t value = 0;
    const sigilhook_status status = sigilhook_runtime_get_shared_u64(name.c_str(), &value);
    outValue = value;
    return static_cast<asBYTE>(status);
}
asBYTE scriptInvokeUsercall(
    asQWORD target, const std::string& returnType, const std::string& parameters,
    const std::string& convention, const CScriptArray& arguments, asQWORD& outReturnValue) {
    std::vector<uint64_t> values;
    values.reserve(arguments.GetSize());
    for (asUINT index = 0; index < arguments.GetSize(); ++index) {
        values.push_back(*static_cast<const asQWORD*>(arguments.At(index)));
    }
    uint64_t result = 0;
    const sigilhook_status status = sigilhook_invoke_usercall(
        static_cast<uint64_t>(target), returnType.c_str(), parameters.c_str(),
        convention.c_str(), values.data(), values.size(), &result);
    outReturnValue = result;
    return static_cast<asBYTE>(status);
}
void registerScriptApi(asIScriptEngine* engine) {
    RegisterStdString(engine);
    RegisterScriptArray(engine, true);
    engine->RegisterGlobalFunction("void setSharedU64(const string &in, uint64)", asFUNCTION(scriptSetSharedU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 sharedU64(const string &in)", asFUNCTION(scriptSharedU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint32 apiVersion()", asFUNCTION(scriptApiVersion), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 buildMode()", asFUNCTION(scriptBuildMode), asCALL_CDECL);
    engine->RegisterGlobalFunction("void clearLastError()", asFUNCTION(scriptClearLastError), asCALL_CDECL);
    engine->RegisterGlobalFunction("void rehook(uint64)", asFUNCTION(scriptRehook), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 hookType(uint64)", asFUNCTION(scriptHookType), asCALL_CDECL);
    engine->RegisterGlobalFunction("void setDebug(uint64, bool)", asFUNCTION(scriptSetDebug), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 trampoline(uint64)", asFUNCTION(scriptGetTrampoline), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 maxDepth(uint64)", asFUNCTION(scriptGetMaxDepth), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 detourScheme(uint64)", asFUNCTION(scriptGetDetourScheme), asCALL_CDECL);
    engine->RegisterGlobalFunction("void setDetourScheme(uint64, uint8)", asFUNCTION(scriptSetDetourScheme), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 originalVFunc(uint64, uint16)", asFUNCTION(scriptGetOriginalVFunc), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 memProtect(uint64, uint64, uint8)", asFUNCTION(scriptMemProtect), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 patternSize(const string &in)", asFUNCTION(scriptPatternSize), asCALL_CDECL);
    engine->RegisterGlobalFunction("string lastError()", asFUNCTION(scriptLastError), asCALL_CDECL);
    engine->RegisterGlobalFunction("void log(const string &in)", asFUNCTION(scriptLog), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 readU64(uint64)", asFUNCTION(scriptReadU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("void writeU64(uint64, uint64)", asFUNCTION(scriptWriteU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 findPattern(uint64, uint64, const string &in)", asFUNCTION(scriptFindPattern), asCALL_CDECL);
    engine->RegisterGlobalFunction("void setHooked(uint64, bool)", asFUNCTION(scriptHook), asCALL_CDECL);
    engine->RegisterGlobalFunction("bool isHooked(uint64)", asFUNCTION(scriptIsHooked), asCALL_CDECL);
    engine->RegisterGlobalFunction("void unhook(uint64)", asFUNCTION(scriptUnhook), asCALL_CDECL);
    engine->RegisterGlobalFunction("void destroyHook(uint64)", asFUNCTION(scriptDestroy), asCALL_CDECL);
    engine->RegisterGlobalFunction("void setMaxDepth(uint64, uint8)", asFUNCTION(scriptSetMaxDepth), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 arg8(uint8)", asFUNCTION(scriptGetArg), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 arg(uint8)", asFUNCTION(scriptGetArgU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("void setArg(uint8, uint64)", asFUNCTION(scriptSetArgU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 getRegister(uint8)", asFUNCTION(scriptGetRegister), asCALL_CDECL);
    engine->RegisterGlobalFunction("bool setRegister(uint8, uint64)", asFUNCTION(scriptSetRegister), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 getFlags()", asFUNCTION(scriptGetFlags), asCALL_CDECL);
    engine->RegisterGlobalFunction("bool setFlags(uint64)", asFUNCTION(scriptSetFlags), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 getInstructionPointer()", asFUNCTION(scriptGetInstructionPointer), asCALL_CDECL);
    engine->RegisterGlobalFunction("bool setInstructionPointer(uint64)", asFUNCTION(scriptSetInstructionPointer), asCALL_CDECL);
    engine->RegisterGlobalFunction("string disassemble(uint64, uint)", asFUNCTION(scriptDisassemble), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 disassembleStatus(uint64, uint, string &out, uint &out)", asFUNCTION(scriptDisassembleStatus), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hexToU64(const string &in)", asFUNCTION(scriptHexToU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 parseHexStatus(const string &in, uint64 &out)", asFUNCTION(scriptParseHexStatus), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 asmCmp(uint64, uint64, uint8)", asFUNCTION(scriptAsmCmp), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 asmTest(uint64, uint64, uint8)", asFUNCTION(scriptAsmTest), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 asmFxsave(array<uint8> &inout)", asFUNCTION(scriptAsmFxsave), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 asmFxrstor(const array<uint8> &in)", asFUNCTION(scriptAsmFxrstor), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 asmRetStatus(uint, uint64 &out)", asFUNCTION(scriptAsmRetStatus), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 asmRet(uint)", asFUNCTION(scriptAsmRet), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 asmMovStackJumpStatus(uint64, uint64, uint64 &out)", asFUNCTION(scriptAsmMovStackJumpStatus), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 asmMovStackJump(uint64, uint64)", asFUNCTION(scriptAsmMovStackJump), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 destroySnippetStatus(uint64)", asFUNCTION(scriptDestroySnippetStatus), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 returnValue()", asFUNCTION(scriptGetReturnU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("void setReturnValue(uint64)", asFUNCTION(scriptSetReturnU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("void callOriginal()", asFUNCTION(scriptCallOriginal), asCALL_CDECL);
    engine->RegisterGlobalFunction("void skipOriginal()", asFUNCTION(scriptSkipOriginal), asCALL_CDECL);
    engine->RegisterGlobalFunction("string statusString(uint8)", asFUNCTION(scriptStatusString), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createDetour(uint64, uint64, uint64 &out, uint64 &out)", asFUNCTION(scriptCreateDetour), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 destroyStatus(uint64)", asFUNCTION(scriptStatusDestroy), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 installHook(uint64)", asFUNCTION(scriptStatusHook), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 removeHook(uint64)", asFUNCTION(scriptStatusUnhook), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 rehookStatus(uint64)", asFUNCTION(scriptStatusRehook), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 setHookedStatus(uint64, bool)", asFUNCTION(scriptStatusSetHooked), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 isHookedStatus(uint64, bool &out)", asFUNCTION(scriptStatusIsHooked), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 hookTypeStatus(uint64, uint8 &out)", asFUNCTION(scriptStatusHookType), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 setDebugStatus(uint64, bool)", asFUNCTION(scriptStatusSetDebug), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 trampolineStatus(uint64, uint64 &out)", asFUNCTION(scriptStatusTrampoline), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 maxDepthStatus(uint64, uint8 &out)", asFUNCTION(scriptStatusMaxDepth), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 setMaxDepthStatus(uint64, uint8)", asFUNCTION(scriptStatusSetMaxDepth), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 setFollowCallStatus(uint64, bool)", asFUNCTION(scriptStatusSetFollowCall), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 detourSchemeStatus(uint64, uint8 &out)", asFUNCTION(scriptStatusDetourScheme), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 setDetourSchemeStatus(uint64, uint8)", asFUNCTION(scriptStatusSetDetourScheme), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createBreakpoint(uint64, uint64, uint64 &out)", asFUNCTION(scriptCreateBreakpoint), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createHardwareBreakpoint(uint64, uint64, uint64, uint64 &out)", asFUNCTION(scriptCreateHardwareBreakpoint), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createIat(const string &in, const string &in, const string &in, uint64, uint64 &out, uint64 &out)", asFUNCTION(scriptCreateIat), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createEat(const string &in, const string &in, uint64, uint64 &out, uint64 &out)", asFUNCTION(scriptCreateEat), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createVFuncEntries(uint64, const array<uint16> &in, const array<uint64> &in, uint64 &out)", asFUNCTION(scriptCreateVFuncEntries), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createVTableEntries(uint64, const array<uint16> &in, const array<uint64> &in, uint8, uint64 &out)", asFUNCTION(scriptCreateVTableEntries), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 originalVFuncStatus(uint64, uint16, uint64 &out)", asFUNCTION(scriptStatusOriginalVFunc), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 createScriptJit(const string &in, const string &in, const string &in, const string &in, uint64 &out, uint64 &out)", asFUNCTION(scriptCreateScriptJit), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 destroyJit(uint64)", asFUNCTION(scriptStatusDestroyJit), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 bindDetourToJit(uint64, uint64, uint64 &out)", asFUNCTION(scriptStatusBindDetourToJit), asCALL_CDECL);
    engine->RegisterGlobalFunction("array<uint8>@ readBytes(uint64, uint)", asFUNCTION(scriptReadBytes), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 writeBytes(uint64, const array<uint8> &in, uint &out)", asFUNCTION(scriptWriteBytes), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 memProtectStatus(uint64, uint64, uint8, uint8 &out)", asFUNCTION(scriptStatusMemProtect), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 findPatternStatus(uint64, uint64, const string &in, uint64 &out)", asFUNCTION(scriptStatusFindPattern), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 loadDirectory(const string &in)", asFUNCTION(scriptLoadDirectory), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 callEntry(const string &in)", asFUNCTION(scriptCallEntry), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 setSharedU64Status(const string &in, uint64)", asFUNCTION(scriptStatusSetSharedU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 sharedU64Status(const string &in, uint64 &out)", asFUNCTION(scriptStatusSharedU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 invokeUsercall(uint64, const string &in, const string &in, const string &in, const array<uint64> &in, uint64 &out)", asFUNCTION(scriptInvokeUsercall), asCALL_CDECL);
}

asQWORD scriptHookNative(asQWORD target, asQWORD callback) {
    sigilhook_handle hook{};
    if (sigilhook_create_detour(target, callback, &hook, nullptr) != SIGILHOOK_OK) return 0;
    return activateHook(hook);
}

asIScriptFunction* findScriptFunction(const std::string& declaration) {
    if (asIScriptContext* context = asGetActiveContext(); context != nullptr && context->GetFunction() != nullptr) {
        asIScriptModule* module = context->GetFunction()->GetModule();
        if (module != nullptr) {
            if (asIScriptFunction* function = module->GetFunctionByDecl(declaration.c_str()); function != nullptr) {
                return function;
            }
        }
    }
    for (auto iterator = g_runtime.modules.rbegin(); iterator != g_runtime.modules.rend(); ++iterator) {
        if (asIScriptFunction* function = (*iterator)->GetFunctionByDecl(declaration.c_str()); function != nullptr) {
            return function;
        }
    }
    return nullptr;
}

asQWORD scriptHookDetourConvention(
    asQWORD target, const std::string& callbackDeclaration, const std::string& signature,
    const std::string& callConvention) {
    if (g_runtime.engine == nullptr) return 0;
    const size_t separator = signature.find(':');
    const std::string returnType = trim(separator == std::string::npos ? signature : signature.substr(0, separator));
    const std::string parameters = separator == std::string::npos ? "" : signature.substr(separator + 1);
    asIScriptFunction* callback = findScriptFunction(callbackDeclaration);
    if (callback == nullptr) {
        writeLog("callback declaration not found: " + callbackDeclaration);
        return 0;
    }

    auto binding = std::make_unique<ScriptBinding>();
    binding->declaration = callbackDeclaration;
    binding->callback = callback;
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    if (sigilhook_create_jit_callback(
            returnType.c_str(), parameters.c_str(), callConvention.c_str(),
            scriptJitCallback, binding.get(), &jit, &callbackAddress) != SIGILHOOK_OK) {
        return 0;
    }
    if (sigilhook_create_detour(target, callbackAddress, &binding->hook, nullptr) != SIGILHOOK_OK) {
        sigilhook_destroy_jit_callback(jit);
        return 0;
    }
    binding->jit = jit;
    if (sigilhook_bind_detour_to_jit(binding->hook, jit, nullptr) != SIGILHOOK_OK) {
        sigilhook_destroy(binding->hook);
        sigilhook_destroy_jit_callback(jit);
        return 0;
    }
    if (sigilhook_hook(binding->hook) != SIGILHOOK_OK) {
        sigilhook_destroy(binding->hook);
        sigilhook_destroy_jit_callback(jit);
        return 0;
    }
    const uint64_t handle = binding->hook.value;
    std::lock_guard bindingLock(g_runtime.bindingsMutex);
    g_runtime.bindings.push_back(std::move(binding));
    return handle;
}

asQWORD scriptHookDetour(asQWORD target, const std::string& callbackDeclaration, const std::string& signature) {
    return scriptHookDetourConvention(target, callbackDeclaration, signature, "");
}

void registerScriptHookApi(asIScriptEngine* engine) {
    engine->RegisterGlobalFunction("uint64 hookNative(uint64, uint64)", asFUNCTION(scriptHookNative), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookDetour(uint64, const string &in, const string &in)", asFUNCTION(scriptHookDetour), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookDetourConvention(uint64, const string &in, const string &in, const string &in)", asFUNCTION(scriptHookDetourConvention), asCALL_CDECL);
    engine->RegisterGlobalFunction("void setFollowCall(uint64, bool)", asFUNCTION(scriptSetFollowCall), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookBreakpoint(uint64, uint64)", asFUNCTION(scriptHookBreakpoint), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookHardwareBreakpoint(uint64, uint64, uint64)", asFUNCTION(scriptHookHardwareBreakpoint), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookIat(const string &in, const string &in, const string &in, uint64)", asFUNCTION(scriptHookIat), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookEat(const string &in, const string &in, uint64)", asFUNCTION(scriptHookEat), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookVFunc(uint64, uint16, uint64)", asFUNCTION(scriptHookVFunc), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 hookVTable(uint64, uint16, uint64, uint8)", asFUNCTION(scriptHookVTable), asCALL_CDECL);
}

bool runEntry(asIScriptModule* module, const char* declaration) {
    if (module == nullptr) return false;
    asIScriptFunction* function = module->GetFunctionByDecl(declaration);
    if (function == nullptr) return true;
    asIScriptContext* context = g_runtime.engine->CreateContext();
    if (context == nullptr) return false;
    const bool result = context->Prepare(function) >= 0 && context->Execute() == asEXECUTION_FINISHED;
    if (context->GetState() != asEXECUTION_FINISHED) {
        const char* exception = context->GetExceptionString();
        int exceptionColumn = 0;
        const char* exceptionSection = nullptr;
        const int exceptionLine = context->GetExceptionLineNumber(&exceptionColumn, &exceptionSection);
        writeLog(std::string("script entry exception in ") + declaration + ": " + (exception == nullptr ? "unknown" : exception));
        writeLog("exception location: " + std::to_string(exceptionLine) + ":" + std::to_string(exceptionColumn) + " in " + (exceptionSection == nullptr ? "" : exceptionSection));
    }
    context->Release();
    return result;
}

fs::path modulePath() {
#if defined(_WIN32)
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&modulePath), &module)) {
        return fs::current_path();
    }
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0) return fs::current_path();
    path.resize(length);
    return fs::path(path).parent_path();
#else
    return fs::current_path();
#endif
}

sigilhook_status startRuntime(const fs::path& requestedDirectory) {
    std::lock_guard lock(g_runtime.mutex);
    if (g_runtime.started) return SIGILHOOK_OK;
    g_runtime.scriptDirectory = requestedDirectory.empty() ? modulePath() / "SigilHook" : requestedDirectory;
    g_runtime.logPath = g_runtime.scriptDirectory / "logs" / "SigilHook.log";
    std::error_code error;
    fs::create_directories(g_runtime.logPath.parent_path(), error);
    sigilhook_set_log_callback(runtimeLogCallback, nullptr);
    g_runtime.engine = asCreateScriptEngine();
    if (g_runtime.engine == nullptr) return SIGILHOOK_ERROR_SCRIPT;
    g_runtime.engine->SetMessageCallback(asFUNCTION(messageCallback), nullptr, asCALL_CDECL);
    registerScriptApi(g_runtime.engine);
    registerScriptHookApi(g_runtime.engine);
    g_runtime.started = true;
    return SIGILHOOK_OK;
}

sigilhook_status loadDirectory(const fs::path& directory) {
    if (!g_runtime.started) {
        const sigilhook_status status = startRuntime(directory);
        if (status != SIGILHOOK_OK) return status;
    }
    std::lock_guard lock(g_runtime.mutex);
    std::lock_guard<std::recursive_mutex> entryLock(g_runtime.entryMutex);
    std::vector<fs::path> scripts;
    std::error_code error;
    for (const auto& entry : fs::directory_iterator(directory, error)) {
        if (entry.is_regular_file() && entry.path().extension() == ".as") {
            scripts.push_back(entry.path());
        }
    }
    if (error) return SIGILHOOK_ERROR_SCRIPT;
    std::sort(scripts.begin(), scripts.end());
    for (const fs::path& script : scripts) {
        std::string sourceError;
        const std::string source = loadScriptSource(script, 0, sourceError);
        if (!sourceError.empty()) {
            writeLog(sourceError);
            return SIGILHOOK_ERROR_SCRIPT;
        }
        asIScriptModule* module = g_runtime.engine->GetModule(script.stem().string().c_str(), asGM_ALWAYS_CREATE);
        if (module == nullptr || module->AddScriptSection(script.string().c_str(), source.c_str(), source.size()) < 0 ||
            module->Build() < 0) {
            writeLog("failed to build " + script.string());
            return SIGILHOOK_ERROR_SCRIPT;
        }
        g_runtime.modules.push_back(module);
        if (!runEntry(module, "void main()")) {
            writeLog("entry point failed in " + script.string());
            return SIGILHOOK_ERROR_SCRIPT;
        }
    }
    return SIGILHOOK_OK;
}

sigilhook_status stopRuntime() {
    std::lock_guard lock(g_runtime.mutex);
    if (!g_runtime.started) return SIGILHOOK_OK;
    g_runtime.stopping.store(true, std::memory_order_release);
    while (g_runtime.activeCallbacks.load(std::memory_order_acquire) != 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::lock_guard<std::recursive_mutex> entryLock(g_runtime.entryMutex);
    for (auto iterator = g_runtime.modules.rbegin(); iterator != g_runtime.modules.rend(); ++iterator) {
        runEntry(*iterator, "void unload()");
    }
    std::vector<std::unique_ptr<ScriptBinding>> bindings;
    {
        std::lock_guard bindingsLock(g_runtime.bindingsMutex);
        bindings.swap(g_runtime.bindings);
    }
    for (auto& binding : bindings) {
        sigilhook_destroy(binding->hook);
        sigilhook_destroy_jit_callback(binding->jit);
    }
    for (asIScriptModule* module : g_runtime.modules) {
        if (module != nullptr) module->Discard();
    }
    g_runtime.modules.clear();
    if (g_runtime.engine != nullptr) {
        g_runtime.engine->ShutDownAndRelease();
        g_runtime.engine = nullptr;
    }
    g_runtime.started = false;
    g_runtime.stopping.store(false, std::memory_order_release);
    sigilhook_set_log_callback(nullptr, nullptr);
    return SIGILHOOK_OK;
}

} // namespace

extern "C" {

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_start(const wchar_t* optionalScriptDirectory) {
    fs::path path;
    if (optionalScriptDirectory != nullptr) path = optionalScriptDirectory;
    return startRuntime(path);
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_stop(void) {
    return stopRuntime();
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_load_directory(const wchar_t* scriptDirectory) {
    if (scriptDirectory == nullptr || *scriptDirectory == L'\0') {
        return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    }
    return loadDirectory(fs::path(scriptDirectory));
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_set_shared_u64(const char* name, uint64_t value) {
    if (name == nullptr || *name == '\0') return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    std::lock_guard lock(g_runtime.sharedMutex);
    g_runtime.sharedValues[name] = value;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_get_shared_u64(const char* name, uint64_t* outValue) {
    if (name == nullptr || *name == '\0' || outValue == nullptr) return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    std::lock_guard lock(g_runtime.sharedMutex);
    const auto iterator = g_runtime.sharedValues.find(name);
    if (iterator == g_runtime.sharedValues.end()) return SIGILHOOK_ERROR_NOT_FOUND;
    *outValue = iterator->second;
    return SIGILHOOK_OK;
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_call_entry(const char* declaration) {
    if (declaration == nullptr) return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    std::lock_guard<std::recursive_mutex> entryLock(g_runtime.entryMutex);
    bool all = true;
    for (asIScriptModule* module : g_runtime.modules) {
        all = runEntry(module, declaration) && all;
    }
    return all ? SIGILHOOK_OK : SIGILHOOK_ERROR_SCRIPT;
}

} // extern "C"
