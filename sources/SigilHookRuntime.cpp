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
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#endif

#ifndef SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS
#  define SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS 5000u
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
    std::recursive_timed_mutex mutex;
    std::recursive_timed_mutex entryMutex;
    std::mutex sharedMutex;
    std::mutex scriptHooksMutex;
    std::unordered_set<uint64_t> scriptHooks;
    std::atomic<bool> started{false};
    std::atomic<bool> stopping{false};
    std::atomic<uint32_t> activeCallbacks{0};
    std::condition_variable callbackCondition;
    std::mutex callbackMutex;
};

RuntimeState g_runtime;
thread_local sigilhook_call_frame* g_currentFrame = nullptr;
thread_local bool g_unloading = false;

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

struct ScriptSection {
    std::string name;
    std::string source;
};

struct IncludeLoadState {
    fs::path root;
    std::vector<fs::path> stack;
    std::unordered_set<std::string> includedHeaders;
    std::vector<ScriptSection>* sections = nullptr;
    std::string error;
};

enum class SourceLineKind {
    ordinary,
    include,
    invalidInclude
};

fs::path normalizedPath(const fs::path& path) {
    std::error_code error;
    const fs::path absolute = fs::absolute(path, error);
    if (error) return path.lexically_normal();
    const fs::path canonical = fs::weakly_canonical(absolute, error);
    return error ? absolute.lexically_normal() : canonical;
}

bool extensionEquals(const fs::path& path, const std::string& expected) {
    std::string extension = path.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return extension == expected;
}

std::string sectionName(const fs::path& path, const fs::path& root) {
    const fs::path relative = path.lexically_relative(root);
    if (!relative.empty()) {
        const auto first = relative.begin();
        if (first != relative.end() && *first != "..") return relative.generic_string();
    }
    return path.generic_string();
}

std::string includeChain(const IncludeLoadState& state) {
    std::string result;
    for (const fs::path& path : state.stack) {
        if (!result.empty()) result += " -> ";
        result += sectionName(path, state.root);
    }
    return result;
}

void setIncludeError(IncludeLoadState& state, const fs::path& path, int line, const std::string& message) {
    if (!state.error.empty()) return;
    std::ostringstream output;
    output << sectionName(path, state.root) << ':' << line << ": " << message;
    const std::string chain = includeChain(state);
    if (!chain.empty()) output << " (include chain: " << chain << ')';
    state.error = output.str();
}

bool startsWithKeyword(const std::string& line, const char* keyword) {
    size_t position = 0;
    if (position >= line.size() || line[position++] != '#') return false;
    while (position < line.size() && (line[position] == ' ' || line[position] == '\t')) ++position;
    const size_t length = std::char_traits<char>::length(keyword);
    if (line.compare(position, length, keyword) != 0) return false;
    position += length;
    if (position == line.size()) return true;
    const unsigned char next = static_cast<unsigned char>(line[position]);
    return !(std::isalnum(next) || next == '_');
}

SourceLineKind classifySourceLine(const std::string& stripped, std::string& includeTarget) {
    if (!startsWithKeyword(stripped, "include")) return SourceLineKind::ordinary;
    size_t position = 1;
    while (position < stripped.size() && (stripped[position] == ' ' || stripped[position] == '\t')) ++position;
    position += std::char_traits<char>::length("include");
    while (position < stripped.size() && (stripped[position] == ' ' || stripped[position] == '\t')) ++position;
    if (position >= stripped.size()) return SourceLineKind::invalidInclude;
    const char delimiter = stripped[position];
    const char closing = delimiter == '"' ? '"' : delimiter == '<' ? '>' : '\0';
    if (closing == '\0') return SourceLineKind::invalidInclude;
    const auto end = stripped.find(closing, position + 1);
    if (end == std::string::npos || end == position + 1) return SourceLineKind::invalidInclude;
    includeTarget = stripped.substr(position + 1, end - position - 1);
    return SourceLineKind::include;
}

bool resolveInclude(const fs::path& source, const fs::path& root, const std::string& target, fs::path& resolved) {
    std::vector<fs::path> candidates;
    const fs::path requested(target);
    if (requested.is_absolute()) {
        candidates.push_back(requested);
    } else {
        candidates.push_back(source.parent_path() / requested);
        candidates.push_back(root / requested);
    }
    for (const fs::path& candidate : candidates) {
        std::error_code error;
        if (fs::is_regular_file(candidate, error) && !error) {
            resolved = normalizedPath(candidate);
            return true;
        }
    }
    return false;
}

bool processScriptFile(
    const fs::path& requestedPath,
    IncludeLoadState& state,
    bool isHeader,
    int depth,
    std::string& output) {
    const fs::path path = normalizedPath(requestedPath);
    const std::string key = path.generic_string();
    if (depth > 16) {
        setIncludeError(state, path, 0, "include depth exceeds 16");
        return false;
    }
    if (std::find(state.stack.begin(), state.stack.end(), path) != state.stack.end()) {
        setIncludeError(state, path, 0, "cyclic include detected");
        return false;
    }
    if (isHeader && state.includedHeaders.contains(key)) return true;

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        setIncludeError(state, path, 0, "cannot open script file");
        return false;
    }

    state.stack.push_back(path);
    std::string line;
    int lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        const std::string stripped = trim(line);
        if (startsWithKeyword(stripped, "pragma") &&
            trim(stripped.substr(7)) == "once") {
            output.push_back('\n');
            continue;
        }

        std::string includeTarget;
        const SourceLineKind kind = classifySourceLine(stripped, includeTarget);
        if (kind == SourceLineKind::invalidInclude) {
            setIncludeError(state, path, lineNumber, "invalid include directive");
            state.stack.pop_back();
            return false;
        }
        if (kind != SourceLineKind::include) {
            output.append(line);
            output.push_back('\n');
            continue;
        }

        output.push_back('\n');
        fs::path includePath;
        if (!resolveInclude(path, state.root, includeTarget, includePath)) {
            setIncludeError(state, path, lineNumber, "include not found: " + includeTarget);
            state.stack.pop_back();
            return false;
        }
        if (!extensionEquals(includePath, ".ash")) {
            setIncludeError(state, path, lineNumber, "include target must use .ash: " + includeTarget);
            state.stack.pop_back();
            return false;
        }
        if (state.includedHeaders.contains(includePath.generic_string())) continue;
        if (std::find(state.stack.begin(), state.stack.end(), includePath) != state.stack.end()) {
            state.stack.push_back(includePath);
            setIncludeError(state, includePath, 0, "cyclic include detected");
            state.stack.pop_back();
            state.stack.pop_back();
            return false;
        }

        std::string headerSource;
        if (!processScriptFile(includePath, state, true, depth + 1, headerSource)) {
            state.stack.pop_back();
            return false;
        }
        state.sections->push_back({sectionName(includePath, state.root), std::move(headerSource)});
        state.includedHeaders.insert(includePath.generic_string());
    }

    state.stack.pop_back();
    if (isHeader) state.includedHeaders.insert(key);
    return true;
}

bool collectScriptFiles(
    const fs::path& directory,
    std::vector<fs::path>& scripts,
    std::vector<fs::path>& headers,
    std::string& error) {
    std::error_code iteratorError;
    fs::recursive_directory_iterator iterator(
        directory, fs::directory_options::skip_permission_denied, iteratorError);
    if (iteratorError) {
        error = "cannot enumerate script directory: " + iteratorError.message();
        return false;
    }

    const fs::recursive_directory_iterator end;
    while (iterator != end) {
        std::error_code entryError;
        const fs::directory_entry& entry = *iterator;
        if (entry.is_regular_file(entryError) && !entryError) {
            if (extensionEquals(entry.path(), ".as")) {
                scripts.push_back(normalizedPath(entry.path()));
            } else if (extensionEquals(entry.path(), ".ash")) {
                headers.push_back(normalizedPath(entry.path()));
            }
        }
        if (entryError) {
            error = "cannot inspect script entry: " + entryError.message();
            return false;
        }
        iterator.increment(iteratorError);
        if (iteratorError) {
            error = "cannot enumerate script directory: " + iteratorError.message();
            return false;
        }
    }

    std::sort(scripts.begin(), scripts.end(), [](const fs::path& left, const fs::path& right) {
        return left.generic_string() < right.generic_string();
    });
    std::sort(headers.begin(), headers.end(), [](const fs::path& left, const fs::path& right) {
        return left.generic_string() < right.generic_string();
    });
    return true;
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
    const sigilhook_handle hook{static_cast<uint64_t>(handle)};
    if (sigilhook_destroy(hook) == SIGILHOOK_OK) {
        std::lock_guard lock(g_runtime.scriptHooksMutex);
        g_runtime.scriptHooks.erase(hook.value);
    }
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

asQWORD scriptGetXmm(asBYTE reg, asBYTE lane) {
    uint64_t value = 0;
    sigilhook_call_frame_get_xmm(
        g_currentFrame, static_cast<uint8_t>(reg), static_cast<uint8_t>(lane), &value);
    return value;
}

bool scriptSetXmm(asBYTE reg, asBYTE lane, asQWORD value) {
    return sigilhook_call_frame_set_xmm(
               g_currentFrame, static_cast<uint8_t>(reg), static_cast<uint8_t>(lane),
               static_cast<uint64_t>(value)) == SIGILHOOK_OK;
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

bool beginScriptCallback() {
    std::lock_guard lock(g_runtime.callbackMutex);
    if (g_runtime.stopping.load(std::memory_order_acquire)) return false;
    g_runtime.activeCallbacks.fetch_add(1, std::memory_order_acq_rel);
    return true;
}

struct ExecutionBudget {
    std::chrono::steady_clock::time_point deadline;
    bool cancelOnStop = true;
};

void executionLineCallback(asIScriptContext* context, ExecutionBudget* budget) {
    if (context == nullptr || budget == nullptr) return;
    if ((budget->cancelOnStop && g_runtime.stopping.load(std::memory_order_acquire)) ||
        std::chrono::steady_clock::now() >= budget->deadline) {
        context->Abort();
    }
}

void finishScriptCallback() {
    {
        std::lock_guard lock(g_runtime.callbackMutex);
        g_runtime.activeCallbacks.fetch_sub(1, std::memory_order_acq_rel);
    }
    g_runtime.callbackCondition.notify_all();
}

bool waitForScriptCallbacks(std::chrono::steady_clock::time_point deadline) {
    std::unique_lock lock(g_runtime.callbackMutex);
    const auto done = [] {
        return g_runtime.activeCallbacks.load(std::memory_order_acquire) == 0;
    };
    if (done()) return true;

    return g_runtime.callbackCondition.wait_until(lock, deadline, done);
}

void scriptJitCallback(sigilhook_call_frame* frame, void* userData) {
    auto* binding = static_cast<ScriptBinding*>(userData);
    if (!beginScriptCallback()) return;
    if (binding == nullptr || binding->callback == nullptr) {
        finishScriptCallback();
        return;
    }

    sigilhook_call_frame* previous = g_currentFrame;
    g_currentFrame = frame;
    asIScriptContext* context = g_runtime.engine != nullptr ? g_runtime.engine->RequestContext() : nullptr;
    if (context != nullptr) {
        ExecutionBudget budget{
            std::chrono::steady_clock::now() +
                std::chrono::milliseconds(SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS),
            true
        };
        context->SetLineCallback(asFUNCTION(executionLineCallback), &budget, asCALL_CDECL);
        if (context->Prepare(binding->callback) >= 0) {
            const int result = context->Execute();
            if (result != asEXECUTION_FINISHED) {
                writeLog("script callback did not finish normally: " + binding->declaration);
            }
        }
        context->ClearLineCallback();
        g_runtime.engine->ReturnContext(context);
    }
    g_currentFrame = previous;
    finishScriptCallback();
}

void scriptSetFollowCall(asQWORD handle, int enabled) {
    sigilhook_set_follow_call_on_target(sigilhook_handle{static_cast<uint64_t>(handle)}, enabled);
}

void trackScriptHook(sigilhook_handle hook) {
    if (hook.value == 0) return;
    std::lock_guard lock(g_runtime.scriptHooksMutex);
    g_runtime.scriptHooks.insert(hook.value);
}

void untrackScriptHook(sigilhook_handle hook) {
    if (hook.value == 0) return;
    std::lock_guard lock(g_runtime.scriptHooksMutex);
    g_runtime.scriptHooks.erase(hook.value);
}

asQWORD activateHook(sigilhook_handle hook) {
    if (sigilhook_hook(hook) != SIGILHOOK_OK) {
        sigilhook_destroy(hook);
        return 0;
    }
    trackScriptHook(hook);
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
    if (status == SIGILHOOK_OK) trackScriptHook(hook);
    return static_cast<asBYTE>(status);
}

asBYTE scriptStatusDestroy(asQWORD handle) {
    const sigilhook_handle hook{static_cast<uint64_t>(handle)};
    const sigilhook_status status = sigilhook_destroy(hook);
    if (status == SIGILHOOK_OK) untrackScriptHook(hook);
    return static_cast<asBYTE>(status);
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
    if (status == SIGILHOOK_OK) trackScriptHook(hook);
    return static_cast<asBYTE>(status);
}

asBYTE scriptCreateHardwareBreakpoint(
    asQWORD target, asQWORD callback, asQWORD thread, asQWORD& outHook) {
    sigilhook_handle hook{};
    const sigilhook_status status = sigilhook_create_hardware_breakpoint(
        static_cast<uint64_t>(target), static_cast<uint64_t>(callback),
        static_cast<uintptr_t>(thread), &hook);
    outHook = hook.value;
    if (status == SIGILHOOK_OK) trackScriptHook(hook);
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
    if (status == SIGILHOOK_OK) trackScriptHook(hook);
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
    if (status == SIGILHOOK_OK) trackScriptHook(hook);
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
    if (status == SIGILHOOK_OK) trackScriptHook(hook);
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
        trackScriptHook(hook);
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

asBYTE scriptReloadRuntime() {
    return static_cast<asBYTE>(sigilhook_runtime_reload());
}

asBYTE scriptReloadRuntimeWithTimeout(asUINT timeoutMs) {
    return static_cast<asBYTE>(sigilhook_runtime_reload_with_timeout(timeoutMs));
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
asQWORD scriptNativeAddress(const std::string& dll, const std::string& name, const std::string& convention);
asBYTE scriptInvokeNativeBlob(asQWORD target, const std::string& signature, const std::string& convention, const CScriptArray& arguments, CScriptArray& returns);
void scriptNativeThrow(asBYTE status);
CScriptArray* scriptNativeStringBytes(const std::string& value, bool wide);
asQWORD scriptBufferAddress(const CScriptArray& bytes);
asQWORD scriptReadBlob(const CScriptArray& bytes, asUINT offset, asUINT width);
void scriptWriteBlob(CScriptArray& bytes, asUINT offset, asUINT width, asQWORD value);
asQWORD scriptFloatBits(float value);
float scriptBitsFloat(asQWORD bits);
asQWORD scriptDoubleBits(double value);
double scriptBitsDouble(asQWORD bits);

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
    engine->RegisterGlobalFunction("uint64 getXmm(uint8, uint8)", asFUNCTION(scriptGetXmm), asCALL_CDECL);
    engine->RegisterGlobalFunction("bool setXmm(uint8, uint8, uint64)", asFUNCTION(scriptSetXmm), asCALL_CDECL);
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
    engine->RegisterGlobalFunction("uint8 reloadRuntime()", asFUNCTION(scriptReloadRuntime), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 reloadRuntimeWithTimeout(uint)", asFUNCTION(scriptReloadRuntimeWithTimeout), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 callEntry(const string &in)", asFUNCTION(scriptCallEntry), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 setSharedU64Status(const string &in, uint64)", asFUNCTION(scriptStatusSetSharedU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 sharedU64Status(const string &in, uint64 &out)", asFUNCTION(scriptStatusSharedU64), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 invokeUsercall(uint64, const string &in, const string &in, const string &in, const array<uint64> &in, uint64 &out)", asFUNCTION(scriptInvokeUsercall), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 nativeAddress(const string &in, const string &in, const string &in)", asFUNCTION(scriptNativeAddress), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint8 invokeNativeBlob(uint64, const string &in, const string &in, const array<uint8> &in, array<uint8> &inout)", asFUNCTION(scriptInvokeNativeBlob), asCALL_CDECL);
    engine->RegisterGlobalFunction("void nativeThrow(uint8)", asFUNCTION(scriptNativeThrow), asCALL_CDECL);
    engine->RegisterGlobalFunction("array<uint8>@ nativeStringBytes(const string &in, bool)", asFUNCTION(scriptNativeStringBytes), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 bufferAddress(const array<uint8> &in)", asFUNCTION(scriptBufferAddress), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 shReadBlob(const array<uint8> &in, uint, uint)", asFUNCTION(scriptReadBlob), asCALL_CDECL);
    engine->RegisterGlobalFunction("void shWriteBlob(array<uint8> &inout, uint, uint, uint64)", asFUNCTION(scriptWriteBlob), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint32 shFloatBits(float)", asFUNCTION(scriptFloatBits), asCALL_CDECL);
    engine->RegisterGlobalFunction("float shBitsFloat(uint32)", asFUNCTION(scriptBitsFloat), asCALL_CDECL);
    engine->RegisterGlobalFunction("uint64 shDoubleBits(double)", asFUNCTION(scriptDoubleBits), asCALL_CDECL);
    engine->RegisterGlobalFunction("double shBitsDouble(uint64)", asFUNCTION(scriptBitsDouble), asCALL_CDECL);
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
    trackScriptHook(binding->hook);
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

bool runEntry(asIScriptModule* module, const char* declaration,
              std::chrono::steady_clock::time_point deadline =
                  (std::chrono::steady_clock::time_point::max)()) {
    if (module == nullptr) return false;
    asIScriptFunction* function = module->GetFunctionByDecl(declaration);
    if (function == nullptr) return true;
    asIScriptContext* context = g_runtime.engine->CreateContext();
    if (context == nullptr) return false;
    ExecutionBudget budget{deadline, !g_unloading};
    context->SetLineCallback(asFUNCTION(executionLineCallback), &budget, asCALL_CDECL);
    const bool result = context->Prepare(function) >= 0 && context->Execute() == asEXECUTION_FINISHED;
    if (context->GetState() != asEXECUTION_FINISHED) {
        const char* exception = context->GetExceptionString();
        int exceptionColumn = 0;
        const char* exceptionSection = nullptr;
        const int exceptionLine = context->GetExceptionLineNumber(&exceptionColumn, &exceptionSection);
        writeLog(std::string("script entry exception in ") + declaration + ": " + (exception == nullptr ? "unknown" : exception));
        writeLog("exception location: " + std::to_string(exceptionLine) + ":" + std::to_string(exceptionColumn) + " in " + (exceptionSection == nullptr ? "" : exceptionSection));
    }
    context->ClearLineCallback();
    context->Release();
    return result;
}

bool destroyScriptBindings() {
    std::vector<uint64_t> hooks;
    {
        std::lock_guard lock(g_runtime.scriptHooksMutex);
        hooks.assign(g_runtime.scriptHooks.begin(), g_runtime.scriptHooks.end());
    }
    std::sort(hooks.rbegin(), hooks.rend());
    for (const uint64_t value : hooks) {
        const auto status = sigilhook_destroy(sigilhook_handle{value});
        if (status != SIGILHOOK_OK && status != SIGILHOOK_ERROR_NOT_FOUND) return false;
        untrackScriptHook(sigilhook_handle{value});
    }
    std::lock_guard bindingsLock(g_runtime.bindingsMutex);
    for (auto& binding : g_runtime.bindings) {
        if (binding == nullptr || binding->jit.value == 0) continue;
        const auto status = sigilhook_destroy_jit_callback(binding->jit);
        if (status != SIGILHOOK_OK && status != SIGILHOOK_ERROR_NOT_FOUND) return false;
        binding->jit = {};
    }
    g_runtime.bindings.clear();
    return true;
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
    if (g_runtime.stopping) return SIGILHOOK_ERROR_BUSY;
    if (g_runtime.started) return SIGILHOOK_OK;
    g_runtime.scriptDirectory = requestedDirectory.empty() ? modulePath() / "SigilHook" : requestedDirectory;
    g_runtime.logPath = g_runtime.scriptDirectory / "logs" / "SigilHook.log";
    std::error_code error;
    fs::create_directories(g_runtime.logPath.parent_path(), error);
    if (error) {
        g_runtime.scriptDirectory.clear();
        g_runtime.logPath.clear();
        return SIGILHOOK_ERROR_SCRIPT;
    }
    sigilhook_set_log_callback(runtimeLogCallback, nullptr);
    g_runtime.engine = asCreateScriptEngine();
    if (g_runtime.engine == nullptr) {
        sigilhook_set_log_callback(nullptr, nullptr);
        g_runtime.scriptDirectory.clear();
        g_runtime.logPath.clear();
        return SIGILHOOK_ERROR_SCRIPT;
    }
    g_runtime.engine->SetMessageCallback(asFUNCTION(messageCallback), nullptr, asCALL_CDECL);
    registerScriptApi(g_runtime.engine);
    registerScriptHookApi(g_runtime.engine);
    g_runtime.started = true;
    return SIGILHOOK_OK;
}

sigilhook_status loadDirectory(const fs::path& directory) {
    if (g_runtime.stopping || asGetActiveContext() != nullptr) return SIGILHOOK_ERROR_BUSY;
    const bool startedHere = !g_runtime.started.load(std::memory_order_acquire);
    if (!g_runtime.started) {
        const sigilhook_status status = startRuntime(directory);
        if (status != SIGILHOOK_OK) return status;
    }
    const auto failLoad = [startedHere](sigilhook_status status) {
        if (startedHere && g_runtime.modules.empty() && g_runtime.engine != nullptr) {
            g_runtime.engine->ShutDownAndRelease();
            g_runtime.engine = nullptr;
            g_runtime.started = false;
            g_runtime.scriptDirectory.clear();
            g_runtime.logPath.clear();
            sigilhook_set_log_callback(nullptr, nullptr);
        }
        return status;
    };
    std::lock_guard lock(g_runtime.mutex);
    std::lock_guard entryLock(g_runtime.entryMutex);
    if (!g_runtime.started || g_runtime.stopping) return SIGILHOOK_ERROR_BUSY;
    if (!g_runtime.modules.empty()) {
        writeLog("script load error: a script application is already loaded");
        return failLoad(SIGILHOOK_ERROR_BUSY);
    }

    const fs::path requestedRoot = normalizedPath(directory);
    if (g_runtime.scriptDirectory != requestedRoot) {
        g_runtime.scriptDirectory = requestedRoot;
        g_runtime.logPath = requestedRoot / "logs" / "SigilHook.log";
        std::error_code logError;
        fs::create_directories(g_runtime.logPath.parent_path(), logError);
        if (logError) return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }
    const fs::path root = normalizedPath(directory);
    const fs::path mainPath = normalizedPath(root / "main.as");
    std::error_code mainError;
    if (!fs::is_regular_file(mainPath, mainError) || mainError) {
        writeLog("script load error: main.as was not found in " + root.string());
        return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }

    std::vector<fs::path> scripts;
    std::vector<fs::path> headers;
    std::string collectionError;
    if (!collectScriptFiles(root, scripts, headers, collectionError)) {
        writeLog("script load error: " + collectionError);
        return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }

    IncludeLoadState includeState;
    includeState.root = root;
    std::vector<ScriptSection> sections;
    includeState.sections = &sections;
    std::string mainSectionName;
    for (const fs::path& script : scripts) {
        std::string source;
        if (!processScriptFile(script, includeState, false, 0, source)) {
            writeLog("script load error: " + includeState.error);
            return failLoad(SIGILHOOK_ERROR_SCRIPT);
        }
        const std::string name = sectionName(script, root);
        if (script == mainPath) mainSectionName = name;
        sections.push_back({name, std::move(source)});
    }

    asIScriptModule* module = g_runtime.engine->GetModule("SigilHook.Application", asGM_ALWAYS_CREATE);
    if (module == nullptr) {
        writeLog("failed to create SigilHook.Application module");
        return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }
    for (const ScriptSection& section : sections) {
        if (module->AddScriptSection(section.name.c_str(), section.source.c_str(), section.source.size()) < 0) {
            writeLog("failed to add script section " + section.name);
            module->Discard();
            return failLoad(SIGILHOOK_ERROR_SCRIPT);
        }
    }
    if (module->Build() < 0) {
        writeLog("failed to build SigilHook.Application; entry definitions must be unique and valid");
        module->Discard();
        return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }

    asIScriptFunction* mainFunction = module->GetFunctionByDecl("void main()");
    if (mainFunction == nullptr) {
        writeLog("script load error: void main() is missing from main.as");
        module->Discard();
        return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }
    const char* mainOwner = nullptr;
    if (mainFunction->GetDeclaredAt(&mainOwner, nullptr, nullptr) < 0 ||
        mainOwner == nullptr || mainSectionName != mainOwner) {
        writeLog("script load error: void main() must be defined in root main.as");
        module->Discard();
        return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }
    asIScriptFunction* unloadFunction = module->GetFunctionByDecl("void unload()");
    if (unloadFunction != nullptr) {
        const char* unloadOwner = nullptr;
        if (unloadFunction->GetDeclaredAt(&unloadOwner, nullptr, nullptr) < 0 ||
            unloadOwner == nullptr || mainSectionName != unloadOwner) {
            writeLog("script load error: optional void unload() must be defined in root main.as");
            module->Discard();
            return failLoad(SIGILHOOK_ERROR_SCRIPT);
        }
    }

    g_runtime.modules.push_back(module);
    if (!runEntry(module, "void main()")) {
        writeLog("entry point failed in " + (root / "main.as").string());
        g_runtime.stopping.store(true, std::memory_order_release);
        const auto rollbackDeadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS);
        if (!waitForScriptCallbacks(rollbackDeadline)) {
            writeLog("rollback deferred: quiesce target calls and stop the runtime before unloading");
            g_runtime.stopping.store(false, std::memory_order_release);
            return SIGILHOOK_ERROR_SCRIPT;
        }
        const bool previousUnloading = g_unloading;
        g_unloading = true;
        const bool unloadResult = runEntry(module, "void unload()", rollbackDeadline);
        g_unloading = previousUnloading;
        if (!unloadResult) {
            writeLog("rollback unload() did not finish normally");
        }
        if (!destroyScriptBindings()) {
            writeLog("rollback deferred: script bindings could not be destroyed");
            g_runtime.stopping.store(false, std::memory_order_release);
            return SIGILHOOK_ERROR_SCRIPT;
        }
        sigilhook_clear_invoker_cache();
        sigilhook_modules_shutdown();
        g_runtime.modules.pop_back();
        module->Discard();
        g_runtime.stopping.store(false, std::memory_order_release);
        return failLoad(SIGILHOOK_ERROR_SCRIPT);
    }
    return SIGILHOOK_OK;
}

sigilhook_status stopRuntime(uint32_t timeoutMs) {
    if (asGetActiveContext() != nullptr) {
        writeLog("runtime stop requested from an active script context; call it from a native thread");
        return SIGILHOOK_ERROR_BUSY;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    g_runtime.stopping.store(true, std::memory_order_release);
    std::unique_lock lock(g_runtime.mutex, std::defer_lock);
    if (!lock.try_lock_until(deadline)) {
        g_runtime.stopping.store(false, std::memory_order_release);
        return SIGILHOOK_ERROR_BUSY;
    }
    std::unique_lock entryLock(g_runtime.entryMutex, std::defer_lock);
    if (!entryLock.try_lock_until(deadline)) {
        g_runtime.stopping.store(false, std::memory_order_release);
        return SIGILHOOK_ERROR_BUSY;
    }
    if (!g_runtime.started) {
        g_runtime.stopping.store(false, std::memory_order_release);
        return SIGILHOOK_OK;
    }
    if (!waitForScriptCallbacks(deadline)) {
        writeLog("runtime stop pending: quiesce native target calls, then retry");
        g_runtime.stopping.store(false, std::memory_order_release);
        return SIGILHOOK_ERROR_BUSY;
    }

    const bool previousUnloading = g_unloading;
    bool unloadSucceeded = true;
    g_unloading = true;
    for (auto iterator = g_runtime.modules.rbegin(); iterator != g_runtime.modules.rend(); ++iterator) {
        unloadSucceeded = runEntry(*iterator, "void unload()", deadline) && unloadSucceeded;
    }
    g_unloading = previousUnloading;
    if (!destroyScriptBindings()) {
        writeLog("runtime cleanup failed; resources retained for a stop retry");
        g_runtime.stopping.store(false, std::memory_order_release);
        return SIGILHOOK_ERROR_BUSY;
    }
    sigilhook_clear_invoker_cache();
    sigilhook_modules_shutdown();
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
    return unloadSucceeded ? SIGILHOOK_OK : SIGILHOOK_ERROR_SCRIPT;
}

sigilhook_status reloadRuntime(uint32_t timeoutMs) {
    if (asGetActiveContext() != nullptr) {
        writeLog("runtime reload requested from an active script context; call it from a native thread");
        return SIGILHOOK_ERROR_BUSY;
    }
    fs::path directory;
    {
        std::lock_guard lock(g_runtime.mutex);
        if (!g_runtime.started || g_runtime.modules.empty()) {
            writeLog("runtime reload skipped: no script application is loaded");
            return SIGILHOOK_ERROR_NOT_FOUND;
        }
        directory = g_runtime.scriptDirectory;
    }
    if (directory.empty()) {
        writeLog("runtime reload skipped: the script directory is not known");
        return SIGILHOOK_ERROR_SCRIPT;
    }

    writeLog("runtime reload requested for " + directory.string());
    const sigilhook_status stopStatus = stopRuntime(timeoutMs);
    if (stopStatus != SIGILHOOK_OK) {
        writeLog("runtime reload aborted: stop returned " + std::to_string(static_cast<int>(stopStatus)));
        return stopStatus;
    }

    const sigilhook_status startStatus = startRuntime(directory);
    if (startStatus != SIGILHOOK_OK) {
        writeLog("runtime reload failed: start returned " + std::to_string(static_cast<int>(startStatus)));
        return startStatus;
    }
    const sigilhook_status loadStatus = loadDirectory(directory);
    if (loadStatus != SIGILHOOK_OK) {
        writeLog("runtime reload failed: load returned " + std::to_string(static_cast<int>(loadStatus)));
        // Keep the public runtime state consistent: a failed load leaves no
        // application behind, so tear the freshly started engine back down.
        const sigilhook_status cleanupStatus = stopRuntime(timeoutMs);
        if (cleanupStatus != SIGILHOOK_OK) {
            writeLog("runtime reload cleanup failed: stop returned " +
                std::to_string(static_cast<int>(cleanupStatus)));
        }
        return loadStatus;
    }
    writeLog("runtime reload completed");
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
    return stopRuntime(SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS);
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_stop_with_timeout(uint32_t timeoutMs) {
    return stopRuntime(timeoutMs);
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_load_directory(const wchar_t* scriptDirectory) {
    if (scriptDirectory == nullptr || *scriptDirectory == L'\0') {
        return SIGILHOOK_ERROR_INVALID_ARGUMENT;
    }
    return loadDirectory(fs::path(scriptDirectory));
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_reload(void) {
    return reloadRuntime(SIGILHOOK_RUNTIME_DEFAULT_STOP_TIMEOUT_MS);
}

sigilhook_status SIGILHOOK_CALL sigilhook_runtime_reload_with_timeout(uint32_t timeoutMs) {
    return reloadRuntime(timeoutMs);
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
    if (g_runtime.stopping && !g_unloading) return SIGILHOOK_ERROR_BUSY;
    std::lock_guard entryLock(g_runtime.entryMutex);
    if (g_runtime.stopping && !g_unloading) return SIGILHOOK_ERROR_BUSY;
    bool all = true;
    for (asIScriptModule* module : g_runtime.modules) {
        all = runEntry(module, declaration) && all;
    }
    return all ? SIGILHOOK_OK : SIGILHOOK_ERROR_SCRIPT;
}

} // extern "C"
namespace {
asQWORD scriptNativeAddress(const std::string& dll, const std::string& name, const std::string& convention) {
    uint64_t address = 0;
    sigilhook_native_address(dll.c_str(), name.c_str(), convention.c_str(), &address);
    return address;
}

asBYTE scriptInvokeNativeBlob(
    asQWORD target, const std::string& signature, const std::string& convention,
    const CScriptArray& arguments, CScriptArray& returns) {
    const asBYTE nativeStatus = static_cast<asBYTE>(sigilhook_invoke_native_blob(
        static_cast<uint64_t>(target), signature.c_str(), signature.c_str(), convention.c_str(),
        const_cast<CScriptArray&>(arguments).GetBuffer(), arguments.GetSize(),
        returns.GetBuffer(), returns.GetSize()));
    return nativeStatus;
}

void scriptNativeThrow(asBYTE status) {
    if (asIScriptContext* context = asGetActiveContext()) {
        context->SetException(sigilhook_status_string(static_cast<sigilhook_status>(status)));
    }
}

CScriptArray* scriptNativeStringBytes(const std::string& value, bool wide) {
    asIScriptContext* context = asGetActiveContext();
    asITypeInfo* type = context == nullptr || context->GetEngine() == nullptr
        ? nullptr : context->GetEngine()->GetTypeInfoByDecl("array<uint8>");
    if (type == nullptr) return nullptr;
    if (!wide) {
        CScriptArray* result = CScriptArray::Create(type, static_cast<asUINT>(value.size() + 1));
        if (result != nullptr) {
            if (!value.empty()) std::memcpy(result->GetBuffer(), value.data(), value.size());
            static_cast<uint8_t*>(result->GetBuffer())[value.size()] = 0;
        }
        return result;
    }
#if defined(_WIN32)
    const int count = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) return nullptr;
    std::wstring wideValue(static_cast<size_t>(count) + 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), wideValue.data(), count);
    CScriptArray* result = CScriptArray::Create(type, static_cast<asUINT>(wideValue.size() * sizeof(wchar_t)));
    if (result != nullptr) std::memcpy(result->GetBuffer(), wideValue.data(), wideValue.size() * sizeof(wchar_t));
    return result;
#else
    CScriptArray* result = CScriptArray::Create(type, static_cast<asUINT>(value.size()));
    if (result != nullptr) {
        if (!value.empty()) std::memcpy(result->GetBuffer(), value.data(), value.size());
        static_cast<uint8_t*>(result->GetBuffer())[value.size()] = 0;
    }
    return result;
#endif
}

asQWORD scriptBufferAddress(const CScriptArray& bytes) {
    return static_cast<asQWORD>(reinterpret_cast<uintptr_t>(const_cast<CScriptArray&>(bytes).GetBuffer()));
}

asQWORD scriptReadBlob(const CScriptArray& bytes, asUINT offset, asUINT width) {
    if (width == 0 || width > 8 || offset > bytes.GetSize() || width > bytes.GetSize() - offset) return 0;
    const auto* data = static_cast<const uint8_t*>(const_cast<CScriptArray&>(bytes).GetBuffer());
    uint64_t value = 0;
    for (asUINT index = 0; index < width; ++index) value |= static_cast<uint64_t>(data[offset + index]) << (index * 8);
    return value;
}

void scriptWriteBlob(CScriptArray& bytes, asUINT offset, asUINT width, asQWORD value) {
    if (width == 0 || width > 8) return;
    const asUINT required = offset + width;
    if (required < offset || required > bytes.GetSize()) bytes.Resize(required);
    auto* data = static_cast<uint8_t*>(bytes.GetBuffer());
    for (asUINT index = 0; index < width; ++index) data[offset + index] = static_cast<uint8_t>(value >> (index * 8));
}

asQWORD scriptFloatBits(float value) {
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

asQWORD scriptDoubleBits(double value) {
    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

float scriptBitsFloat(asQWORD bits) {
    const uint32_t value = static_cast<uint32_t>(bits);
    float result = 0.0f;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

double scriptBitsDouble(asQWORD bits) {
    const uint64_t value = static_cast<uint64_t>(bits);
    double result = 0.0;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}
} // namespace
