// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#ifndef SIGILHOOK_H
#define SIGILHOOK_H

#if defined(__cplusplus)
#  include <cstddef>
#  include <cstdint>
#else
#  include <stddef.h>
#  include <stdint.h>
#endif

#if defined(_WIN32)
#  if defined(SIGILHOOK_BUILDING_DLL)
#    define SIGILHOOK_API __declspec(dllexport)
#  else
#    define SIGILHOOK_API __declspec(dllimport)
#  endif
#  define SIGILHOOK_CALL __cdecl
#else
#  define SIGILHOOK_API __attribute__((visibility("default")))
#  define SIGILHOOK_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sigilhook_handle { uint64_t value; } sigilhook_handle;
typedef struct sigilhook_jit_handle { uint64_t value; } sigilhook_jit_handle;

typedef enum sigilhook_status {
    SIGILHOOK_OK = 0,
    SIGILHOOK_ERROR_INVALID_ARGUMENT = 1,
    SIGILHOOK_ERROR_NOT_FOUND = 2,
    SIGILHOOK_ERROR_UNSUPPORTED = 3,
    SIGILHOOK_ERROR_ARCH_MISMATCH = 4,
    SIGILHOOK_ERROR_HOOK_FAILED = 5,
    SIGILHOOK_ERROR_MEMORY = 6,
    SIGILHOOK_ERROR_SCRIPT = 7,
    SIGILHOOK_ERROR_BUSY = 8,
    SIGILHOOK_ERROR_EXCEPTION = 9
} sigilhook_status;

typedef enum sigilhook_hook_type {
    SIGILHOOK_HOOK_UNKNOWN = 0,
    SIGILHOOK_HOOK_DETOUR = 1,
    SIGILHOOK_HOOK_SOFTWARE_BREAKPOINT = 2,
    SIGILHOOK_HOOK_HARDWARE_BREAKPOINT = 3,
    SIGILHOOK_HOOK_IAT = 4,
    SIGILHOOK_HOOK_EAT = 5,
    SIGILHOOK_HOOK_VFUNC_SWAP = 6,
    SIGILHOOK_HOOK_VTABLE_SWAP = 7
} sigilhook_hook_type;

typedef enum sigilhook_mode {
    SIGILHOOK_MODE_X86 = 1,
    SIGILHOOK_MODE_X64 = 2
} sigilhook_mode;

typedef enum sigilhook_rtti_mode {
    SIGILHOOK_RTTI_NONE = 0,
    SIGILHOOK_RTTI_MSVC = 1,
    SIGILHOOK_RTTI_ITANIUM = 2,
    SIGILHOOK_RTTI_DEFAULT = 3
} sigilhook_rtti_mode;

typedef enum sigilhook_protect {
    SIGILHOOK_PROT_NONE = 0,
    SIGILHOOK_PROT_X = 2,
    SIGILHOOK_PROT_R = 4,
    SIGILHOOK_PROT_W = 8,
    SIGILHOOK_PROT_RWX = 14
} sigilhook_protect;

typedef struct sigilhook_vfunc_entry {
    uint16_t index;
    uint64_t replacement;
} sigilhook_vfunc_entry;

typedef enum sigilhook_register {
    SIGILHOOK_REGISTER_AX = 0,
    SIGILHOOK_REGISTER_CX = 1,
    SIGILHOOK_REGISTER_DX = 2,
    SIGILHOOK_REGISTER_BX = 3,
    SIGILHOOK_REGISTER_SP = 4,
    SIGILHOOK_REGISTER_BP = 5,
    SIGILHOOK_REGISTER_SI = 6,
    SIGILHOOK_REGISTER_DI = 7,
    SIGILHOOK_REGISTER_R8 = 8,
    SIGILHOOK_REGISTER_R9 = 9,
    SIGILHOOK_REGISTER_R10 = 10,
    SIGILHOOK_REGISTER_R11 = 11,
    SIGILHOOK_REGISTER_R12 = 12,
    SIGILHOOK_REGISTER_R13 = 13,
    SIGILHOOK_REGISTER_R14 = 14,
    SIGILHOOK_REGISTER_R15 = 15,
    SIGILHOOK_REGISTER_COUNT = 16
} sigilhook_register;

typedef struct sigilhook_register_context {
    uint64_t registers[SIGILHOOK_REGISTER_COUNT];
    uint64_t flags;
    uint64_t write_mask;
} sigilhook_register_context;

typedef struct sigilhook_call_frame {
    uint64_t* arguments;
    uint8_t argument_count;
    uint64_t* return_value;
    uint8_t* call_original;
    uint8_t* return_value_overridden;
    sigilhook_register_context* registers;
    uint64_t instruction_pointer;
    uint64_t* instruction_pointer_destination;
    uint8_t* instruction_pointer_overridden;
} sigilhook_call_frame;

typedef void (SIGILHOOK_CALL *sigilhook_jit_callback)(
    sigilhook_call_frame* frame, void* user_data);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_get_register(
    const sigilhook_call_frame* frame, sigilhook_register reg, uint64_t* out_value);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_set_register(
    sigilhook_call_frame* frame, sigilhook_register reg, uint64_t value);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_get_flags(
    const sigilhook_call_frame* frame, uint64_t* out_flags);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_set_flags(
    sigilhook_call_frame* frame, uint64_t flags);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_get_instruction_pointer(
    const sigilhook_call_frame* frame, uint64_t* out_address);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_call_frame_set_instruction_pointer(
    sigilhook_call_frame* frame, uint64_t address);

typedef enum sigilhook_log_level {
    SIGILHOOK_LOG_INFO = 0,
    SIGILHOOK_LOG_WARNING = 1,
    SIGILHOOK_LOG_ERROR = 2
} sigilhook_log_level;

typedef void (SIGILHOOK_CALL *sigilhook_log_callback)(
    sigilhook_log_level level, const char* message, void* user_data);

SIGILHOOK_API uint32_t SIGILHOOK_CALL sigilhook_api_version(void);
SIGILHOOK_API sigilhook_mode SIGILHOOK_CALL sigilhook_build_mode(void);
SIGILHOOK_API const char* SIGILHOOK_CALL sigilhook_status_string(sigilhook_status status);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_get_last_error(char* buffer, size_t capacity);
SIGILHOOK_API void SIGILHOOK_CALL sigilhook_clear_last_error(void);
SIGILHOOK_API void SIGILHOOK_CALL sigilhook_set_log_callback(
    sigilhook_log_callback callback, void* user_data);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_detour(
    // out_trampoline is zero until installation; query sigilhook_get_trampoline after hooking.
    uint64_t target, uint64_t callback, sigilhook_handle* out_hook, uint64_t* out_trampoline);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_destroy(sigilhook_handle hook);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_hook(sigilhook_handle hook);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_unhook(sigilhook_handle hook);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_rehook(sigilhook_handle hook);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_set_hooked(sigilhook_handle hook, int hooked);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_is_hooked(sigilhook_handle hook, int* out_hooked);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_get_type(sigilhook_handle hook, sigilhook_hook_type* out_type);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_set_debug(sigilhook_handle hook, int enabled);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_get_trampoline(sigilhook_handle hook, uint64_t* out_trampoline);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_get_max_depth(sigilhook_handle hook, uint8_t* out_depth);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_set_max_depth(sigilhook_handle hook, uint8_t depth);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_set_follow_call_on_target(sigilhook_handle hook, int enabled);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_get_detour_scheme(sigilhook_handle hook, uint8_t* out_scheme);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_set_detour_scheme(sigilhook_handle hook, uint8_t scheme);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_breakpoint(
    uint64_t target, uint64_t callback, sigilhook_handle* out_hook);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_hardware_breakpoint(
    uint64_t target, uint64_t callback, uintptr_t thread, sigilhook_handle* out_hook);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_iat_hook(
    const char* imported_dll, const char* imported_api, const char* module_name,
    uint64_t callback, sigilhook_handle* out_hook, uint64_t* out_original);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_eat_hook(
    const char* exported_api, const char* module_name,
    uint64_t callback, sigilhook_handle* out_hook, uint64_t* out_original);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_vfunc_swap(
    uint64_t object, const sigilhook_vfunc_entry* entries, size_t entry_count,
    sigilhook_handle* out_hook);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_vtable_swap(
    uint64_t object, const sigilhook_vfunc_entry* entries, size_t entry_count,
    sigilhook_rtti_mode rtti_mode, sigilhook_handle* out_hook);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_get_original_vfunc(
    sigilhook_handle hook, uint16_t index, uint64_t* out_original);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_jit_callback(
    const char* return_type, const char* comma_separated_parameters,
    const char* call_convention, sigilhook_jit_callback callback, void* user_data,
    sigilhook_jit_handle* out_jit, uint64_t* out_address);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_destroy_jit_callback(sigilhook_jit_handle jit);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_bind_detour_to_jit(
    sigilhook_handle detour, sigilhook_jit_handle jit, sigilhook_handle* out_hook);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_mem_read(
    uint64_t address, void* destination, size_t size, size_t* out_read);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_mem_write(
    uint64_t address, const void* source, size_t size, size_t* out_written);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_mem_protect(
    uint64_t address, size_t size, sigilhook_protect protection, sigilhook_protect* out_previous);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_find_pattern(
    uint64_t address, size_t size, const char* ida_pattern, uint64_t* out_address);
SIGILHOOK_API uint64_t SIGILHOOK_CALL sigilhook_pattern_size(const char* ida_pattern);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_disassemble(
    uint64_t address, uint32_t max_bytes, char* output, size_t output_capacity,
    size_t* out_decoded_bytes);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_parse_hex(
    const char* text, uint64_t* out_value);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_compute_cmp_flags(
    uint64_t left, uint64_t right, uint8_t operand_size, uint64_t* out_flags);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_compute_test_flags(
    uint64_t left, uint64_t right, uint8_t operand_size, uint64_t* out_flags);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_fxsave(void* buffer, size_t size);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_fxrstor(const void* buffer, size_t size);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_return_snippet(
    uint64_t stack_adjust, uint64_t* out_address);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_destroy_snippet(uint64_t address);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_create_stack_jump_snippet(
    uint64_t stack_pointer, uint64_t target, uint64_t* out_address);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_invoke_usercall(
    uint64_t target, const char* return_type, const char* comma_separated_parameters,
    const char* call_convention, const uint64_t* arguments, size_t argument_count,
    uint64_t* out_return_value);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_clear_invoker_cache(void);

SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_runtime_start(const wchar_t* optional_script_directory);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_runtime_stop(void);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_runtime_stop_with_timeout(uint32_t timeout_ms);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_runtime_load_directory(const wchar_t* script_directory);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_runtime_call_entry(const char* declaration);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_runtime_set_shared_u64(const char* name, uint64_t value);
SIGILHOOK_API sigilhook_status SIGILHOOK_CALL sigilhook_runtime_get_shared_u64(const char* name, uint64_t* out_value);

#ifdef __cplusplus
}
#endif

#endif
