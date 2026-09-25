#include "sigilhook.h"

#include <cassert>
#include <cstdint>

namespace {
#if defined(_MSC_VER)
__declspec(noinline)
#endif
int SIGILHOOK_CALL target(int value) {
    return value + 1;
}

void SIGILHOOK_CALL callback(sigilhook_call_frame* frame, void*) {
    frame->arguments[0] = 41;
    *frame->return_value = 42;
}
}

int main() {
    assert(sigilhook_api_version() >= 0x00020000);
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    assert(sigilhook_create_jit_callback(
        "int", "int", "cdecl", callback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);
    sigilhook_handle hook{};
    uint64_t trampoline = 0;
    assert(sigilhook_create_detour(
        reinterpret_cast<uint64_t>(&target), callbackAddress, &hook, &trampoline) == SIGILHOOK_OK);
    assert(sigilhook_bind_detour_to_jit(hook, jit, nullptr) == SIGILHOOK_OK);
    assert(sigilhook_hook(hook) == SIGILHOOK_OK);
    assert(target(1) == 42);
    assert(sigilhook_unhook(hook) == SIGILHOOK_OK);
    assert(sigilhook_destroy(hook) == SIGILHOOK_OK);
    assert(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    return 0;
}

