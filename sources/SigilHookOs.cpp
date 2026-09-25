#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/SigilHookOsIncludes.hpp"

#ifdef SIGILHOOK_OS_WINDOWS

void SigilHookDebugBreak() {
    DebugBreak();
}

#else

void SigilHookDebugBreak() {
    __asm__("int3");
}

#endif
