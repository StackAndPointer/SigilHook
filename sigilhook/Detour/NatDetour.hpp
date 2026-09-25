#pragma once

#include "sigilhook/SigilHookOs.hpp"

#ifdef SIGILHOOK_ARCH_X64
#include "sigilhook/Detour/x64Detour.hpp"
#else
#include "sigilhook/Detour/x86Detour.hpp"
#endif

namespace SIGILHOOK {
#ifdef SIGILHOOK_ARCH_X64
	using NatDetour = x64Detour;
#else
	using NatDetour = x86Detour;
#endif
}