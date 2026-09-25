#ifndef SIGILHOOK_OS_INCLUDES_HPP
#define SIGILHOOK_OS_INCLUDES_HPP

// This file is used to not include os specific functions that might break other projects
// You should use it in sources

#if defined(SIGILHOOK_OS_WINDOWS)

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
  #define NOMINMAX
#endif
#include <windows.h>

#elif defined(SIGILHOOK_OS_LINUX)

#include <sys/mman.h>
#include <unistd.h>

#elif defined(SIGILHOOK_OS_APPLE)

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>

#endif

#endif