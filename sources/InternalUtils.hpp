#pragma once

// This header defines utilities that are not meant to be used by the users of this library

#ifdef SIGILHOOK_DIAGNOSTICS
#define SIGILHOOK_SET_DIAGNOSTIC(DIAGNOSTIC) setDiagnostic(DIAGNOSTIC)
#else
#define SIGILHOOK_SET_DIAGNOSTIC(DIAGNOSTIC)
#endif
