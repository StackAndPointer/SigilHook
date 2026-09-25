#include <dlfcn.h>
#include <gnu/lib-names.h>

#include <Catch.hpp>

#include "sigilhook/Detour/x64Detour.hpp"
#include "sigilhook/SigilHookOsIncludes.hpp"
#include "sigilhook/Tests/StackCanary.hpp"
#include "sigilhook/Tests/TestEffectTracker.hpp"

#include "../TestUtils.hpp"

namespace {
	EffectTracker effects;
}

// TODO: Translation + INPLACE scheme

SIGILHOOK_TEST_DETOUR_CALLBACK(dlmopen, {
	printf("Hooked dlmopen\n");
});

TEST_CASE("Testing Detours with Translations", "[Translation][ADetour]") {
	SIGILHOOK::test::registerTestLogger();

// dlmopen may or may not have instructions requiring translations.
// Hence, this test was disabled. We need to construct reliable synthetic tests instead.
#if 0
	SECTION("dlmopen (INPLACE)") {
		SIGILHOOK::StackCanary canary;

		const auto* handleBefore = dlmopen(LM_ID_BASE, LIBM_SO, RTLD_NOW);

		SIGILHOOK::x64Detour detour((uint64_t)dlmopen, (uint64_t)dlmopen_hooked, &dlmopen_trmp);
		// Only INPLACE creates conditions for translation, since
		// trampoline will be close to 0x0, where as
		// dlmopen    will be close to 0x00007F__________
		detour.setDetourScheme(SIGILHOOK::x64Detour::detour_scheme_t::INPLACE);
		REQUIRE(detour.hook());

		effects.PushEffect();
		const auto* handleAfter = dlmopen(LM_ID_BASE, LIBM_SO, RTLD_NOW);

		REQUIRE(detour.hasDiagnostic(SIGILHOOK::Diagnostic::TranslatedInstructions));
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(handleAfter == handleBefore);

		REQUIRE(detour.unHook());
	}
#endif
}
