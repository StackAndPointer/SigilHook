#include <Catch.hpp>
#include "sigilhook/PE/IatHook.hpp"
#include "sigilhook/Tests/TestEffectTracker.hpp"
#include "sigilhook/Tests/StackCanary.hpp"
#include "sigilhook/SigilHookOsIncludes.hpp"

EffectTracker iatEffectTracker;

typedef DWORD(__stdcall* tGetCurrentThreadId)();
uint64_t oGetCurrentThreadID;

NOINLINE DWORD __stdcall hkGetCurrentThreadId() {
	iatEffectTracker.PeakEffect().trigger();
	return ((tGetCurrentThreadId)oGetCurrentThreadID)();
}

TEST_CASE("Iat Hook Tests", "[IatHook]") {
	SECTION("Verify api thunk is found and hooked") {
		SIGILHOOK::StackCanary canary;
		volatile DWORD thrdId2 = GetCurrentThreadId();
		UNREFERENCED_PARAMETER(thrdId2);
		SIGILHOOK::IatHook hook("kernel32.dll", "GetCurrentThreadId", (char*)&hkGetCurrentThreadId, (uint64_t*)&oGetCurrentThreadID, L"");
		REQUIRE(hook.hook());
		
		iatEffectTracker.PushEffect();
		REQUIRE(canary.isStackGood());
		volatile DWORD thrdId = GetCurrentThreadId();
		thrdId++;
		REQUIRE(iatEffectTracker.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify api thunk is found and hooked when module explicitly named") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::IatHook hook("kernel32.dll", "GetCurrentThreadId", (char*)&hkGetCurrentThreadId, (uint64_t*)&oGetCurrentThreadID, L"SigilHook.exe");
		REQUIRE(hook.hook());

		iatEffectTracker.PushEffect();
		volatile DWORD thrdId = GetCurrentThreadId();
		thrdId++;
		REQUIRE(hook.unHook());
	}
}