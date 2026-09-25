#include <memory>

#include <Catch.hpp>

#include "sigilhook/Virtuals/VFuncSwapHook.hpp"
#include "sigilhook/Tests/StackCanary.hpp"
#include "sigilhook/Tests/TestEffectTracker.hpp"

EffectTracker vFuncSwapEffects;

class VirtualTest2 {
public:
	virtual ~VirtualTest2() {}

	virtual int __stdcall NoParamVirt() {
		return 4;
	}

	virtual int __stdcall NoParamVirt2() {
		return 7;
	}
};

#pragma warning(disable: 4100)

SIGILHOOK::VFuncMap origVFuncs2;
HOOK_CALLBACK(&VirtualTest2::NoParamVirt, hkVirtNoParams2, {
	SIGILHOOK::StackCanary canary;
	vFuncSwapEffects.PeakEffect().trigger();
	return ((hkVirtNoParams2_t)origVFuncs2.at(1))(_args...);
});

HOOK_CALLBACK(&VirtualTest2::NoParamVirt2, hkVirt2NoParams2, {
	SIGILHOOK::StackCanary canary;
	vFuncSwapEffects.PeakEffect().trigger();
	return ((hkVirtNoParams2_t)origVFuncs2.at(2))(_args...);
});

TEST_CASE("VFuncSwap tests", "[VFuncSwap]") {
	std::shared_ptr<VirtualTest2> ClassToHook(new VirtualTest2);

	SECTION("Verify vfunc redirected") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::VFuncMap redirect = {{(uint16_t)1, (uint64_t)hkVirtNoParams2}};
		SIGILHOOK::VFuncSwapHook hook((char*)ClassToHook.get(), redirect, &origVFuncs2);
		REQUIRE(hook.hook());
		REQUIRE(origVFuncs2.size() == 1);

		vFuncSwapEffects.PushEffect();
		ClassToHook->NoParamVirt();
		REQUIRE(vFuncSwapEffects.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify multiple vfunc redirected") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::VFuncMap redirect = {{(uint16_t)1, (uint64_t)hkVirtNoParams2},{(uint16_t)2, (uint64_t)hkVirt2NoParams2}};
		SIGILHOOK::VFuncSwapHook hook((char*)ClassToHook.get(), redirect, &origVFuncs2);
		REQUIRE(hook.hook());
		REQUIRE(origVFuncs2.size() == 2);

		vFuncSwapEffects.PushEffect();
		ClassToHook->NoParamVirt();
		REQUIRE(vFuncSwapEffects.PopEffect().didExecute());

		vFuncSwapEffects.PushEffect();
		ClassToHook->NoParamVirt2();
		REQUIRE(vFuncSwapEffects.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}
}