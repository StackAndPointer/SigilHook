// NOLINTBEGIN(*-err58-cpp)

#include <Catch.hpp>

#include "sigilhook/Detour/x64Detour.hpp"
#include "sigilhook/ZydisDisassembler.hpp"

#include "sigilhook/Tests/StackCanary.hpp"
#include "sigilhook/Tests/TestEffectTracker.hpp"

#include "sigilhook/SigilHookOsIncludes.hpp"

#include "../TestUtils.hpp"

EffectTracker effects;

NOINLINE void hookMe1() {
	SIGILHOOK::StackCanary canary;
	std::cout << "hookMe1 called" << std::endl;
	volatile int var = 1;
	volatile int var2 = 0;
	var2 += 3;
	var2 = var + var2;
	var2 *= 30 / 3;
	var = 2;
	printf("%d %d\n", var, var2); // 2, 40
	REQUIRE(var == 2);
	REQUIRE(var2 == 40);
}

SIGILHOOK_TEST_DETOUR_CALLBACK(hookMe1, {
	std::cout << "Hook 1 Called! Trampoline: 0x" << std::hex << hookMe1_trmp << std::endl;
});

NOINLINE void hookMe2() {
	SIGILHOOK::StackCanary canary;
	for (int i = 0; i < 10; i++) {
		printf("%d\n", i);
	}
}

SIGILHOOK_TEST_DETOUR_CALLBACK(hookMe2, {
	std::cout << "Hook 2 Called!" << std::endl;
});

unsigned char hookMe3[] = {
	0x57,								// push rdi
	0x74, 0xf9,							// je -5
	0x74, 0xf0,							// je -14
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // [x6] nop
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // [x6] nop
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // [x6] nop
	0xc3								// ret
};

unsigned char hookMe4[] = {
	0x57,								// push rdi
	0x48, 0x83, 0xec, 0x30,				// sub rsp, 0x30
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // [x6] nop
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // [x6] nop
	0x74, 0xf2,							// je 0x0
	0xc3								// ret
};

// test call instructions in prologue
unsigned char hookMe5[] = {
	0x48, 0x83, 0xEC, 0x28,					 // 180009240: sub rsp, 28h
	0xE8, 0x96, 0xA8, 0xFF, 0xFF,			 // call 180003ADF
	0x48, 0x83, 0xC4, 0x28,					 // add rsp, 28h
	0x48, 0xFF, 0xA0, 0x20, 0x01, 0x00, 0x00 // jmp qword ptr[rax+120h]
};

uint64_t nullTramp = 0;
NOINLINE void h_nullstub() {
	SIGILHOOK::StackCanary canary;
	SIGILHOOK_STOP_OPTIMIZATIONS();
}

SIGILHOOK_TEST_DETOUR_CALLBACK(malloc);

TEST_CASE("Testing 64 detours", "[x64Detour],[ADetour]") {
	SIGILHOOK::test::registerTestLogger();

	SECTION("Normal function (VALLOC2)") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour SIGILHOOK_TEST_DETOUR(hookMe1);
		detour.setDetourScheme(SIGILHOOK::x64Detour::VALLOC2);
		// VALLOC2 is not supported on linux so we expect hooking & unhooking to fail
		REQUIRE(detour.hook() == false);
		REQUIRE(detour.unHook() == false);
	}

	SECTION("Normal function (INPLACE)") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour SIGILHOOK_TEST_DETOUR(hookMe1);
		detour.setDetourScheme(SIGILHOOK::x64Detour::INPLACE);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Normal function (CODE_CAVE)") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour SIGILHOOK_TEST_DETOUR(hookMe1);
		detour.setDetourScheme(SIGILHOOK::x64Detour::CODE_CAVE);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Normal function (INPLACE_SHORT)") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour SIGILHOOK_TEST_DETOUR(hookMe1);
		detour.setDetourScheme(SIGILHOOK::x64Detour::INPLACE_SHORT);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Normal function rehook") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour SIGILHOOK_TEST_DETOUR(hookMe1);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		REQUIRE(detour.reHook() == true); // can only really test this doesn't
										  // cause memory corruption easily
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Loop function") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour SIGILHOOK_TEST_DETOUR(hookMe2);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe2();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prol w/src in range") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour detour((uint64_t)&hookMe3, (uint64_t)&h_nullstub, &nullTramp);
		detour.setDetourScheme(SIGILHOOK::x64Detour::ALL);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prol w/src out of range") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour detour((uint64_t)&hookMe4, (uint64_t)&h_nullstub, &nullTramp);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Call instruction early in prologue") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour detour((uint64_t)&hookMe5, (uint64_t)&h_nullstub, &nullTramp);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Hook malloc") {
		SIGILHOOK::StackCanary canary;
		SIGILHOOK::x64Detour SIGILHOOK_TEST_DETOUR(malloc);
		effects.PushEffect(); // catch does some allocations, push effect first
							  // so peak works
		bool result = detour.hook();

		REQUIRE(result == true);

		void *pMem = malloc(16);
		free(pMem);
		detour.unHook(); // unhook so we can popeffect safely w/o catch
						 // allocation happening again
		REQUIRE(effects.PopEffect().didExecute());
	}
}

// NOLINTEND(*-err58-cpp)
