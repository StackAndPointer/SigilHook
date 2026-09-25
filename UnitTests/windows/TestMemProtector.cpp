#include "Catch.hpp"
#include "sigilhook/MemProtector.hpp"
#include "sigilhook/Tests/StackCanary.hpp"

#if defined(SIGILHOOK_OS_WINDOWS)

#include "sigilhook/SigilHookOsIncludes.hpp"

TEST_CASE("Test protflag translation", "[MemProtector],[Enums]") {
	SECTION("flags to native") {
		SIGILHOOK::StackCanary canary;
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X) == PAGE_EXECUTE);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::R) == PAGE_READONLY);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::W) == PAGE_READWRITE);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::R | SIGILHOOK::ProtFlag::W) == PAGE_READWRITE);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R) == PAGE_EXECUTE_READ);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W) == PAGE_EXECUTE_READWRITE);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W | SIGILHOOK::ProtFlag::R) == PAGE_EXECUTE_READWRITE);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::NONE) == PAGE_NOACCESS);
	}

	SECTION("native to flags") {
		SIGILHOOK::StackCanary canary;
		REQUIRE(SIGILHOOK::TranslateProtection(PAGE_EXECUTE) == SIGILHOOK::ProtFlag::X);
		REQUIRE(SIGILHOOK::TranslateProtection(PAGE_READONLY) == SIGILHOOK::ProtFlag::R);
		REQUIRE(SIGILHOOK::TranslateProtection(PAGE_READWRITE) == (SIGILHOOK::ProtFlag::W | SIGILHOOK::ProtFlag::R));
		REQUIRE(SIGILHOOK::TranslateProtection(PAGE_EXECUTE_READ) == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R));
		REQUIRE(SIGILHOOK::TranslateProtection(PAGE_EXECUTE_READWRITE) == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W | SIGILHOOK::ProtFlag::R));
		REQUIRE(SIGILHOOK::TranslateProtection(PAGE_NOACCESS) == SIGILHOOK::ProtFlag::NONE);
	}
}

TEST_CASE("Test setting page protections", "[MemProtector]") {
	SIGILHOOK::StackCanary canary;
	char* page = (char*)VirtualAlloc(0, 4 * 1024, MEM_COMMIT, PAGE_NOACCESS);
	bool isGood = page != nullptr; // indirection because catch reads var, causing access violation
	REQUIRE(isGood);
	SIGILHOOK::MemAccessor accessor;

	{
		SIGILHOOK::MemoryProtector prot((uint64_t)page, 4 * 1024, SIGILHOOK::ProtFlag::R, accessor);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == SIGILHOOK::ProtFlag::NONE);

		SIGILHOOK::MemoryProtector prot1((uint64_t)page, 4 * 1024, SIGILHOOK::ProtFlag::W, accessor);
		REQUIRE(prot1.isGood());
		REQUIRE(prot1.originalProt() == SIGILHOOK::ProtFlag::R);

		SIGILHOOK::MemoryProtector prot2((uint64_t)page, 4 * 1024, SIGILHOOK::ProtFlag::X, accessor);
		REQUIRE(prot2.isGood());
		REQUIRE((prot2.originalProt() & SIGILHOOK::ProtFlag::W));
	}

	// protection should now be NOACCESS if destructors worked
	{
		SIGILHOOK::MemoryProtector prot((uint64_t)page, 4 * 1024, SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R, accessor);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == SIGILHOOK::ProtFlag::NONE);

		SIGILHOOK::MemoryProtector prot1((uint64_t)page, 4 * 1024, SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W, accessor);
		REQUIRE(prot.isGood());
		REQUIRE((prot1.originalProt() == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R)));

		SIGILHOOK::MemoryProtector prot2((uint64_t)page, 4 * 1024, SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R | SIGILHOOK::ProtFlag::W, accessor);
		REQUIRE(prot.isGood());
		REQUIRE(prot2.originalProt() == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R | SIGILHOOK::ProtFlag::W));
	}
	VirtualFree(page, 0, MEM_RELEASE);
}

#endif