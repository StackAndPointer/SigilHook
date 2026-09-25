#include "Catch.hpp"
#include "sigilhook/MemProtector.hpp"
#include "sigilhook/Tests/StackCanary.hpp"

#include "sigilhook/SigilHookOsIncludes.hpp"

TEST_CASE("Test protflag translation", "[MemProtector],[Enums]") {
	SECTION("flags to native") {
		SIGILHOOK::StackCanary canary;
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X) == PROT_EXEC);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::R) == PROT_READ);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::W) == PROT_WRITE);
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::R | SIGILHOOK::ProtFlag::W) == (PROT_READ|PROT_WRITE));
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R) == (PROT_EXEC|PROT_READ));
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W) == (PROT_EXEC|PROT_WRITE));
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W | SIGILHOOK::ProtFlag::R) == (PROT_EXEC|PROT_WRITE|PROT_READ));
		REQUIRE(SIGILHOOK::TranslateProtection(SIGILHOOK::ProtFlag::NONE) == PROT_NONE);
	}

	SECTION("native to flags") {
		SIGILHOOK::StackCanary canary;
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_EXEC) == SIGILHOOK::ProtFlag::X);
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_READ) == SIGILHOOK::ProtFlag::R);
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_WRITE) == SIGILHOOK::ProtFlag::W);
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_WRITE|PROT_READ) == (SIGILHOOK::ProtFlag::W | SIGILHOOK::ProtFlag::R));
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_EXEC|PROT_READ) == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::R));
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_EXEC|PROT_WRITE) == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W));
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_EXEC|PROT_WRITE|PROT_READ) == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W | SIGILHOOK::ProtFlag::R));
		REQUIRE(SIGILHOOK::TranslateProtection(PROT_NONE) == SIGILHOOK::ProtFlag::NONE);
	}
}

TEST_CASE("Test setting page protections", "[MemProtector]") {
	SIGILHOOK::StackCanary canary;
	char* page = (char*)mmap(nullptr, 4*1024, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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
		REQUIRE(prot2.originalProt() == (SIGILHOOK::ProtFlag::X | SIGILHOOK::ProtFlag::W));
	}
	munmap(page, 4*1024);
}

// TODO: test cases when memory slice spans multiple mappings
