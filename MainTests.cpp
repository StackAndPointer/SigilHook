#define CATCH_CONFIG_RUNNER
#include "Catch.hpp"
#include <iostream>

#include "sigilhook/ErrorLog.hpp"
int main(int argc, char* const argv[]) {
#if defined(SIGILHOOK_OS_WINDOWS) && !defined(__GNUC__)
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF );
#endif
	std::cout << "Running SigilHook core tests (derived from PolyHook 2)" << std::endl;
	auto logger = std::make_shared<SIGILHOOK::ErrorLog>();
	logger->setLogLevel(SIGILHOOK::ErrorLevel::INFO);
	SIGILHOOK::Log::registerLogger(logger);
	int result = Catch::Session().run(argc, argv);

//	getchar();
	return result;
}

