#include "./TestUtils.hpp"

#include "sigilhook/ErrorLog.hpp"

#include <memory>

namespace SIGILHOOK::test {

void registerTestLogger() {
	const auto logger = std::make_shared<SIGILHOOK::ErrorLog>();
	logger->setLogLevel(SIGILHOOK::ErrorLevel::INFO);
	SIGILHOOK::Log::registerLogger(logger);
}

}
