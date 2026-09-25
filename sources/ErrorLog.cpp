#include "sigilhook/ErrorLog.hpp"

std::shared_ptr<SIGILHOOK::Logger> SIGILHOOK::Log::m_logger = nullptr;

void SIGILHOOK::Log::registerLogger(std::shared_ptr<Logger> logger) {
	m_logger = logger;
}

void SIGILHOOK::Log::log(std::string msg, ErrorLevel level) {
	if (m_logger) {
		m_logger->log(std::move(msg), level);
	}
}

void SIGILHOOK::ErrorLog::setLogLevel(SIGILHOOK::ErrorLevel level) {
	m_logLevel = level;
}

void SIGILHOOK::ErrorLog::log(const std::string& msg, ErrorLevel level)
{
	push({ msg, level });
}

void SIGILHOOK::ErrorLog::push(const SIGILHOOK::Error& err) {
	if (err.lvl >= m_logLevel) {
		switch (err.lvl) {
		case ErrorLevel::INFO:
			std::cout << "[+] Info: " << err.msg << std::endl;
			break;
		case ErrorLevel::WARN:
			std::cout << "[!] Warn: " << err.msg << std::endl;
			break;
		case ErrorLevel::SEV:
			std::cout << "[!] Error: " << err.msg << std::endl;
			break;
		default:
			std::cout << "Unsupported error message logged " << err.msg << std::endl;
		}
	}

	m_log.push_back(err);
}

SIGILHOOK::Error SIGILHOOK::ErrorLog::pop() {
	Error err{};
	if (!m_log.empty()) {
		err = m_log.back();
		m_log.pop_back();
	}
	return err;
}

SIGILHOOK::ErrorLog& SIGILHOOK::ErrorLog::singleton() {
	static ErrorLog log;
	return log;
}
