#ifndef SIGILHOOK_BPHOOK_HPP
#define SIGILHOOK_BPHOOK_HPP

#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/Exceptions/AVehHook.hpp"
#include "sigilhook/Misc.hpp"

namespace SIGILHOOK {

class BreakPointHook : public AVehHook {
public:
	BreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback);
	BreakPointHook(const char* fnAddress, const char* fnCallback);
	~BreakPointHook() {
		m_impls.erase(AVehHookImpEntry(m_fnAddress, this));
		if (m_hooked) {
			unHook();
		}
	}

	virtual bool hook() override;
	virtual bool unHook() override;
	auto getProtectionObject() {
		return finally([&] () {
			hook();
		});
	}
protected:
	uint64_t m_fnCallback;
	uint64_t m_fnAddress;
	uint8_t m_origByte;
	
	LONG OnException(EXCEPTION_POINTERS* ExceptionInfo) override;
};
}
#endif