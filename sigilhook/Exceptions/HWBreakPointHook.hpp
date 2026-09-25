#ifndef SIGILHOOK_HWBPHOOK_HPP
#define SIGILHOOK_HWBPHOOK_HPP

#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/Exceptions/AVehHook.hpp"
#include "sigilhook/Misc.hpp"

namespace SIGILHOOK {

class HWBreakPointHook : public AVehHook {
public:
	HWBreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback, HANDLE hThread);
	HWBreakPointHook(const char* fnAddress, const char* fnCallback, HANDLE hThread);
	~HWBreakPointHook() {
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
	uint8_t m_regIdx;

	HANDLE m_hThread;

	LONG OnException(EXCEPTION_POINTERS* ExceptionInfo) override;
};
}

#endif