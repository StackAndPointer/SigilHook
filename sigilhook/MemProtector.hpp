//
// Created by steve on 7/10/17.
//

#ifndef SIGILHOOK_MEMORYPROTECTOR_HPP
#define SIGILHOOK_MEMORYPROTECTOR_HPP

#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/MemAccessor.hpp"
#include "sigilhook/Enums.hpp"

std::ostream& operator<<(std::ostream& os, const SIGILHOOK::ProtFlag v);

// prefer enum class over enum
#pragma warning( disable : 26812)

namespace SIGILHOOK {
int	TranslateProtection(const SIGILHOOK::ProtFlag flags);
ProtFlag TranslateProtection(const int prot);

class MemoryProtector {
public:
	MemoryProtector(const uint64_t address, const uint64_t length, const SIGILHOOK::ProtFlag prot, MemAccessor& accessor, bool unsetOnDestroy = true) : m_accessor(accessor) {
		m_address = address;
		m_length = length;
		unsetLater = unsetOnDestroy;

		m_origProtection = SIGILHOOK::ProtFlag::UNSET;
		m_origProtection = m_accessor.mem_protect(address, length, prot, status);
	}

	SIGILHOOK::ProtFlag originalProt() {
		return m_origProtection;
	}

	bool isGood() {
		return status;
	}

	~MemoryProtector() {
		if (m_origProtection == SIGILHOOK::ProtFlag::UNSET || !unsetLater)
			return;

		m_accessor.mem_protect(m_address, m_length, m_origProtection, status);
	}
private:
	SIGILHOOK::ProtFlag m_origProtection;
	MemAccessor& m_accessor;

	uint64_t m_address;
	uint64_t m_length;
	bool status;
	bool unsetLater;
};
}
#endif //SIGILHOOK_MEMORYPROTECTOR_HPP
