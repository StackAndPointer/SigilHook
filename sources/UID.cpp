#include "sigilhook/UID.hpp"

SIGILHOOK::UID::UID(long val) {
	this->val = val;
}

std::atomic_long& SIGILHOOK::UID::singleton() {
	static std::atomic_long base = { -1 };
	base++;
	return base;
}

SIGILHOOK::UID::UID() {
	this->val = -1;
}
