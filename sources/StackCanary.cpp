#include "sigilhook/Tests/StackCanary.hpp"

SIGILHOOK::StackCanary::StackCanary() {
	for (int i = 0; i < 50; i++) {
		buf[i] = 0xCE;
	}
}

bool SIGILHOOK::StackCanary::isStackGood() {
	for (int i = 0; i < 50; i++) {
		if (buf[i] != 0xCE)
			return false;
	}
	return true;
}

SIGILHOOK::StackCanary::~StackCanary() noexcept(false) {
	if (!isStackGood())
		throw "Stack corruption detected";
}