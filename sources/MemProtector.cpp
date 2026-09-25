#include "sigilhook/MemProtector.hpp"
#include "sigilhook/Enums.hpp"
#include "sigilhook/SigilHookOsIncludes.hpp"

std::ostream& operator<<(std::ostream& os, const SIGILHOOK::ProtFlag flags) {
	if (flags == SIGILHOOK::ProtFlag::UNSET) {
		os << "UNSET";
		return os;
	}

	if (flags & SIGILHOOK::ProtFlag::X)
		os << "x";
	else
		os << "-";

	if (flags & SIGILHOOK::ProtFlag::R)
		os << "r";
	else
		os << "-";

	if (flags & SIGILHOOK::ProtFlag::W)
		os << "w";
	else
		os << "-";

	if (flags & SIGILHOOK::ProtFlag::NONE)
		os << "n";
	else
		os << "-";

	if (flags & SIGILHOOK::ProtFlag::P)
		os << " private";
	else if (flags & SIGILHOOK::ProtFlag::S)
		os << " shared";
	return os;
}

#if defined(SIGILHOOK_OS_WINDOWS)

int SIGILHOOK::TranslateProtection(const SIGILHOOK::ProtFlag flags) {
	int NativeFlag = 0;
	if (flags == SIGILHOOK::ProtFlag::X)
		NativeFlag = PAGE_EXECUTE;

	if (flags == SIGILHOOK::ProtFlag::R)
		NativeFlag = PAGE_READONLY;

	if (flags == SIGILHOOK::ProtFlag::W || (flags == (SIGILHOOK::ProtFlag::R | SIGILHOOK::ProtFlag::W)))
		NativeFlag = PAGE_READWRITE;

	if ((flags & SIGILHOOK::ProtFlag::X) && (flags & SIGILHOOK::ProtFlag::R))
		NativeFlag = PAGE_EXECUTE_READ;

	if ((flags & SIGILHOOK::ProtFlag::X) && (flags & SIGILHOOK::ProtFlag::W))
		NativeFlag = PAGE_EXECUTE_READWRITE;

	if (flags & SIGILHOOK::ProtFlag::NONE)
		NativeFlag = PAGE_NOACCESS;
	return NativeFlag;
}

SIGILHOOK::ProtFlag SIGILHOOK::TranslateProtection(const int prot) {
	SIGILHOOK::ProtFlag flags = SIGILHOOK::ProtFlag::UNSET;
	switch (prot) {
	case PAGE_EXECUTE:
		flags = flags | SIGILHOOK::ProtFlag::X;
		break;
	case PAGE_READONLY:
		flags = flags | SIGILHOOK::ProtFlag::R;
		break;
	case PAGE_READWRITE:
		flags = flags | SIGILHOOK::ProtFlag::W;
		flags = flags | SIGILHOOK::ProtFlag::R;
		break;
	case PAGE_EXECUTE_READWRITE:
		flags = flags | SIGILHOOK::ProtFlag::X;
		flags = flags | SIGILHOOK::ProtFlag::R;
		flags = flags | SIGILHOOK::ProtFlag::W;
		break;
	case PAGE_EXECUTE_READ:
		flags = flags | SIGILHOOK::ProtFlag::X;
		flags = flags | SIGILHOOK::ProtFlag::R;
		break;
	case PAGE_NOACCESS:
		flags = flags | SIGILHOOK::ProtFlag::NONE;
		break;
	}
	return flags;
}

#elif defined(SIGILHOOK_OS_LINUX)

int SIGILHOOK::TranslateProtection(const SIGILHOOK::ProtFlag flags) {
	int NativeFlag = PROT_NONE;
	if (flags & SIGILHOOK::ProtFlag::X)
		NativeFlag |= PROT_EXEC;

	if (flags & SIGILHOOK::ProtFlag::R)
		NativeFlag |= PROT_READ;

	if (flags & SIGILHOOK::ProtFlag::W)
		NativeFlag |= PROT_WRITE;

	if (flags & SIGILHOOK::ProtFlag::NONE)
		NativeFlag = PROT_NONE;

	return NativeFlag;
}

SIGILHOOK::ProtFlag SIGILHOOK::TranslateProtection(const int prot) {
	SIGILHOOK::ProtFlag flags = SIGILHOOK::ProtFlag::UNSET;

	if(prot & PROT_EXEC)
		flags = flags | SIGILHOOK::ProtFlag::X;

	if (prot & PROT_READ)
		flags = flags | SIGILHOOK::ProtFlag::R;

	if (prot & PROT_WRITE)
		flags = flags | SIGILHOOK::ProtFlag::W;

	if (prot == PROT_NONE)
		flags = flags | SIGILHOOK::ProtFlag::NONE;

	return flags;
}

#elif defined(SIGILHOOK_OS_APPLE)

int SIGILHOOK::TranslateProtection(const SIGILHOOK::ProtFlag flags) {
	int NativeFlag = VM_PROT_NONE;
	if (flags & SIGILHOOK::ProtFlag::X)
		NativeFlag |= PROT_EXEC;

	if (flags & SIGILHOOK::ProtFlag::R)
		NativeFlag |= PROT_READ;

	if (flags & SIGILHOOK::ProtFlag::W)
		NativeFlag |= PROT_WRITE;

	if (flags & SIGILHOOK::ProtFlag::NONE)
		NativeFlag = PROT_NONE;

	return NativeFlag;
}

SIGILHOOK::ProtFlag SIGILHOOK::TranslateProtection(const int prot) {
	SIGILHOOK::ProtFlag flags = SIGILHOOK::ProtFlag::UNSET;

	if (prot & VM_PROT_EXECUTE)
		flags = flags | SIGILHOOK::ProtFlag::X;

	if (prot & VM_PROT_READ)
		flags = flags | SIGILHOOK::ProtFlag::R;

	if (prot & VM_PROT_WRITE)
		flags = flags | SIGILHOOK::ProtFlag::W;

	if (prot == VM_PROT_NONE)
		flags = flags | SIGILHOOK::ProtFlag::NONE;

	return flags;
}

#endif