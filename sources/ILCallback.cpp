// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
// Derived from PolyHook 2; see LICENSE and THIRD_PARTY_NOTICES.md.
#include "sigilhook/Detour/ILCallback.hpp"

#include "sigilhook/MemProtector.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstddef>
#include <new>
#include <utility>

namespace {

constexpr uint32_t kMaxStackOffset = 0x10000;

std::string lowerCopy(const std::string& value) {
	std::string result = value;
	for (char& ch : result) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	return result;
}

std::string trimCopy(const std::string& value) {
	const size_t first = value.find_first_not_of(" \t\r\n");
	if (first == std::string::npos) return {};
	const size_t last = value.find_last_not_of(" \t\r\n");
	return value.substr(first, last - first + 1);
}

bool parseUnsigned(const std::string& value, uint32_t* out) {
	if (value.empty() || out == nullptr) return false;
	uint32_t parsed = 0;
	const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
	if (result.ec != std::errc() || result.ptr != value.data() + value.size()) return false;
	*out = parsed;
	return true;
}

asmjit::x86::Gp gpRegister(asmjit::Arch arch, uint32_t id) {
	return arch == asmjit::Arch::kX64 ? asmjit::x86::Gp::make_r64(id) : asmjit::x86::Gp::make_r32(id);
}

asmjit::x86::Gp stackPointer(asmjit::Arch arch) {
	return gpRegister(arch, asmjit::x86::Gp::kIdSp);
}

bool isGpFuncValue(const asmjit::FuncValue& value) {
	return value.isReg() && (value.regType() == asmjit::RegType::kGp32 || value.regType() == asmjit::RegType::kGp64);
}

uint32_t pointerSizeFromArch(asmjit::Arch arch) {
	return arch == asmjit::Arch::kX64 ? 8u : 4u;
}

uint32_t alignUp(uint32_t value, uint32_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}

int registerFromName(const std::string& value, asmjit::Arch arch) {
	const std::string name = lowerCopy(trimCopy(value));
	if (name == "ax" || name == "eax" || name == "rax") return SIGILHOOK_REGISTER_AX;
	if (name == "cx" || name == "ecx" || name == "rcx") return SIGILHOOK_REGISTER_CX;
	if (name == "dx" || name == "edx" || name == "rdx") return SIGILHOOK_REGISTER_DX;
	if (name == "bx" || name == "ebx" || name == "rbx") return SIGILHOOK_REGISTER_BX;
	if (name == "sp" || name == "esp" || name == "rsp") return SIGILHOOK_REGISTER_SP;
	if (name == "bp" || name == "ebp" || name == "rbp") return SIGILHOOK_REGISTER_BP;
	if (name == "si" || name == "esi" || name == "rsi") return SIGILHOOK_REGISTER_SI;
	if (name == "di" || name == "edi" || name == "rdi") return SIGILHOOK_REGISTER_DI;
	if (name == "r8" || name == "r8d" || name == "r8w" || name == "r8b") return SIGILHOOK_REGISTER_R8;
	if (name == "r9" || name == "r9d" || name == "r9w" || name == "r9b") return SIGILHOOK_REGISTER_R9;
	if (name == "r10" || name == "r10d" || name == "r10w" || name == "r10b") return SIGILHOOK_REGISTER_R10;
	if (name == "r11" || name == "r11d" || name == "r11w" || name == "r11b") return SIGILHOOK_REGISTER_R11;
	if (name == "r12" || name == "r12d" || name == "r12w" || name == "r12b") return SIGILHOOK_REGISTER_R12;
	if (name == "r13" || name == "r13d" || name == "r13w" || name == "r13b") return SIGILHOOK_REGISTER_R13;
	if (name == "r14" || name == "r14d" || name == "r14w" || name == "r14b") return SIGILHOOK_REGISTER_R14;
	if (name == "r15" || name == "r15d" || name == "r15w" || name == "r15b") return SIGILHOOK_REGISTER_R15;
	(void)arch;
	return -1;
}

bool isRegisterName(const std::string& value) {
	return registerFromName(value, asmjit::Arch::kX64) >= 0;
}

bool isStackLocation(const std::string& value) {
	return lowerCopy(trimCopy(value)).rfind("stack+", 0) == 0;
}

} // namespace

asmjit::CallConvId SIGILHOOK::ILCallback::getCallConv(const std::string& conv) const {
	const std::string value = lowerCopy(trimCopy(conv));
	if (value == "fastcall" || value == "__fastcall") return asmjit::CallConvId::kFastCall;
	if (value == "stdcall" || value == "__stdcall") return asmjit::CallConvId::kStdCall;
	if (value == "thiscall" || value == "__thiscall") return asmjit::CallConvId::kThisCall;
	if (value == "vectorcall" || value == "__vectorcall") return asmjit::CallConvId::kVectorCall;
	return asmjit::CallConvId::kCDecl;
}

#define TYPEID_MATCH_STR_IF(var, T) if (var == #T) { return asmjit::TypeId(asmjit::TypeUtils::TypeIdOfT<T>::kTypeId); }
#define TYPEID_MATCH_STR_ELSEIF(var, T) else if (var == #T) { return asmjit::TypeId(asmjit::TypeUtils::TypeIdOfT<T>::kTypeId); }

asmjit::TypeId SIGILHOOK::ILCallback::getTypeId(const std::string& type) const {
	if (type.find('*') != std::string::npos) {
		return asmjit::TypeId::kUIntPtr;
	}

	TYPEID_MATCH_STR_IF(type, signed char)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned char)
	TYPEID_MATCH_STR_ELSEIF(type, short)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned short)
	TYPEID_MATCH_STR_ELSEIF(type, int)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned int)
	TYPEID_MATCH_STR_ELSEIF(type, long)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned long)
#ifdef SIGILHOOK_OS_WINDOWS
	TYPEID_MATCH_STR_ELSEIF(type, __int64)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned __int64)
#endif
	TYPEID_MATCH_STR_ELSEIF(type, long long)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned long long)
	TYPEID_MATCH_STR_ELSEIF(type, char)
	TYPEID_MATCH_STR_ELSEIF(type, char16_t)
	TYPEID_MATCH_STR_ELSEIF(type, char32_t)
	TYPEID_MATCH_STR_ELSEIF(type, wchar_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint8_t)
	TYPEID_MATCH_STR_ELSEIF(type, int8_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint16_t)
	TYPEID_MATCH_STR_ELSEIF(type, int16_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint32_t)
	TYPEID_MATCH_STR_ELSEIF(type, int32_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint64_t)
	TYPEID_MATCH_STR_ELSEIF(type, int64_t)
	TYPEID_MATCH_STR_ELSEIF(type, float)
	TYPEID_MATCH_STR_ELSEIF(type, double)
	TYPEID_MATCH_STR_ELSEIF(type, bool)
	TYPEID_MATCH_STR_ELSEIF(type, void)
	else if (type == "intptr_t") {
		return asmjit::TypeId::kIntPtr;
	} else if (type == "uintptr_t") {
		return asmjit::TypeId::kUIntPtr;
	}

	return asmjit::TypeId::kVoid;
}

uint8_t SIGILHOOK::ILCallback::getTypeWidth(const std::string& type, asmjit::Arch arch) const {
	const asmjit::TypeId typeId = getTypeId(type);
	if (typeId == asmjit::TypeId::kVoid) return 0;
	if (asmjit::TypeUtils::isAbstract(typeId)) {
		return static_cast<uint8_t>(pointerSizeFromArch(arch));
	}
	return static_cast<uint8_t>(asmjit::TypeUtils::sizeOf(typeId));
}

const SIGILHOOK::ILCallback::CallLayout& SIGILHOOK::ILCallback::callLayout() const {
	return m_callLayout;
}

const std::string& SIGILHOOK::ILCallback::lastError() const {
	return m_lastError;
}

sigilhook_status SIGILHOOK::ILCallback::lastErrorStatus() const {
	return m_lastErrorStatus;
}

bool SIGILHOOK::ILCallback::fail(const std::string& message) {
	m_lastError = message;
	if (message.rfind("Unsupported", 0) == 0 || message.find("not supported") != std::string::npos) {
		m_lastErrorStatus = SIGILHOOK_ERROR_UNSUPPORTED;
	} else if (message.find("x86 usercall cannot") != std::string::npos || message.find("x64 usercall cleanup") != std::string::npos) {
		m_lastErrorStatus = SIGILHOOK_ERROR_ARCH_MISMATCH;
	} else if (message.find("Invalid") != std::string::npos || message.find("Missing") != std::string::npos ||
		message.find("Duplicate") != std::string::npos || message.find("Overlapping") != std::string::npos) {
		m_lastErrorStatus = SIGILHOOK_ERROR_INVALID_ARGUMENT;
	} else {
		m_lastErrorStatus = SIGILHOOK_ERROR_SCRIPT;
	}
	Log::log(message, ErrorLevel::SEV);
	return false;
}

bool SIGILHOOK::ILCallback::parseCallLayout(
	const std::string& callConv,
	const std::string& retType,
	const std::vector<std::string>& paramTypes,
	asmjit::Arch arch,
	asmjit::CallConvId* outCallConv,
	std::string* outError) {
	m_callLayout = {};
	m_lastError.clear();
	const std::string convention = lowerCopy(trimCopy(callConv));
	const bool isUsercall = convention.rfind("usercall:", 0) == 0;
	if (!isUsercall) {
		const std::string normalized = convention.empty() ? "cdecl" : convention;
		if (normalized != "cdecl" && normalized != "__cdecl" &&
			normalized != "stdcall" && normalized != "__stdcall" &&
			normalized != "fastcall" && normalized != "__fastcall" &&
			normalized != "thiscall" && normalized != "__thiscall" &&
			normalized != "vectorcall" && normalized != "__vectorcall") {
			if (outError != nullptr) *outError = "Unsupported calling convention: " + callConv;
			return fail("Unsupported calling convention: " + callConv);
		}
		if (outCallConv != nullptr) *outCallConv = getCallConv(normalized);
		m_callLayout.arguments.resize(paramTypes.size());
		return true;
	}

	m_callLayout.usercall = true;
	const std::string body = convention.substr(9);
	std::vector<std::string> tokens;
	size_t start = 0;
	while (start <= body.size()) {
		const size_t end = body.find(';', start);
		tokens.push_back(body.substr(start, end == std::string::npos ? std::string::npos : end - start));
		if (end == std::string::npos) break;
		start = end + 1;
	}

	const uint32_t pointerSize = pointerSizeFromArch(arch);
	const uint8_t returnWidth = getTypeWidth(retType, arch);
	if (retType != "void" && returnWidth == 0) {
		if (outError != nullptr) *outError = "Unsupported usercall return type: " + retType;
		return fail("Unsupported usercall return type: " + retType);
	}
	if (arch == asmjit::Arch::kX86 && returnWidth > 4) {
		if (outError != nullptr) *outError = "x86 usercall returns wider than 32 bits are not supported";
		return fail("x86 usercall returns wider than 32 bits are not supported");
	}

	m_callLayout.arguments.resize(paramTypes.size());
	std::vector<bool> assigned(paramTypes.size(), false);
	std::vector<bool> usedRegisters(SIGILHOOK_REGISTER_COUNT, false);
	bool hasReturn = false;
	bool hasCleanup = false;
	for (const std::string& rawToken : tokens) {
		const std::string token = lowerCopy(trimCopy(rawToken));
		if (token.empty()) continue;
		const size_t equals = token.find('=');
		if (equals == std::string::npos) {
			if (outError != nullptr) *outError = "Invalid usercall token: " + rawToken;
			return fail("Invalid usercall token: " + rawToken);
		}
		const std::string key = trimCopy(token.substr(0, equals));
		const std::string value = trimCopy(token.substr(equals + 1));
		if (key == "ret") {
			if (hasReturn) {
				if (outError != nullptr) *outError = "Duplicate usercall return mapping";
				return fail("Duplicate usercall return mapping");
			}
			hasReturn = true;
			if (retType == "void" && value != "none") {
				if (outError != nullptr) *outError = "A void usercall cannot declare a return register";
				return fail("A void usercall cannot declare a return register");
			}
			if (retType != "void" && value == "none") {
				if (outError != nullptr) *outError = "A non-void usercall requires a return register";
				return fail("A non-void usercall requires a return register");
			}
			if (value != "none") {
				const int reg = registerFromName(value, arch);
				if (reg < 0 || reg == SIGILHOOK_REGISTER_SP) {
					if (outError != nullptr) *outError = "Invalid usercall return register: " + value;
					return fail("Invalid usercall return register: " + value);
				}
				if (arch == asmjit::Arch::kX86 && reg >= SIGILHOOK_REGISTER_R8) {
					if (outError != nullptr) *outError = "x86 usercall cannot use R8-R15";
					return fail("x86 usercall cannot use R8-R15");
				}
				m_callLayout.returnRegister = reg;
			}
			continue;
		}
		if (key == "cleanup") {
			if (hasCleanup || !parseUnsigned(value, &m_callLayout.calleeCleanup)) {
				if (outError != nullptr) *outError = "Invalid usercall cleanup value: " + value;
				return fail("Invalid usercall cleanup value: " + value);
			}
			if (arch == asmjit::Arch::kX64 && m_callLayout.calleeCleanup != 0) {
				if (outError != nullptr) *outError = "x64 usercall cleanup must be zero";
				return fail("x64 usercall cleanup must be zero");
			}
			if (m_callLayout.calleeCleanup > kMaxStackOffset) {
				if (outError != nullptr) *outError = "usercall cleanup is too large";
				return fail("usercall cleanup is too large");
			}
			hasCleanup = true;
			continue;
		}
		if (key.rfind("arg", 0) != 0) {
			if (outError != nullptr) *outError = "Invalid usercall key: " + key;
			return fail("Invalid usercall key: " + key);
		}
		uint32_t argIndex = 0;
		if (!parseUnsigned(key.substr(3), &argIndex) || argIndex >= paramTypes.size()) {
			if (outError != nullptr) *outError = "Invalid usercall argument index: " + key;
			return fail("Invalid usercall argument index: " + key);
		}
		if (assigned[argIndex]) {
			if (outError != nullptr) *outError = "Duplicate usercall argument mapping: " + key;
			return fail("Duplicate usercall argument mapping: " + key);
		}
		assigned[argIndex] = true;
		const uint8_t width = getTypeWidth(paramTypes[argIndex], arch);
		if (width == 0) {
			if (outError != nullptr) *outError = "Unsupported usercall parameter type: " + paramTypes[argIndex];
			return fail("Unsupported usercall parameter type: " + paramTypes[argIndex]);
		}
		if (isRegisterName(value)) {
			const int reg = registerFromName(value, arch);
			if (reg < 0 || reg == SIGILHOOK_REGISTER_SP || usedRegisters[reg]) {
				if (outError != nullptr) *outError = "Invalid or duplicate usercall register: " + value;
				return fail("Invalid or duplicate usercall register: " + value);
			}
			if (arch == asmjit::Arch::kX86 && reg >= SIGILHOOK_REGISTER_R8) {
				if (outError != nullptr) *outError = "x86 usercall cannot use R8-R15";
				return fail("x86 usercall cannot use R8-R15");
			}
			usedRegisters[reg] = true;
			m_callLayout.arguments[argIndex].kind = ArgumentLocation::Kind::Register;
			m_callLayout.arguments[argIndex].reg = static_cast<uint8_t>(reg);
			continue;
		}
		const std::string stackValue = lowerCopy(trimCopy(value));
		uint32_t stackOffset = 0;
		if (!isStackLocation(stackValue) || !parseUnsigned(stackValue.substr(6), &stackOffset)) {
			if (outError != nullptr) *outError = "Invalid usercall argument location: " + value;
			return fail("Invalid usercall argument location: " + value);
		}
		if (stackOffset < pointerSize || stackOffset >= kMaxStackOffset || (stackOffset & (pointerSize - 1u)) != 0) {
			if (outError != nullptr) *outError = "Invalid usercall stack offset: " + value;
			return fail("Invalid usercall stack offset: " + value);
		}
		m_callLayout.arguments[argIndex].kind = ArgumentLocation::Kind::Stack;
		m_callLayout.arguments[argIndex].stackOffset = static_cast<int32_t>(stackOffset);
		const uint32_t slotWidth = width == 8 ? 8u : pointerSize;
		m_callLayout.stackArgumentBytes = (std::max)(
			m_callLayout.stackArgumentBytes, stackOffset + slotWidth);
	}

	for (size_t index = 0; index < assigned.size(); ++index) {
		if (!assigned[index]) {
			if (outError != nullptr) *outError = "Missing usercall mapping for argument " + std::to_string(index);
			return fail("Missing usercall mapping for argument " + std::to_string(index));
		}
	}
	if (!hasReturn) {
		if (outError != nullptr) *outError = "Missing usercall return mapping";
		return fail("Missing usercall return mapping");
	}
	if (retType != "void" && m_callLayout.returnRegister < 0) {
		if (outError != nullptr) *outError = "Missing usercall return register";
		return fail("Missing usercall return register");
	}

	for (size_t left = 0; left < m_callLayout.arguments.size(); ++left) {
		if (m_callLayout.arguments[left].kind != ArgumentLocation::Kind::Stack) continue;
		const uint32_t leftWidth = getTypeWidth(paramTypes[left], arch) == 8 ? 8u : pointerSize;
		for (size_t right = left + 1; right < m_callLayout.arguments.size(); ++right) {
			if (m_callLayout.arguments[right].kind != ArgumentLocation::Kind::Stack) continue;
			const uint32_t rightWidth = getTypeWidth(paramTypes[right], arch) == 8 ? 8u : pointerSize;
			const uint32_t leftStart = static_cast<uint32_t>(m_callLayout.arguments[left].stackOffset);
			const uint32_t rightStart = static_cast<uint32_t>(m_callLayout.arguments[right].stackOffset);
			if (leftStart < rightStart + rightWidth && rightStart < leftStart + leftWidth) {
				if (outError != nullptr) *outError = "Overlapping usercall stack arguments";
				return fail("Overlapping usercall stack arguments");
			}
		}
	}
	if (outCallConv != nullptr) *outCallConv = asmjit::CallConvId::kCDecl;
	return true;
}

uint64_t SIGILHOOK::ILCallback::allocateCode(asmjit::CodeHolder& code, asmjit::StringLogger& logger) {
	code.setLogger(&logger);
	const asmjit::Error flattenError = code.flatten();
	if (flattenError != asmjit::kErrorOk) {
		fail(std::string("ILCallback flatten failed: ") + asmjit::DebugUtils::errorAsString(flattenError));
		return 0;
	}
	const size_t size = code.codeSize();
	m_callbackBuf = reinterpret_cast<uint64_t>(operator new(size, std::align_val_t{16}, std::nothrow));
	if (m_callbackBuf == 0) {
		fail("Failed to allocate ILCallback JIT memory");
		return 0;
	}
	MemoryProtector writer(m_callbackBuf, size, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
	const asmjit::Error resolveError = code.resolveCrossSectionFixups();
	if (resolveError != asmjit::kErrorOk) {
		fail(std::string("ILCallback fixup resolution failed: ") + asmjit::DebugUtils::errorAsString(resolveError));
		operator delete(reinterpret_cast<void*>(m_callbackBuf), std::align_val_t{16});
		m_callbackBuf = 0;
		return 0;
	}
	const asmjit::Error relocateError = code.relocateToBase(m_callbackBuf);
	if (relocateError != asmjit::kErrorOk) {
		fail(std::string("ILCallback relocation failed: ") + asmjit::DebugUtils::errorAsString(relocateError));
		operator delete(reinterpret_cast<void*>(m_callbackBuf), std::align_val_t{16});
		m_callbackBuf = 0;
		return 0;
	}
	code.copyFlattenedData(reinterpret_cast<unsigned char*>(m_callbackBuf), size);
	MemoryProtector executable(m_callbackBuf, size, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
	if (!executable.isGood()) {
		fail("ILCallback failed to make JIT memory executable");
		operator delete(reinterpret_cast<void*>(m_callbackBuf), std::align_val_t{16});
		m_callbackBuf = 0;
		return 0;
	}
	Log::log("JIT Stub:\n" + std::string(logger.data()), ErrorLevel::INFO);
	return m_callbackBuf;
}

uint64_t SIGILHOOK::ILCallback::getInvokeJitFunc(
	const std::string& retType,
	const std::vector<std::string>& paramTypes,
	uint64_t target,
	const std::string& callConv) {
	if (target == 0) return fail("Invalid usercall target"), 0;
	if (paramTypes.size() > Parameters::kMaxArguments) {
		fail("Invalid callback argument count exceeds 32");
		return 0;
	}
	if (m_callbackBuf != 0) {
		fail("ILCallback invoke stub already exists");
		return 0;
	}
	const asmjit::Arch arch = asmjit::Arch::kHost;
	asmjit::CallConvId unusedCallConv = asmjit::CallConvId::kCDecl;
	std::string parseError;
	if (!parseCallLayout(callConv, retType, paramTypes, arch, &unusedCallConv, &parseError)) return 0;
	if (!m_callLayout.usercall) {
		fail("Invoke stubs require a usercall mapping");
		return 0;
	}

	const uint32_t pointerSize = pointerSizeFromArch(arch);
	const bool is64 = arch == asmjit::Arch::kX64;
	const uint32_t registerCount = is64 ? SIGILHOOK_REGISTER_COUNT : SIGILHOOK_REGISTER_R8;

	asmjit::CodeHolder code;
	auto environment = asmjit::Environment::host();
	environment.setArch(arch);
	if (code.init(environment) != asmjit::kErrorOk) return fail("ILCallback invoke CodeHolder init failed"), 0;
	asmjit::StringLogger logger;
	logger.addFlags(
		asmjit::FormatFlags::kMachineCode | asmjit::FormatFlags::kExplainImms |
		asmjit::FormatFlags::kRegCasts | asmjit::FormatFlags::kHexImms |
		asmjit::FormatFlags::kHexOffsets | asmjit::FormatFlags::kPositions);
	asmjit::x86::Assembler a(&code);
	code.setLogger(&logger);

	if (is64) {
		const uint32_t targetArea = (std::max)(
			32u, m_callLayout.stackArgumentBytes > pointerSize
				? m_callLayout.stackArgumentBytes - pointerSize : 0u);
		const uint32_t localOffset = alignUp(targetArea, 8);
		const uint32_t frameSize = alignUp(localOffset + 24u, 16) + 8u;
		a.push(asmjit::x86::rbx);
		a.push(asmjit::x86::rbp);
		a.push(asmjit::x86::rsi);
		a.push(asmjit::x86::rdi);
		a.push(asmjit::x86::r12);
		a.push(asmjit::x86::r13);
		a.push(asmjit::x86::r14);
		a.push(asmjit::x86::r15);
		a.sub(asmjit::x86::rsp, frameSize);
		a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, localOffset), asmjit::x86::rcx);
		a.mov(asmjit::x86::r10, target);
		a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, localOffset + 8), asmjit::x86::r10);

		for (const auto& location : m_callLayout.arguments) {
			if (location.kind != ArgumentLocation::Kind::Stack) continue;
			const size_t index = static_cast<size_t>(&location - m_callLayout.arguments.data());
			a.mov(asmjit::x86::r10, asmjit::x86::qword_ptr(asmjit::x86::rsp, localOffset));
			a.mov(asmjit::x86::r11, asmjit::x86::qword_ptr(asmjit::x86::r10, static_cast<int32_t>(index * sizeof(uint64_t))));
			a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, location.stackOffset - static_cast<int32_t>(pointerSize)), asmjit::x86::r11);
		}
		auto loadRegister = [&](uint32_t reg) {
			for (size_t index = 0; index < m_callLayout.arguments.size(); ++index) {
				const auto& location = m_callLayout.arguments[index];
				if (location.kind != ArgumentLocation::Kind::Register || location.reg != reg) continue;
				a.mov(asmjit::x86::r10, asmjit::x86::qword_ptr(asmjit::x86::rsp, localOffset));
				a.mov(gpRegister(arch, reg), asmjit::x86::qword_ptr(asmjit::x86::r10, static_cast<int32_t>(index * sizeof(uint64_t))));
			}
		};
		for (uint32_t reg = 0; reg < registerCount; ++reg) {
			if (reg == SIGILHOOK_REGISTER_SP || reg == SIGILHOOK_REGISTER_R10 || reg == SIGILHOOK_REGISTER_R11) continue;
			loadRegister(reg);
		}
		loadRegister(SIGILHOOK_REGISTER_R11);
		loadRegister(SIGILHOOK_REGISTER_R10);

		a.call(asmjit::x86::qword_ptr(asmjit::x86::rsp, localOffset + 8));
		if (m_callLayout.returnRegister >= 0) {
			a.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, localOffset + 16),
				gpRegister(arch, static_cast<uint32_t>(m_callLayout.returnRegister)));
			a.mov(asmjit::x86::rax, asmjit::x86::qword_ptr(asmjit::x86::rsp, localOffset + 16));
		} else {
			a.xor_(asmjit::x86::eax, asmjit::x86::eax);
		}
		a.add(asmjit::x86::rsp, frameSize);
		a.pop(asmjit::x86::r15);
		a.pop(asmjit::x86::r14);
		a.pop(asmjit::x86::r13);
		a.pop(asmjit::x86::r12);
		a.pop(asmjit::x86::rdi);
		a.pop(asmjit::x86::rsi);
		a.pop(asmjit::x86::rbp);
		a.pop(asmjit::x86::rbx);
		a.ret();
	} else {
		const uint32_t targetArea = m_callLayout.stackArgumentBytes > pointerSize
			? m_callLayout.stackArgumentBytes - pointerSize : 0u;
		const uint32_t localOffset = alignUp(targetArea, 4) + 4u;
		const uint32_t frameSize = alignUp(localOffset + 12u, 16);
		a.push(asmjit::x86::ebx);
		a.push(asmjit::x86::esi);
		a.push(asmjit::x86::edi);
		a.push(asmjit::x86::ebp);
		a.sub(asmjit::x86::esp, frameSize);
		a.mov(asmjit::x86::edi, asmjit::x86::dword_ptr(asmjit::x86::esp, static_cast<int32_t>(frameSize + 20u)));
		a.mov(asmjit::x86::dword_ptr(asmjit::x86::esp, localOffset), asmjit::x86::edi);
		a.mov(asmjit::x86::dword_ptr(asmjit::x86::esp, localOffset + 4), static_cast<uint32_t>(target));

		for (const auto& location : m_callLayout.arguments) {
			if (location.kind != ArgumentLocation::Kind::Stack) continue;
			const size_t index = static_cast<size_t>(&location - m_callLayout.arguments.data());
			const uint8_t width = getTypeWidth(paramTypes[index], arch);
			a.mov(asmjit::x86::edi, asmjit::x86::dword_ptr(asmjit::x86::esp, localOffset));
			a.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(asmjit::x86::edi, static_cast<int32_t>(index * sizeof(uint64_t))));
			a.mov(asmjit::x86::dword_ptr(asmjit::x86::esp, location.stackOffset - static_cast<int32_t>(pointerSize)), asmjit::x86::eax);
			if (width == 8) {
				a.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(asmjit::x86::edi, static_cast<int32_t>(index * sizeof(uint64_t) + sizeof(uint32_t))));
				a.mov(asmjit::x86::dword_ptr(asmjit::x86::esp, location.stackOffset - static_cast<int32_t>(pointerSize) + sizeof(uint32_t)), asmjit::x86::eax);
			}
		}
		for (uint32_t reg = 0; reg < registerCount; ++reg) {
			if (reg == SIGILHOOK_REGISTER_SP) continue;
			for (size_t index = 0; index < m_callLayout.arguments.size(); ++index) {
				const auto& location = m_callLayout.arguments[index];
				if (location.kind != ArgumentLocation::Kind::Register || location.reg != reg) continue;
				a.mov(asmjit::x86::edi, asmjit::x86::dword_ptr(asmjit::x86::esp, localOffset));
				a.mov(gpRegister(arch, reg), asmjit::x86::dword_ptr(asmjit::x86::edi, static_cast<int32_t>(index * sizeof(uint64_t))));
			}
		}
		a.call(asmjit::x86::dword_ptr(asmjit::x86::esp, localOffset + 4));
		a.add(asmjit::x86::esp, frameSize - m_callLayout.calleeCleanup);
		a.xor_(asmjit::x86::edx, asmjit::x86::edx);
		if (m_callLayout.returnRegister >= 0) {
			a.mov(asmjit::x86::eax, gpRegister(arch, static_cast<uint32_t>(m_callLayout.returnRegister)));
		} else {
			a.xor_(asmjit::x86::eax, asmjit::x86::eax);
		}
		a.pop(asmjit::x86::ebp);
		a.pop(asmjit::x86::edi);
		a.pop(asmjit::x86::esi);
		a.pop(asmjit::x86::ebx);
		a.ret();
	}

	return allocateCode(code, logger);
}
uint64_t SIGILHOOK::ILCallback::getJitFunc(
	const asmjit::FuncSignature& sig,
	const asmjit::Arch arch,
	const SIGILHOOK::ILCallback::tUserCallback callback) {
	if (m_callbackBuf != 0) {
		fail("ILCallback JIT stub already exists");
		return 0;
	}
	if (callback == nullptr) {
		fail("ILCallback requires a callback");
		return 0;
	}
	if (sig.argCount() > Parameters::kMaxArguments) {
		fail("Invalid callback argument count exceeds 32");
		return 0;
	}

	asmjit::CodeHolder code;
	auto env = asmjit::Environment::host();
	env.setArch(arch);
	const asmjit::Error initError = code.init(env);
	if (initError != asmjit::kErrorOk) {
		fail(std::string("ILCallback CodeHolder init failed: ") + asmjit::DebugUtils::errorAsString(initError));
		return 0;
	}

	asmjit::StringLogger logger;
	logger.addFlags(
		asmjit::FormatFlags::kMachineCode | asmjit::FormatFlags::kExplainImms |
		asmjit::FormatFlags::kRegCasts | asmjit::FormatFlags::kHexImms |
		asmjit::FormatFlags::kHexOffsets | asmjit::FormatFlags::kPositions);
	code.setLogger(&logger);
	asmjit::x86::Compiler cc(&code);
	asmjit::FuncNode* func = cc.addFunc(sig);
	func->frame().resetPreservedFP();

	std::vector<asmjit::x86::Reg> argRegisters;
	for (uint8_t argIndex = 0; argIndex < sig.argCount(); ++argIndex) {
		const asmjit::TypeId argType = sig.args()[argIndex];
		asmjit::x86::Reg arg;
		if (isGeneralReg(argType)) {
			arg = cc.newGp(argType);
		} else if (isXmmReg(argType)) {
			arg = cc.newXmm();
		} else {
			fail("Parameters wider than 64 bits are not supported");
			return 0;
		}
		func->setArg(argIndex, arg);
		argRegisters.push_back(arg);
	}

	m_callLayout.usercall = false;
	m_callLayout.arguments.resize(sig.argCount());
	for (uint8_t argIndex = 0; argIndex < sig.argCount(); ++argIndex) {
		const auto& value = func->detail().arg(argIndex);
		if (value.isReg()) {
			m_callLayout.arguments[argIndex].kind = ArgumentLocation::Kind::Register;
			m_callLayout.arguments[argIndex].reg = static_cast<uint8_t>(value.regId());
		} else {
			m_callLayout.arguments[argIndex].kind = ArgumentLocation::Kind::Stack;
			m_callLayout.arguments[argIndex].stackOffset = value.stackOffset();
		}
	}
	m_callLayout.returnRegister = -1;
	if (func->detail().hasRet() && func->detail().ret().isReg()) {
		const auto& ret = func->detail().ret();
		if (ret.regType() == asmjit::RegType::kGp32 || ret.regType() == asmjit::RegType::kGp64) {
			m_callLayout.returnRegister = static_cast<int>(ret.regId());
		}
	}
	m_callLayout.stackArgumentBytes = func->detail().argStackSize();

	argsStack = cc.newStack(sizeof(Parameters), 16);
	asmjit::x86::Gp argStruct = cc.newUIntPtr("argStruct");
	cc.lea(argStruct, argsStack);
	for (uint8_t argIndex = 0; argIndex < sig.argCount(); ++argIndex) {
		const asmjit::TypeId argType = sig.args()[argIndex];
		asmjit::x86::Mem destination(argStruct, offsetof(Parameters, m_arguments) + sizeof(uint64_t) * argIndex);
		destination.setSize(sizeof(uint64_t));
		if (isGeneralReg(argType)) {
			cc.mov(destination, argRegisters[argIndex].as<asmjit::x86::Gp>());
		} else {
			cc.movq(destination, argRegisters[argIndex].as<asmjit::x86::Vec>());
		}
	}

	const uint32_t registerCount = arch == asmjit::Arch::kX64 ? SIGILHOOK_REGISTER_COUNT : SIGILHOOK_REGISTER_R8;
	for (uint32_t reg = 0; reg < registerCount; ++reg) {
		asmjit::x86::Mem destination(argStruct, offsetof(Parameters, m_registers) + sizeof(uint64_t) * reg);
		destination.setSize(pointerSizeFromArch(arch));
		cc.mov(destination, gpRegister(arch, reg));
	}
	asmjit::x86::Gp flagsRegister = cc.newUIntPtr("flagsRegister");
	if (arch == asmjit::Arch::kX64) cc.pushfq();
	else cc.pushfd();
	cc.pop(flagsRegister);
	asmjit::x86::Mem flagsDestination(argStruct, offsetof(Parameters, m_flags));
	flagsDestination.setSize(pointerSizeFromArch(arch));
	cc.mov(flagsDestination, flagsRegister);
	asmjit::x86::Mem writeMaskDestination(argStruct, offsetof(Parameters, m_writeMask));
	writeMaskDestination.setSize(pointerSizeFromArch(arch));
	cc.mov(writeMaskDestination, 0);
	asmjit::x86::Mem entryStackDestination(argStruct, offsetof(Parameters, m_entryStack));
	entryStackDestination.setSize(pointerSizeFromArch(arch));
	cc.mov(entryStackDestination, 0);

	asmjit::x86::Mem retStack = cc.newStack(sizeof(ReturnValue), 16);
	asmjit::x86::Gp retStruct = cc.newUIntPtr("retStruct");
	cc.lea(retStruct, retStack);
	cc.mov(asmjit::x86::dword_ptr(retStruct, offsetof(ReturnValue, m_retVal)), 0);
	cc.mov(asmjit::x86::dword_ptr(retStruct, offsetof(ReturnValue, m_retVal) + sizeof(uint32_t)), 0);
	cc.mov(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_callOriginal)), 1);
	cc.mov(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_overrideReturn)), 0);
	cc.mov(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_redirect)), 0);
	if (arch == asmjit::Arch::kX64) {
		cc.mov(asmjit::x86::qword_ptr(retStruct, offsetof(ReturnValue, m_redirectAddress)), 0);
	} else {
		// x86 has no 64-bit GPR store encoding. The redirect address is a
		// pointer-sized value on this path, so clear both halves explicitly.
		cc.mov(asmjit::x86::dword_ptr(retStruct, offsetof(ReturnValue, m_redirectAddress)), 0);
		cc.mov(asmjit::x86::dword_ptr(retStruct, offsetof(ReturnValue, m_redirectAddress) + sizeof(uint32_t)), 0);
	}

	asmjit::InvokeNode* invokeNode = nullptr;
	cc.invoke(
		&invokeNode,
		reinterpret_cast<uint64_t>(callback),
		asmjit::FuncSignature::build<void, Parameters*, uint8_t, ReturnValue*>());
	invokeNode->setArg(0, argStruct);
	invokeNode->setArg(1, static_cast<uint8_t>(sig.argCount()));
	invokeNode->setArg(2, retStruct);

	for (uint8_t argIndex = 0; argIndex < sig.argCount(); ++argIndex) {
		const asmjit::TypeId argType = sig.args()[argIndex];
		asmjit::x86::Mem source(argStruct, offsetof(Parameters, m_arguments) + sizeof(uint64_t) * argIndex);
		source.setSize(sizeof(uint64_t));
		if (isGeneralReg(argType)) {
			cc.mov(argRegisters[argIndex].as<asmjit::x86::Gp>(), source);
		} else {
			cc.movq(argRegisters[argIndex].as<asmjit::x86::Vec>(), source);
		}
	}

	auto restoreFlags = [&]() {
		asmjit::x86::Gp flags = cc.newUIntPtr();
		cc.mov(flags, asmjit::x86::Mem(argStruct, offsetof(Parameters, m_flags)));
		cc.push(flags);
		if (arch == asmjit::Arch::kX64) cc.popfq();
		else cc.popfd();
	};

	// Avoid the argument allocator's register; x86 cdecl commonly places its argument in EBX.
	asmjit::x86::Gp originalPointer = cc.zsi();
	cc.mov(originalPointer, reinterpret_cast<uintptr_t>(getTrampolineHolder()));
	cc.mov(originalPointer, asmjit::x86::ptr(originalPointer));

	asmjit::Label skipOriginal = cc.newLabel();
	asmjit::Label finish = cc.newLabel();
	cc.cmp(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_callOriginal)), 0);
	cc.je(skipOriginal);

	restoreFlags();
	asmjit::InvokeNode* originalInvokeNode = nullptr;
	cc.invoke(&originalInvokeNode, originalPointer, sig);
	for (uint8_t argIndex = 0; argIndex < sig.argCount(); ++argIndex) {
		originalInvokeNode->setArg(argIndex, argRegisters[argIndex]);
	}
	if (sig.hasRet()) {
		cc.cmp(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_overrideReturn)), 0);
		cc.jne(finish);
		asmjit::x86::Mem retStackIndex(retStack);
		if (isGeneralReg(sig.ret())) {
			retStackIndex.setSize(asmjit::TypeUtils::sizeOf(sig.ret()));
			asmjit::x86::Gp originalResult = cc.newGp(sig.ret());
			originalInvokeNode->setRet(0, originalResult);
			cc.mov(retStackIndex, originalResult);
		} else {
			retStackIndex.setSize(sizeof(uint64_t));
			asmjit::x86::Vec originalResult = cc.newXmm();
			originalInvokeNode->setRet(0, originalResult);
			cc.movq(retStackIndex, originalResult);
		}
	}
	cc.jmp(finish);
	cc.bind(skipOriginal);
	cc.bind(finish);
	restoreFlags();
	if (sig.hasRet()) {
		asmjit::x86::Mem retStackIndex(retStack);
		if (isGeneralReg(sig.ret())) {
			retStackIndex.setSize(asmjit::TypeUtils::sizeOf(sig.ret()));
			asmjit::x86::Gp result = cc.newGp(sig.ret());
			cc.mov(result, retStackIndex);
			cc.ret(result);
		} else {
			retStackIndex.setSize(sizeof(uint64_t));
			asmjit::x86::Vec result = cc.newXmm();
			cc.movq(result, retStackIndex);
			cc.ret(result);
		}
	} else {
		cc.ret();
	}

	cc.func()->frame().addDirtyRegs(originalPointer);
	const asmjit::Error endError = cc.endFunc();
	const asmjit::Error finalizeError = endError == asmjit::kErrorOk ? cc.finalize() : endError;
	if (endError != asmjit::kErrorOk || finalizeError != asmjit::kErrorOk) {
		fail(std::string("ILCallback failed to finalize the JIT callback: ") + asmjit::DebugUtils::errorAsString(finalizeError));
		return 0;
	}
	return allocateCode(code, logger);
}

uint64_t SIGILHOOK::ILCallback::getUsercallJitFunc(
	const std::string& retType,
	const std::vector<std::string>& paramTypes,
	asmjit::Arch arch,
	const tUserCallback callback) {
	asmjit::CodeHolder code;
	auto env = asmjit::Environment::host();
	env.setArch(arch);
	if (code.init(env) != asmjit::kErrorOk) return fail("ILCallback usercall CodeHolder init failed"), 0;

	asmjit::StringLogger logger;
	logger.addFlags(
		asmjit::FormatFlags::kMachineCode | asmjit::FormatFlags::kExplainImms |
		asmjit::FormatFlags::kRegCasts | asmjit::FormatFlags::kHexImms |
		asmjit::FormatFlags::kHexOffsets | asmjit::FormatFlags::kPositions);
	asmjit::x86::Assembler a(&code);
	code.setLogger(&logger);
	const bool is64 = arch == asmjit::Arch::kX64;
	const uint32_t pointerSize = pointerSizeFromArch(arch);
	const uint8_t returnWidth = getTypeWidth(retType, arch);
	const uint32_t registerCount = is64 ? SIGILHOOK_REGISTER_COUNT : SIGILHOOK_REGISTER_R8;
	const uint32_t stateSize = sizeof(Parameters);
	const uint32_t retOffset = stateSize;
	const uint32_t rawStackSize = alignUp(stateSize + sizeof(ReturnValue), 16) + (is64 ? 8u : 0u);
	const uint32_t callbackStack = is64 ? 32u : 0u;
	const uint32_t stateOffset = callbackStack;
	const uint32_t allocationSize = rawStackSize + callbackStack;
	const uint32_t frameSize = alignUp((std::max)({
		m_callLayout.stackArgumentBytes,
		m_callLayout.calleeCleanup,
		is64 ? 32u : 0u,
		pointerSize
	}), 16);
	const asmjit::x86::Gp sp = stackPointer(arch);
	const asmjit::x86::Gp scratch = is64 ? asmjit::x86::r10 : asmjit::x86::edx;
	const asmjit::x86::Gp scratch2 = is64 ? asmjit::x86::r11 : asmjit::x86::eax;
	const asmjit::x86::Gp stateBase = is64 ? asmjit::x86::r11 : asmjit::x86::ebp;
	const asmjit::x86::Gp stateCopy = is64 ? asmjit::x86::r12 : asmjit::x86::edx;

	a.sub(sp, allocationSize);
	for (uint32_t reg = 0; reg < registerCount; ++reg) {
		if (reg == SIGILHOOK_REGISTER_SP) continue;
		a.mov(asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_registers) + sizeof(uint64_t) * reg), gpRegister(arch, reg));
	}
	a.lea(scratch, asmjit::x86::ptr(sp, static_cast<int32_t>(allocationSize)));
	a.mov(asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_entryStack)), scratch);
	a.mov(asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_registers) + sizeof(uint64_t) * SIGILHOOK_REGISTER_SP), scratch);
	if (is64) a.pushfq();
	else a.pushfd();
	a.pop(scratch);
	a.mov(asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_flags)), scratch);
	asmjit::x86::Mem writeMaskDestination = asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_writeMask));
	writeMaskDestination.setSize(pointerSize);
	a.mov(writeMaskDestination, 0);
	a.mov(asmjit::x86::dword_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_retVal)), 0);
	a.mov(asmjit::x86::dword_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_retVal) + sizeof(uint32_t)), 0);
	a.mov(asmjit::x86::byte_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_callOriginal)), 1);
	a.mov(asmjit::x86::byte_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_overrideReturn)), 0);
	a.mov(asmjit::x86::byte_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_redirect)), 0);
	a.mov(asmjit::x86::qword_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_redirectAddress)), 0);

	for (size_t index = 0; index < m_callLayout.arguments.size(); ++index) {
		const auto& location = m_callLayout.arguments[index];
		const int32_t argOffset = static_cast<int32_t>(offsetof(Parameters, m_arguments)) + static_cast<int32_t>(sizeof(uint64_t) * index);
		if (location.kind == ArgumentLocation::Kind::Register) {
			a.mov(scratch, asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_registers) + sizeof(uint64_t) * location.reg));
			a.mov(asmjit::x86::ptr(sp, stateOffset + argOffset), scratch);
		} else if (is64) {
			a.mov(scratch, asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_entryStack)));
			a.mov(scratch2, asmjit::x86::ptr(scratch, location.stackOffset));
			a.mov(asmjit::x86::ptr(sp, stateOffset + argOffset), scratch2);
		} else {
			a.mov(scratch, asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_entryStack)));
			a.mov(scratch2, asmjit::x86::ptr(scratch, location.stackOffset));
			a.mov(asmjit::x86::ptr(sp, stateOffset + argOffset), scratch2);
			if (getTypeWidth(paramTypes[index], arch) == 8) {
				a.mov(scratch2, asmjit::x86::ptr(scratch, location.stackOffset + 4));
				a.mov(asmjit::x86::ptr(sp, stateOffset + argOffset + sizeof(uint32_t)), scratch2);
			}
		}
	}

	if (is64) {
		a.lea(asmjit::x86::rcx, asmjit::x86::ptr(sp, stateOffset));
		a.mov(asmjit::x86::edx, static_cast<uint8_t>(paramTypes.size()));
		a.lea(asmjit::x86::r8, asmjit::x86::ptr(sp, static_cast<int32_t>(stateOffset + retOffset)));
		a.mov(scratch2, reinterpret_cast<uint64_t>(callback));
		a.call(scratch2);
	} else {
		a.lea(asmjit::x86::eax, asmjit::x86::ptr(sp, stateOffset));
		a.lea(asmjit::x86::ebx, asmjit::x86::ptr(sp, static_cast<int32_t>(stateOffset + retOffset)));
		a.mov(asmjit::x86::edx, reinterpret_cast<uint64_t>(callback));
		a.push(asmjit::x86::ebx);
		a.push(static_cast<uint8_t>(paramTypes.size()));
		a.push(asmjit::x86::eax);
		a.call(asmjit::x86::edx);
		a.add(asmjit::x86::esp, 12);
	}

	asmjit::Label callOriginal = a.newLabel();
	asmjit::Label redirectInstructionPointer = a.newLabel();
	asmjit::Label finishEarly = a.newLabel();
	asmjit::Label finishOriginal = a.newLabel();
	asmjit::Label sharedReturn = a.newLabel();
	a.cmp(asmjit::x86::byte_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_redirect)), 0);
	a.jne(redirectInstructionPointer);
	a.cmp(asmjit::x86::byte_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_callOriginal)), 0);
	a.jne(callOriginal);
	a.jmp(finishEarly);

	a.bind(callOriginal);
	if (frameSize != 0) a.sub(sp, frameSize);
	a.lea(stateBase, asmjit::x86::ptr(sp, static_cast<int32_t>(frameSize + stateOffset)));
	for (size_t index = 0; index < m_callLayout.arguments.size(); ++index) {
		const auto& location = m_callLayout.arguments[index];
		if (location.kind != ArgumentLocation::Kind::Stack) continue;
		const int32_t argOffset = static_cast<int32_t>(offsetof(Parameters, m_arguments)) + static_cast<int32_t>(sizeof(uint64_t) * index);
		const uint32_t stackDestination = static_cast<uint32_t>(location.stackOffset - static_cast<int32_t>(pointerSize));
		const uint8_t width = getTypeWidth(paramTypes[index], arch);
		if (is64) {
			a.mov(scratch, asmjit::x86::ptr(stateBase, argOffset));
			a.mov(asmjit::x86::ptr(sp, stackDestination), scratch);
		} else if (width == 8) {
			a.mov(scratch2, asmjit::x86::ptr(stateBase, argOffset));
			a.mov(scratch, asmjit::x86::ptr(stateBase, argOffset + sizeof(uint32_t)));
			a.mov(asmjit::x86::dword_ptr(sp, stackDestination), scratch2);
			a.mov(asmjit::x86::dword_ptr(sp, stackDestination + sizeof(uint32_t)), scratch);
		} else {
			a.mov(scratch2, asmjit::x86::ptr(stateBase, argOffset));
			asmjit::x86::Mem destination = asmjit::x86::ptr(sp, stackDestination);
			destination.setSize(width);
			a.mov(destination, scratch2);
		}
	}

	const uint32_t stateBaseRegister = is64 ? SIGILHOOK_REGISTER_R11 : SIGILHOOK_REGISTER_BP;
	const uint32_t stateCopyRegister = is64 ? SIGILHOOK_REGISTER_R12 : SIGILHOOK_REGISTER_DX;
	for (uint32_t reg = 0; reg < registerCount; ++reg) {
		if (reg == SIGILHOOK_REGISTER_SP || reg == stateBaseRegister) continue;
		a.mov(gpRegister(arch, reg), asmjit::x86::ptr(stateBase, offsetof(Parameters, m_registers) + sizeof(uint64_t) * reg));
	}
	a.mov(stateBase, asmjit::x86::ptr(stateBase, offsetof(Parameters, m_registers) + sizeof(uint64_t) * stateBaseRegister));
	if (is64) a.push(asmjit::x86::qword_ptr(sp, static_cast<int32_t>(frameSize + stateOffset + offsetof(Parameters, m_flags))));
	else a.push(asmjit::x86::dword_ptr(sp, static_cast<int32_t>(frameSize + stateOffset + offsetof(Parameters, m_flags))));
	if (is64) a.popfq();
	else a.popfd();
	asmjit::x86::Mem trampolinePointer = asmjit::x86::ptr(reinterpret_cast<uint64_t>(getTrampolineHolder()));
	trampolinePointer.setSize(pointerSize);
	a.call(trampolinePointer);
	const uint32_t afterCallAdjustment = frameSize - m_callLayout.calleeCleanup;
	if (afterCallAdjustment != 0) a.add(sp, afterCallAdjustment);
	if (m_callLayout.returnRegister >= 0) {
		a.cmp(asmjit::x86::byte_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_overrideReturn)), 0);
		asmjit::Label keepOriginalReturn = a.newLabel();
		a.jne(keepOriginalReturn);
		asmjit::x86::Mem originalReturn = asmjit::x86::ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_retVal));
		originalReturn.setSize(returnWidth);
		a.mov(originalReturn, gpRegister(arch, m_callLayout.returnRegister));
		a.bind(keepOriginalReturn);
	}
	a.jmp(finishOriginal);

	a.bind(finishOriginal);
	if (m_callLayout.returnRegister >= 0) {
		a.cmp(asmjit::x86::byte_ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_overrideReturn)), 0);
		asmjit::Label keepOriginalReturn = a.newLabel();
		a.je(keepOriginalReturn);
		asmjit::x86::Mem overriddenReturn = asmjit::x86::ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_retVal));
		overriddenReturn.setSize(returnWidth);
		a.mov(gpRegister(arch, m_callLayout.returnRegister), overriddenReturn);
		a.bind(keepOriginalReturn);
	}
	a.jmp(sharedReturn);

	a.bind(finishEarly);
	if (m_callLayout.returnRegister >= 0) {
		asmjit::x86::Mem resultValue = asmjit::x86::ptr(sp, stateOffset + retOffset + offsetof(ReturnValue, m_retVal));
		resultValue.setSize(returnWidth);
		a.mov(scratch2, resultValue);
		a.mov(asmjit::x86::ptr(sp, stateOffset + offsetof(Parameters, m_registers) + sizeof(uint64_t) * m_callLayout.returnRegister), scratch2);
	}
	a.lea(stateBase, asmjit::x86::ptr(sp, stateOffset));
	for (uint32_t reg = 0; reg < registerCount; ++reg) {
		if (reg == SIGILHOOK_REGISTER_SP || reg == stateBaseRegister) continue;
		a.mov(gpRegister(arch, reg), asmjit::x86::ptr(stateBase, offsetof(Parameters, m_registers) + sizeof(uint64_t) * reg));
	}
	a.mov(stateBase, asmjit::x86::ptr(stateBase, offsetof(Parameters, m_registers) + sizeof(uint64_t) * stateBaseRegister));
	a.jmp(sharedReturn);

	a.bind(redirectInstructionPointer);
	a.lea(stateBase, asmjit::x86::ptr(sp, stateOffset));
	const uint32_t redirectAddressReg = is64 ? SIGILHOOK_REGISTER_R10 : SIGILHOOK_REGISTER_AX;
	a.mov(gpRegister(arch, redirectAddressReg), asmjit::x86::ptr(stateBase, retOffset + offsetof(ReturnValue, m_redirectAddress)));
	for (uint32_t reg = 0; reg < registerCount; ++reg) {
		if (reg == SIGILHOOK_REGISTER_SP || reg == stateBaseRegister || reg == redirectAddressReg) continue;
		a.mov(gpRegister(arch, reg), asmjit::x86::ptr(stateBase, offsetof(Parameters, m_registers) + sizeof(uint64_t) * reg));
	}
	a.mov(stateCopy, stateBase);
	a.mov(stateBase, asmjit::x86::ptr(stateBase, offsetof(Parameters, m_registers) + sizeof(uint64_t) * stateBaseRegister));
	if (is64) a.push(asmjit::x86::qword_ptr(sp, stateOffset + offsetof(Parameters, m_flags)));
	else a.push(asmjit::x86::dword_ptr(sp, stateOffset + offsetof(Parameters, m_flags)));
	if (is64) a.popfq(); else a.popfd();
	a.mov(sp, asmjit::x86::ptr(stateCopy, offsetof(Parameters, m_entryStack)));
	a.mov(stateCopy, asmjit::x86::ptr(stateCopy, offsetof(Parameters, m_registers) + sizeof(uint64_t) * stateCopyRegister));
	a.jmp(gpRegister(arch, redirectAddressReg));
	a.bind(sharedReturn);
	if (is64) {
		a.push(asmjit::x86::qword_ptr(sp, stateOffset + offsetof(Parameters, m_flags)));
		a.popfq();
	} else {
		a.push(asmjit::x86::dword_ptr(sp, stateOffset + offsetof(Parameters, m_flags)));
		a.popfd();
	}
	// LEA restores the stack without disturbing the flags restored above.
	a.lea(sp, asmjit::x86::ptr(sp, static_cast<int32_t>(allocationSize)));
	a.ret(m_callLayout.calleeCleanup);

	return allocateCode(code, logger);
}

uint64_t SIGILHOOK::ILCallback::getJitFunc(
	const std::string& retType,
	const std::vector<std::string>& paramTypes,
	const asmjit::Arch arch,
	const tUserCallback callback,
	std::string callConv) {
	asmjit::CallConvId callConvId = asmjit::CallConvId::kCDecl;
	std::string error;
	if (paramTypes.size() > Parameters::kMaxArguments) {
		fail("Invalid callback argument count exceeds 32");
		return 0;
	}
	if (!parseCallLayout(callConv, retType, paramTypes, arch, &callConvId, &error)) return 0;
	if (m_callLayout.usercall) return getUsercallJitFunc(retType, paramTypes, arch, callback);

	const asmjit::TypeId returnTypeId = getTypeId(retType);
	if (retType != "void" && returnTypeId == asmjit::TypeId::kVoid) {
		fail("Unsupported ILCallback return type: " + retType);
		return 0;
	}
	asmjit::FuncSignature sig(callConvId, asmjit::FuncSignature::kNoVarArgs, returnTypeId);
	for (const std::string& paramType : paramTypes) {
		const asmjit::TypeId typeId = getTypeId(paramType);
		if (typeId == asmjit::TypeId::kVoid) {
			fail("Unsupported ILCallback parameter type: " + paramType);
			return 0;
		}
		sig.addArg(typeId);
	}

	const uint32_t pointerSize = pointerSizeFromArch(arch);
	bool canUseRegisterStub = (retType == "void" || getTypeWidth(retType, arch) <= pointerSize);
	for (const std::string& paramType : paramTypes) {
		const asmjit::TypeId typeId = getTypeId(paramType);
		// Route all GPR-only signatures through the explicit-layout stub so stack
		// arguments, register writeback, flags, and IP redirection stay consistent.
		canUseRegisterStub = canUseRegisterStub && isGeneralReg(typeId);
	}

	if (canUseRegisterStub) {
		asmjit::FuncDetail detail;
		auto environment = asmjit::Environment::host();
		environment.setArch(arch);
		if (detail.init(sig, environment) == asmjit::kErrorOk && (!sig.hasRet() || detail.retPack().count() == 1)) {
			CallLayout layout;
			layout.usercall = true;
			if (detail.hasFlag(asmjit::CallConvFlags::kCalleePopsStack)) layout.calleeCleanup = detail.argStackSize();
			layout.arguments.resize(paramTypes.size());
			bool supported = true;
			for (size_t index = 0; index < paramTypes.size(); ++index) {
				if (detail.argPack(index).count() != 1) {
					supported = false;
					break;
				}
				const asmjit::FuncValue& value = detail.arg(index);
				const uint32_t width = getTypeWidth(paramTypes[index], arch);
				if (isGpFuncValue(value)) {
					layout.arguments[index].kind = ArgumentLocation::Kind::Register;
					layout.arguments[index].reg = static_cast<uint8_t>(value.regId());
				} else if (value.isStack()) {
					const uint32_t entryOffset = pointerSize + static_cast<uint32_t>(value.stackOffset());
					layout.arguments[index].kind = ArgumentLocation::Kind::Stack;
					layout.arguments[index].stackOffset = static_cast<int32_t>(entryOffset);
					layout.stackArgumentBytes = (std::max)(layout.stackArgumentBytes, entryOffset + (width == 8 ? 8u : pointerSize));
				} else {
					supported = false;
					break;
				}
			}
			if (sig.hasRet()) {
				const asmjit::FuncValue& value = detail.ret();
				if (isGpFuncValue(value)) layout.returnRegister = static_cast<int>(value.regId());
				else supported = false;
			}
			if (supported) {
				m_callLayout = std::move(layout);
				return getUsercallJitFunc(retType, paramTypes, arch, callback);
			}
		}
	}

	return getJitFunc(sig, arch, callback);
}

uint64_t* SIGILHOOK::ILCallback::getTrampolineHolder() {
	return &m_trampolinePtr;
}

bool SIGILHOOK::ILCallback::isGeneralReg(const asmjit::TypeId typeId) const {
	switch (typeId) {
	case asmjit::TypeId::kInt8:
	case asmjit::TypeId::kUInt8:
	case asmjit::TypeId::kInt16:
	case asmjit::TypeId::kUInt16:
	case asmjit::TypeId::kInt32:
	case asmjit::TypeId::kUInt32:
	case asmjit::TypeId::kInt64:
	case asmjit::TypeId::kUInt64:
	case asmjit::TypeId::kIntPtr:
	case asmjit::TypeId::kUIntPtr:
		return true;
	default:
		return false;
	}
}

bool SIGILHOOK::ILCallback::isXmmReg(const asmjit::TypeId typeId) const {
	switch (typeId) {
	case asmjit::TypeId::kFloat32:
	case asmjit::TypeId::kFloat64:
		return true;
	default:
		return false;
	}
}

SIGILHOOK::ILCallback::ILCallback() {
	m_callbackBuf = 0;
	m_trampolinePtr = 0;
}

SIGILHOOK::ILCallback::~ILCallback() {
	if (m_callbackBuf != 0) {
		operator delete(reinterpret_cast<void*>(m_callbackBuf), std::align_val_t{16});
	}
}
