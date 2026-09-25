// SPDX-License-Identifier: MIT
// Derived from PolyHook 2; see LICENSE and THIRD_PARTY_NOTICES.md.
#include "sigilhook/Detour/ILCallback.hpp"

#include "sigilhook/MemProtector.hpp"

#include <algorithm>
#include <cstddef>
#include <new>
#include <utility>

asmjit::CallConvId SIGILHOOK::ILCallback::getCallConv(const std::string& conv) {
	if (conv == "cdecl") {
		return asmjit::CallConvId::kCDecl;
	} else if (conv == "stdcall") {
		return asmjit::CallConvId::kStdCall;
	} else if (conv == "fastcall") {
		return asmjit::CallConvId::kFastCall;
	}
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

uint8_t SIGILHOOK::ILCallback::getTypeWidth(const std::string& type) const {
	const asmjit::TypeId typeId = getTypeId(type);
	return typeId == asmjit::TypeId::kVoid ? 0 : static_cast<uint8_t>(asmjit::TypeUtils::sizeOf(typeId));
}

uint64_t SIGILHOOK::ILCallback::getJitFunc(
	const asmjit::FuncSignature& sig,
	const asmjit::Arch arch,
	const SIGILHOOK::ILCallback::tUserCallback callback) {
	if (m_callbackBuf != 0) {
		Log::log("ILCallback JIT stub already exists", ErrorLevel::SEV);
		return 0;
	}
	if (callback == nullptr) {
		Log::log("ILCallback requires a callback", ErrorLevel::SEV);
		return 0;
	}

	asmjit::CodeHolder code;
	auto env = asmjit::Environment::host();
	env.setArch(arch);
	const asmjit::Error initError = code.init(env);
	if (initError != asmjit::kErrorOk) {
		Log::log(std::string("ILCallback CodeHolder init failed: ") + asmjit::DebugUtils::errorAsString(initError), ErrorLevel::SEV);
		return 0;
	}

	asmjit::x86::Compiler cc(&code);
	asmjit::FuncNode* func = cc.addFunc(sig);

	asmjit::StringLogger log;
	auto formatFlags =
		asmjit::FormatFlags::kMachineCode | asmjit::FormatFlags::kExplainImms | asmjit::FormatFlags::kRegCasts |
		asmjit::FormatFlags::kHexImms | asmjit::FormatFlags::kHexOffsets | asmjit::FormatFlags::kPositions;
	log.addFlags(formatFlags);
	code.setLogger(&log);

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
			Log::log("Parameters wider than 64 bits are not supported", ErrorLevel::SEV);
			return 0;
		}
		func->setArg(argIndex, arg);
		argRegisters.push_back(arg);
	}

	const uint32_t stackSize = static_cast<uint32_t>(
		sizeof(uint64_t) * (std::max)(size_t{1}, static_cast<size_t>(sig.argCount())));
	argsStack = cc.newStack(stackSize, 16);
	asmjit::x86::Mem argsStackIndex(argsStack);
	asmjit::x86::Gp argOffset = cc.newUIntPtr();
	argsStackIndex.setIndex(argOffset);
	argsStackIndex.setSize(sizeof(uint64_t));

	cc.mov(argOffset, 0);
	for (uint8_t argIndex = 0; argIndex < sig.argCount(); ++argIndex) {
		const asmjit::TypeId argType = sig.args()[argIndex];
		if (isGeneralReg(argType)) {
			cc.mov(argsStackIndex, argRegisters[argIndex].as<asmjit::x86::Gp>());
		} else {
			cc.movq(argsStackIndex, argRegisters[argIndex].as<asmjit::x86::Vec>());
		}
		cc.add(argOffset, sizeof(uint64_t));
	}

	asmjit::x86::Gp argStruct = cc.newUIntPtr("argStruct");
	cc.lea(argStruct, argsStack);
	asmjit::x86::Gp argCountParam = cc.newUInt8();
	cc.mov(argCountParam, static_cast<uint8_t>(sig.argCount()));

	asmjit::x86::Mem retStack = cc.newStack(sizeof(ReturnValue), 16);
	asmjit::x86::Gp retStruct = cc.newUIntPtr("retStruct");
	cc.lea(retStruct, retStack);
	cc.mov(asmjit::x86::dword_ptr(retStruct, offsetof(ReturnValue, m_retVal)), 0);
	cc.mov(asmjit::x86::dword_ptr(retStruct, offsetof(ReturnValue, m_retVal) + sizeof(uint32_t)), 0);
	cc.mov(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_callOriginal)), 1);
	cc.mov(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_overrideReturn)), 0);

	asmjit::InvokeNode* invokeNode = nullptr;
	cc.invoke(
		&invokeNode,
		reinterpret_cast<uint64_t>(callback),
		asmjit::FuncSignature::build<void, Parameters*, uint8_t, ReturnValue*>());
	invokeNode->setArg(0, argStruct);
	invokeNode->setArg(1, argCountParam);
	invokeNode->setArg(2, retStruct);

	cc.mov(argOffset, 0);
	for (uint8_t argIndex = 0; argIndex < sig.argCount(); ++argIndex) {
		const asmjit::TypeId argType = sig.args()[argIndex];
		if (isGeneralReg(argType)) {
			cc.mov(argRegisters[argIndex].as<asmjit::x86::Gp>(), argsStackIndex);
		} else {
			cc.movq(argRegisters[argIndex].as<asmjit::x86::Vec>(), argsStackIndex);
		}
		cc.add(argOffset, sizeof(uint64_t));
	}

	asmjit::x86::Gp originalPointer = cc.zbx();
	cc.mov(originalPointer, reinterpret_cast<uintptr_t>(getTrampolineHolder()));
	cc.mov(originalPointer, asmjit::x86::ptr(originalPointer));

	asmjit::Label skipOriginal = cc.newLabel();
	asmjit::Label finish = cc.newLabel();
	cc.cmp(asmjit::x86::byte_ptr(retStruct, offsetof(ReturnValue, m_callOriginal)), 0);
	cc.je(skipOriginal);

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
	const asmjit::Error endFuncError = cc.endFunc();
	if (endFuncError != asmjit::kErrorOk) {
		Log::log(std::string("ILCallback endFunc failed: ") + asmjit::DebugUtils::errorAsString(endFuncError), ErrorLevel::SEV);
		return 0;
	}
	const asmjit::Error finalizeError = cc.finalize();
	if (finalizeError != asmjit::kErrorOk) {
		Log::log(std::string("ILCallback finalize failed: ") + asmjit::DebugUtils::errorAsString(finalizeError), ErrorLevel::SEV);
		return 0;
	}
	const asmjit::Error flattenError = code.flatten();
	if (flattenError != asmjit::kErrorOk) {
		Log::log(std::string("ILCallback flatten failed: ") + asmjit::DebugUtils::errorAsString(flattenError), ErrorLevel::SEV);
		return 0;
	}

	const size_t size = code.codeSize();
	m_callbackBuf = reinterpret_cast<uint64_t>(
		operator new(size, std::align_val_t{16}, std::nothrow));
	if (m_callbackBuf == 0) {
		Log::log("Failed to allocate ILCallback JIT memory", ErrorLevel::SEV);
		return 0;
	}
	MemoryProtector writer(m_callbackBuf, size, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
	const asmjit::Error resolveError = code.resolveCrossSectionFixups();
	if (resolveError != asmjit::kErrorOk) {
		Log::log(std::string("ILCallback fixup resolution failed: ") + asmjit::DebugUtils::errorAsString(resolveError), ErrorLevel::SEV);
		operator delete(reinterpret_cast<void*>(m_callbackBuf), std::align_val_t{16});
		m_callbackBuf = 0;
		return 0;
	}

	const asmjit::Error relocateError = code.relocateToBase(m_callbackBuf);
	if (relocateError != asmjit::kErrorOk) {
		Log::log(std::string("ILCallback relocation failed: ") + asmjit::DebugUtils::errorAsString(relocateError), ErrorLevel::SEV);
		operator delete(reinterpret_cast<void*>(m_callbackBuf), std::align_val_t{16});
		m_callbackBuf = 0;
		return 0;
	}
	code.copyFlattenedData(reinterpret_cast<unsigned char*>(m_callbackBuf), size);
	MemoryProtector executable(m_callbackBuf, size, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
	if (!executable.isGood()) {
		Log::log("ILCallback failed to make JIT memory executable", ErrorLevel::SEV);
		operator delete(reinterpret_cast<void*>(m_callbackBuf), std::align_val_t{16});
		m_callbackBuf = 0;
		return 0;
	}

	Log::log("JIT Stub:\n" + std::string(log.data()), ErrorLevel::INFO);
	return m_callbackBuf;
}

uint64_t SIGILHOOK::ILCallback::getJitFunc(
	const std::string& retType,
	const std::vector<std::string>& paramTypes,
	const asmjit::Arch arch,
	const tUserCallback callback,
	std::string callConv) {
	const asmjit::TypeId returnTypeId = getTypeId(retType);
	if (retType != "void" && returnTypeId == asmjit::TypeId::kVoid) {
		Log::log("Unsupported ILCallback return type: " + retType, ErrorLevel::SEV);
		return 0;
	}

	asmjit::FuncSignature sig(getCallConv(callConv), asmjit::FuncSignature::kNoVarArgs, returnTypeId);
	for (const std::string& paramType : paramTypes) {
		const asmjit::TypeId typeId = getTypeId(paramType);
		if (typeId == asmjit::TypeId::kVoid) {
			Log::log("Unsupported ILCallback parameter type: " + paramType, ErrorLevel::SEV);
			return 0;
		}
		sig.addArg(typeId);
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
