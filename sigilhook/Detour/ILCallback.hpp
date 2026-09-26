// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
// Derived from PolyHook 2; see LICENSE and THIRD_PARTY_NOTICES.md.
#ifndef SIGILHOOK_ILCALLBACK_HPP
#define SIGILHOOK_ILCALLBACK_HPP

#pragma warning(push, 0)
#include <asmjit/x86.h>
#pragma warning(pop)

#pragma warning(disable : 4200)
#include "include/sigilhook.h"
#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/ErrorLog.hpp"
#include "sigilhook/Enums.hpp"
#include "sigilhook/MemAccessor.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace SIGILHOOK {
	class ILCallback : public MemAccessor {
	public:
		struct Parameters {
			static constexpr uint8_t kMaxArguments = 32;

			template<typename T>
			void setArg(const uint8_t idx, const T val) const {
				*(T*)getArgPtr(idx) = val;
			}

			template<typename T>
			T getArg(const uint8_t idx) const {
				return *(T*)getArgPtr(idx);
			}

			// The generated stub and the callback bridge depend on this layout.
			volatile uint64_t m_arguments[kMaxArguments];
			uint64_t m_registers[SIGILHOOK_REGISTER_COUNT];
			uint64_t m_flags;
			uint64_t m_writeMask;
			uint64_t m_entryStack;

		private:
			char* getArgPtr(const uint8_t idx) const {
				return ((char*)&m_arguments) + sizeof(uint64_t) * idx;
			}
		};

		struct ReturnValue {
			unsigned char* getRetPtr() const {
				return (unsigned char*)&m_retVal;
			}
			uint64_t m_retVal;
			uint8_t m_callOriginal;
			uint8_t m_overrideReturn;
		};

		struct ArgumentLocation {
			enum class Kind : uint8_t {
				Register,
				Stack
			};

			Kind kind = Kind::Register;
			uint8_t reg = SIGILHOOK_REGISTER_AX;
			int32_t stackOffset = 0;
		};

		struct CallLayout {
			bool usercall = false;
			uint32_t calleeCleanup = 0;
			uint32_t stackArgumentBytes = 0;
			int returnRegister = -1;
			std::vector<ArgumentLocation> arguments;
		};

		typedef void(*tUserCallback)(const Parameters* params, const uint8_t count, const ReturnValue* ret);
		typedef uint64_t(*tInvokeCallback)(const uint64_t* arguments);

		ILCallback();
		~ILCallback();

		uint64_t getJitFunc(const asmjit::FuncSignature& sig, const asmjit::Arch arch, const tUserCallback callback);

		// Supported standard conventions are cdecl, stdcall, fastcall, thiscall, and vectorcall.
		// A custom convention has the form:
		//   usercall:ret=eax;arg0=ecx;arg1=stack+8;cleanup=8
		uint64_t getJitFunc(
			const std::string& retType,
			const std::vector<std::string>& paramTypes,
			const asmjit::Arch arch,
			const tUserCallback callback,
			std::string callConv = "");

		uint64_t getInvokeJitFunc(
			const std::string& retType,
			const std::vector<std::string>& paramTypes,
			uint64_t target,
			const std::string& callConv);

		uint64_t* getTrampolineHolder();
		uint8_t getTypeWidth(const std::string& type) const;
		const CallLayout& callLayout() const;
		sigilhook_status lastErrorStatus() const;
		const std::string& lastError() const;

	private:
		bool isGeneralReg(const asmjit::TypeId typeId) const;
		bool isXmmReg(const asmjit::TypeId typeId) const;

		asmjit::CallConvId getCallConv(const std::string& conv) const;
		asmjit::TypeId getTypeId(const std::string& type) const;
		bool parseCallLayout(
			const std::string& callConv,
			const std::string& retType,
			const std::vector<std::string>& paramTypes,
			asmjit::Arch arch,
			asmjit::CallConvId* outCallConv,
			std::string* outError);
		uint64_t getUsercallJitFunc(
			const std::string& retType,
			const std::vector<std::string>& paramTypes,
			asmjit::Arch arch,
			const tUserCallback callback);

		bool fail(const std::string& message);
		uint64_t allocateCode(asmjit::CodeHolder& code, asmjit::StringLogger& logger);

		uint64_t m_callbackBuf;
		asmjit::x86::Mem argsStack;
		uint64_t m_trampolinePtr;
		CallLayout m_callLayout;
		std::string m_lastError;
		sigilhook_status m_lastErrorStatus = SIGILHOOK_ERROR_SCRIPT;
	};
}
#endif // SIGILHOOK_ILCALLBACK_HPP
