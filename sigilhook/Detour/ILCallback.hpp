#ifndef SIGILHOOK_ILCALLBACK_HPP
#define SIGILHOOK_ILCALLBACK_HPP

#pragma warning(push, 0)  
#include <asmjit/x86.h>
#pragma warning( pop )

#pragma warning( disable : 4200)
#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/ErrorLog.hpp"
#include "sigilhook/Enums.hpp"
#include "sigilhook/MemAccessor.hpp"

namespace SIGILHOOK {
	class ILCallback : public MemAccessor {
	public:
		struct Parameters {
			template<typename T>
			void setArg(const uint8_t idx, const T val) const {
				*(T*)getArgPtr(idx) = val;
			}

			template<typename T>
			T getArg(const uint8_t idx) const {
				return *(T*)getArgPtr(idx);
			}

			// asm depends on this specific type
			// we the ILCallback allocates stack space that is set to point here
			volatile uint64_t m_arguments;
		private:
			// must be char* for aliasing rules to work when reading back out
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

		typedef void(*tUserCallback)(const Parameters* params, const uint8_t count, const ReturnValue* ret);

		ILCallback();
		~ILCallback();

		/* Construct a callback given the raw signature at runtime. 'Callback' param is the C stub to transfer to,
		where parameters can be modified through a structure which is written back to the parameter slots depending
		on calling convention.*/
		uint64_t getJitFunc(const asmjit::FuncSignature& sig, const asmjit::Arch arch, const tUserCallback callback);

		/* Construct a callback given the typedef as a string. Types are any valid C/C++ data type (basic types), and pointers to
		anything are just a uintptr_t. Calling convention is defaulted to whatever is typical for the compiler you use, you can override with
		stdcall, fastcall, or cdecl (cdecl is default on x86). On x64 those map to the same thing.*/
		uint64_t getJitFunc(const std::string& retType, const std::vector<std::string>& paramTypes, const asmjit::Arch arch, const tUserCallback callback, std::string callConv = "");
		uint64_t* getTrampolineHolder();
		uint8_t getTypeWidth(const std::string& type) const;
	private:
		// does a given type fit in a general purpose register (i.e. is it integer type)
		bool isGeneralReg(const asmjit::TypeId typeId) const;
		// float, double, simd128
		bool isXmmReg(const asmjit::TypeId typeId) const;

		asmjit::CallConvId getCallConv(const std::string& conv);
		asmjit::TypeId getTypeId(const std::string& type) const;

		uint64_t m_callbackBuf;
		asmjit::x86::Mem argsStack;

		// ptr to trampoline allocated by hook, we hold this so user doesn't need to.
		uint64_t m_trampolinePtr;
	};
}
#endif // SIGILHOOK_ILCALLBACK_HPP
