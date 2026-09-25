#ifndef SIGILHOOK_VFUNCSWAPHOOK_HPP
#define SIGILHOOK_VFUNCSWAPHOOK_HPP

#include "sigilhook/SigilHookOs.hpp"
#include "sigilhook/IHook.hpp"
#include "sigilhook/MemProtector.hpp"
#include "sigilhook/Misc.hpp"

namespace SIGILHOOK {
typedef std::map<uint16_t, uint64_t> VFuncMap;


class VFuncSwapHook : public SIGILHOOK::IHook {
public:
	VFuncSwapHook(const uint64_t Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs);
	VFuncSwapHook(const char* Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs);
	virtual ~VFuncSwapHook() {
		if (m_hooked) {
			unHook();
		}
	}

	virtual bool hook() override;
	virtual bool unHook() override;
	virtual HookType getType() const override {
		return HookType::VTableSwap;
	}
protected:
	uint16_t countVFuncs();
	uint64_t  m_class;
	uintptr_t* m_vtable;

	uint16_t  m_vFuncCount;

	// index -> ptr val 
	VFuncMap m_redirectMap;
	VFuncMap* m_userOrigMap;
};
}
#endif